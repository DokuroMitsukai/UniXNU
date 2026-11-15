"""Userdata payload: the raw image for the device's `userdata` partition.

It holds the unchanged OS and SystemOS disk images of the IPSW, byte for byte, behind a small manifest
(the SHNGROOT layout the native UFS root driver reads):

    0x000000  manifest block (4096 bytes), zero padding to 1 MiB
    0x100000  window "OS"        the whole attached OS disk image, 1 MiB aligned
    ....      window "SystemOS"  the whole attached SystemOS disk image, 1 MiB aligned
    ....      object "OS.vroot"  an optional version-2 data object, 4096 aligned

Manifest (little endian): "SHNGROOT", u32 version, u32 count, u64 image_bytes, then `count` 128-byte
entries {char name[32], u64 offset, u64 size, u32 block_size, u32 flags, u8 sha256[32], 40 reserved},
and at byte 4064 the SHA-256 of bytes 0..4063. Version 1 holds only block windows (block size 512,
flags 1). Version 2 adds data objects the kernel reads itself (block size 4096, flags 3); objects are
listed in board.toml `[userdata] objects = [{ name, path }]` and are never published as block devices.

The images come from the IPSW (a local file or a remote URL, see ipsw.py) and are checked against the pins of
board.toml. The raw disk of each disk image is read without mounting: attached read-only with hdiutil on macOS,
decoded by udif.py on other hosts. Nothing is flashed: the report prints the fastboot command, to be run by the user.
"""
import contextlib
import hashlib
import json
import platform
import plistlib
import re
import struct
import subprocess

from . import udif
from .ipsw import Ipsw
from .util import Error, log, run, sha256_file, tool

MIB = 1 << 20
CHUNK = 8 * MIB


def paths(ctx):
    out = ctx.work / 'userdata'
    return out, out / 'userdata-root.img', out / 'userdata-root.json'


def image_size(dmg):
    if platform.system() != 'Darwin':
        return udif.Image(dmg).size
    info = subprocess.run(['hdiutil', 'imageinfo', '-plist', str(dmg)], capture_output=True, check=True).stdout
    return plistlib.loads(info)['Size Information']['Total Bytes']


def attach(dmg):
    """Attach read-only without mounting; return the whole-disk device."""
    out = subprocess.run(['hdiutil', 'attach', '-nomount', '-readonly', '-noverify', '-noautofsck', str(dmg)],
                         capture_output=True, text=True, check=True).stdout
    for line in out.splitlines():
        match = re.match(r'(/dev/disk\d+)\s', line)
        if match:
            return match.group(1)
    raise Error('could not find the attached disk device')


def disk_blocks(dmg, size):
    """The raw disk of a disk image, in order: hdiutil's /dev/rdiskN on macOS, udif.py on other hosts."""
    if platform.system() != 'Darwin':
        yield from udif.Image(dmg).blocks()
        return
    device = attach(dmg)
    try:
        raw = device.replace('/dev/disk', '/dev/rdisk')
        done = 0
        with open(raw, 'rb', buffering=0) as handle:
            while done < size:
                want = min(CHUNK, size - done)
                data = handle.read(want)
                if len(data) != want:
                    raise Error(f'short read from {raw} at {done}')
                yield data
                done += want
    finally:
        subprocess.run(['hdiutil', 'detach', device], capture_output=True)


def manifest_bytes(version, entries, image_bytes):
    """Serialize the 4096-byte SHNGROOT header; entries are (name, offset, size, block_size, flags, sha256)."""
    header = bytearray(4096)
    header[0:8] = b'SHNGROOT'
    struct.pack_into('<IIQ', header, 8, version, len(entries), image_bytes)
    for index, (name, offset, size, block_size, flags, digest) in enumerate(entries):
        struct.pack_into('<32sQQII32s40s', header, 24 + 128 * index,
                         name.encode(), offset, size, block_size, flags, digest, bytes(40))
    header[4064:4096] = hashlib.sha256(bytes(header[:4064])).digest()
    return header


def build(ctx, dry_run=False):
    log('userdata payload')
    spec = ctx.board.get('userdata')
    if not spec:
        raise Error('board.toml has no [userdata]')
    if platform.system() == 'Darwin':
        tool('hdiutil', 'the disk images are attached with macOS hdiutil')
    source = Ipsw(ctx)
    capacity = (spec['last_lba'] - spec['first_lba'] + 1) * spec.get('lba_bytes', 4096)
    objects = []
    for item in spec.get('objects', []):
        path = ctx.device / item['path']
        if not path.is_file():
            raise Error(f'userdata object source not found: {path}')
        size = path.stat().st_size
        if size <= 0:
            raise Error(f'userdata object is empty: {path}')
        objects.append((item['name'], path, size))
    if len(spec['windows']) > 4 or len(objects) > 4:
        raise Error('userdata supports at most 4 windows and 4 objects')
    names = [window['name'] for window in spec['windows']] + [name for name, _, _ in objects]
    if len(names) != len(set(names)):
        raise Error('userdata window and object names must be unique')
    if dry_run:
        for window in spec['windows']:
            name, size, _ = source.info(window['component'])
            log(f'userdata: {window["name"]} would be extracted from {name} ({size >> 20} MiB)')
        for name, path, size in objects:
            log(f'userdata: object {name} would be copied from {path} ({size} bytes)')
        log('userdata: dry run, nothing extracted or written')
        return None
    sources = [(window['name'], source.extract(window['component'])) for window in spec['windows']]
    layout, cursor = [], MIB
    for name, dmg in sources:
        size = image_size(dmg)
        layout.append((name, cursor, size, 512, 1))
        cursor += (size + MIB - 1) // MIB * MIB
    for name, path, size in objects:
        layout.append((name, cursor, size, 4096, 3))
        cursor = (cursor + size + 4095) // 4096 * 4096
    total = (cursor + 4095) // 4096 * 4096
    version = 2 if objects else 1
    log(f'userdata: image {total} bytes ({total / 2**30:.2f} GiB) in a partition of {capacity} bytes, '
        f'manifest version {version}')
    if total > capacity:
        raise Error('the image is larger than the userdata partition')
    for name, dmg in sources:
        log(f'userdata: {name} from {dmg.name}')
    for name, path, size in objects:
        log(f'userdata: {name} from {path}')
    out, image, report = paths(ctx)
    out.mkdir(parents=True, exist_ok=True)
    entries = []
    offset_of = {name: offset for name, offset, _, _, _ in layout}
    with image.open('wb') as target:
        target.truncate(total)
        for name, dmg in sources:
            offset = offset_of[name]
            size = image_size(dmg)
            digest = hashlib.sha256()
            target.seek(offset)
            done = 0
            with contextlib.closing(disk_blocks(dmg, size)) as blocks:
                for data in blocks:
                    digest.update(data)
                    target.write(data)
                    done += len(data)
            if done != size:
                raise Error(f'{dmg.name}: {done} bytes of raw disk, expected {size}')
            entries.append((name, offset, size, 512, 1, digest.digest()))
            log(f'userdata: {name} {size} bytes at {offset:#x} sha256 {digest.hexdigest()}')
        for name, path, size in objects:
            offset = offset_of[name]
            digest = hashlib.sha256()
            target.seek(offset)
            with path.open('rb') as source_file:
                done = 0
                while done < size:
                    data = source_file.read(min(CHUNK, size - done))
                    if not data:
                        raise Error(f'{path}: short read at {done}')
                    digest.update(data)
                    target.write(data)
                    done += len(data)
            entries.append((name, offset, size, 4096, 3, digest.digest()))
            log(f'userdata: {name} object {size} bytes at {offset:#x} sha256 {digest.hexdigest()}')
        header = manifest_bytes(version, entries, total)
        target.seek(0)
        target.write(header)
    windows = [entry for entry in entries if entry[3] == 512]
    data = {'image_bytes': total, 'image_sha256': sha256_file(image), 'manifest_version': version,
            'manifest_sha256': hashlib.sha256(bytes(header)).hexdigest(),
            'windows': [{'name': n, 'offset': o, 'size': s, 'sha256': d.hex()} for n, o, s, _, _, d in windows],
            'objects': [{'name': n, 'offset': o, 'size': s, 'sha256': d.hex()}
                        for n, o, s, block_size, _, d in entries if block_size == 4096],
            'userdata_bytes': capacity, 'flash_command': f'fastboot flash userdata {image}',
            'source': 'remote' if source.remote else 'local', 'hardware_tested': False}
    report.write_text(json.dumps(data, indent=2) + '\n')
    log(f'userdata: {image}')
    log(f'flash it yourself with: {data["flash_command"]}')
    return image
