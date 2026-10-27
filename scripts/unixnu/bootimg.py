"""Android boot image: BootShim + UEFI FD, compressed and with the device tree appended as the
Mu-Silicium [boot_image_kernel] settings say, plus an optional ramdisk.

Inputs are a Mu-Silicium checkout (BootShim sources, Resources/Configs/<device>.toml, mkbootimg.py),
the built firmware volume and, when the device tree is appended, a compiled device tree. The image
is meant for "fastboot boot" only. The result is verified by unpacking it again; the output is
deterministic.
"""
import gzip
import hashlib
import json
import shutil
import struct
import subprocess
import tempfile
import zlib
from pathlib import Path

from .config import load_toml
from .util import Error, log, run, sha256_file, tool

DEFAULTS = {'header_version': 0, 'base': 0, 'kernel_offset': 0x8000, 'tags_offset': 0x1e00000, 'pagesize': 4096}
MKBOOTIMG_FLAGS = ('base', 'kernel_offset', 'tags_offset', 'pagesize', 'header_version', 'ramdisk_offset', 'second_offset', 'cmdline')


def compile_shim(uefi, base, size, requires_header, scratch):
    clang, objcopy, nm = tool('clang'), tool('llvm-objcopy', 'brew install llvm'), tool('llvm-nm', 'brew install llvm')
    source = uefi / 'BootShim/BootShim.S'
    if not source.is_file():
        raise Error(f'{source} missing: --uefi must be a Mu-Silicium checkout')
    obj = scratch / 'shim.o'
    run([clang, '--target=aarch64-none-elf', '-c', f'-DFD_BASE={base}', f'-DFD_SIZE={size}',
         f'-DREQUIRES_KERNEL_HEADER={int(requires_header)}', source, '-o', obj], capture=True)
    run([objcopy, '-O', 'binary', obj, scratch / 'shim.bin'], capture=True)
    shim = (scratch / 'shim.bin').read_bytes()
    symbols = run([nm, '-n', obj], capture=True)
    offset = next((int(line.split()[0], 16) for line in symbols.splitlines() if line.endswith(' _Payload')), None)
    if offset != len(shim):
        raise Error('a literal pool or padding separates the _Payload label from the appended firmware volume')
    if requires_header and (shim[56:60] != b'ARM\x64' or struct.unpack_from('<QQ', shim, 8) != (base, len(shim) + size)):
        raise Error('the ARM64 image header does not describe the shim plus the firmware volume')
    return shim


def patch_dtb(dtb, nodes, scratch):
    """Add device-tree nodes the stock bootloader expects (board.toml [[bootimg.dtb_node]])."""
    if not nodes:
        return dtb
    fdtput, fdtget = tool('fdtput', 'brew install dtc'), tool('fdtget', 'brew install dtc')
    work = scratch / 'device.dtb'
    work.write_bytes(dtb)
    for node in nodes:
        # fdtput -c refuses to touch a node that already exists (FDT_ERR_EXISTS);
        # boards commonly patch the status of existing SPI/touch nodes.
        exists = subprocess.run(
            [fdtget, '-l', str(work), node['path']],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        ).returncode == 0
        if not exists:
            run([fdtput, '-c', work, node['path']], capture=True)
        for prop in node.get('props', []):
            values = prop['value'] if isinstance(prop['value'], list) else [prop['value']]
            run([fdtput, '-t', prop.get('type', 's'), work, node['path'], prop['name'], *[str(v) for v in values]], capture=True)
            got = run([fdtget, '-t', prop.get('type', 's'), work, node['path'], prop['name']], capture=True).split()
            kind = prop.get('type', 's')
            if kind in ('x', 'i', 'u') and [int(v, 16 if kind == 'x' else 10) for v in got] != [int(str(v), 0) for v in values]:
                raise Error(f'dtb node {node["path"]} property {prop["name"]} did not round-trip')
    return work.read_bytes()


def settings(ctx, uefi):
    fw = ctx.board.get('firmware', {})
    config = load_toml(uefi / 'Resources/Configs' / f'{fw["config"]}.toml') if fw.get('config') else {}
    values = dict(DEFAULTS)
    values.update(config.get('boot_image', {}))
    values.update(ctx.board.get('bootimg', {}).get('image', {}))
    fd = config.get('uefi_fd', {})
    return values, fd.get('base'), fd.get('size'), config.get('boot_shim', {}).get('requires_kernel_header', True), config


def build(ctx, uefi, fd, dtb, ramdisk=None, output=None):
    log('bootimg')
    image, base, size, requires_header, config = settings(ctx, uefi)
    mkbootimg = uefi / 'Resources/Scripts/mkbootimg.py'
    if not mkbootimg.is_file():
        raise Error(f'{mkbootimg} missing: --uefi must be a Mu-Silicium checkout')
    if not fd or not Path(fd).is_file():
        raise Error(f'firmware volume not found: {fd}; run ./unixnu build firmware --uefi {uefi}')
    kernel_config = config.get('boot_image_kernel', {})
    compression = kernel_config.get('kernel_compression', 'gzip')
    if compression not in ('gzip', 'none'):
        raise Error(f'[boot_image_kernel] kernel_compression: unsupported value {compression!r} (gzip or none)')
    append_dtb = bool(kernel_config.get('append_dtb', True))
    if append_dtb and (not dtb or not Path(dtb).is_file()):
        raise Error(f'device tree (--dtb) not found: {dtb}')
    firmware = Path(fd).read_bytes()
    if base is None or size is None:
        raise Error('the Mu-Silicium device config has no [uefi_fd] base and size')
    if len(firmware) != size:
        raise Error(f'firmware volume is {len(firmware):#x} bytes, the device config says {size:#x}')
    out = Path(output) if output else ctx.work / 'boot/boot.img'
    out.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix='unixnu-bootimg-') as scratch_name:
        scratch = Path(scratch_name)
        shim = compile_shim(uefi, base, size, requires_header, scratch)
        if ramdisk:
            ramdisk_path = Path(ramdisk)
            if not ramdisk_path.is_file():
                raise Error(f'ramdisk not found: {ramdisk_path}')
        else:
            ramdisk_path = scratch / 'ramdisk'
            ramdisk_path.write_bytes(b'')
        ramdisk_size = ramdisk_path.stat().st_size
        nodes = list(ctx.board.get('bootimg', {}).get('dtb_node', []))
        if ramdisk_size:
            initrd_start = image['base'] + image.get('ramdisk_offset', 0x01000000)
            initrd_end = initrd_start + ramdisk_size
            nodes.append({
                'path': '/chosen',
                'props': [
                    {'name': 'linux,initrd-start', 'type': 'x', 'value': ['0x0', f'{initrd_start:#x}']},
                    {'name': 'linux,initrd-end', 'type': 'x', 'value': ['0x0', f'{initrd_end:#x}']},
                ],
            })
        tree = b''
        if append_dtb:
            tree = patch_dtb(Path(dtb).read_bytes(), nodes, scratch)
            if tree[:4] != b'\xd0\x0d\xfe\xed' or struct.unpack_from('>I', tree, 4)[0] != len(tree):
                raise Error('invalid compiled device tree')
        combined = shim + firmware
        kernel = (gzip.compress(combined, mtime=0) if compression == 'gzip' else combined) + tree
        kernel_path = scratch / f'Image{".gz" if compression == "gzip" else ""}{"-dtb" if append_dtb else ""}'
        kernel_path.write_bytes(kernel)
        command = ['python3', mkbootimg, '--kernel', kernel_path, '--ramdisk', ramdisk_path, '-o', out]
        for key in MKBOOTIMG_FLAGS:
            if key in image:
                command += [f'--{key}', str(image[key])]
        run(command, capture=True)
        report = verify(out, combined, tree, ramdisk_path, image, compression)
    report.update(image_sha256=sha256_file(out), image_bytes=out.stat().st_size, fd_sha256=sha256_file(fd),
                  dtb_sha256=sha256_file(dtb) if append_dtb else None,
                  patched_dtb_sha256=hashlib.sha256(tree).hexdigest() if tree else None,
                  shim_bytes=len(shim), kernel_compression=compression,
                  dtb_appended=append_dtb, hardware_tested=False)
    (out.parent / 'boot.json').write_text(json.dumps(report, indent=2) + '\n')
    log(f'bootimg: {out} ({out.stat().st_size} bytes)')
    return out


def verify(path, combined, tree, ramdisk_path, image, compression='gzip'):
    """Unpack the image and compare every part with its input."""
    data = Path(path).read_bytes()
    kernel_size, kernel_address, ramdisk_size, ramdisk_address, second_size, _, tags, page, version, _ = struct.unpack_from('<10I', data, 8)
    if data[:8] != b'ANDROID!' or second_size or version != image['header_version'] or page != image['pagesize']:
        raise Error('boot image header does not match the requested parameters')
    if kernel_address != image['base'] + image['kernel_offset'] or tags != image['base'] + image['tags_offset']:
        raise Error('boot image load addresses do not match the requested offsets')
    # mkbootimg writes a zero ramdisk address when no ramdisk is supplied.
    expected_ramdisk_address = (image['base'] + image.get('ramdisk_offset', 0x01000000)) if ramdisk_size else 0
    if ramdisk_address != expected_ramdisk_address:
        raise Error('boot image ramdisk load address does not match the requested offset')
    kernel = data[page:page + kernel_size]
    if compression == 'gzip':
        unpacker = zlib.decompressobj(16 + zlib.MAX_WBITS)
        if unpacker.decompress(kernel) != combined or not unpacker.eof or unpacker.unused_data != tree:
            raise Error('gzip, firmware and appended device tree do not round-trip')
    elif kernel != combined + tree:
        raise Error('firmware and appended device tree do not round-trip')
    start = page * (1 + -(-kernel_size // page))
    if data[start:start + ramdisk_size] != Path(ramdisk_path).read_bytes():
        raise Error('ramdisk bytes differ')
    return {'kernel_sha256': hashlib.sha256(kernel).hexdigest(), 'ramdisk_bytes': ramdisk_size,
            'ramdisk_address': hex(ramdisk_address), 'header_version': version,
            'kernel_address': hex(kernel_address), 'tags_address': hex(tags)}
