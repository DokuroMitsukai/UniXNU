#!/usr/bin/env python3
"""Build, sign and verify the bounded RAM-root report fixture.

This is a host-side development instrument, not a deployment signer. It uses
rcodesign only for the ad-hoc Mach-O signature and then independently parses
and checks the CodeDirectory and every signed page. The resulting trust-cache
bundle is scoped to this fixture's own CDHash.
"""
import argparse
import hashlib
import json
import os
import re
import struct
import subprocess
import sys
import uuid
from pathlib import Path
from types import SimpleNamespace

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts'))

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--output', type=Path, default=ROOT / 'build/ram-root-report')
parser.add_argument('--tree', type=Path, required=True, help='UniXNU output tree containing .cache/fakeroot')
parser.add_argument('--toolchain', type=Path, required=True, help='Linux toolchain root')
parser.add_argument('--rcodesign', type=Path, required=True, help='rcodesign binary')
parser.add_argument('--identifier', default='org.blu-sharky.ram-root-report')
parser.add_argument('--diagnostic', choices=('report', 'fs-timer'), default='report',
                    help='bounded EL0 report or mockfs read/timer diagnostic')
parser.add_argument('--test-size', type=int, default=12288,
                    help='size of the deterministic /probe.bin test file')
args = parser.parse_args()
if args.test_size < 0 or args.test_size > 32 * 1024 * 1024:
    parser.error('test file size must be between 0 and 32 MiB')
if args.diagnostic == 'fs-timer' and args.test_size < 12288:
    parser.error('the fs-timer diagnostic requires a test file of at least 12288 bytes')

out = args.output.resolve()
out.mkdir(parents=True, exist_ok=True)
os.environ['UNIXNU_TOOLCHAIN'] = str(args.toolchain)
from unixnu.kernel import linux_env  # noqa: E402

env = dict(os.environ)
env.update(linux_env(SimpleNamespace(tree=args.tree.resolve())))

def run(command):
    subprocess.run([str(part) for part in command], check=True, env=env)

sdk = subprocess.check_output(['xcrun', '--sdk', 'iphoneos', '--show-sdk-path'], text=True, env=env).strip()
source = ROOT / 'scripts/qemu-entry/native-user.S'
user_o = out / 'user.o'
unsigned = out / 'launchd.macho'
diagnostic_flag = ('-DNATIVE_RAM_ROOT_FS_TIMER=1' if args.diagnostic == 'fs-timer'
                   else '-DNATIVE_RAM_ROOT_REPORT=1')
run(['xcrun', 'clang', '-target', 'arm64-apple-ios17.0', '-isysroot', sdk,
     diagnostic_flag, '-c', source, '-o', user_o])
run(['xcrun', 'ld', '-arch', 'arm64', '-static', '-e', '_start',
     '-platform_version', 'ios', '17.0', '17.0', user_o, '-o', out / 'launchd-static.macho'])
run(['xcrun', 'vtool', '-set-build-version', 'ios', '17.0', '17.0',
     '-replace', '-output', unsigned, out / 'launchd-static.macho'])
unsigned_sha256 = hashlib.sha256(unsigned.read_bytes()).hexdigest()

run([args.rcodesign, 'sign', '--binary-identifier', args.identifier, unsigned])

data = unsigned.read_bytes()

def load_commands(data):
    magic, _, _, _, ncmds, _ = struct.unpack_from('<6I', data, 0)
    if magic != 0xfeedfacf:
        raise SystemExit(f'not a 64-bit little-endian Mach-O: {magic:#x}')
    at = 32
    for _ in range(ncmds):
        command, size = struct.unpack_from('<II', data, at)
        yield command, at, size
        at += size

signature = None
for command, at, _ in load_commands(data):
    if command == 0x1d:
        signature = struct.unpack_from('<II', data, at + 8)
if signature is None:
    raise SystemExit('rcodesign did not write LC_CODE_SIGNATURE')
sig_off, sig_size = signature
if sig_off + sig_size > len(data):
    raise SystemExit('signature exceeds the Mach-O file')
blob = data[sig_off:sig_off + sig_size]
magic, blob_len, count = struct.unpack_from('>III', blob, 0)
if magic != 0xfade0cc0 or blob_len > len(blob):
    raise SystemExit('malformed code-signature SuperBlob')

def code_directories():
    for index in range(count):
        slot, at = struct.unpack_from('>II', blob, 12 + index * 8)
        cd_magic, cd_len = struct.unpack_from('>II', blob, at)
        if cd_magic != 0xfade0c02:
            continue
        if cd_len < 44 or at + cd_len > len(blob):
            raise SystemExit('malformed CodeDirectory')
        (version, _, hash_offset, _, special_slots, code_slots,
         code_limit) = struct.unpack_from('>7I', blob, at + 8)
        hash_size, hash_type, _, page_log2 = struct.unpack_from('>4B', blob, at + 36)
        yield dict(slot=slot, offset=at, length=cd_len, version=version,
                   hash_offset=hash_offset, special_slots=special_slots,
                   code_slots=code_slots, code_limit=code_limit,
                   hash_size=hash_size, hash_type=hash_type,
                   page_log2=page_log2, cd=blob[at:at + cd_len])

directories = list(code_directories())
sha256 = [cd for cd in directories if cd['hash_type'] == 2 and cd['hash_size'] == 32 and
          cd['page_log2'] == 12]
if len(sha256) != 1:
    raise SystemExit(f'expected one SHA-256/4K CodeDirectory; found {len(directories)} directories')
cd = sha256[0]
page_size = 1 << cd['page_log2']
if cd['code_limit'] > len(data):
    raise SystemExit('CodeDirectory codeLimit exceeds the signed file')
expected_slots = (cd['code_limit'] + page_size - 1) // page_size
if expected_slots != cd['code_slots']:
    raise SystemExit(f'CodeDirectory slot count differs: {cd["code_slots"]} != {expected_slots}')
if cd['hash_offset'] + cd['code_slots'] * cd['hash_size'] > cd['length']:
    raise SystemExit('CodeDirectory hash table exceeds the CodeDirectory')
for index in range(cd['code_slots']):
    start = index * page_size
    end = min(start + page_size, cd['code_limit'])
    actual = hashlib.sha256(data[start:end]).digest()
    expected = cd['cd'][cd['hash_offset'] + index * cd['hash_size']:
                        cd['hash_offset'] + (index + 1) * cd['hash_size']]
    if actual != expected:
        raise SystemExit(f'signed page {index} hash mismatch')
cdhash = hashlib.sha256(cd['cd']).digest()[:20]
identifier = uuid.uuid5(uuid.NAMESPACE_URL, args.identifier + ':' + cdhash.hex())
module = struct.pack('<I16sI', 2, identifier.bytes, 1) + cdhash + bytes([2, 0, 0, 0])
trust = struct.pack('<2I', 1, 8) + module
(out / 'trustcache.bundle').write_bytes(trust)
(out / 'trustcache.json').write_text(json.dumps({
    'purpose': 'explicit trust for the owned RAM-root report fixture only',
    'identifier': args.identifier,
    'process_sha256': hashlib.sha256(data).hexdigest(),
    'cdhash': cdhash.hex(),
    'code_directory_sha256': hashlib.sha256(cd['cd']).hexdigest(),
    'module_version': 2,
    'entries': 1,
    'signature_hash_page_bytes': page_size,
    'signed_pages_verified': cd['code_slots'],
    'bundle_sha256': hashlib.sha256(trust).hexdigest(),
    'apple_trust_chain_verified': False,
    'test_instrument_only': True,
}, indent=2) + '\n')

test = bytearray(args.test_size)
for page in range((args.test_size + 4095) // 4096):
    marker = (0xa0 + page) & 0xff
    start = page * 4096
    test[start:min(start + 4096, args.test_size)] = bytes([marker]) * (
        min(start + 4096, args.test_size) - start)
test = bytes(test)
test_offset = max(8192, (4096 + len(data) + 4095) & ~4095)
image_size = (test_offset + len(test) + 4095) & ~4095
image = bytearray(image_size)
if image_size > 32 * 1024 * 1024:
    raise SystemExit('N4KROOT image exceeds the mockfs 32 MiB limit')
struct.pack_into('<8sII4Q', image, 0, b'N4KROOT\0', 1, 2, 4096, len(data), test_offset, len(test))
image[4096:4096 + len(data)] = data
image[test_offset:test_offset + len(test)] = test
root = out / 'root.img'
root.write_bytes(image)

# Re-read the container and check the bounds exactly as mockfs_mountroot does.
root_data = root.read_bytes()
magic, version, count, launch_offset, launch_size, check_offset, check_size = \
    struct.unpack_from('<8sII4Q', root_data, 0)
if (magic != b'N4KROOT\0' or version != 1 or count != 2 or launch_offset != 4096 or
        check_offset < 8192 or check_offset % 4096 or launch_size > check_offset - launch_offset or
        check_size > len(root_data) - check_offset):
    raise SystemExit('N4KROOT container does not satisfy the mockfs bounds')
if root_data[launch_offset:launch_offset + launch_size] != data:
    raise SystemExit('N4KROOT launch bytes differ from the signed fixture')

symbols = subprocess.check_output(['xcrun', 'nm', '-U', unsigned], text=True, env=env)
addresses = {name: int(address, 16) for address, name in
             re.findall(r'^([0-9a-fA-F]+)\s+\S+\s+(_\S+)$', symbols, re.M)}
(out / 'addresses.json').write_text(json.dumps(addresses, indent=2) + '\n')
(out / 'fixture.json').write_text(json.dumps({
    'purpose': 'bounded RAM-root/EL0 report fixture; not an authenticated-root result',
    'signer': 'rcodesign ad-hoc; CodeDirectory independently parsed and page-verified',
    'diagnostic': args.diagnostic,
    'unsigned_sha256': unsigned_sha256,
    'signed_sha256': hashlib.sha256(data).hexdigest(),
    'cdhash': cdhash.hex(),
    'code_directory_sha256': hashlib.sha256(cd['cd']).hexdigest(),
    'page_size': page_size,
    'signed_pages_verified': cd['code_slots'],
    'trustcache_sha256': hashlib.sha256(trust).hexdigest(),
    'root_image_sha256': hashlib.sha256(root_data).hexdigest(),
    'launch_offset': launch_offset,
    'launch_size': launch_size,
    'test_offset': check_offset,
    'test_size': check_size,
    'root_image_size': len(root_data),
    'report_message': ('RAMROOT-FST PASS: pid=1 page=4096 fs=read+seek+eof timer=poll'
                       if args.diagnostic == 'fs-timer'
                       else 'RAMROOT-EL0 PASS: pid=1 page=4096'),
    'test_file_sha256': hashlib.sha256(test).hexdigest(),
    'test_file_size': len(test),
    'apple_trust_chain_verified': False,
    'test_instrument_only': True,
}, indent=2) + '\n')
print(json.dumps({
    'signed_sha256': hashlib.sha256(data).hexdigest(),
    'cdhash': cdhash.hex(),
    'trustcache_sha256': hashlib.sha256(trust).hexdigest(),
    'root_image_sha256': hashlib.sha256(root_data).hexdigest(),
    'signed_pages_verified': cd['code_slots'],
}, indent=2))
