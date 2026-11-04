#!/usr/bin/env python3
"""Qualify the original ordinary-ARM64 block-storage ABI.

The reference object is compiled from the pinned public Darwin 23
IOStorageFamily source.  It is an annotation instrument and is never linked or
executed.  The live metadata comes from a bounded QEMU stop of the actual
candidate kernel at ``_bsd_init``; a compile-only check is not a substitute.

The defaults reproduce the original macOS-host invocation.  The Linux/QEMU
path uses ``--candidate``, ``--plan``, ``--snapshot``, ``--metaclass-object``
and the explicit tool paths.
"""
import argparse
import hashlib
import json
from pathlib import Path
import re
import shutil
import struct
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'kits/XnuPrelink'))
import native_prelink as np

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--candidate', type=Path,
                    default=ROOT / 'build/xnu-prelink/native-apfs-load-positive.macho',
                    help='prelinked candidate kernel Mach-O')
parser.add_argument('--plan', type=Path,
                    help='candidate plan JSON; defaults to the candidate .json')
parser.add_argument('--snapshot', type=Path,
                    default=ROOT / 'build/darwinboot-storage-native-metadata/gdb-stop.json',
                    help='live QEMU stop record for this candidate')
parser.add_argument('--aes-audit', type=Path,
                    default=ROOT / 'build/image4-ignition/aes-interface-audit.json',
                    help='AES audit supplying compiled_metaclass_offsets')
parser.add_argument('--metaclass-object', type=Path,
                    help='compiled OSMetaClass.cpo; derives the member offsets '
                         'directly instead of reading --aes-audit')
parser.add_argument('--output', type=Path,
                    default=ROOT / 'build/storage-abi/interface-audit.json')
parser.add_argument('--work-dir', type=Path, default=ROOT / 'build/storage-abi')
parser.add_argument('--source', type=Path, default=ROOT / 'refer/IOStorageFamily')
parser.add_argument('--compile-record', type=Path,
                    default=ROOT / 'build/xnu/ios-obj/DEVELOPMENT_ARM64_BCM2837/'
                                  'iokit/DEVELOPMENT/IOPlatformExpert.cpo.json')
parser.add_argument('--sdk-header', type=Path,
                    help='TargetConditionals.h; defaults to the xcrun SDK path')
parser.add_argument('--sdk-version', help='SDK version string; defaults to xcrun')
parser.add_argument('--dwarfdump', default='dwarfdump',
                    help='DWARF dumper; use llvm-dwarfdump on Linux')
parser.add_argument('--osfmk-include', type=Path,
                    default=ROOT / '.cache/xnu-work/osfmk',
                    help='extra osfmk include directory when it exists')
parser.add_argument('--derive-only', action='store_true',
                    help='stop after deriving the candidate addresses')
args = parser.parse_args()

source = args.source.resolve()
candidate = args.candidate.resolve()
plan_path = args.plan.resolve() if args.plan else candidate.with_suffix('.json')
snapshot_path = args.snapshot.resolve()
out = args.work_dir.resolve()
headers = out / 'include/IOKit/storage'
headers.mkdir(parents=True, exist_ok=True)
for path in source.glob('*.h'):
    shutil.copyfile(path, headers / path.name)
revision = subprocess.check_output(['git', '-C', str(source), 'rev-parse', 'HEAD'], text=True).strip()
if revision != 'e45fbe30a7879e0b16e26dddb78538f1b00e0bff':
    raise SystemExit('Unexpected public Darwin 23 IOStorageFamily source')
# Only this platform-selection header is missing from the source-kernel SDK.
if args.sdk_header:
    conditions = args.sdk_header.resolve()
else:
    sdk = Path(subprocess.check_output(['xcrun', '--sdk', 'macosx', '--show-sdk-path'],
                                      text=True).strip())
    conditions = sdk / 'usr/include/TargetConditionals.h'
shutil.copyfile(conditions, out / 'include/TargetConditionals.h')
record = json.loads(args.compile_record.read_text().strip().rstrip(','))
obj_path = out / 'IOBlockStorageDevice-reference.o'
arguments = record['arguments']
command, index = [], 0
while index < len(arguments):
    value = arguments[index]
    if value == record['file']:
        command.append(str(source / 'IOBlockStorageDevice.cpp'))
    elif value == '-o':
        command += ['-o', str(obj_path)]
        index += 1
    elif value in ('-MF', '-MJ'):
        index += 1
    elif value == '-Xclang' and arguments[index + 1].startswith('-W'):
        index += 1
    elif value.startswith('-Wno-'):
        command.append(value)
    elif not value.startswith('-W') and value not in ('-MD', '-MP'):
        command.append(value)
    index += 1
command += ['-I', str(out / 'include')]
if args.osfmk_include.is_dir():
    command += ['-I', str(args.osfmk_include)]
command += ['-Wall', '-Wextra', '-Werror', '-Wno-unused-parameter', '-Wno-deprecated-declarations',
            '-Wno-c99-designator', '-Wno-reorder-init-list', '-Wno-unnecessary-virtual-specifier',
            '-Wno-deprecated-enum-enum-conversion',
            # clang 24 reports this new warning as an error after -Werror even
            # when the build's -Wno- form precedes it.  The XNU build does not
            # use -Werror here; keep the audit strict for every other warning.
            '-Wno-error=missing-designated-field-initializers']
(out / 'compile-command.json').write_text(json.dumps(command, indent=2) + '\n')
r = subprocess.run(command, cwd=record['directory'], capture_output=True, text=True)
(out / 'compile.log').write_text(r.stdout + r.stderr)
if r.returncode:
    raise SystemExit((r.stdout + r.stderr)[-3500:])


def require(value, message):
    if not value:
        raise SystemExit(message)


obj = obj_path.read_bytes()
om = np.macho(obj)
require(om['kind'] == 1, 'Expected an ordinary ARM64 reference object')
dwarf = subprocess.check_output([args.dwarfdump, '--name=IOBlockStorageDevice',
                                 '--show-children', str(obj_path)], text=True)
class_size = re.search(r'DW_AT_name\s+\("IOBlockStorageDevice"\)[\s\S]{0,200}?'
                       r'DW_AT_byte_size\s+\((0x[0-9a-f]+)\)', dwarf)
require(class_size and int(class_size[1], 16) == 0x90, 'Actual compiled public class size changed')
version_command = next(at for command, at, size in om['commands'] if command == 0x32)
require(struct.unpack_from('<II', obj, version_command + 8) == (2, 0x110000),
        'Expected iOS 17 reference deployment')
sycmd = next(at for command, at, size in om['commands'] if command == 2)
symoff, count, stroff, _ = struct.unpack_from('<4I', obj, sycmd + 8)
symbols = []
for i in range(count):
    ix, kind, _, _, value = struct.unpack_from('<IBBHQ', obj, symoff + i * 16)
    symbols.append(dict(name=obj[stroff + ix:obj.index(b'\0', stroff + ix)].decode(),
                        value=value, kind=kind))
vtable = next(s['value'] for s in symbols if s['name'] == '__ZTV20IOBlockStorageDevice')
end = min(s['value'] for s in symbols if not s['kind'] & 0xe0 and s['kind'] & 0xe == 0xe and
          s['value'] > vtable)
relocations = {}
for segment in om['segments']:
    for section in segment['sections']:
        if section['va'] <= vtable < section['va'] + section['size']:
            ro, rc = struct.unpack_from('<II', obj, section['command_offset'] + 56)
            for i in range(rc):
                address, word = struct.unpack_from('<II', obj, ro + i * 8)
                if word >> 27 & 1 and word >> 28 == 0 and word >> 25 & 3 == 3:
                    relocations[section['va'] + address] = symbols[word & 0xffffff]['name']
methods = []
for at in range(vtable + 16, end, 8):
    if at not in relocations:
        break
    methods.append(relocations[at])
require(len(methods) == 190 and methods.count('___cxa_pure_virtual') == 14,
        'Public iOS class dispatch shape changed')
kernel = candidate.read_bytes()
plan = json.loads(plan_path.read_text())
require(hashlib.sha256(kernel).hexdigest() == plan['candidate_sha256'] and
        plan['original_sha256'] ==
        'f18b4df865405f2a287b84977d7aca745e056d656d9fc9df1662970ce2969de7',
        'Unexpected original candidate provenance')
native = np.macho(kernel)
exports = np.exports(kernel, native)
by_name = {name: va for va, names in exports.items() for name in names}
extents = [e for e in plan['extents'] if e['module'] == 'com.apple.iokit.IOStorageFamily']
const = next(e for e in extents if e['segment'] == '__DATA_CONST')
text = next(e for e in extents if e['segment'] == '__TEXT_EXEC')


def read(va, length):
    at = np.backed_offset(native['segments'], va, length, len(kernel))
    return kernel[at:at + length]


require(hashlib.sha256(read(text['va'], text['size'])).hexdigest() ==
        plan['original_executable_sha256']['com.apple.iokit.IOStorageFamily'],
        'Original storage executable code changed')
blob = read(const['va'], const['size'])
found = []
for at in range(0, len(blob) - (len(methods) + 2) * 8 + 1, 8):
    if blob[at:at + 16] != bytes(16):
        continue
    pointers = struct.unpack_from('<' + 'Q' * len(methods), blob, at + 16)
    if all(pointers[i] == by_name[name] for i, name in enumerate(methods) if name in by_name):
        found.append((const['va'] + at, pointers))
require(len(found) == 1, 'Cannot uniquely identify the original block-storage class dispatch')
table, pointers = found[0]
matched = sum(name in by_name for name in methods)
require(matched == 176, 'Unexpected original/native kernel binding count')
for i, name in enumerate(methods):
    if name not in by_name:
        require(text['va'] <= pointers[i] < text['va'] + text['size'],
                'Owned storage method outside original text')


def relative_branch(address, instruction):
    immediate = instruction & 0x3ffffff
    if immediate & 0x2000000:
        immediate -= 0x4000000
    return address + immediate * 4


def thunk_names(address):
    a, load, branch = struct.unpack('<3I', read(address, 12))
    require(a & 0x9f00001f == 0x90000010 and load & 0xffc003ff == 0xf9400210 and branch == 0xd61f0200,
            'Unqualified original native import thunk')
    immediate = ((a >> 5 & 0x7ffff) << 2) | (a >> 29 & 3)
    if immediate & 0x100000:
        immediate -= 0x200000
    slot = (address & ~4095) + immediate * 4096 + (load >> 10 & 4095) * 8
    target = struct.unpack('<Q', read(slot, 8))[0]
    return exports.get(target, [])


constructors = []
for address in range(text['va'], text['va'] + text['size'] - 32, 4):
    words = struct.unpack('<8I', read(address, 32))
    if (words[:2] != (0xa9bf7bfd, 0x910003fd) or words[2] & 0xfc000000 != 0x94000000 or
            words[3] & 0x9f00001f != 0x90000008 or words[4] & 0xffc003ff != 0x91000108 or
            words[5:] != (0xf9000008, 0xa8c17bfd, 0xd65f03c0)):
        continue
    immediate = ((words[3] >> 5 & 0x7ffff) << 2) | (words[3] >> 29 & 3)
    if immediate & 0x100000:
        immediate -= 0x200000
    stored = ((address + 12) & ~4095) + immediate * 4096 + (words[4] >> 10 & 4095)
    if stored == table + 16:
        constructors.append((address, relative_branch(address + 8, words[2])))
require(len(constructors) == 1 and
        '__ZN9IOServiceC2EPK11OSMetaClass' in thunk_names(constructors[0][1]),
        'Original protected block constructor does not forward to actual source IOService')
destructor = pointers[0] - 4
word = struct.unpack('<I', read(destructor, 4))[0]
require(word & 0xfc000000 == 0x14000000 and
        '__ZN9IOServiceD2Ev' in thunk_names(relative_branch(destructor, word)),
        'Unqualified actual base destructor')
require(all(read(pointers[i], 4) == struct.pack('<I', 0xd4200020) for i in (0, 1)),
        'Unexpected original abstract complete-destructor behavior')
function = pointers[7]
a, add, ret = struct.unpack('<3I', read(function, 12))
require(a & 0x9f00001f == 0x90000000 and add & 0xffc003ff == 0x91000000 and ret == 0xd65f03c0,
        'Unqualified original storage metaclass getter')
immediate = ((a >> 5 & 0x7ffff) << 2) | (a >> 29 & 3)
if immediate & 0x100000:
    immediate -= 0x200000
meta = (function & ~4095) + immediate * 4096 + (add >> 10 & 4095)
service_meta = by_name['__ZN9IOService10gMetaClassE']
source_sha256 = hashlib.sha256((source / 'IOBlockStorageDevice.cpp').read_bytes()).hexdigest()
reference_sha256 = hashlib.sha256(obj).hexdigest()
if args.derive_only:
    derive = dict(source_revision=revision, source_sha256=source_sha256,
                  reference_object_sha256=reference_sha256,
                  candidate_sha256=plan['candidate_sha256'],
                  original_sha256=plan['original_sha256'],
                  vtable=hex(table), metaclass=hex(meta),
                  service_metaclass=hex(service_meta),
                  method_slots=len(methods), kernel_bindings=matched,
                  methods=[dict(slot=i, reference_name=name, candidate_target=hex(pointers[i]),
                                kernel_names=exports.get(pointers[i], []))
                           for i, name in enumerate(methods)])
    (out / 'derive.json').write_text(json.dumps(derive, indent=2) + '\n')
    print(f'DERIVE: vtable={table:#x} metaclass={meta:#x} '
          f'service_metaclass={service_meta:#x} slots={len(methods)} bindings={matched}')
    raise SystemExit(0)
snapshot = json.loads(snapshot_path.read_text())
require(snapshot['kernel_sha256'] == plan['candidate_sha256'] and
        not snapshot['bounded_timeout_interrupted'],
        'Wrong or incomplete live storage metadata observation')
actual = bytes.fromhex(snapshot['memory'][f'{meta:x}:50'])
service = bytes.fromhex(snapshot['memory'][f'{service_meta:x}:50'])
# The member offsets are a compile-time property of the same XNU source.  The
# Linux/QEMU path derives them from OSMetaClass.cpo directly; the macOS path
# keeps consuming the existing AES audit.
if args.metaclass_object:
    metaclass_object = args.metaclass_object.resolve()
    metaclass_dwarf = subprocess.check_output(
        [args.dwarfdump, '--name=OSMetaClass', '--show-children', str(metaclass_object)],
        text=True)
    layout = {}
    for member in metaclass_dwarf.split('DW_TAG_member')[1:]:
        name = re.search(r'DW_AT_name\s+\("([^"]+)"\)', member)
        position = re.search(r'DW_AT_data_member_location\s+\((0x[0-9a-f]+)\)', member)
        if name and position and name[1] in ('superClassLink', 'className', 'classSize'):
            layout[name[1]] = int(position[1], 16)
    require(layout == dict(superClassLink=16, className=24, classSize=32),
            'Compiled metaclass ABI changed')
    layout_source = dict(kind='compiled-osmetaclass-dwarf',
                         object_sha256=hashlib.sha256(metaclass_object.read_bytes()).hexdigest(),
                         offsets=layout)
else:
    aes_audit = args.aes_audit.resolve()
    layout = json.loads(aes_audit.read_text())['compiled_metaclass_offsets']
    require(layout == dict(superClassLink=16, className=24, classSize=32),
            'Compiled metaclass ABI changed')
    layout_source = dict(kind='aes-interface-audit',
                         file_sha256=hashlib.sha256(aes_audit.read_bytes()).hexdigest(),
                         offsets=layout)
require(struct.unpack_from('<Q', actual, layout['superClassLink'])[0] == service_meta and
        struct.unpack_from('<I', actual, layout['classSize'])[0] == 0x90 and
        struct.unpack_from('<I', service, layout['classSize'])[0] == 0x88,
        'Live block-storage class/parent ABI mismatch')
r = {k: int(v, 16) for k, v in snapshot['system_registers'].items()}
sctlr = r.get('SCTLR_EL1', r.get('SCTLR'))
require(sctlr is not None and sctlr & 1 and r['TTBR0_EL1'] and r['TTBR1_EL1'],
        'Live translation is not enabled with both roots')
require(r['TCR_EL1'] >> 14 & 3 == 0 and r['TCR_EL1'] >> 30 & 3 == 2,
        'Live translation is not native 4K')
if args.sdk_version:
    sdk_version = args.sdk_version
else:
    try:
        sdk_version = subprocess.check_output(['xcrun', '--sdk', 'macosx',
                                               '--show-sdk-version'], text=True).strip()
    except (OSError, subprocess.CalledProcessError):
        sdk_version = '17.0'
result = dict(public_source_revision=revision, source_sha256=source_sha256,
              reference_object_sha256=reference_sha256,
              reference_object_executed_or_linked=False,
              platform_header_sdk_version=sdk_version,
              platform_header_sha256=hashlib.sha256(conditions.read_bytes()).hexdigest(),
              candidate_sha256=plan['candidate_sha256'],
              candidate_plan_sha256=hashlib.sha256(plan_path.read_bytes()).hexdigest(),
              original_sha256=plan['original_sha256'],
              snapshot_sha256=hashlib.sha256(snapshot_path.read_bytes()).hexdigest(),
              original_executable_code_unchanged=True,
              method_slots=190, kernel_bindings=matched, pure_virtual_slots=14,
              inherited_kernel_methods=162,
              vtable=hex(table), original_metaclass=hex(meta),
              source_ioservice_metaclass=hex(service_meta),
              original_protected_constructor=hex(constructors[0][0]),
              original_base_destructor=hex(destructor),
              abstract_complete_destructors_trap=True,
              live_instance_sizes=dict(IOBlockStorageDevice=0x90, IOService=0x88),
              live_native_4k=True, metaclass_layout_source=layout_source,
              compiled_public_class_size=int(class_size[1], 16),
              methods=[dict(slot=i, reference_name=name, candidate_target=hex(pointers[i]),
                            kernel_names=exports.get(pointers[i], []))
                       for i, name in enumerate(methods)],
              disk_read_tested=False, transport_implemented=False, hardware_tested=False)
args.output.parent.mkdir(parents=True, exist_ok=True)
args.output.write_text(json.dumps(result, indent=2) + '\n')
print('PASS: 190 ordinary iOS storage slots; 176 kernel bindings '
      '(162 inherited + 14 pure virtual)')
print('Live original block/service sizes 0x90/0x88 and native 4K. '
      'Annotation object is never linked/executed; block I/O remains unqualified.')
