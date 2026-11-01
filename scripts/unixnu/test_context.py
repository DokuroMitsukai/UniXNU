"""The production Context, CLI selection and input precedence on isolated fixtures."""
import json
import os
import unittest
import zipfile
import plistlib
from contextlib import contextmanager
from pathlib import Path
from tempfile import TemporaryDirectory
from types import SimpleNamespace
from unittest.mock import patch

from . import cli, config, feeds, ipsw, kernel

PROFILE = 'ipados-17.7.11-21H461'
OTHER = 'ipados-26.5.2-23F84'
DEVICE = 'gta4l'
DEFCONFIG = 'gta4l_defconfig'


def build_options(path, text='[build]\n'):
    path.write_text(text)
    return path


@contextmanager
def clean_environment(**values):
    keys = set(config.BUILD_ENV.values()) | set(values) | {'GITHUB_TOKEN', 'UNIXNU_LOCAL'}
    saved = {key: os.environ.pop(key, None) for key in keys}
    os.environ.update({key: value for key, value in values.items() if value is not None})
    try:
        yield
    finally:
        for key, value in saved.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value


class Fixture:
    def __init__(self, base, profiles=(PROFILE,)):
        self.base = base
        self.root = base / 'UniXNU'
        self.device = base / 'device'
        self.soc = base / 'soc'
        self.out = base / 'out'
        arch = self.root / 'profiles/arch/arm64'
        arch.mkdir(parents=True)
        (arch / 'profile.toml').write_text('[arch]\nname = "arm64"\n')
        for name in profiles:
            directory = self.root / 'profiles/os' / name
            directory.mkdir(parents=True)
            (directory / 'profile.toml').write_text(
                f'[os]\nname = "{name}"\narch = "arm64"\nxnu_version = "10063.141.1"\n'
                '[ipsw]\nproduct = "iPad7,1"\nversion = "17.7.11"\nbuild = "21H461"\n'
                'device_class = "j120ap"\nchip_id = 32785\nboard_id = 12\n'
                '[kernel.prelink]\nkernelcache_sha256 = "' + 'a' * 64 + '"\n')
        (self.root / 'feeds.toml').write_text('')
        self.soc.mkdir()
        (self.soc / 'soc.toml').write_text('[soc]\nname = "SM6115"\n')
        self.device.mkdir()
        (self.device / 'configs').mkdir()
        (self.device / 'configs' / DEFCONFIG).write_text('CONFIG_XNU_NATIVE_PAN=n\n')
        (self.device / 'configs/other_defconfig').write_text('CONFIG_XNU_NATIVE_PAN=y\n')
        (self.device / 'feeds.toml').write_text('')
        (self.root / 'components.toml').write_text('')
        self.write_board()

    def write_board(self, os_profile=PROFILE, mapping=None, package=True, kernel=True,
                    name=DEVICE, extra=''):
        mapping = {PROFILE: DEFCONFIG} if mapping is None else mapping
        text = f'schema_version = 2\n[board]\nname = "{name}"\nsoc_source = "sm6115"\n'
        text += f'os_profile = "{os_profile}"\n'
        if package:
            text += '[package]\nunixnu = "../UniXNU"\nboot_partition_bytes = 100663296\n'
            text += '[package.defconfig]\n'
            for key, value in mapping.items():
                text += f'"{key}" = "{value}"\n'
        if kernel:
            text += '[kernel]\ndefconfig = "gta4l_defconfig"\narchives = ["board"]\n'
        text += ('[payload]\nvolume = "GTA4LESP"\nsize_mib = 192\n'
                 '[firmware]\nconfig = "gta4l"\n'
                 '[bootimg]\ndtb = "build/gta4l/boot.dtb"\n')
        (self.device / 'board.toml').write_text(text + extra)

    def arguments(self, command='status', *extra, config_file=None, out=True):
        arguments = [command, '-D', str(self.device)]
        if out:
            arguments += ['--out', str(self.out)]
        arguments += ['--local-module', f'soc:sm6115={self.soc}']
        arguments += list(extra)
        if config_file is not None:
            arguments += ['--config', str(config_file)]
        return cli.parser().parse_args(arguments)

    def context(self, command='status', *extra, config_file=None, out=True):
        with patch.object(config, 'ROOT', self.root):
            return config.Context(self.arguments(command, *extra, config_file=config_file, out=out))


class SelectionTests(unittest.TestCase):
    def test_full_profile_selects_the_mapped_configuration(self):
        with TemporaryDirectory() as directory, clean_environment():
            fixture = Fixture(Path(directory))
            build = build_options(Path(directory) / 'build.toml')
            ctx = fixture.context('release', '--os', PROFILE, config_file=build)
            self.assertEqual(ctx.schema_version, 2)
            self.assertEqual(ctx.name, DEVICE)
            self.assertEqual(ctx.os_name, PROFILE)
            self.assertEqual(ctx.config_name, DEFCONFIG)
            self.assertEqual(ctx.work, fixture.out / DEVICE / PROFILE / DEVICE)
            self.assertEqual(ctx.profile_roots['arch'], fixture.root / 'profiles/arch/arm64')
            self.assertEqual(ctx.profile_roots['soc'], fixture.soc)
            self.assertEqual(ctx.profile_roots['os'], fixture.root / 'profiles/os' / PROFILE)
            self.assertEqual(ctx.profile_files, [fixture.root / 'profiles/arch/arm64/profile.toml',
                                                 fixture.soc / 'soc.toml',
                                                 fixture.root / 'profiles/os' / PROFILE / 'profile.toml',
                                                 fixture.device / 'board.toml'])
            self.assertEqual(ctx.board['board']['os_profile'], PROFILE)
            self.assertEqual(ctx.board['package']['boot_partition_bytes'], 100663296)
            self.assertEqual(ctx.board['payload']['size_mib'], 192)
            self.assertEqual(ctx.board['os']['xnu_version'], '10063.141.1')
            self.assertEqual(ctx.args.build_config, str(build))

    def test_alias_selects_the_same_target(self):
        with TemporaryDirectory() as directory, clean_environment():
            fixture = Fixture(Path(directory))
            build = build_options(Path(directory) / 'build.toml')
            ctx = fixture.context('status', '--os', '17', config_file=build)
            self.assertEqual(ctx.os_name, PROFILE)
            self.assertEqual(ctx.config_name, DEFCONFIG)
            self.assertEqual(ctx.work, fixture.out / DEVICE / PROFILE / DEVICE)

    def test_ambiguous_alias_fails_before_soc_resolution(self):
        with TemporaryDirectory() as directory, clean_environment():
            fixture = Fixture(Path(directory), profiles=(PROFILE, 'ipados-17.2.2-2B2'))
            build = build_options(Path(directory) / 'build.toml')
            arguments = fixture.arguments('status', '--os', '17', config_file=build)
            with patch.object(feeds, 'resolve_soc', side_effect=AssertionError('resolved the SoC')):
                with patch.object(config, 'ROOT', fixture.root):
                    with self.assertRaisesRegex(Exception, '--os 17'):
                        config.Context(arguments)

    def test_foreign_installed_profile_fails_before_soc_resolution(self):
        with TemporaryDirectory() as directory, clean_environment():
            fixture = Fixture(Path(directory), profiles=(PROFILE, OTHER))
            build = build_options(Path(directory) / 'build.toml')
            arguments = fixture.arguments('status', '--os', '26', config_file=build)
            with patch.object(feeds, 'resolve_soc', side_effect=AssertionError('resolved the SoC')):
                with patch.object(config, 'ROOT', fixture.root):
                    with self.assertRaisesRegex(Exception, 'does not package that OS profile'):
                        config.Context(arguments)

    def test_missing_installed_profile_or_mapping_fails_before_soc(self):
        cases = (
            ({'os_profile': OTHER}, None, 'OS profile is not installed'),
            ({}, {PROFILE: '../outside_defconfig'}, r'must name a defconfig'),
            ({}, {PROFILE: 'missing_defconfig'}, r'configs/missing_defconfig is missing'),
            ({'os_profile': '../escape'}, None, r'os_profile must be a profile directory name'),
        )
        for board, mapping, message in cases:
            with self.subTest(board=board, mapping=mapping), TemporaryDirectory() as directory, clean_environment():
                fixture = Fixture(Path(directory))
                fixture.write_board(mapping=mapping, **board)
                build = build_options(Path(directory) / 'build.toml')
                with patch.object(feeds, 'resolve_soc', side_effect=AssertionError('resolved the SoC')):
                    with patch.object(config, 'ROOT', fixture.root):
                        with self.assertRaisesRegex(Exception, message):
                            config.Context(fixture.arguments('status', config_file=build))

    def test_missing_defconfig_selection_fails(self):
        with TemporaryDirectory() as directory, clean_environment():
            fixture = Fixture(Path(directory))
            fixture.write_board(package=False, kernel=False)
            build = build_options(Path(directory) / 'build.toml')
            with patch.object(config, 'ROOT', fixture.root):
                with self.assertRaisesRegex(Exception, r'needs \[kernel\] defconfig or a selected defconfig'):
                    config.Context(fixture.arguments('status', config_file=build))

    def test_declared_profile_identity_conflicts_are_rejected(self):
        cases = (('arch = "arm64"', 'arch = "x86_64"', 'this tree builds arm64 only'),
                 (f'name = "{PROFILE}"', 'name = "ipados-99.0.0-99Z99"',
                  'not the profile directory name'))
        for old, new, message in cases:
            with self.subTest(old=old), TemporaryDirectory() as directory, clean_environment():
                fixture = Fixture(Path(directory))
                profile = fixture.root / 'profiles/os' / PROFILE / 'profile.toml'
                profile.write_text(profile.read_text().replace(old, new))
                build = build_options(Path(directory) / 'build.toml')
                with patch.object(config, 'ROOT', fixture.root):
                    with self.assertRaisesRegex(Exception, message):
                        config.Context(fixture.arguments('status', config_file=build))

    def test_per_os_override_cannot_replace_the_package_contract_or_profile(self):
        with TemporaryDirectory() as directory, clean_environment():
            fixture = Fixture(Path(directory))
            fixture.write_board(extra=(
                f'[os_overrides."{PROFILE}"]\n'
                'package = { boot_partition_bytes = 1 }\n'
                'board = { os_profile = "ipados-99.0.0-99Z99" }\n'))
            build = build_options(Path(directory) / 'build.toml')
            ctx = fixture.context('release', config_file=build)
            self.assertEqual(ctx.board['package']['boot_partition_bytes'], 100663296)
            self.assertEqual(ctx.board['board']['os_profile'], PROFILE)

    def test_resolved_profile_identity_conflicts_are_rejected(self):
        cases = (('os = { arch = "x86_64" }', r'resolved \[os\] arch'),
                 ('os = { name = "ipados-99.0.0-99Z99" }', r'resolved \[os\] name'))
        for override, message in cases:
            with self.subTest(override=override), TemporaryDirectory() as directory, clean_environment():
                fixture = Fixture(Path(directory))
                fixture.write_board(extra=f'[os_overrides."{PROFILE}"]\n{override}\n')
                build = build_options(Path(directory) / 'build.toml')
                with patch.object(config, 'ROOT', fixture.root):
                    with self.assertRaisesRegex(Exception, message):
                        config.Context(fixture.arguments('status', config_file=build))

    def test_stale_saved_state_cannot_redirect_release_or_explicit_os(self):
        with TemporaryDirectory() as directory, clean_environment():
            fixture = Fixture(Path(directory))
            build = build_options(Path(directory) / 'build.toml')
            fixture.out.mkdir()
            (fixture.out / 'state.json').write_text(json.dumps(
                {'device': str(fixture.device), 'configurations': {str(fixture.device): 'other_defconfig'}}))
            release = fixture.context('release', config_file=build)
            self.assertEqual(release.config_name, DEFCONFIG)
            explicit = fixture.context('build', '--os', PROFILE, config_file=build)
            self.assertEqual(explicit.config_name, DEFCONFIG)
            saved = fixture.context('build', config_file=build)
            self.assertEqual(saved.config_name, 'other_defconfig')

    def test_defconfig_name_is_used_for_defconfig_only(self):
        with TemporaryDirectory() as directory, clean_environment():
            fixture = Fixture(Path(directory))
            build = build_options(Path(directory) / 'build.toml')
            ctx = fixture.context('defconfig', DEFCONFIG, config_file=build)
            self.assertEqual(ctx.config_name, DEFCONFIG)
            self.assertEqual(ctx.config_path, fixture.out / DEVICE / PROFILE / DEVICE / '.config')

    def test_status_does_not_write_saved_state(self):
        with TemporaryDirectory() as directory, clean_environment():
            fixture = Fixture(Path(directory))
            build = build_options(Path(directory) / 'build.toml')
            fixture.context('status', config_file=build)
            self.assertFalse((fixture.out / 'state.json').exists())


class BuildOptionTests(unittest.TestCase):
    def test_explicit_file_flags_and_environment_precedence(self):
        with TemporaryDirectory() as directory, clean_environment(
                UNIXNU_IPSW='https://example.invalid/env.ipsw',
                UNIXNU_KERNELCACHE='/tmp/env.cache', JOBS='5'):
            fixture = Fixture(Path(directory))
            explicit = build_options(Path(directory) / 'explicit.toml',
                                     '[build]\n'
                                     'ipsw = "explicit.ipsw"\n'
                                     'kernelcache = "explicit.cache"\n'
                                     'jobs = 3\n'
                                     'target = "RELEASE"\n'
                                     'kernel_args = ["a=1", "b=2"]\n')
            arguments = fixture.arguments(
                'status', '--ipsw', 'flag.ipsw', '--kernelcache', 'flag.cache', '-j', '7',
                '--target', 'DEBUG', '--kernel-arg', 'a=9', '--kernel-arg', 'c=3',
                config_file=explicit)
            with patch.object(config, 'ROOT', fixture.root):
                ctx = config.Context(arguments)
            self.assertEqual(str(ctx.args.ipsw), 'flag.ipsw')
            self.assertEqual(str(ctx.args.kernelcache), 'flag.cache')
            self.assertEqual(ctx.args.jobs, 7)
            self.assertEqual(ctx.args.target, 'DEBUG')
            self.assertEqual(ctx.args.kernel_arg, ['b=2', 'a=9', 'c=3'])
            self.assertEqual(ctx.args.build_config, str(explicit))

    def test_relative_config_paths_resolve_beside_the_file(self):
        with TemporaryDirectory() as directory, clean_environment():
            fixture = Fixture(Path(directory))
            explicit = build_options(Path(directory) / 'explicit.toml',
                                     '[build]\n'
                                     'ipsw = "restore.ipsw"\n'
                                     'kernelcache = "cache.bin"\n'
                                     'out = "build-out"\n')
            with patch.object(config, 'ROOT', fixture.root):
                ctx = config.Context(fixture.arguments('status', config_file=explicit, out=False))
            self.assertEqual(ctx.args.ipsw, str((explicit.parent / 'restore.ipsw').resolve()))
            self.assertEqual(ctx.args.kernelcache, str((explicit.parent / 'cache.bin').resolve()))
            self.assertEqual(ctx.out_root, (explicit.parent / 'build-out').resolve())

    def test_url_values_are_not_path_expanded(self):
        with TemporaryDirectory() as directory, clean_environment():
            fixture = Fixture(Path(directory))
            explicit = build_options(Path(directory) / 'explicit.toml',
                                     '[build]\nipsw = "https://example.invalid/restore.ipsw"\n')
            with patch.object(config, 'ROOT', fixture.root):
                ctx = config.Context(fixture.arguments('status', config_file=explicit))
            self.assertEqual(ctx.args.ipsw, 'https://example.invalid/restore.ipsw')

    def test_environment_beats_the_default_local_file(self):
        with TemporaryDirectory() as directory, clean_environment(
                UNIXNU_IPSW='https://example.invalid/env.ipsw'):
            fixture = Fixture(Path(directory))
            (fixture.root / 'unixnu.local.toml').write_text('[build]\nipsw = "local.ipsw"\n')
            with patch.object(config, 'ROOT', fixture.root):
                ctx = config.Context(fixture.arguments('status'))
            self.assertIsNone(ctx.args.ipsw)
            self.assertEqual(ctx.option_text('ipsw', 'UNIXNU_IPSW'), 'https://example.invalid/env.ipsw')
            self.assertEqual(ctx.args.build_config, str(fixture.root / 'unixnu.local.toml'))

    def test_environment_beats_the_config_file_for_paths(self):
        with TemporaryDirectory() as directory, clean_environment(
                UNIXNU_IPSW='https://example.invalid/env.ipsw',
                UNIXNU_KERNELCACHE='/tmp/env.cache', UNIXNU_UEFI='/tmp/env-uefi',
                UNIXNU_DTB='/tmp/env.dtb', UNIXNU_OUT='/tmp/env-out'):
            fixture = Fixture(Path(directory))
            explicit = build_options(Path(directory) / 'explicit.toml',
                                     '[build]\n'
                                     'ipsw = "file.ipsw"\n'
                                     'kernelcache = "file.cache"\n'
                                     'uefi = "file-uefi"\n'
                                     'dtb = "file.dtb"\n'
                                     'out = "file-out"\n')
            with patch.object(config, 'ROOT', fixture.root):
                ctx = config.Context(fixture.arguments('status', config_file=explicit, out=False))
            self.assertIsNone(ctx.args.ipsw)
            self.assertEqual(ctx.option_text('ipsw', 'UNIXNU_IPSW'), 'https://example.invalid/env.ipsw')
            self.assertEqual(ctx.option('kernelcache', 'UNIXNU_KERNELCACHE'), Path('/tmp/env.cache').resolve())
            self.assertEqual(ctx.option('uefi', 'UNIXNU_UEFI'), Path('/tmp/env-uefi').resolve())
            self.assertEqual(ctx.option('dtb', 'UNIXNU_DTB'), Path('/tmp/env.dtb').resolve())
            self.assertEqual(ctx.out_root, Path('/tmp/env-out').resolve())

    def test_device_flag_beats_environment_and_environment_beats_saved_state(self):
        with TemporaryDirectory() as directory, clean_environment():
            fixture = Fixture(Path(directory))
            devices = {}
            for name in ('state', 'environment'):
                path = Path(directory) / name
                path.mkdir()
                (path / 'board.toml').write_text(f'schema_version = 1\n[board]\nname = "{name}"\n')
                devices[name] = path
            fixture.out.mkdir()
            (fixture.out / 'state.json').write_text(json.dumps({'device': str(devices['state'])}))
            explicit = fixture.arguments('status')
            implicit = fixture.arguments('status')
            implicit.device = None
            with clean_environment(UNIXNU_DEVICE=str(devices['environment'])):
                with patch.object(config, 'ROOT', fixture.root):
                    self.assertEqual(config.Context(explicit).device, fixture.device.resolve())
                    self.assertEqual(config.Context(implicit).device, devices['environment'].resolve())
            with patch.object(config, 'ROOT', fixture.root):
                self.assertEqual(config.Context(implicit).device, devices['state'].resolve())

    def test_invalid_options_are_rejected(self):
        with TemporaryDirectory() as directory, clean_environment():
            fixture = Fixture(Path(directory))
            cases = {'[build]\nunknown = "x"\n': 'unknown build option',
                     '[build]\njobs = 0\n': 'positive integer',
                     '[build]\ntarget = "FAST"\n': 'DEBUG or RELEASE',
                     '[build]\nkernel_args = "a=1"\n': 'array of strings',
                     '[tool]\nname = "x"\n': 'expected a \\[build\\] table'}
            for text, message in cases.items():
                with self.subTest(text=text):
                    explicit = build_options(Path(directory) / 'bad.toml', text)
                    with patch.object(config, 'ROOT', fixture.root):
                        with self.assertRaisesRegex(Exception, message):
                            config.Context(fixture.arguments('status', config_file=explicit))


class IpwAndKernelInputTests(unittest.TestCase):
    def manifest(self, product='iPad7,1', version='17.7.11', build='21H461',
                 device_class='j120ap', chip='8011', board='0C'):
        return {
            'ProductVersion': version,
            'ProductBuildVersion': build,
            'SupportedProductTypes': [product],
            'BuildIdentities': [{
                'Info': {'DeviceClass': device_class, 'RestoreBehavior': 'Erase'},
                'ApChipID': chip,
                'ApBoardID': board,
            }],
        }

    def check(self, manifest, config_values=None):
        with TemporaryDirectory() as directory:
            root = Path(directory)
            archive = root / 'restore.ipsw'
            with zipfile.ZipFile(archive, 'w') as bundle:
                bundle.writestr('BuildManifest.plist', plistlib.dumps(manifest))
            board = {'ipsw': config_values or {
                'product': 'iPad7,1', 'version': '17.7.11', 'build': '21H461',
                'device_class': 'j120ap', 'chip_id': 32785, 'board_id': 12}}
            ctx = SimpleNamespace(board=board, out_root=root / 'out', option_text=lambda *a: None)
            with patch.object(ipsw, 'log'):
                source = ipsw.Ipsw(ctx, spec=str(archive))
            self.addCleanup(source.stream.close)
            self.addCleanup(source.zip.close)
            return source

    def test_matching_manifest_is_accepted(self):
        source = self.check(self.manifest())
        self.assertEqual(source.identity['Info']['DeviceClass'], 'j120ap')

    def test_wrong_version_product_and_identity_are_rejected(self):
        with self.assertRaisesRegex(Exception, 'the board expects 17.7.11 \\(21H461\\)'):
            self.check(self.manifest(version='18.0'))
        with self.assertRaisesRegex(Exception, 'the board expects 17.7.11 \\(21H461\\) for iPad7,1'):
            self.check(self.manifest(product='iPad8,1'))
        with self.assertRaisesRegex(Exception, 'no Erase build identity'):
            self.check(self.manifest(device_class='j120apx'))
        with self.assertRaisesRegex(Exception, 'no Erase build identity'):
            self.check(self.manifest(chip='8022'))
        with self.assertRaisesRegex(Exception, 'no Erase build identity'):
            self.check(self.manifest(board='0D'))

    def test_missing_and_wrong_kernelcache_fail_before_prelink(self):
        with TemporaryDirectory() as directory:
            root = Path(directory)
            ctx = SimpleNamespace(
                board={'kernel': {'prelink': {'kernelcache_sha256': 'a' * 64}}},
                tree=root / 'tree', work=root / 'work', logs=root / 'logs')
            missing = root / 'missing.cache'
            ctx.option = lambda flag, env=None: missing
            with patch.object(kernel, 'log'):
                with patch.object(kernel, 'run', side_effect=AssertionError('prelink ran')):
                    with self.assertRaisesRegex(Exception, 'kernelcache not found'):
                        kernel.prelink(ctx)
                    wrong = root / 'wrong.cache'
                    wrong.write_bytes(b'not the qualified kernelcache')
                    ctx.option = lambda flag, env=None: wrong
                    with self.assertRaisesRegex(Exception, 'does not match the kernelcache'):
                        kernel.prelink(ctx)


class FeedOverrideTests(unittest.TestCase):
    def sources(self, base):
        root = base / 'UniXNU'
        device = base / 'device'
        for directory in (root / 'drivers/foo', device / 'drivers/foo'):
            directory.mkdir(parents=True)
        local = base / 'local-drivers/foo'
        local.mkdir(parents=True)
        cli = base / 'cli-drivers/foo'
        cli.mkdir(parents=True)
        feed = base / 'feed-drivers/bar'
        feed.mkdir(parents=True)
        (device / 'local.toml').write_text('[local]\ndrivers = "' + str(base / 'local-drivers') + '"\n')
        (device / 'feeds.toml').write_text(
            '[[source]]\nname = "bar"\nkind = "driver"\nlocal = "' + str(feed) + '"\n')
        return root, device, local, cli, feed

    def context(self, base, *, local_module=None, local=None):
        root = base / 'UniXNU'
        device = base / 'device'
        args = SimpleNamespace(local_module=local_module, local=local,
                               local_drivers=None, local_kits=None, local_patches=None,
                               local_scripts=None, local_package=None)
        return SimpleNamespace(root=root, device=device, soc=None, schema_version=1,
                               board={}, profile_roots={'device': device}, args=args,
                               lock_path=device / 'unixnu.lock')

    def test_device_local_module_beats_repository_directories(self):
        with TemporaryDirectory() as directory:
            base = Path(directory)
            root, device, local, cli, feed = self.sources(base)
            modules = feeds.resolve(self.context(base))
            foo = modules[('driver', 'foo')]
            self.assertEqual(foo.path, local)
            self.assertEqual(foo.origin, 'local (local.toml)')
            self.assertEqual(modules[('driver', 'bar')].origin, 'local (feeds)')

    def test_cli_module_beats_the_device_local_file(self):
        with TemporaryDirectory() as directory:
            base = Path(directory)
            root, device, local, cli, feed = self.sources(base)
            modules = feeds.resolve(self.context(base, local_module=[f'driver:foo={cli}']))
            self.assertEqual(modules[('driver', 'foo')].path, cli)
            self.assertEqual(modules[('driver', 'foo')].origin, 'local (--local-module)')

    def test_local_root_beats_the_device_local_file(self):
        with TemporaryDirectory() as directory:
            base = Path(directory)
            root, device, local, cli, feed = self.sources(base)
            alternate = base / 'alternate'
            (alternate / 'drivers/foo').mkdir(parents=True)
            (alternate / 'drivers/extra').mkdir(parents=True)
            modules = feeds.resolve(self.context(base, local=str(alternate)))
            self.assertEqual(modules[('driver', 'foo')].path, alternate / 'drivers/foo')
            self.assertEqual(modules[('driver', 'foo')].origin, 'local (--local)')
            self.assertEqual(modules[('driver', 'extra')].origin, 'local (--local)')


if __name__ == '__main__':
    unittest.main()
