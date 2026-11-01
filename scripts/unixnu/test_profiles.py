"""Profile selection and per-OS board overrides."""
import tomllib
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from types import SimpleNamespace
from unittest.mock import patch

from . import feeds, profiles
from .util import Error

REPOSITORY = Path(__file__).resolve().parents[2]
PROFILE = 'ipados-17.7.11-21H461'


def context(root, os_argument=None):
    return SimpleNamespace(root=root, args=SimpleNamespace(os=os_argument), profile_roots={}, profile_files=[])


class ResolveOsTests(unittest.TestCase):
    def test_alias_and_full_name(self):
        with TemporaryDirectory() as directory:
            root = Path(directory)
            for name in (PROFILE, 'ipados-26.5.2-23F84'):
                (root / 'profiles/os' / name).mkdir(parents=True)
            ctx = context(root)
            self.assertEqual(profiles.resolve_os(ctx, PROFILE), PROFILE)
            self.assertEqual(profiles.resolve_os(ctx, '17'), PROFILE)
            self.assertEqual(profiles.resolve_os(ctx, '26'), 'ipados-26.5.2-23F84')

    def test_unknown_alias_is_rejected(self):
        with TemporaryDirectory() as directory:
            root = Path(directory)
            (root / 'profiles/os' / PROFILE).mkdir(parents=True)
            with self.assertRaisesRegex(Error, '--os 27'):
                profiles.resolve_os(context(root), '27')

    def test_ambiguous_alias_is_rejected(self):
        with TemporaryDirectory() as directory:
            root = Path(directory)
            for name in ('ipados-17.1.1-1A1', 'ipados-17.2.2-2B2'):
                (root / 'profiles/os' / name).mkdir(parents=True)
            with self.assertRaisesRegex(Error, '--os 17'):
                profiles.resolve_os(context(root), '17')

    def test_retained_profile_is_the_only_one_in_the_repository(self):
        names = sorted(path.name for path in (REPOSITORY / 'profiles/os').iterdir() if path.is_dir())
        self.assertEqual(names, [PROFILE])
        with self.assertRaisesRegex(Error, '--os 26'):
            profiles.resolve_os(context(REPOSITORY), '26')
        with self.assertRaisesRegex(Error, '--os 27'):
            profiles.resolve_os(context(REPOSITORY), '27')


class OsOverrideTests(unittest.TestCase):
    def build(self, root):
        arch = root / 'profiles/arch/arm64'
        arch.mkdir(parents=True)
        (arch / 'profile.toml').write_text('[arch]\nname = "arm64"\n')
        soc = root / 'soc'
        soc.mkdir()
        (soc / 'soc.toml').write_text('[soc]\nname = "SM6115"\n')
        os_root = root / 'profiles/os' / PROFILE
        os_root.mkdir(parents=True)
        (os_root / 'profile.toml').write_text(
            '[os]\nname = "' + PROFILE + '"\narch = "arm64"\n'
            '[kernel]\narchives = ["profile"]\nconfig_fragments = ["profile"]\n'
            '[payload]\nroot_policies = ["profile"]\n')
        device = root / 'device'
        device.mkdir()
        (device / 'configs').mkdir()
        (device / 'configs/gta4l_defconfig').write_text('CONFIG_XNU_NATIVE_PAN=n\n')
        board = (
            '[board]\nsoc_source = "sm6115"\nos_profile = "' + PROFILE + '"\n'
            '[package]\nunixnu = "../UniXNU"\nboot_partition_bytes = 100663296\n'
            '[package.defconfig]\n"' + PROFILE + '" = "gta4l_defconfig"\n'
            '[kernel]\ndefconfig = "gta4l_defconfig"\narchives = ["board"]\n'
            '[payload]\nvolume = "GTA4LESP"\n'
            '[os_overrides."' + PROFILE + '"]\nremove = ["kernel.config_fragments", "payload.root_policies"]\n'
            '[os_overrides."' + PROFILE + '".kernel]\narchives = ["override"]\n')
        (device / 'board.toml').write_text(board)
        ctx = context(root)
        ctx.device = device
        ctx.raw_board = tomllib.loads(board)
        ctx.soc = None
        return ctx, soc

    def test_selected_override_merges_and_removes(self):
        with TemporaryDirectory() as directory:
            ctx, soc = self.build(Path(directory))
            with patch.object(feeds, 'resolve_soc', return_value=SimpleNamespace(path=soc)):
                result = profiles.load(ctx)
            self.assertEqual(result['kernel']['archives'], ['override'])
            self.assertNotIn('config_fragments', result['kernel'])
            self.assertNotIn('root_policies', result['payload'])
            self.assertEqual(result['payload']['volume'], 'GTA4LESP')
            self.assertEqual(result['board']['os_profile'], PROFILE)

    def test_os_argument_selects_the_profile(self):
        with TemporaryDirectory() as directory:
            ctx, soc = self.build(Path(directory))
            ctx.args.os = '17'
            with patch.object(feeds, 'resolve_soc', return_value=SimpleNamespace(path=soc)):
                result = profiles.load(ctx)
            self.assertEqual(ctx.profile_roots['os'], Path(directory) / 'profiles/os' / PROFILE)
            self.assertEqual(result['board']['os_profile'], PROFILE)

    def test_arm64e_profile_is_rejected(self):
        with TemporaryDirectory() as directory:
            ctx, soc = self.build(Path(directory))
            (Path(directory) / 'profiles/os' / PROFILE / 'profile.toml').write_text(
                '[os]\nname = "' + PROFILE + '"\narch = "arm64e"\n')
            with patch.object(feeds, 'resolve_soc', return_value=SimpleNamespace(path=soc)):
                with self.assertRaisesRegex(Error, 'arch is arm64e'):
                    profiles.load(ctx)

    def test_installed_profile_outside_the_package_contract_is_rejected(self):
        with TemporaryDirectory() as directory:
            ctx, soc = self.build(Path(directory))
            foreign = Path(directory) / 'profiles/os/ipados-26.5.2-23F84'
            foreign.mkdir()
            (foreign / 'profile.toml').write_text('[os]\nname = "ipados-26.5.2-23F84"\narch = "arm64"\n')
            ctx.args.os = '26'
            with patch.object(feeds, 'resolve_soc', side_effect=AssertionError('resolved the SoC before validation')):
                with self.assertRaisesRegex(Error, 'does not package that OS profile'):
                    profiles.load(ctx)

    def test_path_like_os_profile_is_rejected(self):
        with TemporaryDirectory() as directory:
            ctx, soc = self.build(Path(directory))
            ctx.raw_board['board']['os_profile'] = '../' + PROFILE
            with patch.object(feeds, 'resolve_soc', side_effect=AssertionError('resolved the SoC before validation')):
                with self.assertRaisesRegex(Error, 'must be a profile directory name'):
                    profiles.load(ctx)

    def test_missing_profile_file_is_rejected(self):
        with TemporaryDirectory() as directory:
            ctx, soc = self.build(Path(directory))
            (Path(directory) / 'profiles/os' / PROFILE / 'profile.toml').unlink()
            with patch.object(feeds, 'resolve_soc', side_effect=AssertionError('resolved the SoC before validation')):
                with self.assertRaisesRegex(Error, 'is not installed'):
                    profiles.load(ctx)

    def test_missing_mapped_defconfig_is_rejected(self):
        with TemporaryDirectory() as directory:
            ctx, soc = self.build(Path(directory))
            ctx.raw_board['package']['defconfig'][PROFILE] = 'missing_defconfig'
            with patch.object(feeds, 'resolve_soc', side_effect=AssertionError('resolved the SoC before validation')):
                with self.assertRaisesRegex(Error, 'configs/missing_defconfig is missing'):
                    profiles.load(ctx)

    def test_override_cannot_change_the_package_contract(self):
        with TemporaryDirectory() as directory:
            ctx, soc = self.build(Path(directory))
            with (Path(directory) / 'device/board.toml').open('a') as stream:
                stream.write('[os_overrides."' + PROFILE + '".package]\nboot_partition_bytes = 1\n')
            ctx.raw_board = tomllib.loads((Path(directory) / 'device/board.toml').read_text())
            with patch.object(feeds, 'resolve_soc', return_value=SimpleNamespace(path=soc)):
                result = profiles.load(ctx)
            self.assertEqual(result['package']['boot_partition_bytes'], 100663296)

    def test_override_cannot_change_the_profile_identity(self):
        with TemporaryDirectory() as directory:
            ctx, soc = self.build(Path(directory))
            with (Path(directory) / 'device/board.toml').open('a') as stream:
                stream.write('[os_overrides."' + PROFILE + '".os]\nname = "ipados-26.5.2-23F84"\n')
            ctx.raw_board = tomllib.loads((Path(directory) / 'device/board.toml').read_text())
            with patch.object(feeds, 'resolve_soc', return_value=SimpleNamespace(path=soc)):
                with self.assertRaisesRegex(Error, 'resolved \[os\] name'):
                    profiles.load(ctx)


if __name__ == '__main__':
    unittest.main()
