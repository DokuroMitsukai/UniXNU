"""Side-effect-free effective resolution for offline inventories."""
import json
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from . import inspection

PROFILE = 'ipados-17.7.11-21H461'


def write(path, text):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text)
    return path


class Fixture:
    def __init__(self, base, soc_cache=True, component_override=False):
        self.base = base
        self.device = base / 'device'
        self.root = base / 'UniXNU'
        self.soc = base / 'soc'
        self.out = base / 'out'
        write(self.root / 'profiles/arch/arm64/profile.toml',
              '[arch]\nname = "arm64"\n[os]\narch = "arm64"\n')
        write(self.root / 'profiles/os' / PROFILE / 'profile.toml',
              f'[os]\nname = "{PROFILE}"\narch = "arm64"\nxnu_version = "10063.141.1"\n'
              '[kernel.prelink]\nkernelcache_sha256 = "' + 'a' * 64 + '"\n')
        write(self.root / 'feeds.toml',
              '[[source]]\nname = "xnu"\nkind = "refer"\n'
              'git = "https://example.invalid/xnu"\ncommit = "' + 'd' * 40 + '"\n'
              'path = "refer/xnu"\n')
        write(self.root / 'components.toml',
              '[[component]]\nid = "Foo"\nkind = "driver"\nrepository = "https://example.invalid/Foo.git"\n'
              'revision = "' + 'e' * 40 + '"\npath = "drivers/Foo"\n')
        write(self.soc / 'soc.toml', '[soc]\nname = "SM6115"\n')
        write(self.root / 'drivers/Foo/Kit.toml', '[kit]\nname = "Foo"\n')
        write(self.device / 'configs/gta4l_defconfig', 'CONFIG_XNU_NATIVE_PAN=n\n')
        write(self.device / 'patches/xnu/series', 'local.patch\n')
        write(self.device / 'patches/xnu/local.patch', 'device patch\n')
        write(self.device / 'feeds.toml',
              '[[source]]\nname = "sm6115"\nkind = "soc"\nlocal = "../soc"\n')
        if component_override:
            write(self.device / 'local.toml',
                  '[[source]]\nname = "Foo"\nkind = "driver"\nlocal = "../local-foo"\n')
            write(base / 'local-foo/Kit.toml', '[kit]\nname = "Foo"\n')
        write(self.device / 'board.toml',
              'schema_version = 2\n'
              '[board]\nname = "gta4l"\nsoc_source = "sm6115"\n'
              f'os_profile = "{PROFILE}"\n'
              '[components]\ninclude = ["Foo"]\n'
              '[package]\nboot_partition_bytes = 100663296\n'
              f'[package.defconfig]\n"{PROFILE}" = "gta4l_defconfig"\n'
              '[kernel]\ndefconfig = "gta4l_defconfig"\npatch_series = ["device:patches/xnu/series"]\n')

    def inspect(self):
        return inspection.inspect(self.device, root=self.root, out_root=self.out)


class InspectTests(unittest.TestCase):
    def test_clean_resolution_selects_the_mapped_target(self):
        with TemporaryDirectory() as directory:
            fixture = Fixture(Path(directory))
            result = fixture.inspect()
            self.assertTrue(result['resolved'], result['errors'])
            self.assertEqual(result['errors'], [])
            selection = result['selection']
            self.assertEqual(selection['name'], 'gta4l')
            self.assertEqual(selection['os_profile'], PROFILE)
            self.assertEqual(selection['config'], 'gta4l_defconfig')
            self.assertEqual(selection['work'], str(fixture.out / 'gta4l' / PROFILE / 'gta4l'))
            self.assertEqual([item['path'] for item in result['profile_files']],
                             [str(fixture.root / 'profiles/arch/arm64/profile.toml'),
                              str(fixture.soc / 'soc.toml'),
                              str(fixture.root / 'profiles/os' / PROFILE / 'profile.toml'),
                              str(fixture.device / 'board.toml')])
            self.assertTrue(all(item['sha256'] for item in result['profile_files']))
            self.assertEqual(result['selection']['config'], 'gta4l_defconfig')
            soc = [module for module in result['modules'] if module['name'] == 'sm6115'][0]
            self.assertEqual(soc['origin'], 'local (feeds)')
            self.assertEqual(soc['path'], str(fixture.soc))
            foo = [module for module in result['modules'] if module['name'] == 'Foo'][0]
            self.assertEqual(foo['origin'], 'base')
            self.assertFalse(foo['local'])
            self.assertEqual(foo['pin'], 'e' * 40)
            self.assertEqual([item['name'] for item in result['patches']], ['local.patch'])
            self.assertFalse((fixture.out / 'state.json').exists())

    def test_local_component_override_is_visible(self):
        with TemporaryDirectory() as directory:
            fixture = Fixture(Path(directory), component_override=True)
            result = fixture.inspect()
            self.assertTrue(result['resolved'], result['errors'])
            foo = [module for module in result['modules'] if module['name'] == 'Foo'][0]
            self.assertTrue(foo['local'])
            self.assertEqual(foo['origin'], 'local (feeds)')
            self.assertEqual(foo['path'], str(fixture.base / 'local-foo'))
            self.assertIsNone(foo['pin'])

    def test_missing_soc_cache_is_reported_not_raised(self):
        with TemporaryDirectory() as directory:
            base = Path(directory)
            fixture = Fixture(base)
            write(fixture.device / 'feeds.toml',
                  '[[source]]\nname = "sm6115"\nkind = "soc"\n'
                  'git = "https://example.invalid/soc"\ncommit = "' + 'f' * 40 + '"\n')
            result = fixture.inspect()
            self.assertFalse(result['resolved'])
            self.assertIsNone(result['selection'])
            self.assertTrue(any('not cached' in error for error in result['errors']))

    def test_malformed_device_file_is_reported(self):
        with TemporaryDirectory() as directory:
            fixture = Fixture(Path(directory))
            (fixture.device / 'board.toml').write_text('not = [toml')
            result = fixture.inspect()
            self.assertFalse(result['resolved'])
            self.assertTrue(result['errors'])

    def test_saved_state_and_host_inputs_are_ignored(self):
        with TemporaryDirectory() as directory:
            base = Path(directory)
            fixture = Fixture(base)
            fixture.out.mkdir()
            (fixture.out / 'state.json').write_text(json.dumps(
                {'device': str(fixture.device), 'configurations': {str(fixture.device): 'other_defconfig'}}))
            write(fixture.root / 'unixnu.local.toml', '[build]\njobs = 99\n')
            result = fixture.inspect()
            self.assertTrue(result['resolved'], result['errors'])
            self.assertEqual(result['selection']['config'], 'gta4l_defconfig')
            self.assertEqual(result['selection'], {
                'name': 'gta4l', 'os_profile': PROFILE, 'config': 'gta4l_defconfig',
                'work': str(fixture.out / 'gta4l' / PROFILE / 'gta4l')})


if __name__ == '__main__':
    unittest.main()
