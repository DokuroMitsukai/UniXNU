"""Tree assembly copies changed scripts by content: same-size edits and stale mtimes still refresh."""
import os
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from . import tree


def write(path, data, mtime=None):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)
    if mtime is not None:
        os.utime(path, (mtime, mtime))


class CopyScriptsTests(unittest.TestCase):
    def setUp(self):
        self.temporary = TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.source = Path(self.temporary.name) / 'source'
        self.destination = Path(self.temporary.name) / 'destination'
        self.source.mkdir()
        self.destination.mkdir()

    def test_same_size_edit_with_older_source_refreshes(self):
        write(self.source / 'build.py', b'print(1)\n', mtime=1000)
        write(self.destination / 'build.py', b'print(2)\n', mtime=2000)
        tree._copy_scripts(self.source, self.destination)
        self.assertEqual((self.destination / 'build.py').read_bytes(), b'print(1)\n')

    def test_identical_content_is_not_copied(self):
        write(self.source / 'build.py', b'print(1)\n', mtime=2000)
        write(self.destination / 'build.py', b'print(1)\n', mtime=1000)
        before = (self.destination / 'build.py').stat().st_mtime_ns
        tree._copy_scripts(self.source, self.destination)
        self.assertEqual((self.destination / 'build.py').stat().st_mtime_ns, before)

    def test_symlink_target_is_replaced_by_a_regular_file(self):
        write(self.source / 'build.py', b'print(1)\n')
        outside = Path(self.temporary.name) / 'outside.py'
        write(outside, b'outside\n')
        (self.destination / 'build.py').symlink_to(outside)
        tree._copy_scripts(self.source, self.destination)
        target = self.destination / 'build.py'
        self.assertFalse(target.is_symlink())
        self.assertEqual(target.read_bytes(), b'print(1)\n')

    def test_nested_scripts_copy_and_pycache_is_skipped(self):
        write(self.source / 'unixnu/build.py', b'print(1)\n')
        write(self.source / 'unixnu/__pycache__/build.cpython-311.pyc', b'cache')
        tree._copy_scripts(self.source, self.destination)
        self.assertEqual((self.destination / 'unixnu/build.py').read_bytes(), b'print(1)\n')
        self.assertFalse((self.destination / 'unixnu/__pycache__').exists())


if __name__ == '__main__':
    unittest.main()
