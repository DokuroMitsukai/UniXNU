"""Linux toolchain environment checks; no system-wide shims required."""
import os
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from .kernel import linux_env
from .util import Error


class LinuxEnvironmentTests(unittest.TestCase):
    def test_prefix_shim(self):
        with tempfile.TemporaryDirectory() as directory:
            prefix = Path(directory)
            for name in ('llvm/bin/clang', 'CommandLineTools/usr/bin/ld',
                         'CommandLineTools/usr/bin/xnu-host-cc', 'CommandLineTools/usr/libexec/migcom',
                         'XcodeDefault.xctoolchain/usr/bin/iig', 'bin/xcrun', 'bin/lzfse'):
                path = prefix / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.touch()
            with patch.dict(os.environ, UNIXNU_TOOLCHAIN=str(prefix)):
                ctx = SimpleNamespace(tree=prefix / 'tree')
                env = linux_env(ctx)
                self.assertIn(str(prefix / 'bin'), env['PATH'].split(os.pathsep))
                (prefix / 'bin/xcrun').unlink()
                with self.assertRaisesRegex(Error, 'bin/xcrun missing'):
                    linux_env(ctx)


if __name__ == '__main__':
    unittest.main()
