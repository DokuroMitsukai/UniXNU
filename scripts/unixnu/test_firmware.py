"""Firmware preflight entries carry arguments and reach the device checkout through UNIXNU_DEVICE."""
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from . import firmware


class Stop(Exception):
    """Ends build() at the preflight call under test."""


class PreflightTests(unittest.TestCase):
    def context(self, entries, skip=False):
        tree = Path('/tmp/unixnu-test/tree')
        return SimpleNamespace(
            tree=tree,
            device=Path('/tmp/unixnu-test/device'),
            logs=Path('/tmp/unixnu-test/logs'),
            work=Path('/tmp/unixnu-test/work'),
            jobs=1,
            args=SimpleNamespace(skip_preflight=skip),
            board={'firmware': {'config': 'gta4l', 'dsc': 'board.dsc', 'fd': '{target}.fd',
                                'preflight': entries, 'packages': ['{uefi}']}},
        )

    def invoke(self, ctx):
        calls = []

        def stop(command, **kwargs):
            calls.append((command, kwargs))
            raise Stop

        config = {'uefi_fd': {'base': 0x1000, 'size': 0x1000}}
        with patch.object(firmware, 'log'), \
                patch.object(firmware, 'tool'), \
                patch.object(firmware, 'uefi_config', return_value=(ctx.board['firmware'], config)), \
                patch.object(firmware, 'run', side_effect=stop):
            with self.assertRaises(Stop):
                firmware.build(ctx, {}, Path('/tmp/unixnu-test/uefi'), Path('/tmp/unixnu-test/edk2'))
        return calls

    def test_entry_arguments_are_split(self):
        ctx = self.context(['scripts/preflight.py --flag value'])
        (command, kwargs), = self.invoke(ctx)
        self.assertEqual(command, ['python3', ctx.tree / 'scripts/preflight.py', '--flag', 'value'])
        self.assertEqual(kwargs['cwd'], ctx.tree)
        self.assertEqual(kwargs['env']['UNIXNU_UEFI'], '/tmp/unixnu-test/uefi')
        self.assertEqual(kwargs['env']['UNIXNU_DEVICE'], str(ctx.device))

    def test_absolute_entry_path_is_used_as_is(self):
        absolute = '/opt/preflight/check.py'
        ctx = self.context([absolute])
        (command, _), = self.invoke(ctx)
        self.assertEqual(command, ['python3', Path(absolute)])

    def test_unknown_quoting_raises_before_any_run(self):
        ctx = self.context(["scripts/preflight.py 'unterminated"])
        with patch.object(firmware, 'log'), \
                patch.object(firmware, 'tool'), \
                patch.object(firmware, 'uefi_config',
                             return_value=(ctx.board['firmware'],
                                           {'uefi_fd': {'base': 0x1000, 'size': 0x1000}})), \
                patch.object(firmware, 'run') as run:
            with self.assertRaises(ValueError):
                firmware.build(ctx, {}, Path('/tmp/unixnu-test/uefi'), Path('/tmp/unixnu-test/edk2'))
        run.assert_not_called()


if __name__ == '__main__':
    unittest.main()
