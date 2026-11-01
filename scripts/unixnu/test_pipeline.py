"""Release manifest, verification and step-order checks, without a build."""
import json
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from types import SimpleNamespace
from unittest.mock import patch

from . import cli, feeds, patches, pipeline
from .util import Error


class Module:
    def __init__(self, path=None, commit=None):
        self.path = path
        self.commit = commit


def context(root, boot_partition=None, arguments=('-v', 'serial=3')):
    work = root / 'ipados-17.7.11-21H461' / 'gta4l'
    for name in ('boot', 'kernel', 'payload'):
        (work / name).mkdir(parents=True)
    (work / 'boot/boot.img').write_bytes(b'boot image')
    (work / 'kernel/kernel.macho').write_bytes(b'kernel')
    (work / 'payload/payload.img').write_bytes(b'payload')
    (work / 'payload/payload.json').write_text(json.dumps({'kernel_args': ' '.join(arguments)}))
    board = {'package': {}}
    if boot_partition is not None:
        board['package']['boot_partition_bytes'] = boot_partition
    return SimpleNamespace(work=work, board=board, name='gta4l', config_name='gta4l_defconfig')


def manifest(ctx):
    files = pipeline.outputs(ctx)
    modules = {('kernel', 'xnu'): Module(commit='d8b80295118ef25ac3a784134bcf95cd8e88109f'),
               ('soc', 'sm6115'): Module(path=str(ctx.work), commit=None)}
    with patch.object(pipeline, 'log'):
        return pipeline.write_manifest(ctx, modules, [Path('/patches/xnu/series')], files), files


class ManifestTests(unittest.TestCase):
    def test_manifest_records_outputs_and_resolved_revisions(self):
        with TemporaryDirectory() as directory:
            ctx = context(Path(directory))
            target, files = manifest(ctx)
            recorded = json.loads(target.read_text())
            self.assertEqual(recorded['device'], 'gta4l')
            self.assertEqual(recorded['os_profile'], 'ipados-17.7.11-21H461')
            self.assertEqual(recorded['configuration'], 'gta4l_defconfig')
            self.assertEqual(recorded['kernel_command_line_bytes'], len('-v serial=3'))
            self.assertEqual(recorded['patches'], ['/patches/xnu/series'])
            self.assertEqual(recorded['revisions']['kernel:xnu'], 'd8b80295118ef25ac3a784134bcf95cd8e88109f')
            self.assertIsNone(recorded['revisions']['soc:sm6115'])
            for name, path in files.items():
                self.assertEqual(recorded['outputs'][name]['bytes'], path.stat().st_size)
            self.assertEqual(target, ctx.work / 'package.manifest.json')


class VerifyTests(unittest.TestCase):
    def test_clean_manifest_passes(self):
        with TemporaryDirectory() as directory:
            ctx = context(Path(directory))
            target, files = manifest(ctx)
            with patch.object(pipeline, 'log'):
                pipeline.verify(ctx, files, target)

    def test_missing_output_fails(self):
        with TemporaryDirectory() as directory:
            ctx = context(Path(directory))
            target, files = manifest(ctx)
            files['payload.img'].unlink()
            with patch.object(pipeline, 'log'):
                with self.assertRaisesRegex(Error, 'output missing: payload.img'):
                    pipeline.verify(ctx, files, target)

    def test_changed_output_fails(self):
        with TemporaryDirectory() as directory:
            ctx = context(Path(directory))
            target, files = manifest(ctx)
            files['boot.img'].write_bytes(b'changed')
            with patch.object(pipeline, 'log'):
                with self.assertRaisesRegex(Error, 'boot.img differs from the manifest'):
                    pipeline.verify(ctx, files, target)

    def test_command_line_limit(self):
        with TemporaryDirectory() as directory:
            ctx = context(Path(directory), arguments=('a' * 999, 'b'))
            target, files = manifest(ctx)
            with patch.object(pipeline, 'log'):
                with self.assertRaisesRegex(Error, 'kernel command line is 1001 bytes'):
                    pipeline.verify(ctx, files, target)

    def test_boot_partition_limit(self):
        with TemporaryDirectory() as directory:
            ctx = context(Path(directory), boot_partition=4)
            target, files = manifest(ctx)
            with patch.object(pipeline, 'log'):
                with self.assertRaisesRegex(Error, 'the boot partition holds 4'):
                    pipeline.verify(ctx, files, target)

    def test_missing_payload_report(self):
        with TemporaryDirectory() as directory:
            ctx = context(Path(directory))
            (ctx.work / 'payload/payload.json').unlink()
            with self.assertRaisesRegex(Error, 'the payload step did not run'):
                pipeline.command_line(ctx)


class ReleaseContext:
    def __init__(self, root, **arguments):
        self.tree = root / 'tree'
        self.work = root / 'out/gta4l'
        self.config_name = 'gta4l_defconfig'
        self.schema_version = 2
        self.soc = SimpleNamespace(name='sm6115')
        self.board = {'ipsw': {'url': 'https://example.invalid/restore.ipsw'},
                      'bootimg': {'dtb': 'build/gta4l/boot.dtb'}}
        values = dict(no_deps=False, check=False, ipsw=None, names=[], update=True,
                      action=None, components=None, name=None, steps=None,
                      fd='fd', ramdisk='ramdisk', output='output', dtb=None)
        values.update(arguments)
        self.args = SimpleNamespace(**values)

    def refuse_example(self):
        return None


class ReleaseTests(unittest.TestCase):
    def exercise(self, ctx, fail=None):
        calls = []
        def record(name, result=None):
            def run(*arguments):
                calls.append(name)
                if name == fail:
                    raise Error(f'{name} failed')
                return result
            return run
        modules = {('kernel', 'xnu'): Module(commit='d8b80295118ef25ac3a784134bcf95cd8e88109f')}
        targets = {'boot.img': ctx.work / 'boot.img'}
        with patch.object(cli, 'cmd_fetch', record('deps')), \
                patch.object(cli, 'cmd_ipsw', record('ipsw')), \
                patch.object(cli, 'cmd_defconfig', record('preflight')), \
                patch.object(feeds, 'resolve', return_value=modules), \
                patch.object(patches, 'plan', return_value=[Path('/patches/xnu/series')]), \
                patch.object(cli, 'cmd_build', record('build')), \
                patch.object(cli, 'cmd_bootimg', record('pack')), \
                patch.object(pipeline, 'outputs', return_value=targets), \
                patch.object(pipeline, 'write_manifest', record('manifest', Path('/manifest.json'))), \
                patch.object(pipeline, 'verify', record('verify')), \
                patch.object(cli, 'log'):
            if fail:
                with self.assertRaisesRegex(Error, f'{fail} failed'):
                    cli.cmd_release(ctx)
            else:
                cli.cmd_release(ctx)
        return calls

    def test_steps_run_in_order_and_boot_dtb_is_passed(self):
        with TemporaryDirectory() as directory:
            ctx = ReleaseContext(Path(directory))
            calls = self.exercise(ctx)
            self.assertEqual(calls, ['deps', 'ipsw', 'preflight', 'build', 'pack', 'manifest', 'verify'])
            self.assertEqual(ctx.args.dtb, str(ctx.tree / 'build/gta4l/boot.dtb'))
            self.assertIsNone(ctx.args.fd)
            self.assertIsNone(ctx.args.ramdisk)
            self.assertIsNone(ctx.args.output)

    def test_check_stops_before_build(self):
        with TemporaryDirectory() as directory:
            ctx = ReleaseContext(Path(directory), check=True)
            self.assertEqual(self.exercise(ctx), ['deps', 'ipsw', 'preflight'])

    def test_no_deps_skips_fetch_and_ipsw(self):
        with TemporaryDirectory() as directory:
            ctx = ReleaseContext(Path(directory), no_deps=True)
            self.assertEqual(self.exercise(ctx), ['preflight', 'build', 'pack', 'manifest', 'verify'])

    def test_failed_step_stops_the_release(self):
        with TemporaryDirectory() as directory:
            ctx = ReleaseContext(Path(directory))
            self.assertEqual(self.exercise(ctx, fail='build'), ['deps', 'ipsw', 'preflight', 'build'])

    def test_every_step_failure_stops_later_steps(self):
        expected = {'deps': ['deps'],
                    'ipsw': ['deps', 'ipsw'],
                    'preflight': ['deps', 'ipsw', 'preflight'],
                    'pack': ['deps', 'ipsw', 'preflight', 'build', 'pack'],
                    'manifest': ['deps', 'ipsw', 'preflight', 'build', 'pack', 'manifest'],
                    'verify': ['deps', 'ipsw', 'preflight', 'build', 'pack', 'manifest', 'verify']}
        for fail, calls in expected.items():
            with self.subTest(fail=fail), TemporaryDirectory() as directory:
                ctx = ReleaseContext(Path(directory))
                self.assertEqual(self.exercise(ctx, fail=fail), calls)

    def test_check_failure_stops_before_build(self):
        with TemporaryDirectory() as directory:
            ctx = ReleaseContext(Path(directory), check=True)
            self.assertEqual(self.exercise(ctx, fail='preflight'), ['deps', 'ipsw', 'preflight'])


if __name__ == '__main__':
    unittest.main()
