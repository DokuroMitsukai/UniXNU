"""Command output redaction for tokens and signed URLs."""
import io
import unittest
from contextlib import redirect_stderr, redirect_stdout
from tempfile import TemporaryDirectory
from types import SimpleNamespace
from unittest.mock import patch

from . import util

TOKEN = 'ghp_' + 'a' * 36
SIGNED = ('https://cdn.example.invalid/restore.ipsw?token=secretvalue&sig=signaturevalue'
          '&ok=1')


class RedactTests(unittest.TestCase):
    def test_token_and_signed_url(self):
        text = util.redact(f'{TOKEN} {SIGNED}')
        self.assertNotIn(TOKEN, text)
        self.assertNotIn('secretvalue', text)
        self.assertNotIn('signaturevalue', text)
        self.assertIn('<redacted>', text)
        self.assertIn('ok=1', text)

    def test_bearer_and_credentials(self):
        credential = 'github_pat_' + 'b' * 30
        text = util.redact(f'Authorization: Bearer abc.def {credential}')
        self.assertNotIn('abc.def', text)
        self.assertNotIn(credential, text)
        text = util.redact('https://user:password@example.invalid/path')
        self.assertNotIn('user', text)
        self.assertNotIn('password', text)

    def test_plain_assignment(self):
        text = util.redact('token=abc password:def api_key=ghi')
        for secret in ('abc', 'def', 'ghi'):
            self.assertNotIn(secret, text)


class RunTests(unittest.TestCase):
    def test_captured_failure_is_redacted(self):
        result = SimpleNamespace(returncode=1, stdout='', stderr=f'fatal {TOKEN} {SIGNED}')
        with patch.object(util.subprocess, 'run', return_value=result):
            with self.assertRaises(util.Error) as raised:
                util.run(['git', 'fetch', SIGNED], capture=True)
        message = str(raised.exception)
        self.assertNotIn(TOKEN, message)
        self.assertNotIn('secretvalue', message)
        self.assertIn('<redacted>', message)

    def test_log_tail_is_redacted(self):
        with TemporaryDirectory() as directory:
            log = f'{directory}/build.log'

            def write(command, **arguments):
                arguments['stdout'].write(f'fatal {TOKEN} {SIGNED}\n')
                return SimpleNamespace(returncode=1)

            stderr = io.StringIO()
            with patch.object(util.subprocess, 'run', side_effect=write):
                with redirect_stderr(stderr):
                    with self.assertRaises(util.Error) as raised:
                        util.run(['make', SIGNED], log_file=log)
            output = stderr.getvalue() + str(raised.exception)
            self.assertNotIn(TOKEN, output)
            self.assertNotIn('secretvalue', output)
            self.assertIn(log, output)

    def test_echoed_command_is_redacted(self):
        stdout = io.StringIO()
        with patch.object(util.subprocess, 'run', return_value=SimpleNamespace(returncode=0)):
            with redirect_stdout(stdout):
                util.run(['tool', '--url', SIGNED])
        output = stdout.getvalue()
        self.assertNotIn('secretvalue', output)
        self.assertIn('<redacted>', output)
