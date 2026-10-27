"""Retry behavior of prepare-xnu-source.py's GitHub header fetches."""
import importlib.util
import io
from pathlib import Path
import unittest
from unittest.mock import patch
import urllib.error
import warnings

SCRIPT = Path(__file__).with_name('prepare-xnu-source.py')
SPEC = importlib.util.spec_from_file_location('prepare_xnu_source', SCRIPT)
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


class Response:
    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False

    def read(self):
        return b'ok'


class FetchTests(unittest.TestCase):
    def test_transient_timeout_retries(self):
        calls = []

        def urlopen(request, timeout):
            calls.append(timeout)
            if len(calls) < 3:
                raise TimeoutError('temporary TLS timeout')
            return Response()

        with patch.object(MODULE.urllib.request, 'urlopen', side_effect=urlopen), \
                patch.object(MODULE.time, 'sleep'):
            self.assertEqual(MODULE.fetch('https://example.invalid/header'), b'ok')
        self.assertEqual(calls, [60, 60, 60])

    def test_http_client_error_is_not_retried(self):
        calls = []

        def urlopen(request, timeout):
            calls.append(timeout)
            raise urllib.error.HTTPError(request.full_url, 404, 'not found', {}, io.BytesIO())

        with warnings.catch_warnings():
            warnings.simplefilter('ignore', ResourceWarning)
            with patch.object(MODULE.urllib.request, 'urlopen', side_effect=urlopen), \
                    patch.object(MODULE.time, 'sleep'):
                with self.assertRaises(urllib.error.HTTPError):
                    MODULE.fetch('https://example.invalid/header')
        self.assertEqual(len(calls), 1)


if __name__ == '__main__':
    unittest.main()
