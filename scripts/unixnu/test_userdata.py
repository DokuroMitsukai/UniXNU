"""SHNGROOT manifest serialization for block windows and version-2 data objects."""
import hashlib
import struct
import unittest

from .userdata import manifest_bytes


def entry(name, offset, size, block_size, flags, digest=bytes(32)):
    return (name, offset, size, block_size, flags, digest)


class ManifestTests(unittest.TestCase):
    def test_version_one_matches_the_window_only_layout(self):
        header = manifest_bytes(1, [entry('OS', 1 << 20, 4096, 512, 1),
                                    entry('SystemOS', 2 << 20, 4096, 512, 1)], 3 << 20)
        self.assertEqual(header[0:8], b'SHNGROOT')
        self.assertEqual(struct.unpack_from('<IIQ', header, 8), (1, 2, 3 << 20))
        name, offset, size, block_size, flags = struct.unpack_from('<32sQQII', header, 24)
        self.assertEqual((name.rstrip(b'\0'), offset, size, block_size, flags),
                         (b'OS', 1 << 20, 4096, 512, 1))
        self.assertEqual(header[4064:4096], hashlib.sha256(bytes(header[:4064])).digest())

    def test_version_two_marks_objects_with_their_own_block_size_and_flags(self):
        header = manifest_bytes(2, [entry('OS', 1 << 20, 4096, 512, 1),
                                    entry('SystemOS', 2 << 20, 4096, 512, 1),
                                    entry('OS.vroot', 3 << 20, 4096, 4096, 3),
                                    entry('SystemOS.vroot', 4 << 20, 4096, 4096, 3)], 5 << 20)
        self.assertEqual(struct.unpack_from('<IIQ', header, 8), (2, 4, 5 << 20))
        entries = [struct.unpack_from('<32sQQII', header, 24 + 128 * index) for index in range(4)]
        self.assertEqual([(e[4], e[3]) for e in entries], [(1, 512), (1, 512), (3, 4096), (3, 4096)])

    def test_sha256_field_is_covered_by_the_header_digest(self):
        first = manifest_bytes(2, [entry('OS', 1 << 20, 4096, 512, 1, bytes([1]) * 32),
                                   entry('OS.vroot', 2 << 20, 4096, 4096, 3, bytes([2]) * 32)], 3 << 20)
        second = bytearray(first)
        second[24 + 128 + 56] ^= 1
        self.assertEqual(first[4064:4096], hashlib.sha256(bytes(first[:4064])).digest())
        self.assertNotEqual(second[4064:4096], hashlib.sha256(bytes(second[:4064])).digest())

    def test_names_are_bounded_and_zero_terminated(self):
        header = manifest_bytes(2, [entry('OS.vroot', 4096, 4096, 4096, 3)], 8192)
        self.assertEqual(header[24 + 32 - 1], 0)


if __name__ == '__main__':
    unittest.main()
