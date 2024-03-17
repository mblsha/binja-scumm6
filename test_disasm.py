#!/usr/bin/env python3
import unittest
from kaitaistruct import KaitaiStream, BytesIO

test_cases = [
    (b"", ""),
]

from pprint import pprint
from scumm6_container import *

# class DecodeContainerTest(unittest.TestCase):
#     def test_parse(self):
#         for t in test_cases:
#             self.assertEqual(r[1], t[1])
#             self.assertEqual(r[2], len(t[0]))

# if __name__ == '__main__':
#     unittest.main()
