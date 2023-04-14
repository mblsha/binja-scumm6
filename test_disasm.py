#!/usr/bin/env python3
import unittest
from kaitaistruct import KaitaiStream, BytesIO

test_cases = [
    (b'', ''),
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

def pretty_scumm(block, pos, level):
    if not getattr(block.block_type, 'value', None):
        return block

    type_str = (block.block_type.value.to_bytes(length=4))
    r = {}
    if type(block.block_data) == Scumm6Container.NestedBlocks:
        pos += 8
        arr = []
        for b in block.block_data.blocks:
            arr.append(pretty_scumm(b, pos, level+1))
            pos += b.block_size
        r[type_str] = arr
    else:
        r[type_str] = (hex(pos), block.block_data)
    return r

filename = ''
data = open(filename, 'rb').read()
ks = KaitaiStream(BytesIO(data))
r = Scumm6Container(ks)
pprint(get_script_addrs(r.blocks[0], 0))
pprint(pretty_scumm(r.blocks[0], 0, 0))
