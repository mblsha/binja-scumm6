from .disasm import Scumm6Disasm

from .scumm6_opcodes import Scumm6Opcodes

import os
from pprint import pprint

from typing import List, Tuple

OpType = Scumm6Opcodes.OpType


# NOTE: the .lecf is the un-xored file
path = os.path.join(os.path.dirname(__file__), "..", "DOTTDEMO.001.lecf")
with open(path, "rb") as f:
    lecf = f.read()
path = os.path.join(os.path.dirname(__file__), "..", "DOTTDEMO.000.rnam")
with open(path, "rb") as f:
    rnam = f.read()


def test_decode_container() -> None:
    disasm = Scumm6Disasm()
    r = disasm.decode_container(lecf)
    assert r is not None
    scripts, state = r

    pprint(scripts)
    assert len(scripts) == 65
    assert scripts[0] == (1179, 1180, "room1_exit", 1)
    assert scripts[1] == (1188, 1189, "room1_enter", 1)
    assert scripts[2] == (33360, 33365, "room2_exit", 2)
    assert scripts[3] == (33373, 33391, "room2_enter", 2)

    # LocalScripts
    assert scripts[4] == (33410, 33435, "room2_local200", 2)
    assert scripts[5] == (33444, 33546, "room2_local201", 2)

    assert scripts[-1] == (962497, 962967, "room12_scrp1", 12)

    # state
    pprint(state)
    assert len(state.rooms) == 12
    assert len(state.rooms_dict) == 12
    assert len(state.rooms_addrs) == 12

    assert state.rooms[0].num == 1
    assert state.rooms[0].scrp == 0
    assert state.rooms[0].funcs["exit"] == 1179
    assert state.rooms[0].funcs["enter"] == 1188

    assert len(state.room_ids) == 12
    assert state.room_ids[61] == 0x851D6

    assert len(state.block_to_script) == 65
    assert state.block_to_script[0x851D6 + 0x7368] == 0x8C546


def test_decode_instruction_none() -> None:
    disasm = Scumm6Disasm()
    assert disasm.decode_instruction(b"", 0) is None

    # not enough length for push_byte
    assert disasm.decode_instruction(b"\x00", 0) is None


def test_decode_instruction() -> None:
    disasm = Scumm6Disasm()

    # push_byte
    dis = disasm.decode_instruction(b"\x00\xff", 0)
    assert dis is not None
    assert dis.op.id == OpType.push_byte
    assert dis.id == "push_byte"
    assert dis.op.body.data == -1
    assert dis.addr == 0
    assert dis.length == 2

    dis = disasm.decode_instruction(b"\x00\x12", 0x1234)
    assert dis is not None
    assert dis.op.id == OpType.push_byte
    assert dis.id == "push_byte"
    assert dis.op.body.data == 0x12
    assert dis.addr == 0x1234


def test_decode_rnam() -> None:
    disasm = Scumm6Disasm()
    r = disasm.decode_rnam(rnam)
    print(r)
    print(r.num_entries)

    # DSCR: room_no -> room_offset
    # index: room_no, room_offset
    scripts: List[Tuple[int, int]] = []
    for i in range(r.num_entries):
        index = r.index_no[i]
        room_offset = r.room_offset[i]
        scripts.append((index, room_offset))

    assert scripts[1] == (61, 0x7368)
    #     print(f"{i} {index} -> {hex(room_offset)}")
    # assert r is None
