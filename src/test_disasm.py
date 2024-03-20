from . import binja_api  # noqa: F401
from binaryninja.enums import SegmentFlag, SectionSemantics

from .disasm import Scumm6Disasm, decode_rnam_dscr

from .scumm6_opcodes import Scumm6Opcodes

import os
from pprint import pprint


OpType = Scumm6Opcodes.OpType
VarType = Scumm6Opcodes.VarType


# NOTE: the .lecf is the un-xored file
lecf_path = os.path.join(
    os.path.dirname(os.path.dirname(__file__)), "DOTTDEMO.bsc6"
)
with open(lecf_path, "rb") as f:
    lecf = f.read()


def test_decode_container() -> None:
    disasm = Scumm6Disasm()
    r = disasm.decode_container(lecf_path, lecf)
    assert r is not None
    scripts, state = r

    pprint(scripts)
    assert len(scripts) == 66
    sf = SegmentFlag.SegmentContainsCode
    ss = SectionSemantics.ReadOnlyCodeSectionSemantics
    assert scripts[0] == (1179, 1180, "room1_exit", True, sf, ss)
    assert scripts[1] == (1188, 1189, "room1_enter", True, sf, ss)
    assert scripts[2] == (33360, 33365, "room2_exit", True, sf, ss)
    assert scripts[3] == (33373, 33391, "room2_enter", True, sf, ss)

    # LocalScripts
    assert scripts[4] == (33410, 33435, "room2_local200", True, sf, ss)
    assert scripts[5] == (33444, 33546, "room2_local201", True, sf, ss)

    assert scripts[-2] == (962497, 962967, "room12_scrp1", True, sf, ss)

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

    assert len(state.dscr) == 140

    assert len(state.bstr) == 58


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

    # push_word_var 56
    dis = disasm.decode_instruction(b"\x03\x38\x00", 0x1234)
    assert dis is not None
    assert dis.op.id == OpType.push_word_var
    assert dis.id == "push_word_var"
    assert dis.op.body.data == 56
    assert dis.op.body.type == VarType.scumm_var
    assert dis.addr == 0x1234


def test_get_script_nums() -> None:
    disasm = Scumm6Disasm()
    r = disasm.decode_container(lecf_path, lecf)
    assert r is not None
    _, state = r

    sn = disasm.get_script_nums(state)
    assert sn[0x8C546] == 1
    assert sn[0xEAFC1] == 139


def test_get_script_ptr() -> None:
    disasm = Scumm6Disasm()
    r = disasm.decode_container(lecf_path, lecf)
    assert r is not None
    _, state = r

    # boot script
    assert disasm.get_script_ptr(state, 1, -1) == 0x8C546

    assert disasm.get_script_ptr(state, 5, -1) == 0x8493
    assert disasm.get_script_ptr(state, 121, -1) == 0x8DA90

    # local scripts
    assert disasm.get_script_ptr(state, 200, 33360) == 33410
    assert disasm.get_script_ptr(state, 201, 33360) == 33444

    # FIXME: figure out how SCUMMVM handles this
    assert not disasm.get_script_ptr(state, 85, 0x8D53B)
    assert not disasm.get_script_ptr(state, 86, 0x8CCEA)
