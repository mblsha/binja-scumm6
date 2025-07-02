"""SCUMM6 container parsing and script extraction utilities.

This module handles parsing .bsc6 container files and extracting script information
for use with the Binary Ninja view and analysis tools.
"""

from binja_helpers import binja_api  # noqa: F401
from binaryninja.enums import SegmentFlag, SectionSemantics

from kaitaistruct import KaitaiStream, BytesIO
from .scumm6_container import Scumm6Container  # type: ignore[attr-defined]
from .sorted_list import SortedList

from typing import Any, Dict, List, Tuple, Optional, NamedTuple
from dataclasses import dataclass, field

SEGMENT_CODE_FLAG = getattr(SegmentFlag, "SegmentContainsCode", SegmentFlag.SegmentExecutable)

BlockType = Scumm6Container.BlockType


class Resource(NamedTuple):
    room_no: int
    room_offset: int


@dataclass
class Room:
    num: int
    start: int
    end: int

    scrp: int = 0
    funcs: Dict[str, int] = field(default_factory=dict)


@dataclass
class State:
    rooms: List[Room] = field(default_factory=list)
    # addr -> room
    rooms_dict: Dict[int, Room] = field(default_factory=dict)
    # start_addr
    rooms_addrs: SortedList = field(default_factory=SortedList)

    # id -> start_addr
    # used for global script pointers
    room_ids: Dict[int, int] = field(default_factory=dict)

    # block_addr -> script_addr
    # used for global script pointers
    block_to_script: Dict[int, int] = field(default_factory=dict)

    # global script ids
    dscr: List[Resource] = field(default_factory=list)

    # string -> addr
    bstr: Dict[str, int] = field(default_factory=dict)


class ScriptAddr(NamedTuple):
    start: int
    end: int
    name: str
    create_function: bool
    segment_flag: SegmentFlag
    section_semantics: SectionSemantics


# https://github.com/scummvm/scummvm/blob/74b6c4d35aaeeb6892c358f0c3e41d8be98c79ea/engines/scumm/resource.cpp#L455
# DSCR: readResTypeList(rtScript): room_no -> room_offset
def decode_rnam_dscr(r: Scumm6Container) -> List[Resource]:
    dscr = None
    for b in r.blocks:
        if b.block_type == BlockType.dscr:
            dscr = b.block_data
            break

    if not dscr:
        raise ValueError("No DSCR block found at top-level")

    scripts: List[Resource] = []
    for i in range(dscr.num_entries):
        index = dscr.index_no[i]
        room_offset = dscr.room_offset[i]
        scripts.append(Resource(index, room_offset))

    return scripts


def pretty_scumm(block: Any, pos: int = 0, level: int = 0) -> Any:
    """Pretty-print SCUMM container block structure."""
    if not getattr(block.block_type, "value", None):
        return block

    type_str = block.block_type.value.to_bytes(length=4, byteorder="big")
    r: Dict[str, Tuple[str, Any] | Any] = {}

    if isinstance(block.block_data, Scumm6Container.NestedBlocks):
        pos += 8
        arr = []
        for b in block.block_data.blocks:
            arr.append(pretty_scumm(b, pos, level + 1))
            pos += b.block_size
        r[type_str] = arr
    else:
        r[type_str] = (hex(pos), block.block_data)
    return r


def get_script_addrs(block: Any, state: State, pos: int = 0) -> List[ScriptAddr]:
    """Extract script addresses and metadata from container blocks."""
    r = []

    if block.block_type == BlockType.room:
        room = Room(num=len(state.rooms) + 1, start=pos, end=pos + block.block_size)
        state.rooms.append(room)
        state.rooms_dict[room.start] = room
        state.rooms_addrs.insert_sorted(room.start)

    if isinstance(block.block_data, Scumm6Container.NestedBlocks):
        pos += 8
        for b in block.block_data.blocks:
            r.extend(get_script_addrs(b, state, pos))
            pos += b.block_size
    elif isinstance(block.block_data, Scumm6Container.Script):
        room = state.rooms[-1]
        assert room
        name = block.block_type.name
        if block.block_type == BlockType.scrp:
            room.scrp += 1
            name = f"scrp{room.scrp}"
        elif block.block_type == BlockType.encd:
            name = "enter"
        elif block.block_type == BlockType.excd:
            name = "exit"

        start = pos + 8
        assert name not in room.funcs
        room.funcs[name] = start

        state.block_to_script[pos] = start

        r.append(
            ScriptAddr(
                start=start,
                end=pos + block.block_size,
                name=f"room{room.num}_{name}",
                create_function=True,
                segment_flag=SEGMENT_CODE_FLAG,
                section_semantics=SectionSemantics.ReadOnlyCodeSectionSemantics,
            )
        )
    elif isinstance(block.block_data, Scumm6Container.LocalScript):
        room = state.rooms[-1]
        assert room

        start = pos + 8 + 1
        name = f"local{block.block_data.index}"
        assert name not in room.funcs
        room.funcs[name] = start

        state.block_to_script[pos] = start

        r.append(
            ScriptAddr(
                start=start,
                end=pos + block.block_size,
                name=f"room{room.num}_{name}",
                create_function=True,
                segment_flag=SEGMENT_CODE_FLAG,
                section_semantics=SectionSemantics.ReadOnlyCodeSectionSemantics,
            )
        )
    elif isinstance(block.block_data, Scumm6Container.Loff):
        for room in block.block_data.rooms:
            state.room_ids[room.room_id] = room.room_offset
    elif isinstance(block.block_data, Scumm6Container.Bstr):
        start = pos + 8
        for s in block.block_data.string:
            state.bstr[s] = start
            start += len(s) + 1

        r.append(
            ScriptAddr(
                start=pos + 8,
                end=pos + block.block_size,
                name="Strings",
                create_function=False,
                segment_flag=SegmentFlag.SegmentReadable,
                section_semantics=SectionSemantics.ReadWriteDataSectionSemantics,
            )
        )
    # TODO: VerbScript
    # elif type(block.block_data) == Scumm6Container.VerbScript:

    return r


class ContainerParser:
    """Parser for SCUMM6 .bsc6 container files."""

    @staticmethod
    def decode_container(
        lecf_filename: str, data: bytes
    ) -> Optional[Tuple[List[ScriptAddr], State]]:
        """Decode a SCUMM6 container file and extract script information."""
        ks = KaitaiStream(BytesIO(data))
        r = Scumm6Container(ks)
        state = State()
        state.dscr = decode_rnam_dscr(r)

        pos = 0
        scripts = []
        for b in r.blocks:
            scripts.extend(get_script_addrs(b, state, pos))
            pos += b.block_size
        return scripts, state

    @staticmethod
    def get_script_ptr(state: State, script_num: int, call_addr: int) -> Optional[int]:
        """Get script pointer from script number and call address."""
        if script_num >= len(state.dscr):
            # local script
            room_addr = state.rooms_addrs.closest_left_match(call_addr)
            assert room_addr
            room = state.rooms_dict[room_addr]

            name = f"local{script_num}"
            addr = room.funcs[name]
            return addr

        res = state.dscr[script_num]
        if res.room_no not in state.room_ids:
            return None

        room_addr = state.room_ids[res.room_no]
        block_addr = room_addr + res.room_offset
        return state.block_to_script[block_addr]

    @staticmethod
    def get_script_nums(state: State) -> Dict[int, int]:
        """Get mapping from script address to script number."""
        r: Dict[int, int] = {}

        for i in range(len(state.dscr)):
            if state.dscr[i].room_no not in state.room_ids:
                continue
            ptr = ContainerParser.get_script_ptr(state, i, -1)
            assert ptr
            r[ptr] = i

        return r


# Legacy compatibility alias
Scumm6Disasm = ContainerParser
