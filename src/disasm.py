import os
from kaitaistruct import KaitaiStream, BytesIO
from .scumm6_opcodes import Scumm6Opcodes
from .scumm6_container import Scumm6Container

from typing import Any, Dict, List, Tuple, Optional, NamedTuple
from dataclasses import dataclass, field
from .sorted_list import SortedList

BlockType = Scumm6Container.BlockType


def is_valid_filename(filename: str) -> bool:
    if filename.endswith(".001.lecf"):
        return True
    raise ValueError(f"Invalid filename: {filename} (Expected '.001.lecf' extension)")


def get_rnam_filename(filename: str) -> str:
    return filename.replace(".001.lecf", ".000.rnam")


class Resource(NamedTuple):
    room_no: int
    room_offset: int


def read_dscr(lecf_filename: str) -> List[Resource]:
    rnam_filename = get_rnam_filename(lecf_filename)
    if not os.path.exists(rnam_filename):
        raise ValueError(f"File not found: {rnam_filename}")

    with open(rnam_filename, "rb") as f:
        data = f.read()
    return decode_rnam_dscr(data)


# https://github.com/scummvm/scummvm/blob/74b6c4d35aaeeb6892c358f0c3e41d8be98c79ea/engines/scumm/resource.cpp#L455
# DSCR: readResTypeList(rtScript): room_no -> room_offset
def decode_rnam_dscr(data: bytes) -> List[Resource]:
    ks = KaitaiStream(BytesIO(data))
    r = Scumm6Container(ks)

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


class ScriptAddr(NamedTuple):
    start: int
    end: int
    name: str
    room: int


def get_script_addrs(block: Any, state: State, pos: int = 0) -> List[ScriptAddr]:
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
                room=room.num,
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
                room=room.num,
            )
        )
    elif isinstance(block.block_data, Scumm6Container.Loff):
        for room in block.block_data.rooms:
            state.room_ids[room.room_id] = room.room_offset
    # TODO: VerbScript
    # elif type(block.block_data) == Scumm6Container.VerbScript:
    return r


class Instruction(NamedTuple):
    op: Scumm6Opcodes.Op
    id: str
    length: int
    data: bytes
    addr: int


class Scumm6Disasm:
    def __init__(self) -> None:
        pass

    def decode_instruction(self, data: bytes, addr: int) -> Optional[Instruction]:
        if len(data) <= 0:
            return None
        try:
            ks = KaitaiStream(BytesIO(data))
            r = Scumm6Opcodes(ks)
            op_i = str(r.op.id).replace("OpType.", "")
            return Instruction(r.op, id=op_i, length=ks.pos(), data=data, addr=addr)
        except EOFError:
            return None
        except UnicodeDecodeError:
            print("UnicodeDecodeError at", hex(addr))
            raise
        except Exception as e:
            if "end of stream reached, but no terminator 0 found" in str(e):
                return None
            raise

    def decode_container(
        self, lecf_filename: str, data: bytes
    ) -> Optional[Tuple[List[ScriptAddr], State]]:
        dscr = read_dscr(lecf_filename)

        ks = KaitaiStream(BytesIO(data))
        r = Scumm6Container(ks)
        state = State()
        state.dscr = dscr
        return get_script_addrs(r.blocks[0], state, 0), state
