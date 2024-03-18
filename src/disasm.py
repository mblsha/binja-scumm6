from kaitaistruct import KaitaiStream, BytesIO
from .scumm6_opcodes import Scumm6Opcodes
from .scumm6_container import Scumm6Container

BlockType = Scumm6Container.BlockType


from typing import Any, Dict, List, Tuple, Optional, NamedTuple
from dataclasses import dataclass, field
from .sorted_list import SortedList


def pretty_scumm(block: Scumm6Container.Block, pos: int = 0, level: int = 0) -> Any:
    if not getattr(block.block_type, "value", None):
        return block
    type_str = block.block_type.value.to_bytes(length=4)
    r: Dict[str, Tuple[str, Any] | Any] = {}
    if type(block.block_data) == Scumm6Container.NestedBlocks:
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


class ScriptAddr(NamedTuple):
    start: int
    end: int
    name: str
    room: int


def get_script_addrs(
    block: Scumm6Container.Block, state: State, pos: int = 0
) -> List[ScriptAddr]:
    r = []

    if block.block_type == BlockType.room:
        room = Room(num=len(state.rooms) + 1, start=pos, end=pos + block.block_size)
        state.rooms.append(room)
        state.rooms_dict[room.start] = room
        state.rooms_addrs.insert_sorted(room.start)

    if type(block.block_data) == Scumm6Container.NestedBlocks:
        pos += 8
        for b in block.block_data.blocks:
            r.extend(get_script_addrs(b, state, pos))
            pos += b.block_size
    elif type(block.block_data) == Scumm6Container.Script:
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
        assert not name in room.funcs
        room.funcs[name] = start

        r.append(
            ScriptAddr(
                start=start,
                end=pos + block.block_size,
                name=f"room{room.num}_{name}",
                room=room.num,
            )
        )
    elif type(block.block_data) == Scumm6Container.LocalScript:
        room = state.rooms[-1]
        assert room

        start = pos + 8 + 1
        name = f"local{block.block_data.index}"
        assert not name in room.funcs
        room.funcs[name] = start

        r.append(
            ScriptAddr(
                start=start,
                end=pos + block.block_size,
                name=f"room{room.num}_{name}",
                room=room.num,
            )
        )
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

    def decode_container(self, data: bytes) -> Optional[Tuple[List[ScriptAddr], State]]:
        if len(data) <= 0:
            return None
        try:
            ks = KaitaiStream(BytesIO(data))
            r = Scumm6Container(ks)
            state = State()
            return get_script_addrs(r.blocks[0], state, 0), state
        except EOFError:
            return None
        except Exception as e:
            if "end of stream reached, but no terminator 0 found" in str(e):
                return None
            raise
