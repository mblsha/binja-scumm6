from kaitaistruct import KaitaiStream, BytesIO
from .scumm6_opcodes import Scumm6Opcodes
from .scumm6_container import Scumm6Container

BlockType = Scumm6Container.BlockType


from typing import Dict, List, Tuple, Optional, NamedTuple


def pretty_scumm(block, pos=0, level=0):
    if not getattr(block.block_type, "value", None):
        return block
    type_str = block.block_type.value.to_bytes(length=4)
    r = {}
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


class ScriptAddr(NamedTuple):
    start: int
    end: int
    name: str


def get_script_addrs(
    block: Scumm6Container.Block, state: Dict[str, int], pos: int = 0
) -> List[ScriptAddr]:
    r = []

    if block.block_type == BlockType.room:
        state["room"] += 1
        state["scrp"] = 0

    if type(block.block_data) == Scumm6Container.NestedBlocks:
        pos += 8
        for b in block.block_data.blocks:
            r.extend(get_script_addrs(b, state, pos))
            pos += b.block_size
    elif type(block.block_data) == Scumm6Container.Script:
        name = block.block_type.name
        if block.block_type == BlockType.scrp:
            state["scrp"] += 1
            name = f'scrp{state["scrp"]}'
        elif block.block_type == BlockType.encd:
            name = "enter"
        elif block.block_type == BlockType.excd:
            name = "exit"

        r.append(
            ScriptAddr(
                (pos + 8), (pos + block.block_size), f'room{state["room"]}_{name}'
            )
        )
    elif type(block.block_data) == Scumm6Container.LocalScript:
        r.append(
            ScriptAddr(
                (pos + 8 + 1),
                (pos + block.block_size),
                f'room{state["room"]}_local{block.block_data.index}',
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
    def __init__(self):
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

    def decode_container(self, data: bytes) -> Optional[List[ScriptAddr]]:
        if len(data) <= 0:
            return None
        try:
            ks = KaitaiStream(BytesIO(data))
            r = Scumm6Container(ks)
            state = {
                "room": 0,
            }
            return get_script_addrs(r.blocks[0], state, 0)
        except EOFError:
            return None
        except Exception as e:
            if "end of stream reached, but no terminator 0 found" in str(e):
                return None
            raise
