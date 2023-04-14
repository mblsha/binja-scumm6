from kaitaistruct import KaitaiStream, BytesIO
from .scumm6_opcodes import Scumm6Opcodes
from .scumm6_container import Scumm6Container

def pretty_scumm(block, pos=0, level=0):
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

def get_script_addrs(block, pos=0):
    r = []
    if type(block.block_data) == Scumm6Container.NestedBlocks:
        pos += 8
        for b in block.block_data.blocks:
            r.extend(get_script_addrs(b, pos))
            pos += b.block_size
    elif type(block.block_data) == Scumm6Container.Script:
        r.append(((pos + 8), (pos + block.block_size)))
    elif type(block.block_data) == Scumm6Container.LocalScript:
        r.append(((pos + 8 + 1), (pos + block.block_size)))
    # TODO: VerbScript
    # elif type(block.block_data) == Scumm6Container.VerbScript:
    return r

class Scumm6Disasm:
    def __init__(self):
        pass

    def decode_instruction(self, data: bytes, addr: int):
        if len(data) <= 0:
            return None
        try:
            ks = KaitaiStream(BytesIO(data))
            r = Scumm6Opcodes(ks)
            op_i = str(r.op.id).replace('OpType.', '')
            return r.op, op_i, ks.pos()
        except EOFError:
            return None
        except Exception as e:
            if "end of stream reached, but no terminator 0 found" in str(e):
                return None
            raise

    def decode_container(self, data: bytes):
        if len(data) <= 0:
            return None
        try:
            ks = KaitaiStream(BytesIO(data))
            r = Scumm6Container(ks)
            return get_script_addrs(r.blocks[0], 0)
        except EOFError:
            return None
        except Exception as e:
            if "end of stream reached, but no terminator 0 found" in str(e):
                return None
            raise
