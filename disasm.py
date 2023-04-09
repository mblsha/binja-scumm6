from kaitaistruct import KaitaiStream, BytesIO
from .scumm6_opcodes import Scumm6Opcodes

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

