from typing import Any, List, Optional
from binja_helpers.tokens import Token
from binaryninja.lowlevelil import LowLevelILFunction
from binaryninja.function import InstructionInfo


class Instruction:
    def __init__(self, op_details: Any, length: int) -> None:
        self.op_details = op_details  # The Kaitai-decoded object
        self._length = length

    def render(self) -> List[Token]:
        raise NotImplementedError

    def lift(self, il: LowLevelILFunction, addr: int) -> None:
        il.append(il.unimplemented())

    def analyze(self, info: InstructionInfo, addr: int) -> None:
        info.length = self._length

    def fuse(self, sister: 'Instruction') -> Optional['Instruction']:
        return None  # No fusion by default

    def length(self) -> int:
        return self._length
