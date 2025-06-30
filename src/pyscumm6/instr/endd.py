"""End instruction implementation."""

from typing import List
from binja_helpers.tokens import Token, TInstr
from binaryninja.lowlevelil import LowLevelILFunction
from binaryninja import InstructionInfo
from .opcodes import Instruction


class Endd(Instruction):
    """End instruction (opcode 0xFF) - marks the end of a script."""
    
    def render(self, as_operand: bool = False) -> List[Token]:
        """Render as 'end'."""
        return [TInstr("end")]
    
    def lift(self, il: LowLevelILFunction, addr: int) -> None:
        """Generate LLIL for end instruction - no operation."""
        # End instruction doesn't generate any LLIL
        # It just marks the end of a script
        pass
    
    def analyze(self, info: InstructionInfo, addr: int) -> None:
        """Analyze control flow - end terminates the function."""
        info.length = self._length
        # No branches - execution stops here