"""Base instruction class for SCUMM6 opcodes."""

from abc import ABC, abstractmethod
from typing import Any, List, Optional
from binja_helpers.tokens import Token
from binaryninja.lowlevelil import LowLevelILFunction
from binaryninja import InstructionInfo


class Instruction(ABC):
    """Base class for all SCUMM6 instructions."""
    
    def __init__(self, kaitai_op: Any, length: int, addr: Optional[int] = None) -> None:
        """
        Initialize an instruction with its Kaitai-parsed data.
        
        Args:
            kaitai_op: The Kaitai-parsed instruction object
            length: The length of the instruction in bytes
            addr: The address of the instruction (optional)
        """
        self.op_details = kaitai_op
        self._length = length
        self.addr = addr
        self.fused_operands: List['Instruction'] = []
    
    def produces_result(self) -> bool:
        """Returns True if this instruction produces a result that can be consumed by other instructions."""
        return False  # Default: most instructions don't produce consumable results

    @property
    def stack_pop_count(self) -> int:
        """
        The number of values this instruction expects to pop from the stack.
        This can be inspected by other instructions or analysis passes.
        Returns -1 for instructions with a variable number of stack arguments.
        """
        # Default to 0 for instructions that don't pop anything or are not yet implemented.
        return 0

    @abstractmethod
    def render(self, as_operand: bool = False) -> List[Token]:
        """
        Generate disassembly text tokens for this instruction.
        
        Args:
            as_operand: True if this instruction is being rendered as an operand
                       to another instruction (affects parentheses usage)
        
        Returns:
            List of tokens representing the disassembled instruction
        """
        pass

    @abstractmethod
    def lift(self, il: LowLevelILFunction, addr: int) -> None:
        """
        Lift the instruction to Low-Level IL.
        
        Args:
            il: The Low-Level IL function to append to
            addr: The address of this instruction
        """
        pass

    def analyze(self, info: InstructionInfo, addr: int) -> None:
        """Set instruction analysis info."""
        info.length = self._length

    def fuse(self, sister: 'Instruction') -> Optional['Instruction']:
        """Attempt to fuse with another instruction. Default: no fusion."""
        return None

    def length(self) -> int:
        """Get the instruction length in bytes."""
        return self._length
