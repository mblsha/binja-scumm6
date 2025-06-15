"""Base instruction class for SCUMM6 opcodes."""

from abc import ABC, abstractmethod
from typing import Any, List, Optional
from binja_helpers.tokens import Token
from binaryninja.lowlevelil import LowLevelILFunction
from binaryninja import InstructionInfo


class Instruction(ABC):
    """Base class for all SCUMM6 instructions."""
    
    def __init__(self, kaitai_op: Any, length: int) -> None:
        """
        Initialize an instruction with its Kaitai-parsed data.
        
        Args:
            kaitai_op: The Kaitai-parsed instruction object
            length: The length of the instruction in bytes
        """
        self.op_details = kaitai_op
        self._length = length

    @abstractmethod
    def render(self) -> List[Token]:
        """
        Generate disassembly text tokens for this instruction.
        
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
