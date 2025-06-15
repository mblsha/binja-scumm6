"""New decoder implementation using object-oriented instruction classes."""

from typing import Optional
from kaitaistruct import KaitaiStream
from io import BytesIO

# Import the Kaitai-generated parser
from ..scumm6_opcodes import Scumm6Opcodes

# Import your new instruction infrastructure
from .instr.opcodes import Instruction
from .instr.opcode_table import OPCODE_MAP


def decode(data: bytes, addr: int) -> Optional[Instruction]:
    """
    Decodes a single instruction from a byte stream using the new
    object-oriented approach.
    
    Args:
        data: Raw instruction bytes
        addr: Address of the instruction
        
    Returns:
        Instruction object or None if decoding failed
    """
    try:
        # 1. Use Kaitai Struct to parse the raw bytes.
        #    This is the only place we directly interact with Kaitai for parsing.
        ks = KaitaiStream(BytesIO(data))
        parsed_op = Scumm6Opcodes(ks).op
        length = ks.pos()

        # 2. Look up the corresponding Python class in our map.
        op_type = parsed_op.id
        InstructionClass = OPCODE_MAP.get(op_type)

        if InstructionClass:
            # 3. Instantiate the wrapper class, passing in the Kaitai
            #    object and the instruction length.
            return InstructionClass(kaitai_op=parsed_op, length=length)
        else:
            # Handle opcodes not yet migrated to the new system.
            # You can create a generic "UnknownInstruction" class for this.
            return None

    except Exception:
        # Kaitai can raise various errors on invalid/incomplete data.
        return None