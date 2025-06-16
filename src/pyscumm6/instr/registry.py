"""Auto-generated instruction class registry."""

from typing import Dict, Type
from .opcodes import Instruction
from .factories import generate_all_instructions

# Auto-generate all instruction classes from metadata
INSTRUCTION_REGISTRY: Dict[str, Type[Instruction]] = generate_all_instructions()

def get_instruction_class(name: str) -> Type[Instruction]:
    """Get an instruction class by name."""
    return INSTRUCTION_REGISTRY[name]

# Export for backwards compatibility
__all__ = ['INSTRUCTION_REGISTRY', 'get_instruction_class'] + list(INSTRUCTION_REGISTRY.keys())