"""Auto-generated instruction class registry with lazy loading."""

from typing import Dict, Type

class _LazyInstructionRegistry:
    """Lazy-loading instruction registry wrapper."""
    
    def __init__(self):
        self._registry: Dict[str, Type] = {}
        self._loaded = False
    
    def _ensure_loaded(self):
        if not self._loaded:
            from .opcodes import Instruction
            from .factories import generate_all_instructions
            self._registry = generate_all_instructions()
            self._loaded = True
    
    def __getitem__(self, key: str):
        self._ensure_loaded()
        return self._registry[key]
    
    def __contains__(self, key: str):
        self._ensure_loaded()
        return key in self._registry
    
    def items(self):
        self._ensure_loaded()
        return self._registry.items()
    
    def keys(self):
        self._ensure_loaded() 
        return self._registry.keys()
    
    def values(self):
        self._ensure_loaded()
        return self._registry.values()

# Lazy-loaded registry instance
INSTRUCTION_REGISTRY = _LazyInstructionRegistry()

def get_instruction_class(name: str):
    """Get an instruction class by name."""
    return INSTRUCTION_REGISTRY[name]

# Export for backwards compatibility
__all__ = ['INSTRUCTION_REGISTRY', 'get_instruction_class']