"""Auto-generated instruction class registry with lazy loading."""

from typing import Dict, Type, Any

class _LazyInstructionRegistry:
    """Lazy-loading instruction registry wrapper."""
    
    def __init__(self) -> None:
        self._registry: Dict[str, Type[Any]] = {}
        self._loaded = False
    
    def _ensure_loaded(self) -> None:
        if not self._loaded:
            from .factories import generate_all_instructions
            self._registry = generate_all_instructions()
            self._loaded = True
    
    def __getitem__(self, key: str) -> Type[Any]:
        self._ensure_loaded()
        return self._registry[key]
    
    def __contains__(self, key: str) -> bool:
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

def get_instruction_class(name: str) -> Type[Any]:
    """Get an instruction class by name."""
    return INSTRUCTION_REGISTRY[name]

# Export for backwards compatibility
__all__ = ['INSTRUCTION_REGISTRY', 'get_instruction_class']