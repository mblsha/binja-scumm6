"""Smart factory functions for generating instruction classes."""

from typing import Type, Dict, List
from binja_helpers.tokens import Token

from .opcodes import Instruction
from .smart_bases import (SmartIntrinsicOp, SmartVariableOp, SmartArrayOp, SmartComplexOp, 
                         SmartBinaryOp, SmartUnaryOp, SmartComparisonOp, SmartSemanticIntrinsicOp)
from .configs import (IntrinsicConfig, VariableConfig, ArrayConfig, ComplexConfig, StackConfig,
                     SemanticIntrinsicConfig, INTRINSIC_CONFIGS, VARIABLE_CONFIGS, ARRAY_CONFIGS, 
                     COMPLEX_CONFIGS, STACK_CONFIGS, SEMANTIC_CONFIGS)

def create_intrinsic_instruction(name: str, config: IntrinsicConfig) -> Type[Instruction]:
    """Create an intrinsic instruction class from configuration."""
    
    class GeneratedIntrinsicOp(SmartIntrinsicOp):
        _name = name
        _config = config
        __doc__ = config.doc
        
        def render(self) -> List[Token]:
            return super().render()
    
    GeneratedIntrinsicOp.__name__ = name.title().replace("_", "")
    GeneratedIntrinsicOp.__qualname__ = name.title().replace("_", "")
    return GeneratedIntrinsicOp

def create_variable_instruction(name: str, config: VariableConfig) -> Type[Instruction]:
    """Create a variable operation instruction class from configuration."""
    
    class GeneratedVariableOp(SmartVariableOp):
        _name = name
        _config = config
        __doc__ = config.doc
    
    GeneratedVariableOp.__name__ = name.title().replace("_", "")
    GeneratedVariableOp.__qualname__ = name.title().replace("_", "")
    return GeneratedVariableOp

def create_array_instruction(name: str, config: ArrayConfig) -> Type[Instruction]:
    """Create an array operation instruction class from configuration."""
    
    class GeneratedArrayOp(SmartArrayOp):
        _name = name
        _config = config
        __doc__ = config.doc
    
    GeneratedArrayOp.__name__ = name.title().replace("_", "")
    GeneratedArrayOp.__qualname__ = name.title().replace("_", "")
    return GeneratedArrayOp

def create_complex_instruction(name: str, config: ComplexConfig) -> Type[Instruction]:
    """Create a complex operation instruction class from configuration."""
    
    class GeneratedComplexOp(SmartComplexOp):
        _name = name
        _config = config
        __doc__ = config.doc
    
    GeneratedComplexOp.__name__ = name.title().replace("_", "")
    GeneratedComplexOp.__qualname__ = name.title().replace("_", "")
    return GeneratedComplexOp

def create_stack_instruction(name: str, config: StackConfig) -> Type[Instruction]:
    """Create a stack operation instruction class from configuration."""
    
    if config.is_comparison:
        class GeneratedComparisonOp(SmartComparisonOp):
            _name = name
            _config = config
            __doc__ = config.doc
        GeneratedComparisonOp.__name__ = name.title().replace("_", "")
        GeneratedComparisonOp.__qualname__ = name.title().replace("_", "")
        return GeneratedComparisonOp
    elif config.is_unary:
        class GeneratedUnaryOp(SmartUnaryOp):
            _name = name
            _config = config
            __doc__ = config.doc
        GeneratedUnaryOp.__name__ = name.title().replace("_", "")
        GeneratedUnaryOp.__qualname__ = name.title().replace("_", "")
        return GeneratedUnaryOp
    else:
        class GeneratedBinaryOp(SmartBinaryOp):
            _name = name
            _config = config
            __doc__ = config.doc
        GeneratedBinaryOp.__name__ = name.title().replace("_", "")
        GeneratedBinaryOp.__qualname__ = name.title().replace("_", "")
        return GeneratedBinaryOp

def create_semantic_intrinsic_instruction(name: str, config: SemanticIntrinsicConfig) -> Type[Instruction]:
    """Create a semantic intrinsic instruction class following descumm philosophy."""
    
    class GeneratedSemanticIntrinsicOp(SmartSemanticIntrinsicOp):
        _name = name
        _config = config
        __doc__ = config.doc
        
        def render(self) -> List[Token]:
            return super().render()
    
    GeneratedSemanticIntrinsicOp.__name__ = name.title().replace("_", "")
    GeneratedSemanticIntrinsicOp.__qualname__ = name.title().replace("_", "")
    return GeneratedSemanticIntrinsicOp

def generate_all_instructions() -> Dict[str, Type[Instruction]]:
    """Generate all instruction classes from configurations."""
    registry: Dict[str, Type[Instruction]] = {}
    
    # Generate intrinsic instructions
    for name, config in INTRINSIC_CONFIGS.items():
        registry[name] = create_intrinsic_instruction(name, config)
    
    # Generate variable instructions  
    for name, var_config in VARIABLE_CONFIGS.items():
        registry[name] = create_variable_instruction(name, var_config)
    
    # Generate array instructions
    for name, array_config in ARRAY_CONFIGS.items():
        registry[name] = create_array_instruction(name, array_config)
    
    # Generate complex instructions
    for name, complex_config in COMPLEX_CONFIGS.items():
        registry[name] = create_complex_instruction(name, complex_config)
    
    # Generate stack instructions
    for name, stack_config in STACK_CONFIGS.items():
        registry[name] = create_stack_instruction(name, stack_config)
    
    # Generate semantic intrinsic instructions (following descumm philosophy)
    for name, semantic_config in SEMANTIC_CONFIGS.items():
        registry[name] = create_semantic_intrinsic_instruction(name, semantic_config)
    
    return registry