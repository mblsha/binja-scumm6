# Implementation Plan: Metadata-Driven Instruction Architecture

## Step 1: Create Configuration Data Structures

### File: `src/pyscumm6/instr/configs.py`

```python
"""Metadata-driven instruction configurations."""

from dataclasses import dataclass
from typing import Optional, Callable, Any, Dict
from enum import Enum

@dataclass
class IntrinsicConfig:
    """Configuration for intrinsic operations."""
    pop_count: int = 0
    push_count: int = 0
    doc: str = ""
    special_lift: Optional[str] = None  # Name of special lift method

@dataclass  
class VariableConfig:
    """Configuration for variable operations."""
    var_type: str  # "byte" or "word"
    operation: str  # "inc", "dec", "read", "write"
    doc: str = ""

@dataclass
class ArrayConfig:
    """Configuration for array operations."""
    element_type: str  # "byte" or "word"
    operation: str     # "read", "write", "inc", "dec"
    indexed: bool = False
    doc: str = ""

@dataclass
class ComplexConfig:
    """Configuration for complex operations with sub-commands."""
    body_type_name: str  # e.g., "ActorOps", "VerbOps"
    doc: str = ""

@dataclass
class StackConfig:
    """Configuration for stack operations."""
    il_op_name: str
    display_name: Optional[str] = None
    is_comparison: bool = False
    is_unary: bool = False
    doc: str = ""

# ============================================================================
# INSTRUCTION METADATA - Replaces 100+ class definitions
# ============================================================================

# Intrinsic Operations (100+ classes -> single config table)
INTRINSIC_CONFIGS: Dict[str, IntrinsicConfig] = {
    # Drawing Operations
    "draw_object": IntrinsicConfig(pop=2, doc="Draw object with ID and state"),
    "draw_object_at": IntrinsicConfig(pop=3, doc="Draw object at position"),
    "draw_blast_object": IntrinsicConfig(doc="Draw blast object"),
    "set_blast_object_window": IntrinsicConfig(doc="Set blast object window"),
    
    # Audio Operations  
    "start_sound": IntrinsicConfig(pop=1, doc="Start sound"),
    "stop_sound": IntrinsicConfig(pop=1, doc="Stop sound"),
    "start_music": IntrinsicConfig(pop=1, doc="Start music"),
    "stop_music": IntrinsicConfig(doc="Stop music"),
    "is_sound_running": IntrinsicConfig(pop=1, push=1, doc="Check if sound running"),
    
    # Actor Query Operations
    "get_actor_moving": IntrinsicConfig(pop=1, push=1, doc="Get actor moving state"),
    "get_actor_room": IntrinsicConfig(pop=1, push=1, doc="Get actor room"),
    "get_actor_costume": IntrinsicConfig(pop=1, push=1, doc="Get actor costume"),
    "get_actor_walk_box": IntrinsicConfig(pop=1, push=1, doc="Get actor walk box"),
    "get_actor_elevation": IntrinsicConfig(pop=1, push=1, doc="Get actor elevation"),
    "get_actor_width": IntrinsicConfig(pop=1, push=1, doc="Get actor width"),
    "get_actor_scale_x": IntrinsicConfig(pop=1, push=1, doc="Get actor scale X"),
    "get_actor_anim_counter": IntrinsicConfig(pop=1, push=1, doc="Get actor anim counter"),
    "get_actor_from_xy": IntrinsicConfig(pop=1, push=1, doc="Get actor from coordinates"),
    "get_actor_layer": IntrinsicConfig(pop=1, push=1, doc="Get actor layer"),
    
    # Actor Movement Operations
    "face_actor": IntrinsicConfig(pop=1, doc="Face actor"),
    "animate_actor": IntrinsicConfig(pop=1, doc="Animate actor"),
    "walk_actor_to_obj": IntrinsicConfig(pop=3, doc="Walk actor to object"),
    "walk_actor_to": IntrinsicConfig(pop=3, doc="Walk actor to position"),
    "put_actor_at_xy": IntrinsicConfig(pop=4, doc="Put actor at coordinates"),
    "put_actor_at_object": IntrinsicConfig(pop=3, doc="Put actor at object"),
    
    # Object Operations
    "get_object_x": IntrinsicConfig(pop=1, push=1, doc="Get object X position"),
    "get_object_y": IntrinsicConfig(pop=1, push=1, doc="Get object Y position"),
    "get_object_old_dir": IntrinsicConfig(pop=1, push=1, doc="Get object old direction"),
    "get_object_new_dir": IntrinsicConfig(pop=1, push=1, doc="Get object new direction"),
    "pickup_object": IntrinsicConfig(pop=1, doc="Pick up object"),
    "find_object": IntrinsicConfig(pop=2, push=1, doc="Find object"),
    "find_all_objects": IntrinsicConfig(push=1, doc="Find all objects"),
    "stamp_object": IntrinsicConfig(doc="Stamp object"),
    
    # Special Instructions with Custom Lift Logic
    "stop_object_code1": IntrinsicConfig(doc="Stop object code 1", special_lift="no_ret_lift"),
    "stop_object_code2": IntrinsicConfig(doc="Stop object code 2", special_lift="no_ret_lift"),
    "cutscene": IntrinsicConfig(doc="Start cutscene", special_lift="cutscene_lift"),
    
    # ... (90+ more entries in compact table format)
}

# Variable Operations (4 classes -> config table)
VARIABLE_CONFIGS: Dict[str, VariableConfig] = {
    "byte_var_inc": VariableConfig("byte", "inc", "Increment byte variable"),
    "word_var_inc": VariableConfig("word", "inc", "Increment word variable"),
    "byte_var_dec": VariableConfig("byte", "dec", "Decrement byte variable"), 
    "word_var_dec": VariableConfig("word", "dec", "Decrement word variable"),
}

# Array Operations (12 classes -> config table)
ARRAY_CONFIGS: Dict[str, ArrayConfig] = {
    "byte_array_read": ArrayConfig("byte", "read", doc="Read from byte array"),
    "word_array_read": ArrayConfig("word", "read", doc="Read from word array"),
    "byte_array_indexed_read": ArrayConfig("byte", "read", indexed=True, doc="Indexed byte array read"),
    "word_array_indexed_read": ArrayConfig("word", "read", indexed=True, doc="Indexed word array read"),
    "byte_array_write": ArrayConfig("byte", "write", doc="Write to byte array"),
    "word_array_write": ArrayConfig("word", "write", doc="Write to word array"),
    "byte_array_indexed_write": ArrayConfig("byte", "write", indexed=True, doc="Indexed byte array write"),
    "word_array_indexed_write": ArrayConfig("word", "write", indexed=True, doc="Indexed word array write"),
    "byte_array_inc": ArrayConfig("byte", "inc", doc="Increment byte array element"),
    "word_array_inc": ArrayConfig("word", "inc", doc="Increment word array element"),
    "byte_array_dec": ArrayConfig("byte", "dec", doc="Decrement byte array element"),
    "word_array_dec": ArrayConfig("word", "dec", doc="Decrement word array element"),
}

# Complex Operations (6 classes -> config table)
COMPLEX_CONFIGS: Dict[str, ComplexConfig] = {
    "actor_ops": ComplexConfig("ActorOps", "Actor operations with sub-commands"),
    "verb_ops": ComplexConfig("VerbOps", "Verb operations with sub-commands"),
    "array_ops": ComplexConfig("ArrayOps", "Array operations with sub-commands"),
    "room_ops": ComplexConfig("RoomOps", "Room operations with sub-commands"),
    "system_ops": ComplexConfig("SystemOps", "System operations with sub-commands"),
    "resource_routines": ComplexConfig("ResourceRoutines", "Resource management operations"),
}

# Stack Operations
STACK_CONFIGS: Dict[str, StackConfig] = {
    "add": StackConfig("add", doc="Addition"),
    "sub": StackConfig("sub", doc="Subtraction"),
    "mul": StackConfig("mult", "mul", doc="Multiplication"),
    "div": StackConfig("div_signed", "div", doc="Division"),
    "land": StackConfig("and_expr", "land", doc="Logical AND"),
    "lor": StackConfig("or_expr", "lor", doc="Logical OR"),
    "nott": StackConfig("nott", is_unary=True, doc="Logical NOT"),
    "eq": StackConfig("compare_equal", "eq", is_comparison=True, doc="Equal"),
    "neq": StackConfig("compare_not_equal", "neq", is_comparison=True, doc="Not equal"),
    "gt": StackConfig("compare_signed_greater_than", "gt", is_comparison=True, doc="Greater than"),
    "lt": StackConfig("compare_signed_less_than", "lt", is_comparison=True, doc="Less than"),
    "le": StackConfig("compare_signed_less_equal", "le", is_comparison=True, doc="Less than or equal"),
    "ge": StackConfig("compare_signed_greater_equal", "ge", is_comparison=True, doc="Greater than or equal"),
}
```

## Step 2: Create Smart Factory Functions

### File: `src/pyscumm6/instr/factories.py`

```python
"""Smart factory functions for generating instruction classes."""

from typing import Type, Dict, Any
from binja_helpers.tokens import Token, TInstr, TSep, TInt
from binaryninja.lowlevelil import LowLevelILFunction, LLIL_TEMP

from .opcodes import Instruction
from .base_classes import SmartIntrinsicOp, SmartVariableOp, SmartArrayOp, SmartComplexOp, SmartStackOp
from .configs import (IntrinsicConfig, VariableConfig, ArrayConfig, ComplexConfig, StackConfig,
                     INTRINSIC_CONFIGS, VARIABLE_CONFIGS, ARRAY_CONFIGS, COMPLEX_CONFIGS, STACK_CONFIGS)

def create_intrinsic_instruction(name: str, config: IntrinsicConfig) -> Type[Instruction]:
    """Create an intrinsic instruction class from configuration."""
    
    class GeneratedIntrinsicOp(SmartIntrinsicOp):
        _name = name
        _config = config
        __doc__ = config.doc
        
        def render(self) -> List[Token]:
            return [TInstr(name)]
    
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
        base_class = SmartComparisonOp
    elif config.is_unary:
        base_class = SmartUnaryOp
    else:
        base_class = SmartBinaryOp
    
    class GeneratedStackOp(base_class):
        _name = name
        _config = config
        __doc__ = config.doc
    
    GeneratedStackOp.__name__ = name.title().replace("_", "")
    GeneratedStackOp.__qualname__ = name.title().replace("_", "")
    return GeneratedStackOp

def generate_all_instructions() -> Dict[str, Type[Instruction]]:
    """Generate all instruction classes from configurations."""
    registry = {}
    
    # Generate intrinsic instructions
    for name, config in INTRINSIC_CONFIGS.items():
        registry[name] = create_intrinsic_instruction(name, config)
    
    # Generate variable instructions  
    for name, config in VARIABLE_CONFIGS.items():
        registry[name] = create_variable_instruction(name, config)
    
    # Generate array instructions
    for name, config in ARRAY_CONFIGS.items():
        registry[name] = create_array_instruction(name, config)
    
    # Generate complex instructions
    for name, config in COMPLEX_CONFIGS.items():
        registry[name] = create_complex_instruction(name, config)
    
    # Generate stack instructions
    for name, config in STACK_CONFIGS.items():
        registry[name] = create_stack_instruction(name, config)
    
    return registry
```

## Step 3: Create Smart Base Classes

### File: `src/pyscumm6/instr/base_classes.py`

```python
"""Smart base classes for generated instruction types."""

from abc import abstractmethod
from typing import List, Optional
from binja_helpers.tokens import Token, TInstr, TSep, TInt
from binaryninja.lowlevelil import LowLevelILFunction, LLIL_TEMP
from binaryninja.enums import BranchType

from .opcodes import Instruction
from .configs import IntrinsicConfig, VariableConfig, ArrayConfig, ComplexConfig, StackConfig
from ...scumm6_opcodes import Scumm6Opcodes

class SmartIntrinsicOp(Instruction):
    """Self-configuring intrinsic operation base class."""
    
    _name: str
    _config: IntrinsicConfig
    
    def render(self) -> List[Token]:
        return [TInstr(self._name)]
    
    def lift(self, il: LowLevelILFunction, addr: int) -> None:
        # Handle special lift cases
        if self._config.special_lift:
            special_method = getattr(self, self._config.special_lift)
            special_method(il, addr)
            return
            
        # Handle UnknownOp case - generate double unimplemented
        if isinstance(self.op_details.body, Scumm6Opcodes.UnknownOp):
            il.append(il.unimplemented())
            il.append(il.unimplemented())
            return
        
        # Standard intrinsic lift
        params = [il.pop(4) for _ in range(self._config.pop_count)]
        
        if self._config.push_count > 0:
            outputs = [il.reg(4, LLIL_TEMP(i)) for i in range(self._config.push_count)]
            il.append(il.intrinsic(outputs, self._name, params))
            for out_reg in outputs:
                il.append(il.push(4, out_reg))
        else:
            il.append(il.intrinsic([], self._name, params))
    
    def no_ret_lift(self, il: LowLevelILFunction, addr: int) -> None:
        """Special lift for instructions that don't return."""
        self.lift(il, addr)  # Do standard lift first
        il.append(il.no_ret())
    
    def cutscene_lift(self, il: LowLevelILFunction, addr: int) -> None:
        """Special lift for cutscene with dynamic argument count."""
        # Custom logic for cutscene argument parsing
        if hasattr(self.op_details.body, 'args') and hasattr(self.op_details.body.args, '__len__'):
            pop_count = len(self.op_details.body.args)
        else:
            pop_count = 0
            
        params = [il.pop(4) for _ in range(pop_count)]
        il.append(il.intrinsic([], self._name, params))

class SmartVariableOp(Instruction):
    """Self-configuring variable operation base class."""
    
    _name: str
    _config: VariableConfig
    
    def render(self) -> List[Token]:
        var_id = self.op_details.body.data
        return [
            TInstr(self._name),
            TSep("("),
            TInt(f"var_{var_id}"),
            TSep(")"),
        ]
    
    def lift(self, il: LowLevelILFunction, addr: int) -> None:
        from ... import vars
        
        expected_type = (Scumm6Opcodes.ByteVarData if self._config.var_type == "byte" 
                        else Scumm6Opcodes.WordVarData)
        
        assert isinstance(self.op_details.body, expected_type), \
            f"Expected {expected_type.__name__} body, got {type(self.op_details.body)}"
        
        if self._config.operation == "inc":
            current_value = vars.il_get_var(il, self.op_details.body)
            incremented_value = il.add(4, current_value, il.const(4, 1))
            il.append(vars.il_set_var(il, self.op_details.body, incremented_value))
        elif self._config.operation == "dec":
            current_value = vars.il_get_var(il, self.op_details.body)
            decremented_value = il.sub(4, current_value, il.const(4, 1))
            il.append(vars.il_set_var(il, self.op_details.body, decremented_value))

class SmartComplexOp(Instruction):
    """Unified complex operation handler."""
    
    _name: str
    _config: ComplexConfig
    
    def render(self) -> List[Token]:
        subop_name = self.op_details.body.subop.name
        return [TInstr(f"{self._name}.{subop_name}")]
    
    def lift(self, il: LowLevelILFunction, addr: int) -> None:
        from ...scumm6_opcodes import Scumm6Opcodes
        
        # Get the expected body type dynamically
        expected_type = getattr(Scumm6Opcodes, self._config.body_type_name)
        assert isinstance(self.op_details.body, expected_type), \
            f"Expected {expected_type.__name__} body, got {type(self.op_details.body)}"
        
        # Access the subop and its body
        subop = self.op_details.body.subop
        subop_body = self.op_details.body.body
        
        # Construct intrinsic name
        intrinsic_name = f"{self._name}.{subop.name}"
        
        # Handle parameters based on subop_body attributes
        pop_count = getattr(subop_body, "pop_count", 0)
        push_count = getattr(subop_body, "push_count", 0)
        
        # Pop arguments and call intrinsic
        params = [il.pop(4) for _ in range(pop_count)]
        
        if push_count > 0:
            il.append(il.intrinsic([il.reg(4, LLIL_TEMP(0))], intrinsic_name, params))
            il.append(il.push(4, il.reg(4, LLIL_TEMP(0))))
        else:
            il.append(il.intrinsic([], intrinsic_name, params))

# Smart stack operation base classes
class SmartBinaryOp(Instruction):
    """Self-configuring binary stack operation."""
    
    _name: str
    _config: StackConfig
    
    def render(self) -> List[Token]:
        display_name = self._config.display_name or self._name
        return [TInstr(display_name)]
    
    def lift(self, il: LowLevelILFunction, addr: int) -> None:
        assert isinstance(self.op_details.body, Scumm6Opcodes.NoData), \
            f"Expected NoData body, got {type(self.op_details.body)}"
        
        # Pop two values: a (top), b (second)
        il.append(il.set_reg(4, LLIL_TEMP(0), il.pop(4)))  # a
        il.append(il.set_reg(4, LLIL_TEMP(1), il.pop(4)))  # b

        # Get the operation from the il object
        il_func = getattr(il, self._config.il_op_name)

        # Push result: b op a
        op1 = il.reg(4, LLIL_TEMP(1))
        op2 = il.reg(4, LLIL_TEMP(0))
        result = il_func(4, op1, op2)
        il.append(il.push(4, result))

# Similar implementations for SmartUnaryOp, SmartComparisonOp, SmartArrayOp...
```

## Step 4: Create Auto-Generated Registry

### File: `src/pyscumm6/instr/registry.py`

```python
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
```

## Step 5: Update Opcode Table

### File: `src/pyscumm6/instr/opcode_table.py` (Updated)

```python
"""Opcode-to-class mapping for SCUMM6 instructions."""

from typing import Dict, Type
from ...scumm6_opcodes import Scumm6Opcodes
from .opcodes import Instruction
from .registry import INSTRUCTION_REGISTRY
from .generic import make_push_constant_instruction, make_intrinsic_instruction

# Use auto-generated classes for most instructions
OPCODE_MAP: Dict[Scumm6Opcodes.OpType, Type[Instruction]] = {
    # Factory-generated constants
    Scumm6Opcodes.OpType.push_byte: make_push_constant_instruction(
        "push_byte", Scumm6Opcodes.ByteData, 4
    ),
    Scumm6Opcodes.OpType.push_word: make_push_constant_instruction(
        "push_word", Scumm6Opcodes.WordData, 4
    ),
    
    # Auto-generated from metadata (replaces 150+ manual mappings)
    **{getattr(Scumm6Opcodes.OpType, name): cls 
       for name, cls in INSTRUCTION_REGISTRY.items()
       if hasattr(Scumm6Opcodes.OpType, name)},
    
    # Manual mappings for special cases
    Scumm6Opcodes.OpType.push_byte_var: INSTRUCTION_REGISTRY['push_byte_var'],
    Scumm6Opcodes.OpType.push_word_var: INSTRUCTION_REGISTRY['push_word_var'],
    Scumm6Opcodes.OpType.dup: INSTRUCTION_REGISTRY['dup'],
    # ... any other special cases
}
```

## Implementation Impact

### Before vs After Comparison

**Before (Current)**:
- 165+ individual instruction class definitions  
- 1740+ lines of repetitive boilerplate code
- Manual class creation for each instruction
- Difficult maintenance and extension

**After (Proposed)**:
- Single metadata configuration file (~200 lines)
- Smart factory functions (~300 lines)  
- Enhanced base classes (~400 lines)
- Auto-generated instruction registry (~50 lines)
- **Total: ~950 lines vs 1740+ lines (45% reduction)**

### Developer Experience Transformation

**Adding New Instruction - Before**:
```python
# 15+ lines of boilerplate
class NewOperation(IntrinsicOp):
    """New operation with 2 parameters."""
    
    @property
    def intrinsic_name(self) -> str:
        return "new_operation"

# Plus opcode mapping update
Scumm6Opcodes.OpType.new_operation: instructions.NewOperation,
```

**Adding New Instruction - After**:
```python
# Single line in config
"new_operation": IntrinsicConfig(pop=2, doc="New operation with 2 parameters"),
```

This refactoring achieves both maximum compactness and elegance while maintaining full functionality and improving extensibility.