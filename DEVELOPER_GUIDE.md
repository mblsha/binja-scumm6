# SCUMM6 Metadata-Driven Architecture - Developer Guide

## Overview

The SCUMM6 instruction system uses a modern metadata-driven architecture that dramatically reduces boilerplate code and simplifies adding new instructions.

## Architecture Components

### 1. Configuration System (`src/pyscumm6/instr/configs.py`)

Define instruction behavior through declarative metadata:

```python
@dataclass
class IntrinsicConfig:
    pop_count: int = 0      # Arguments popped from stack
    push_count: int = 0     # Values pushed to stack  
    doc: str = ""          # Documentation
    special_lift: Optional[str] = None  # Custom lift method name

INTRINSIC_CONFIGS = {
    "draw_object": IntrinsicConfig(
        pop_count=2, 
        doc="Draw object with ID and state"
    ),
}
```

### 2. Smart Base Classes (`src/pyscumm6/instr/smart_bases.py`)

Self-configuring classes that implement common instruction patterns:

- `SmartIntrinsicOp` - Engine function calls
- `SmartStackOp` - Stack operations (binary/unary/comparison)  
- `SmartVariableOp` - Variable increment/decrement
- `SmartArrayOp` - Array read/write operations
- `SmartComplexOp` - Complex operations with sub-commands

### 3. Factory System (`src/pyscumm6/instr/factories.py`)

Auto-generates instruction classes from configuration metadata:

```python
def create_intrinsic_instruction(name: str, config: IntrinsicConfig) -> Type[Instruction]:
    class GeneratedIntrinsicOp(SmartIntrinsicOp):
        _name = name
        _config = config
    return GeneratedIntrinsicOp
```

### 4. Registry System (`src/pyscumm6/instr/registry.py`)

Lazy-loaded registry that creates all instruction classes on-demand:

```python
INSTRUCTION_REGISTRY["draw_object"]  # Returns auto-generated class
```

## Adding New Instructions

### Simple Intrinsic Operation

Add one line to `INTRINSIC_CONFIGS`:

```python
"new_function": IntrinsicConfig(pop_count=1, push_count=1, doc="Description"),
```

Then map it in `opcode_table.py`:

```python
Scumm6Opcodes.OpType.new_function: INSTRUCTION_REGISTRY["new_function"],
```

### Stack Operation

Add to `STACK_CONFIGS`:

```python
"new_op": StackConfig(il_op_name="add", doc="Addition operation"),
```

### Variable Operation

Add to `VARIABLE_CONFIGS`:

```python
"new_var_op": VariableConfig(
    var_type="word", 
    operation="inc", 
    doc="Increment word variable"
),
```

### Complex Operation with Sub-Commands

Add to `COMPLEX_CONFIGS`:

```python
"new_complex": ComplexConfig(
    body_type_name="NewComplexOp",
    doc="Complex operation with sub-commands"
),
```

### Custom Lift Method

For special behavior, add a `special_lift` method name:

```python
"special_instruction": IntrinsicConfig(
    pop_count=0,
    special_lift="custom_lift_method",
    doc="Instruction with custom behavior"
),
```

Then implement in the smart base class:

```python
def custom_lift_method(self, il: LowLevelILFunction, addr: int) -> None:
    # Custom implementation
    pass
```

## Benefits

### Developer Productivity
- **Before**: 15+ lines of class definition + manual mapping
- **After**: 1 line of configuration metadata
- **Improvement**: 93%+ reduction in development effort

### Maintainability
- **Single Source of Truth**: All behavior defined in configuration
- **Declarative Design**: Instructions defined as data, not code
- **Type Safety**: Full mypy compatibility
- **Self-Documenting**: Configuration serves as specification

### Extensibility
- Easy addition of new instruction types
- Plugin-ready architecture
- Configuration validation
- Behavioral composition through metadata

## Migration from Legacy

The system supports hybrid operation:

1. **Auto-Generated**: Use `INSTRUCTION_REGISTRY["name"]`
2. **Legacy Factory**: Use `make_intrinsic_instruction()` 
3. **Manual Classes**: Direct class implementation for complex cases

This allows gradual migration while maintaining compatibility.

## Testing

All auto-generated instructions are automatically tested for:

- LLIL generation consistency
- Disassembly output consistency  
- Type safety
- Behavioral equivalence with original implementation

## Performance

- **Lazy Loading**: Classes generated only when accessed
- **Memory Efficient**: Metadata-driven approach uses less memory
- **Fast Generation**: Dynamic class creation is optimized
- **Zero Runtime Overhead**: Generated classes are identical to manual ones