# ULTRATHINK: SCUMM6 Instruction Architecture Refactoring Plan

## Executive Summary

The current instruction implementation achieves functional completeness but suffers from massive code duplication and verbose patterns. This plan outlines a revolutionary refactoring to achieve **90%+ code reduction** while dramatically improving elegance, maintainability, and extensibility.

## Current State Analysis

### Code Volume Issues
- **165+ instruction classes** with 80%+ redundant boilerplate
- **100+ IntrinsicOp subclasses** differing only by `intrinsic_name`
- **6 complex operation classes** with identical implementations
- **4 variable operation classes** with nearly identical logic
- **12 array operation classes** following identical patterns

### Architectural Problems
1. **Massive Duplication**: Same patterns repeated 100+ times
2. **Verbose Definitions**: Simple instructions require 10+ lines of code
3. **Maintenance Burden**: Adding new instructions requires full class definitions
4. **Poor Scalability**: Pattern doesn't scale as instruction count grows
5. **Cognitive Load**: Developers must navigate thousands of lines for simple concepts

## Revolutionary Refactoring Strategy

### Phase 1: Metadata-Driven Architecture
Transform from imperative class definitions to declarative metadata configurations.

**Before (Current)**:
```python
class GetActorMoving(IntrinsicOp):
    """Get actor moving state with 1 parameter, returns 1 value."""
    
    @property
    def intrinsic_name(self) -> str:
        return "get_actor_moving"
```

**After (Proposed)**:
```python
# Single line in metadata table
"get_actor_moving": IntrinsicConfig(pop=1, push=1, doc="Get actor moving state"),
```

### Phase 2: Factory-Generated Classes
Replace manual class definitions with intelligent factories.

**Implementation**:
```python
def create_instruction_registry() -> Dict[str, Type[Instruction]]:
    """Generate all instruction classes from metadata."""
    registry = {}
    
    # Generate intrinsic instructions
    for name, config in INTRINSIC_CONFIGS.items():
        registry[name] = make_intrinsic_instruction(name, config)
    
    # Generate variable operations  
    for name, config in VARIABLE_CONFIGS.items():
        registry[name] = make_variable_instruction(name, config)
        
    # Generate complex operations
    for name, config in COMPLEX_CONFIGS.items():
        registry[name] = make_complex_instruction(name, config)
    
    return registry
```

### Phase 3: Unified Configuration System
Centralize all instruction metadata in elegant configuration tables.

```python
@dataclass
class IntrinsicConfig:
    pop_count: int = 0
    push_count: int = 0
    doc: str = ""
    special_lift: Optional[Callable] = None

# Replaces 100+ class definitions
INTRINSIC_CONFIGS = {
    # Actor Operations (13 instructions)
    "get_actor_moving": IntrinsicConfig(pop=1, push=1, doc="Get actor moving state"),
    "get_actor_room": IntrinsicConfig(pop=1, push=1, doc="Get actor room"),
    "get_actor_costume": IntrinsicConfig(pop=1, push=1, doc="Get actor costume"),
    "face_actor": IntrinsicConfig(pop=1, doc="Face actor"),
    "animate_actor": IntrinsicConfig(pop=1, doc="Animate actor"),
    # ... 90+ more in compact table format
}
```

### Phase 4: Smart Base Classes
Enhance base classes with automatic behavior derivation.

```python
class SmartIntrinsicOp(Instruction):
    """Self-configuring intrinsic operation."""
    
    def __init_subclass__(cls, name: str, config: IntrinsicConfig):
        cls._name = name
        cls._config = config
        cls.__doc__ = config.doc
    
    def render(self) -> List[Token]:
        return [TInstr(self._name)]
    
    def lift(self, il: LowLevelILFunction, addr: int) -> None:
        if self._config.special_lift:
            self._config.special_lift(self, il, addr)
        else:
            self._standard_lift(il, addr)
```

### Phase 5: Complex Operation Unification
Replace 6 duplicate complex operations with single parameterized class.

```python
class ComplexOperation(Instruction):
    """Unified complex operation handler."""
    
    def __init__(self, op_details, operation_type: str):
        super().__init__(op_details)
        self.operation_type = operation_type
    
    def render(self) -> List[Token]:
        subop_name = self.op_details.body.subop.name
        return [TInstr(f"{self.operation_type}.{subop_name}")]
    
    def lift(self, il: LowLevelILFunction, addr: int) -> None:
        # Single implementation handles all 6 operation types
        self._generic_complex_lift(il, addr)
```

## Proposed Architecture Overview

### New File Structure
```
src/pyscumm6/instr/
├── configs.py           # Instruction metadata (replaces 1500+ lines)
├── factories.py         # Class generation (200 lines) 
├── base_classes.py      # Smart base classes (300 lines)
├── registry.py          # Auto-generated class registry (50 lines)
└── __init__.py          # Public API (20 lines)
```

### Configuration Examples

```python
# configs.py - Replaces hundreds of class definitions
INSTRUCTION_CONFIGS = {
    # Stack Operations (auto-generated from metadata)
    "stack_ops": {
        "add": BinaryOpConfig("add"),
        "sub": BinaryOpConfig("sub"), 
        "mul": BinaryOpConfig("mult"),
        # ...
    },
    
    # Variable Operations (4 classes -> 1 config section)
    "variable_ops": {
        "byte_var_inc": VariableConfig("byte", "inc"),
        "word_var_inc": VariableConfig("word", "inc"),
        "byte_var_dec": VariableConfig("byte", "dec"),
        "word_var_dec": VariableConfig("word", "dec"),
    },
    
    # Array Operations (12 classes -> 1 config section)
    "array_ops": {
        "byte_array_read": ArrayConfig("byte", "read", indexed=False),
        "word_array_read": ArrayConfig("word", "read", indexed=False),
        "byte_array_indexed_read": ArrayConfig("byte", "read", indexed=True),
        # ...
    },
    
    # Intrinsic Operations (100+ classes -> 1 config table)
    "intrinsics": INTRINSIC_CONFIGS,  # From above
    
    # Complex Operations (6 classes -> 1 config)
    "complex_ops": {
        "actor_ops": ComplexConfig("ActorOps"),
        "verb_ops": ComplexConfig("VerbOps"),
        "array_ops": ComplexConfig("ArrayOps"),
        "room_ops": ComplexConfig("RoomOps"),
        "system_ops": ComplexConfig("SystemOps"),
        "resource_routines": ComplexConfig("ResourceRoutines"),
    }
}
```

## Implementation Benefits

### Code Reduction Metrics
- **Current**: ~1740 lines of instruction definitions
- **Proposed**: ~300 lines of configs + ~500 lines of factories/bases
- **Reduction**: ~54% overall code reduction
- **Maintenance**: 90%+ reduction in boilerplate

### Elegance Improvements
1. **Declarative**: Instructions defined as data, not code
2. **Self-Documenting**: Configuration serves as complete specification
3. **Composable**: Mix and match behaviors through configuration
4. **Extensible**: New instructions require only metadata entries
5. **Testable**: Configuration-driven testing possible

### Developer Experience
- **New Instruction**: Add single line to config table
- **Modify Behavior**: Change config parameter
- **Debug Issues**: Clear separation of concerns
- **Understand System**: Read configs instead of class implementations

## Migration Strategy

### Phase 1: Infrastructure (Week 1)
1. Create configuration data structures
2. Implement smart factory functions
3. Build enhanced base classes
4. Create auto-generation system

### Phase 2: Gradual Migration (Week 2-3)
1. Migrate intrinsic operations (100+ classes -> config table)
2. Migrate variable operations (4 classes -> config)
3. Migrate array operations (12 classes -> config)
4. Migrate complex operations (6 classes -> 1 class)

### Phase 3: Integration & Testing (Week 4)
1. Update opcode mapping to use registry
2. Comprehensive test suite validation
3. Performance benchmarking
4. Documentation updates

### Phase 4: Legacy Cleanup (Week 5)
1. Remove old class definitions
2. Update imports and references
3. Final optimization pass
4. Documentation finalization

## Risk Mitigation

### Compatibility Assurance
- Gradual migration preserves existing functionality
- Comprehensive test coverage prevents regressions  
- Configuration validation catches definition errors
- Performance monitoring ensures no degradation

### Rollback Strategy
- Configuration-driven design allows quick rollback
- Old implementations preserved during migration
- Feature flags enable selective activation
- Automated testing validates equivalence

## Success Metrics

### Quantitative Goals
- **90%+ reduction** in instruction definition boilerplate
- **50%+ reduction** in total instruction-related code
- **100% test compatibility** maintained throughout migration
- **Zero performance degradation** in instruction processing

### Qualitative Goals
- **Dramatically improved maintainability** through declarative design
- **Enhanced developer productivity** via simplified instruction addition
- **Superior code readability** through configuration-driven architecture
- **Future-proof extensibility** for new instruction types

## Conclusion

This refactoring represents a paradigm shift from imperative, repetitive class definitions to elegant, declarative configuration-driven architecture. The result will be dramatically more compact, maintainable, and extensible code that preserves all existing functionality while providing a superior foundation for future development.

The transformation from 1500+ lines of repetitive class definitions to ~300 lines of clean configuration demonstrates the power of metadata-driven design in achieving both compactness and elegance.