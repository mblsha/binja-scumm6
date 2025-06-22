# SCUMM6 Instruction Fusion Status

This document summarizes the current instruction fusion capabilities in the SCUMM6 Binary Ninja plugin.

## Fusion Overview

Instruction fusion combines multiple stack-based operations into higher-level semantic expressions, improving readability and enabling better decompilation.

## Currently Implemented Fusion

### 1. Binary Operations (add, sub, mul, div)
- **Full Fusion**: When both operands are push instructions
  - `add(10, 5)` from `push_word(10)`, `push_word(5)`, `add`
  - `mul(var_7, var_7)` from `push_word_var(var_7)`, `push_word_var(var_7)`, `mul`
  - `div(var_10, 2)` from `push_word_var(var_10)`, `push_word(2)`, `div`
- **Partial Fusion**: When one operand is already on stack
  - `sub(var_1, ...)` when first operand comes from stack

### 2. Object Query Operations
- `getObjectX(var_0)` - fuses with object ID parameter
- `getObjectY(var_0)` - fuses with object ID parameter
- `get_state(var_0)` - fuses with object ID parameter
- `get_object_old_dir`, `get_object_new_dir` - similar fusion

### 3. Variable Write Operations
- `var_137 = 0` from `push_word(0)`, `write_word_var(var_137)`
- Works with both byte and word variables

### 4. Array Operations
- `byte_array_write(array_5[3])` - fuses array ID and index
- `word_array_write(array_10[var_i])` - supports variable indices

### 5. Conditional Jumps
- `if var_5 <= var_3 goto +10` - fuses comparison and jump
- `unless goto +18` - handles negated conditions

### 6. Function Calls
- `startScript(93, [1])` - variable argument functions
- `stopScript(0)` - single parameter functions
- `setState(var_0, 1)` - multi-parameter functions
- `talkActor("message", actor_id)` - includes string extraction

### 7. Complex Operations
- `roomOps.setScreen(0, 200)` - sub-command operations
- `printDebug.msg("text")` - with message extraction

## Fusion Architecture

### Base Classes Supporting Fusion
1. **SmartBinaryOp** - Binary arithmetic/logical operations
2. **SmartFusibleIntrinsic** - Intrinsic functions with parameters
3. **SmartWriteVar** - Variable assignment operations
4. **SmartArrayOp** - Array access operations
5. **SmartConditionalJump** - Conditional branching
6. **FusibleMultiOperandMixin** - Shared fusion logic

### Key Methods
- `fuse(previous: Instruction)` - Attempts to fuse with previous instruction
- `produces_result()` - Indicates if instruction can be consumed by others
- `_is_fusible_push()` - Checks if instruction can be fused

## Current Limitations

1. **Multi-level Expressions**: Complex nested expressions like `sub(getObjectX(var_0), var_1)` don't fully fuse due to stack semantics
2. **Cross-Block Fusion**: Fusion doesn't work across basic block boundaries
3. **Lookahead Issues**: The fusion algorithm sometimes processes instructions out of order in complex sequences

## Real-World Impact

In the room8_scrp18 collision detection script:
- **Before Fusion**: 290 lines with individual stack operations
- **After Fusion**: ~220 lines with semantic expressions
- **Readability**: Significantly improved with expressions like `mul(var_5, var_5)` instead of separate push/mul operations

## Future Enhancement Opportunities

1. **Expression Tree Building**: Full AST construction for complete expressions
2. **Pattern Matching**: Recognize common idioms (loops, switches)
3. **Cross-Block Fusion**: Handle fusion across basic block boundaries
4. **Semantic Variable Names**: Integration with symbol resolution