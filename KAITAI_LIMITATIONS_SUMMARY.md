# Kaitai Struct Limitations for SCUMM6: Executive Summary

## The Core Problem

Kaitai Struct is designed for **static binary format parsing**, while SCUMM6 is a **dynamic stack-based scripting language**. This fundamental mismatch creates significant limitations.

## What Kaitai Does Badly for SCUMM6

### 1. **No Runtime Context** ❌
- **Problem**: Can't track stack state between instructions
- **Impact**: Variable argument instructions remain opaque
- **Example**: `startScript` needs previous stack values to know argument count

### 2. **No Semantic Understanding** ❌
- **Problem**: Sees bytes, not meaning
- **Impact**: Can't produce human-readable output like descumm
- **Example**: Shows `0x5C 0x14 0x00` instead of `if goto +20`

### 3. **Static Parsing Only** ❌
- **Problem**: Each instruction parsed in isolation
- **Impact**: Can't understand instruction sequences that form logical operations
- **Example**: Can't recognize if-else patterns or loop constructs

### 4. **No Cross-References** ❌
- **Problem**: Can't resolve resource IDs to names
- **Impact**: Shows `drawObject(15, 3)` instead of `drawObject(OBJ_DOOR, STATE_OPEN)`

### 5. **Limited String Handling** ❌
- **Problem**: Treats messages as byte arrays
- **Impact**: Can't parse escape sequences, format codes, or variable substitutions
- **Example**: Returns raw bytes instead of `"Hello %s{playerName}"`

## Comparison: Kaitai vs Descumm

| Feature | Kaitai Output | Descumm Output | Gap |
|---------|---------------|----------------|-----|
| Variable args | `call_func_list` | `startScript(50, [1,2,3])` | Huge |
| Control flow | `iff(20)` | `if goto label_20` | Medium |
| Expressions | Individual ops | `VAR_X = (A + B) * C` | Huge |
| Messages | Byte array | Formatted string | Large |
| Resources | Numeric IDs | Symbolic names | Medium |

## Critical Missing Features

### 1. **Dynamic Repeat Count**
```yaml
# What we need:
args:
  repeat: runtime_value
  repeat-source: previous_stack_pop
```

### 2. **Instruction Context**
```yaml
# What we need:
parse_with_context:
  stack_state: true
  previous_instructions: 10
```

### 3. **Semantic Patterns**
```yaml
# What we need:
patterns:
  - if_else_detection
  - loop_recognition
  - expression_building
```

## Recommended Solution

### Short Term: Post-Processing Layer ✅

Build a semantic analyzer that:
1. Parses with Kaitai (gets structure right)
2. Simulates stack execution (resolves arguments)
3. Applies patterns (recognizes constructs)
4. Generates descumm output (human readable)

### Long Term: Kaitai Enhancement Proposal 📋

Submit RFC to Kaitai project for:
1. Stack machine support
2. Runtime-determined repeats
3. Cross-instruction context
4. Semantic annotations

## Why This Matters

### Current State 😞
- Binary Ninja shows: `push(3) push(5) add write_var(10)`
- Reverse engineer must mentally track stack

### With Improvements 😊
- Binary Ninja shows: `VAR_RESULT = 3 + 5`
- Instantly understandable

## Immediate Action Items

1. **Implement Stack Simulator** (1 week)
   - Track push/pop operations
   - Resolve variable arguments
   
2. **Add Pattern Matcher** (1 week)
   - Recognize control flow
   - Build expressions
   
3. **Create Semantic Formatter** (1 week)
   - Generate descumm-style output
   - Add resource name resolution

## Conclusion

Kaitai Struct alone cannot handle SCUMM6's complexity. A **hybrid approach** combining Kaitai's binary parsing with custom semantic analysis is the optimal solution. This provides:

- ✅ Accurate binary parsing (Kaitai's strength)
- ✅ Semantic understanding (our added layer)
- ✅ Descumm-quality output (end goal)
- ✅ Maintainable architecture (clear separation)

The investment in building this semantic layer will dramatically improve the reverse engineering experience for SCUMM6 games in Binary Ninja.