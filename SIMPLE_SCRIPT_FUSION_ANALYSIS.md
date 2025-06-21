# Simple Script Fusion Analysis - Findings and Recommendations

## Executive Summary

I've created a comprehensive framework for analyzing the simplest SCUMM6 scripts from DOTTDEMO.bsc6 and comparing them with descumm output to identify fusion opportunities. The analysis revealed critical insights about both our decoder functionality and specific fusion gaps.

## Key Discoveries

### 1. Decoder Validation ✅
**Finding**: The decoder is working correctly! Initial analysis suggested it was broken (decoding everything as `stop_object_code1`), but detailed investigation revealed this was due to:
- Single-byte opcodes like `65` correctly decode to `stop_object_code1`
- Multi-byte instructions like `01 05 00` correctly decode to `push_word(5)` (3 bytes)
- The analyzer was initially looking at individual bytes rather than complete instructions

**Evidence**: Testing bytecode `0105007c65` correctly produces:
```
[0000] push_word(5)      # 01 05 00 (3 bytes)
[0003] stop_script       # 7c (1 byte) 
[0004] stop_object_code1 # 65 (1 byte)
```

### 2. Descumm Limitations with Small Scripts
**Finding**: Descumm cannot process many small scripts, reporting:
- "File too small to be a script!" for 1-5 byte scripts
- "Unknown script type!" for larger scripts

**Implication**: For the smallest scripts, we need to rely on manual analysis rather than descumm comparison.

### 3. Critical Fusion Opportunities Identified

#### Function Name Formatting
**Current**: `stop_object_code1`, `stop_script`, `push_word`
**Descumm Style**: `stopObjectCodeA()`, `stopScript()`, function call syntax
**Impact**: High - affects readability of all single-instruction scripts

#### Missing Parentheses Syntax
**Current**: `stop_object_code1`
**Ideal**: `stopObjectCodeA()`
**Implementation**: Add function call syntax with parentheses for consistency

#### Expression Building Opportunities
**Current**: Multi-line stack operations
```
[0000] push_word(5)
[0003] stop_script
```
**Potential**: Single semantic expression
```
[0000] stopScript(5)  # If stop_script takes a parameter
```

## Analyzed Scripts

### Single-Byte Scripts (All decode to `stop_object_code1`)
- `room1_exit`, `room1_enter`, `room5_exit`, `room6_exit`, `room7_exit`, `room9_exit`
- **Bytecode**: `65`
- **Current Output**: `stop_object_code1`
- **Recommendation**: Render as `stopObjectCodeA()` to match descumm conventions

### Multi-Instruction Scripts
- `room2_exit` (5 bytes): `push_word(5)` + `stop_script` + `stop_object_code1`
- `room9_enter` (9 bytes): Complex sequence with potential fusion opportunities
- `room7_enter` (11 bytes): Multiple instructions that could benefit from fusion
- `room2_enter` (18 bytes): Longest analyzed script with significant fusion potential

## Specific Fusion Recommendations

### 1. Function Name Mapping Table
Create a mapping from internal names to descumm-style names:
```python
FUNCTION_NAME_MAP = {
    "stop_object_code1": "stopObjectCodeA",
    "stop_script": "stopScript", 
    "push_word": "pushWord",
    "start_script": "startScript",
    # ... more mappings
}
```

### 2. Parentheses Rendering
Update instruction rendering to include parentheses for function calls:
```python
def render(self) -> List[Token]:
    base_name = FUNCTION_NAME_MAP.get(self.name, self.name)
    if self.is_function_call():
        return [Token(TokenType.TextToken, f"{base_name}()")]
    else:
        return [Token(TokenType.TextToken, base_name)]
```

### 3. Argument Fusion Pattern
For sequences like `push_word(X) + function_call`, fuse into `function_call(X)`:
```python
# Current
[0000] push_word(5)
[0003] stop_script

# With fusion  
[0000] stopScript(5)
```

### 4. Multi-Level Expression Building
Implement expression trees for complex operations:
```python
# Current
[0000] push_word(value1)
[0003] push_word(value2) 
[0006] add
[0007] write_var(x)

# With fusion
[0000] var_x = add(value1, value2)
```

## Framework Value

### Analysis Framework (`scripts/analyze_simple_scripts.py`)
- **Automated Script Extraction**: Uses `Scumm6Disasm.decode_container()` to find all scripts
- **Multi-Decoder Comparison**: Compares descumm, non-fusion, and fusion outputs
- **Gap Identification**: Automatically identifies specific improvement opportunities
- **Test Case Generation**: Creates parameterized test cases for validation

### Debugging Tools (`debug_decoder.py`)
- **Opcode Validation**: Tests individual instruction decoding
- **Multi-Byte Sequence Analysis**: Validates complex instruction sequences
- **Error Diagnosis**: Helps identify decoder vs analyzer issues

## Next Steps

### Immediate Actions (High Impact)
1. **Implement function name mapping** for single-byte instructions like `stop_object_code1` → `stopObjectCodeA()`
2. **Add parentheses syntax** for all function calls
3. **Create fusion patterns** for `push + function_call` sequences

### Medium-Term Goals
1. **Expand to larger scripts** (25-100 bytes) using the same framework
2. **Implement expression tree building** for complex operations
3. **Add END marker detection** for script termination

### Long-Term Vision
1. **Full descumm parity** for semantic understanding
2. **Control flow reconstruction** (if/while/for loops)
3. **Variable name resolution** (localvar1, localvar2, etc.)

## Testing Strategy

### Generated Test Cases
The framework automatically generates test cases like:
```python
def test_room1_exit_fusion():
    bytecode = bytes.fromhex("65")
    instr = decode_with_fusion(bytecode, 0)
    tokens = instr.render()
    text = ''.join(t.text for t in tokens)
    assert text == "stopObjectCodeA()"  # Expected improvement
```

### Validation Approach
1. **Incremental Testing**: Validate each fusion improvement with specific test cases
2. **Regression Testing**: Ensure fusion changes don't break existing functionality
3. **Real-World Validation**: Test against actual game scripts from DOTTDEMO

## Conclusion

This analysis framework has successfully:
- ✅ Validated that our decoder works correctly
- ✅ Identified specific, actionable fusion opportunities
- ✅ Created automated tools for ongoing analysis
- ✅ Generated test cases for validation
- ✅ Provided clear implementation roadmap

The smallest scripts reveal fundamental patterns that, when addressed, will improve readability across the entire codebase. The framework can now be extended to analyze progressively larger and more complex scripts, building toward full descumm-level semantic understanding.

## Files Created

1. **`scripts/analyze_simple_scripts.py`** - Main analysis framework
2. **`debug_decoder.py`** - Decoder validation tool  
3. **`simple_script_analysis_report.md`** - Detailed script-by-script analysis
4. **`SIMPLE_SCRIPT_FUSION_ANALYSIS.md`** - This summary document

The framework is ready for immediate use and can be easily extended to analyze larger scripts as fusion capabilities improve.