# SCUMM6 Binary Ninja Plugin - Development Guide

## Running Tests

To run tests correctly, use one of these methods:

### Method 1: Use the test runner script (Recommended)
```bash
./run-tests.fish --once
```

This script automatically:
- Sets up the proper mocking environment
- Runs ruff, mypy, and pytest
- Watches for file changes (unless `--once` is used)

### Method 2: Run pytest directly with proper environment
```bash
python scripts/run_pytest_direct.py
```

This ensures the `FORCE_BINJA_MOCK=1` environment variable is set and loads the mocked Binary Ninja API.

## Why the Special Test Setup?

This plugin requires Binary Ninja to be installed and licensed. For testing without a license, we use a mocked version of the Binary Ninja API. The key requirements are:

1. Set `FORCE_BINJA_MOCK=1` environment variable
2. Import `binja_helpers.binja_api` before any real Binary Ninja modules
3. Ensure `binja_helpers_tmp` is in the Python path

## Test Structure

- Individual test files can set up mocking by importing `os` and setting `os.environ["FORCE_BINJA_MOCK"] = "1"` at the top
- All tests should import `from binja_helpers import binja_api  # noqa: F401` to ensure proper mocking

## Common Issues

- **License errors**: If you see `RuntimeError: License is not valid. Please supply a valid license.` when running tests or mypy, you need to force the use of mock Binary Ninja functions. Make sure to use the proper test runner or set `FORCE_BINJA_MOCK=1` environment variable before running any commands that import Binary Ninja modules.
- **Import errors**: The mocked API may not have all the same imports as the real Binary Ninja API

## Binary Ninja License Issues

When working with this plugin without a valid Binary Ninja license, you'll encounter license validation errors. This happens because:

1. The plugin imports real Binary Ninja modules (`binaryninja.architecture`, `binaryninja.binaryview`, etc.)
2. Binary Ninja validates its license when these modules are loaded
3. Without a valid license, operations fail with `RuntimeError: License is not valid`

**Solution**: Always use `FORCE_BINJA_MOCK=1` when:
- Running tests (`FORCE_BINJA_MOCK=1 python -m pytest`)
- Running mypy (`FORCE_BINJA_MOCK=1 mypy src/`)
- Running any Python script that imports from this plugin
- Working in development environments without Binary Ninja license

The mock system provides stub implementations of all Binary Ninja classes and functions needed for development and testing.

## MyPy Type Checking

**All mypy errors/warnings must be fixed.** No mypy errors are acceptable in this codebase.

- **Empowerment to Fix Stubs**: If you encounter `[assignment]` or `[override]` errors related to class inheritance from Binary Ninja base classes, it's highly likely our mock stubs (`binja_helpers_tmp/stubs/`) are incorrect. **You are empowered and encouraged to fix the incorrect type definitions in the `.pyi` stub files.** This is preferable to adding `# type: ignore` or changing working code to match a broken stub.

**Only use `# type: ignore[arg-type]` for "Argument ... has incompatible type" errors** where Mock objects don't match real Binary Ninja types. All other errors must be fixed properly:

- Function signature errors: Add proper type annotations
- Missing attributes: Create proper abstractions/wrapper functions  
- LLIL-related errors: Fix the actual types, never ignore
- Import and module path issues: Fix the imports
- Class inheritance issues: Fix with proper typing, don't ignore

**Never ignore:**
- `[no-any-return]` - Fix return types properly
- `[attr-defined]` - Create proper method abstractions
- `[misc]` for subclassing - Let mypy handle inheritance properly
- Anything related to LLIL lifting or instruction processing

## Common Error Patterns and Fixes

This section provides specific rules for fixing common `ruff`, `mypy`, and `pytest` errors.

### Pattern 1: Unused Imports (Ruff `F401`)

- **Symptom (ruff)**: `F401 [*] '...' imported but unused`
- **Analysis**: The code is importing a module or object that is never used in the file. This is unnecessary and should be cleaned up.
- **Fix**:
  1. Identify the file and line number from the ruff error message.
  2. Remove the unused import from the `import` statement.
  3. **Autonomous Fix**: You can run `ruff check --fix .` to fix these errors automatically.

### Pattern 2: Unused Type Ignore (Mypy `unused-ignore`)

- **Symptom (mypy)**: `Unused "type: ignore" comment [unused-ignore]`
- **Analysis**: A `# type: ignore` comment exists on a line that mypy no longer considers an error. This can happen after fixing code or updating mypy. The comment is now obsolete.
- **Fix**:
  1. Identify the file and line number from the mypy error message.
  2. Delete the entire `# type: ignore[...]` comment from that line.

### Pattern 3: Incorrect Binary Ninja API Imports

- **Symptoms (pytest & mypy)**:
  - `pytest`: `ImportError: cannot import name 'BinaryView' from 'binaryninja' ... Did you mean: 'binaryview'?`
  - `mypy`: `Argument 1 to "set" of "LastBV" has incompatible type "binaryninja.BinaryView"; expected "binaryninja.binaryview.BinaryView" [arg-type]`
- **Analysis**: This combination of errors indicates that a type (like `BinaryView` or `Architecture`) is being imported from the top-level `binaryninja` package instead of its correct submodule. The mypy error shows two different type paths (`binaryninja.BinaryView` vs. `binaryninja.binaryview.BinaryView`), confirming the issue.
- **Fix**:
  1. **Identify the incorrect import**: Look for lines like `from binaryninja import BinaryView` or `from binaryninja import Architecture`.
  2. **Determine the correct submodule**: The error message often provides a hint (e.g., `Did you mean: 'binaryview'?`). The correct submodule is almost always the lowercase version of the class name.
     - `BinaryView` is in `binaryninja.binaryview`
     - `Architecture` is in `binaryninja.architecture`
     - `LowLevelILFunction` is in `binaryninja.lowlevelil`
  3. **Correct the import statement**:
     - Change `from binaryninja import BinaryView` to `from binaryninja.binaryview import BinaryView`.
     - Change `from binaryninja import Architecture` to `from binaryninja.architecture import Architecture`.
  4. **Apply globally**: Apply this correction to all files in the project that exhibit this error to ensure consistency.
  5. **Re-run checkers**: After fixing the imports, re-run `mypy`. The `[arg-type]` errors related to this issue should now be resolved.

### Pattern 4: Incompatible Assignment in Subclass (`[assignment]`)

- **Symptom (mypy)**: `Incompatible types in assignment (expression has type "X", base class "Y" defined the type as "Z") [assignment]`
- **Analysis**: This error occurs when you define a class attribute (like a dictionary or list) in a subclass, and its type is incompatible with the type defined in the parent class. This is a strong indicator that the type definitions in our **mocked Binary Ninja stubs** (`binja_helpers_tmp/stubs/`) are incorrect or overly broad.
- **Fix**: The idiomatic fix is to correct the stub file, not to add a `# type: ignore` or change the working code.
  1. **Locate the Stub**: Find the base class mentioned in the error message within the `binja_helpers_tmp/stubs/` directory. For `Architecture`, this is likely `binja_helpers_tmp/stubs/binaryninja/architecture.pyi`.
  2. **Analyze the Mismatch**: The error message tells you the exact types. For example, your code might use `dict[RegisterName, ...]` while the stub uses `dict[RegisterName | str, ...]`. The extra `| str` is the cause of the problem due to type invariance.
  3. **Correct the Stub**: You are **empowered to correct the stub file**. Change the overly broad type in the `.pyi` file to match the more specific, correct type used in the codebase.
     - **Example**: Change `regs: Dict[Union[RegisterName, str], RegisterInfo]` to `regs: Dict[RegisterName, RegisterInfo]`.
  4. **Verify**: Re-run mypy. The error should be resolved.

## Architecture Overview

### Decoder Selection System
The plugin now supports two decoders via architecture variants:

- **Scumm6()** - Default (uses new semantic decoder)
- **Scumm6Legacy()** - Legacy implementation for compatibility
- **Scumm6New()** - Explicit new semantic decoder

### Key Files and Their Roles

#### Core Architecture
- **`src/scumm6.py`** - Main Binary Ninja architecture with decoder selection
- **`src/disasm.py`** - Legacy disassembler and container parsing
- **`src/view.py`** - Binary Ninja view integration

#### New Semantic Decoder
- **`src/pyscumm6/disasm.py`** - New object-oriented decoder entry point
- **`src/pyscumm6/instr/opcodes.py`** - Base instruction classes
- **`src/pyscumm6/instr/instructions.py`** - Concrete instruction implementations
- **`src/pyscumm6/instr/configs.py`** - Metadata-driven configurations
- **`src/pyscumm6/instr/factories.py`** - Dynamic class generation
- **`src/pyscumm6/instr/smart_bases.py`** - Smart base classes with semantic features

#### Data Formats
- **`src/scumm6_opcodes.py`** - Generated Kaitai parser for SCUMM6 bytecode
- **`src/scumm6_container.py`** - Generated Kaitai parser for .bsc6 files
- **`DOTTDEMO.bsc6`** - Day of the Tentacle demo data for testing

### Testing Strategy

#### Test Categories
1. **Unit tests** - Individual instruction testing
2. **Integration tests** - Full decoder pipeline
3. **Comparison tests** - Legacy vs new decoder validation
4. **Real data tests** - Using actual game scripts

#### Key Test Files
- **`src/test_instruction_migration.py`** - Validates equivalence between decoders
- **`src/test_descumm_comparison.py`** - Compares with descumm tool output
- **`src/test_disasm.py`** - Container parsing and script extraction
- **`src/test_scumm6.py`** - Architecture-level testing

### Development Workflow

#### Making Changes to Instructions
1. **For existing instructions**: Edit in `src/pyscumm6/instr/instructions.py`
2. **For new instructions**: Add config to `src/pyscumm6/instr/configs.py`, mapping to `opcode_table.py`
3. **For semantic intrinsics**: Use `semantic_op()` helper in configs
4. **Always run tests**: `./run-tests.fish --once` to ensure no regressions

#### Adding New Test Data
- Use `DOTTDEMO.bsc6` for real script data
- Extract specific scripts with the disasm module
- Use `room8_scrp18` as a reference example (ellipse collision detection)

#### Debugging Issues
- **Runtime errors**: Check `FORCE_BINJA_MOCK=1` is set
- **Type errors**: Run `FORCE_BINJA_MOCK=1 mypy src/`
- **Test failures**: Use `-v` flag for verbose output
- **New decoder issues**: Compare with legacy output in migration tests

### Architecture Patterns

#### Instruction Implementation
```python
class MyInstruction(Instruction):
    def render(self) -> List[Token]:
        # Return display tokens
        
    def lift(self, il: LowLevelILFunction, addr: int) -> None:
        # Generate Binary Ninja LLIL
```

#### Semantic Intrinsics
```python
"my_operation": semantic_op(
    name="my_operation",
    params=["param1", "param2"], 
    doc="Description of operation"
)
```

#### Configuration-Driven Generation
- Most instructions are generated from metadata in `configs.py`
- Use factories in `factories.py` for dynamic class creation
- Keeps instruction count manageable (100+ classes → config tables)

### Kaitai Struct Limitations

The project has identified key limitations in Kaitai Struct for SCUMM6:
1. **No runtime context** - Can't track stack state between instructions
2. **No semantic understanding** - Sees bytes, not meaning
3. **Static parsing only** - Each instruction parsed in isolation
4. **No cross-references** - Can't resolve resource IDs to names

See `KAITAI_*.md` files for detailed analysis and improvement proposals.

### Descumm Compatibility Goals

The project aims to achieve descumm-level semantic output:
- **Expression building**: `x = (a + b)` instead of separate operations
- **Control flow**: `while (x < y) { ... }` instead of raw jumps  
- **Function arguments**: Resolve all arguments from stack operations
- **Variable names**: Symbolic names instead of numeric IDs

Current gap analysis available in `test_descumm_comparison.py`.

## Comparing Plugin Output Against Descumm

The plugin includes a comprehensive testing framework for comparing its disassembly output against the industry-standard `descumm` tool. This helps measure semantic understanding gaps and track progress toward descumm-level output quality.

### Running Descumm Comparison Tests

#### Method 1: Run all comparison tests
```bash
python scripts/run_pytest_direct.py src/test_descumm_comparison.py -v
```

#### Method 2: Run only the parametrized comparison framework
```bash
python scripts/run_pytest_direct.py src/test_descumm_comparison.py::test_script_comparison -v
```

#### Method 3: Run a specific test case
```bash
python scripts/run_pytest_direct.py "src/test_descumm_comparison.py::test_script_comparison[room8_scrp18_collision_detection]" -v
```

#### Method 4: Pattern matching for descumm-related tests
```bash
python scripts/run_pytest_direct.py -k "descumm" -v
```

### Test Framework Architecture

The comparison framework in `src/test_descumm_comparison.py` provides:

1. **Data-Driven Test Cases**: Use `ScriptComparisonTestCase` dataclass to define test scenarios
2. **Session-Scoped Fixture**: `test_environment` loads `DOTTDEMO.bsc6` and builds `descumm` once per session
3. **Dynamic Script Extraction**: Automatically extracts bytecode from real SCUMM6 game files
4. **Triple Execution**: Runs `descumm`, `Scumm6Legacy`, and `Scumm6New` on identical bytecode
5. **Optional Golden Master Testing**: Compares outputs against expected strings (optional per disassembler)
6. **Output Verification**: Always verifies that all disassemblers produce non-empty output

### Output Quality Comparison

**Descumm Output (Semantic):**
```
[0000] (43) localvar5 = (**** INVALID DATA **** - localvar1)
[0007] (43) localvar6 = (getObjectY(localvar0) - localvar2) 
[0012] (43) localvar5 = abs(localvar5)
[0020] (5D) if (localvar5 > localvar3) {
[002A] (43)   var137 = 0
[0030] (7C)   stopScript(0)
[0034] (**) }
```

**Scumm6Legacy Output (Raw):**
```
[0000] push_word(src.scumm6_opcodes, 137)
[0003] is_script_running(src.scumm6_opcodes, 1, 1)
[0004] nott(src.scumm6_opcodes)
[0005] if_not(src.scumm6_opcodes, 18)
[0008] push_word(src.scumm6_opcodes, 93)
```

**Scumm6New Output (Clean Assembly-like):**
```
[0000] push_word(137)
[0003] is_script_running
[0004] nott
[0005] unless goto +18
[0008] push_word(93)
```

### Adding New Test Cases

#### Full Comparison Test (All Three Disassemblers)
```python
script_test_cases.append(
    ScriptComparisonTestCase(
        test_id="room11_enter_initialization",
        script_name="room11_enter",
        expected_descumm_output=dedent("""
            [0000] (5D) if (!**** INVALID DATA ****) {
            [0004] (5F)   startScriptQuick(93,[1])
            [000E] (9C)   roomOps.setScreen(0,200)
            [0016] (**) }
            [0016] (65) stopObjectCodeA()
            END
        """).strip(),
        expected_legacy_disasm_output=dedent("""
            [0000] push_word(src.scumm6_opcodes, 137)
            [0003] is_script_running(src.scumm6_opcodes, 1, 1)
            [0004] nott(src.scumm6_opcodes)
            [0005] if_not(src.scumm6_opcodes, 18)
        """).strip(),
        expected_new_disasm_output=dedent("""
            [0000] push_word(137)
            [0003] is_script_running
            [0004] nott
            [0005] unless goto +18
        """).strip()
    )
)
```

#### Output Verification Test (No Expected Content)
```python
script_test_cases.append(
    ScriptComparisonTestCase(
        test_id="room2_enter_output_verification",
        script_name="room2_enter"
        # No expected outputs - just verifies all disassemblers produce output
    )
)
```

### Key Insights from Comparison Tests

1. **Expression Building**: Descumm reconstructs high-level expressions like `localvar5 = abs(localvar5)` while the plugin shows individual stack operations
2. **Control Flow**: Descumm shows semantic constructs like `if (condition) { ... }` while the plugin shows raw conditional jumps
3. **Variable Context**: Descumm understands variable semantics and shows meaningful names, while the plugin uses generic `var_N` notation
4. **Function Recognition**: Descumm recognizes SCUMM function calls and shows them with parameters, while the plugin shows raw opcodes

### Requirements for Comparison Tests

- **descumm tool**: Automatically built from `scummvm-tools/` directory
- **DOTTDEMO.bsc6**: Day of the Tentacle demo file (auto-extracted from ZIP if available)
- **Mock Binary Ninja**: Tests run with `FORCE_BINJA_MOCK=1` for license-free operation

### Test Data Source

All comparison tests use real SCUMM6 bytecode from **Day of the Tentacle Demo**:
- **Container**: `DOTTDEMO.bsc6` (parsed with Kaitai Struct)
- **Test Scripts**: Multiple real game scripts including:
  - `room8_scrp18` (463 bytes, ellipse collision detection algorithm)
  - `room11_enter` (27 bytes, room initialization script)
- **Scripts Available**: 66 total scripts from rooms 1-12 plus global scripts

### Current Test Cases

1. **`room8_scrp18_collision_detection`**: Complex collision detection (descumm + new disasm comparison)
2. **`room11_enter_initialization`**: Room initialization script (all three disassemblers comparison)
3. **`room2_enter_output_verification`**: Output verification only (no content assertions)

This real-world data ensures the comparison tests reflect actual game engine semantics rather than synthetic test cases.

## Instruction Fusion System

The plugin implements a sophisticated instruction fusion system that combines stack-based operations into higher-level semantic expressions. This improves readability and enables better decompilation.

### Overview

Instruction fusion transforms sequences like:
```
push_byte(10)
push_byte(5)
add
```
Into semantic expressions like:
```
add(10, 5)
```

### Architecture

#### Key Components

1. **Base Infrastructure**: All instructions have a `fused_operands: List['Instruction'] = []` field
2. **Fusion Method**: Consumer instructions implement `fuse(self, previous: Instruction) -> Optional['Instruction']`
3. **Decoder Functions**:
   - `decode()` - Normal instruction decoding (no fusion)
   - `decode_with_fusion()` - Applies fusion for LLIL generation

#### How Fusion Works

The fusion system uses a **look-behind** approach:
1. Consumer instructions (like `add`, `sub`, `write_var`) check the previous instruction
2. If it's a fusible push operation, they create a fused version
3. The decoder handles iterative fusion for multi-operand cases

Example fusion sequence:
```python
# Input bytecode
[push_byte(10), push_byte(5), add]

# Fusion process
1. push_byte(10) → decoded normally
2. push_byte(5) → decoded normally  
3. add → fuses with push_byte(5) → add(..., 5)
4. add(..., 5) → fuses with push_byte(10) → add(10, 5)

# Result
add(10, 5) with stack_pop_count=0
```

### Implementing Fusion for New Instructions

#### Step 1: Identify Fusible Instructions

Consumer instructions that pop values from stack are candidates:
- Variable writes: `write_byte_var`, `write_word_var`
- Array operations: `byte_array_write`, `word_array_write`
- Function calls: `draw_object`, `start_script`, `walk_actor_to`
- Control flow: `if_not`, `iff` (can fuse with comparisons)

#### Step 2: Implement the fuse() Method

```python
class WriteByteVar(SmartWriteVar):
    def fuse(self, previous: Instruction) -> Optional['WriteByteVar']:
        # Only fuse if we need an operand
        if len(self.fused_operands) >= 1:
            return None
            
        # Check if previous is a fusible push
        if not self._is_fusible_push(previous):
            return None
            
        # Create fused instruction
        fused = copy.deepcopy(self)
        fused.fused_operands.append(previous)
        fused._length = self._length + previous.length()
        return fused
```

#### Step 3: Update render() Method

```python
def render(self) -> List[Token]:
    if self.fused_operands:
        # Show as assignment: var_10 = 5
        tokens = []
        tokens.append(Token(TokenType.VariableNameToken, f"var_{self.var_num}"))
        tokens.append(Token(TokenType.OperatorToken, " = "))
        tokens.extend(self._render_operand(self.fused_operands[0]))
        return tokens
    else:
        # Normal stack-based rendering
        return super().render()
```

#### Step 4: Update lift() Method  

```python
def lift(self, il: LowLevelILFunction, addr: int) -> None:
    if self.fused_operands:
        # Direct assignment without stack pop
        value_expr = self._lift_operand(il, self.fused_operands[0])
        il.append(il.set_reg(1, f"var_{self.var_num}", value_expr))
    else:
        # Normal stack-based lifting
        super().lift(il, addr)
```

### Fusion Helpers

The `SmartBinaryOp` base class provides useful fusion helpers:

```python
def _is_fusible_push(self, instr: Instruction) -> bool:
    """Check if instruction is a push that can be fused."""
    return instr.__class__.__name__ in [
        'PushByte', 'PushWord', 'PushByteVar', 'PushWordVar'
    ]

def _render_operand(self, operand: Instruction) -> List[Token]:
    """Render a fused operand appropriately."""
    if operand.__class__.__name__ in ['PushByteVar', 'PushWordVar']:
        return [Token(TokenType.VariableNameToken, f"var_{operand.var_num}")]
    else:
        return [Token(TokenType.IntegerToken, str(operand.value), operand.value)]

def _lift_operand(self, il: LowLevelILFunction, operand: Instruction) -> Any:
    """Lift a fused operand to IL expression."""
    if operand.__class__.__name__ in ['PushByteVar', 'PushWordVar']:
        return il.reg(1, f"var_{operand.var_num}")
    else:
        return il.const(1, operand.value)
```

### Testing Fusion

Always write comprehensive tests for new fusion implementations:

```python
def test_write_var_fusion(self):
    """Test fusion of push_byte + write_byte_var."""
    bytecode = bytes([
        0x00, 0x05,  # push_byte(5)
        0x42, 0x0A   # write_byte_var(var_10)
    ])
    
    instruction = decode_with_fusion(bytecode, 0x1000)
    
    # Should be write_var with fused operand
    assert instruction.__class__.__name__ == "WriteByteVar"
    assert len(instruction.fused_operands) == 1
    assert instruction.stack_pop_count == 0
    
    # Should render as assignment
    tokens = instruction.render()
    text = ''.join(t.text for t in tokens)
    assert text == "var_10 = 5"
```

### Advanced Fusion Patterns

#### Multi-Level Fusion

For complex expressions, allow fused instructions to participate in further fusion:

```python
# Goal: var_x = (a + b) * c
push_var(a)
push_var(b) 
add         # → add(a, b)
push_var(c)
mul         # → mul(add(a, b), c)
write_var(x) # → var_x = mul(add(a, b), c)
```

#### Control Flow Fusion

Fuse comparisons with conditionals for readable control flow:

```python
# Current:
push_var(x)
push_byte(10)
gt
if_not  # → unless goto

# With fusion:
if_not(gt(var_x, 10))  # → if (var_x <= 10)
```

### Best Practices

1. **Always preserve semantics**: Fusion should not change program behavior
2. **Handle edge cases**: Partial fusion, invalid sequences, cross-block boundaries
3. **Test thoroughly**: Each fusible instruction needs comprehensive test coverage
4. **Document limitations**: Some patterns may not be fusible due to complexity
5. **Consider performance**: Fusion adds overhead - use judiciously

### Debugging Fusion Issues

1. **Use decode() vs decode_with_fusion()**: Compare outputs to isolate fusion problems
2. **Check operand order**: Stack semantics (LIFO) must be preserved
3. **Verify lengths**: Fused instruction length = sum of component lengths
4. **Test incrementally**: Start with simple cases, build up to complex patterns

### Future Enhancements

- **Expression tree building**: Full AST construction from bytecode
- **Pattern matching**: Recognize common idioms (loops, switches)
- **Semantic variable names**: Integration with symbol resolution
- **Cross-block fusion**: Handle fusion across basic block boundaries safely

### Critical Implementation Lessons

Based on practical experience implementing fusion for 40+ instruction types, here are the most important lessons learned:

#### Common Pitfalls and Their Solutions

1. **Kaitai Parsing Edge Cases**
   ```python
   # Problem: write_byte_var falls through to UnknownOp due to Kaitai parsing bug
   # Solution: Handle gracefully in render() and tests
   def render(self) -> List[Token]:
       if hasattr(self.op_details, 'var_num'):
           var_id = self.op_details.var_num
       else:
           var_id = "?"  # Handle UnknownOp gracefully
   ```

2. **Operand Order Preservation (Critical for Stack Semantics)**
   ```python
   # WRONG: Can break stack semantics
   fused.fused_operands = [previous] + self.fused_operands
   
   # CORRECT: Preserves LIFO order
   fused.fused_operands.append(previous)
   ```

3. **Token Import Errors**
   ```python
   # WRONG: Direct Binary Ninja imports fail in mock environment
   from binaryninja import TokenType
   
   # CORRECT: Use local token helpers
   from binja_helpers.tokens import TInt, TText, TSep
   ```

4. **Bytecode Format Debugging**
   ```python
   # Always verify bytecode formats with actual disassembly
   # Example: word_array_write uses 2-byte array ID, not 1-byte
   bytecode = bytes([
       0x00, 0x0A,        # push_byte(10)
       0xD4, 0x05, 0x00,  # word_array_write(array_5) - note 2-byte array ID
       0x03               # index (1 byte)
   ])
   ```

#### Testing Strategy That Works

1. **Always Test Both Fusion and Non-Fusion Paths**
   ```python
   def test_instruction_both_modes(self):
       bytecode = bytes([0x00, 0x05, 0x42, 0x0A])
       
       # Test normal decoding
       normal = decode(bytecode, 0x1000)
       assert normal.__class__.__name__ == "PushByte"
       
       # Test fusion decoding  
       fused = decode_with_fusion(bytecode, 0x1000)
       assert fused.__class__.__name__ == "WriteByteVar"
       assert len(fused.fused_operands) == 1
   ```

2. **Verify Semantic Equivalence**
   ```python
   def test_fusion_preserves_semantics(self):
       # Both should produce equivalent LLIL
       normal_il = generate_il_sequence(decode(bytecode))
       fused_il = generate_il_sequence(decode_with_fusion(bytecode))
       # Compare final state, not intermediate operations
   ```

3. **Test Length Calculations**
   ```python
   def test_fused_length_correct(self):
       fused = decode_with_fusion(bytecode, 0x1000)
       expected_length = 2 + 2  # push_byte(2) + write_byte_var(2)
       assert fused.length() == expected_length
   ```

#### Performance Considerations

1. **Deep Copy Overhead**: Use `copy.deepcopy()` sparingly - only when creating fused instructions
2. **Iterative Fusion**: The decoder may need multiple passes for complex expressions
3. **Stack Pop Optimization**: Fused instructions should set `stack_pop_count = 0` to avoid redundant pops

#### Class Name vs Instance Checking

Always use class name checking for instruction type detection:
```python
# CORRECT: Works with both real and mock instructions
def _is_fusible_push(self, instr: Instruction) -> bool:
    return instr.__class__.__name__ in ['PushByte', 'PushWord', 'PushByteVar']

# WRONG: isinstance() can fail with mock objects
def _is_fusible_push(self, instr: Instruction) -> bool:
    return isinstance(instr, (PushByte, PushWord))  # Breaks in tests
```

#### Decoder Architecture Insights

1. **Separation of Concerns**: Keep `decode()` and `decode_with_fusion()` separate - never merge
2. **Buffer Management**: The fusion decoder needs to look ahead/behind, requiring careful buffer management
3. **Error Propagation**: Fusion failures should gracefully fall back to normal decoding

#### Integration with Binary Ninja

1. **Token Generation**: Use semantic tokens (`VariableNameToken`, `OperatorToken`) for better syntax highlighting
2. **LLIL Generation**: Fused instructions generate more efficient IL (fewer stack operations)
3. **Cross-Reference Support**: Fused expressions improve Binary Ninja's analysis capabilities

These lessons capture 3 weeks of intensive fusion implementation work and should prevent common mistakes in future development.
