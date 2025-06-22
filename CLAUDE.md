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

## Binary Ninja Plugin Stability & Best Practices

This section documents critical lessons learned from production Binary Ninja usage and provides essential patterns for maintaining plugin stability.

### Critical Runtime Error Fixes

The plugin addresses the three most common Binary Ninja runtime errors. These patterns apply to any Binary Ninja plugin development:

#### 1. KeyError for 'var_X' Registers

**Problem**: `KeyError: 'var_X'` when LLIL generation references undefined registers.

**Root Cause**: Plugin generates IL with register names (like `var_0`, `var_136`) that aren't declared in the architecture's register dictionary.

**Solution**: Add all plugin-specific registers to the `Architecture.regs` dictionary.

```python
class Scumm6(Architecture):
    # Define all registers used by your IL generation
    regs = {
        RegisterName("sp"): RegisterInfo(RegisterName("sp"), 4),
        # Add your plugin's virtual registers
        **{
            RegisterName(f"var_{i}"): RegisterInfo(RegisterName(f"var_{i}"), 4)
            for i in range(800)  # NUM_SCUMM_VARS
        }
    }
```

**Key Insight**: Every register name used in `il.reg()` or `il.set_reg()` must be pre-declared in the architecture.

#### 2. AttributeError for NoneType Labels

**Problem**: `AttributeError: 'NoneType' object has no attribute 'handle'` when creating conditional jumps.

**Root Cause**: `il.get_label_for_address()` returns `None` for invalid/out-of-bounds jump targets, but code assumes it always returns a valid label.

**Solution**: Add defensive checks before using labels in control flow IL.

```python
def lift_conditional_jump(self, il: LowLevelILFunction, addr: int) -> None:
    target_addr = addr + self.length() + self.jump_offset
    true_label = il.get_label_for_address(il.arch, target_addr)
    
    # Defensive check for invalid jump targets
    if true_label is None:
        # Target is outside function scope or invalid
        return  # Graceful degradation
    
    false_label = LowLevelILLabel()
    il.append(il.if_expr(condition, true_label, false_label))
    il.mark_label(false_label)
```

**Key Insight**: Always validate labels before use in `il.if_expr()` or similar control flow operations.

#### 3. AttributeError for 'int' has no attribute 'name'

**Problem**: `AttributeError: 'int' object has no attribute 'name'` when accessing enum attributes.

**Root Cause**: Kaitai parsers sometimes return raw integers instead of enum objects due to parsing edge cases.

**Solution**: Add type checking and enum conversion with error handling.

```python
def process_subop(self, subop: Any) -> str:
    # Handle both enum objects and raw integers
    if isinstance(subop, int):
        try:
            subop = MyEnumType(subop)  # Convert int to enum
        except ValueError:
            return f"unknown_{subop}"  # Graceful fallback
    
    return subop.name  # Now safe to access .name
```

**Key Insight**: Never assume Kaitai struct fields are properly typed enums; always handle raw integer cases.

### Enabling Instruction Fusion in Production

Instruction fusion dramatically improves decompiler output by combining stack operations into semantic expressions.

#### Implementation Pattern

```python
class MyArchitecture(Architecture):
    def get_instruction_low_level_il(self, data: bytes, addr: int, il: LowLevelILFunction) -> Optional[int]:
        # Use fusion for LLIL generation (better decompilation)
        instruction = decode_with_fusion(data, addr)
        if instruction:
            instruction.lift(il, addr)
            return instruction.length()
        return None
    
    def get_instruction_text(self, data: bytes, addr: int) -> Optional[Tuple[List[InstructionTextToken], int]]:
        # Use normal decode for display (preserves granularity)
        instruction = decode(data, addr)
        if instruction:
            tokens = instruction.render()
            return [token.to_binja() for token in tokens], instruction.length()
        return None
```

**Key Insight**: Use fusion for LLIL (semantic analysis) but not for display text (user clarity).

### MyPy Error Resolution Patterns

#### Idiomatic Fixes for Common MyPy Errors

**Statement is unreachable [unreachable]**
- **Problem**: Dead code that static analysis proves can never execute
- **Fix**: Remove the unreachable statements (don't just add type: ignore)
- **Example**: Delete `il.append(il.unimplemented())` calls after defensive returns

**Unused "type: ignore" comment [unused-ignore]**
- **Problem**: Type annotations fixed the underlying issue, making ignore obsolete
- **Fix**: Remove the entire `# type: ignore[...]` comment
- **Example**: Delete `# type: ignore[misc]` from working class definitions

**Class cannot subclass "Architecture" [misc]**
- **Problem**: Mock stubs see base classes as Any type during testing
- **Fix**: Add `# type: ignore[misc]` only when actually needed for mocked types
- **Example**: `class MyArch(Architecture): # type: ignore[misc]` only for mock compatibility

#### MyPy Development Workflow

```bash
# Check both real and mock environments
mypy --explicit-package-bases src/
FORCE_BINJA_MOCK=1 mypy --explicit-package-bases src/

# Run comprehensive test suite
./run-tests.fish --once
```

**Best Practice**: Fix mypy errors by improving code, not by adding type: ignore comments.

### Development Anti-Patterns to Avoid

1. **Register Mismatches**: Never use register names in IL that aren't in `Architecture.regs`
2. **Unsafe Label Usage**: Never call `il.if_expr()` without validating label existence
3. **Enum Assumptions**: Never assume Kaitai fields are properly typed enums
4. **Dead Code Retention**: Never keep unreachable code just to silence mypy
5. **Ignore Comment Accumulation**: Never leave obsolete `# type: ignore` comments

### Performance and Debugging Tips

#### Binary Ninja Plugin Development

- **IL Debugging**: Use Binary Ninja's IL view to verify your lift() methods generate correct intermediate language
- **Fusion Testing**: Compare `decode()` vs `decode_with_fusion()` outputs to verify semantic correctness
- **Mock vs Real**: Always test with both `FORCE_BINJA_MOCK=1` and real Binary Ninja environments
- **Error Logging**: Use Binary Ninja's log system instead of print() for production plugins

#### Test-Driven Development

```python
def test_instruction_stability():
    """Test critical error patterns don't regress."""
    # Test register existence
    arch = MyArchitecture()
    assert RegisterName("var_0") in arch.regs
    
    # Test label handling
    il = MockLowLevelILFunction()
    instruction = decode_with_fusion(bytecode, addr)
    instruction.lift(il, addr)  # Should not crash
    
    # Test enum handling
    complex_instruction = decode_complex_op(complex_bytecode)
    tokens = complex_instruction.render()  # Should not crash
    assert len(tokens) > 0
```

This proactive testing approach catches stability issues before they reach production.

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

## Multi-Level Expression Building

The instruction fusion system has been extended to support complex expression trees through a **result-producing instruction protocol**. This enables fused instructions to participate in further fusion, creating nested expressions like `mul((add(var_5, var_7)), var_3)`.

### Architecture for Expression Trees

#### Result-Producing Protocol
```python
class Instruction:
    def produces_result(self) -> bool:
        """Returns True if this instruction produces a result that can be consumed by other instructions."""
        return False  # Default: most instructions don't produce consumable results

class SmartBinaryOp(Instruction):
    def produces_result(self) -> bool:
        """Binary operations produce results that can be consumed by other instructions."""
        return True
```

#### Enhanced Fusibility Detection
```python
def _is_fusible_push(self, instr: Instruction) -> bool:
    """Check if instruction is a push that can be fused or produces a consumable result."""
    # Check for basic push instructions
    if instr.__class__.__name__ in ['PushByte', 'PushWord', 'PushByteVar', 'PushWordVar']:
        return True
    
    # Check if instruction produces a result that can be consumed
    # This enables multi-level expression building
    if instr.produces_result():
        return True
        
    return False
```

### Expression Tree Rendering Patterns

#### Nested Expression Handling
```python
def _render_operand(self, operand: Instruction) -> List[Token]:
    """Render a fused operand appropriately."""
    if operand.__class__.__name__ in ['PushByteVar', 'PushWordVar']:
        return [TInt(f"var_{operand.op_details.body.data}")]
    elif operand.__class__.__name__ in ['PushByte', 'PushWord']:
        return [TInt(str(operand.op_details.body.data))]
    elif operand.produces_result():
        # This is a result-producing instruction (like a fused expression)
        # Render it as a nested expression with parentheses
        tokens = []
        tokens.append(TText("("))
        tokens.extend(operand.render())
        tokens.append(TText(")"))
        return tokens
    else:
        return [TText("operand")]
```

### Multi-Level Expression Examples

#### Two-Level Expressions
```python
# Bytecode sequence:
push_byte_var(var_5)    # 0x02, 0x05
push_byte_var(var_7)    # 0x02, 0x07
add                     # 0x14
push_byte_var(var_3)    # 0x02, 0x03  
mul                     # 0x16

# Fusion result:
mul((add(var_5, var_7)), var_3)
```

#### Three-Level Expressions
```python
# Bytecode sequence:
push_byte(10)           # 0x00, 0x0A
push_byte(5)            # 0x00, 0x05
add                     # 0x14
push_byte(3)            # 0x00, 0x03
mul                     # 0x16
push_byte(2)            # 0x00, 0x02
sub                     # 0x15

# Fusion result:
sub((mul((add(10, 5)), 3)), 2)
```

### Implementation Best Practices

#### 1. Mark Appropriate Instructions as Result Producers
Only instructions that push values onto the stack should return `True` from `produces_result()`:
- **Arithmetic operations**: add, sub, mul, div
- **Comparison operations**: eq, neq, gt, lt, le, ge
- **Logical operations**: land, lor, nott
- **Function calls**: get_object_x, get_actor_x, etc.

#### 2. Preserve Existing Fusion Capabilities
Multi-level fusion should extend, not replace, existing push-based fusion:
```python
# This should still work (basic fusion)
push_byte(10)
push_byte(5)
add

# And this should now work (multi-level fusion)
push_byte(1)
push_byte(2)
add
push_byte(3)
mul
```

#### 3. Handle Recursive Rendering Safely
When rendering nested expressions, ensure proper parenthetical grouping:
```python
# Good: mul((add(a, b)), c)
# Bad:  mul(add(a, b), c)  # Ambiguous precedence
```

#### 4. Testing Strategy for Expression Trees
```python
def test_multi_level_expression():
    """Test complex multi-level expression building."""
    bytecode = bytes([
        0x02, 0x05,  # push_byte_var(var_5)
        0x02, 0x07,  # push_byte_var(var_7)  
        0x14,        # add
        0x02, 0x03,  # push_byte_var(var_3)
        0x16         # mul
    ])
    
    fused = decode_with_fusion(bytecode, 0x1000)
    assert fused.__class__.__name__ == "Mul"
    assert len(fused.fused_operands) == 2
    
    # Verify nested structure
    add_operand = fused.fused_operands[0]
    assert add_operand.__class__.__name__ == "Add"
    assert add_operand.produces_result() == True
    
    # Verify rendering
    tokens = fused.render()
    text = ''.join(str(t.text if hasattr(t, 'text') else t) for t in tokens)
    assert "mul" in text and "add" in text and "var_5" in text
```

### Common Challenges and Solutions

#### 1. IL Generation for Nested Expressions
**Problem**: Complex operand lifting for nested expressions requires architectural changes.
**Solution**: Use placeholder IL for now, plan future architectural improvements.

```python
def _lift_operand(self, il: LowLevelILFunction, operand: Instruction) -> Any:
    """Lift a fused operand to IL expression."""
    if operand.produces_result():
        # Complex case: would need to execute operand's lift method
        # For now, use placeholder - future enhancement needed
        return il.const(4, 0)  # Placeholder
```

#### 2. Stack Semantics Preservation
**Problem**: Multi-level fusion must preserve LIFO stack ordering.
**Solution**: Maintain consistent operand ordering throughout fusion chain.

#### 3. Token Text Extraction in Tests
**Problem**: Different token types have different text access patterns.
**Solution**: Use robust text extraction pattern:

```python
def safe_token_text(tokens):
    return ''.join(str(t.text if hasattr(t, 'text') else t) for t in tokens)
```

### Performance Considerations

#### 1. Deep Copy Overhead
Multi-level fusion increases deep copy operations. Monitor performance with complex expressions.

#### 2. Recursive Rendering
Deeply nested expressions can impact rendering performance. Consider depth limits for pathological cases.

#### 3. Memory Usage
Expression trees consume more memory than flat instruction sequences. Profile memory usage with real game scripts.

### Validation Against Descumm Output

Multi-level expression building brings the plugin significantly closer to descumm-level semantic understanding:

**Descumm Target:**
```
[0000] localvar5 = (getObjectX(localvar0) + 10)
```

**Plugin Progress:**
```
[0000] add((get_object_x(var_0)), 10)
```

**Remaining Gap:**
- Variable assignment fusion (write operations)
- Semantic function name resolution
- Local variable naming conventions

This implementation provides the foundation for achieving descumm-level decompilation quality through hierarchical expression trees rather than flat bytecode sequences.

## Systematic Descumm Improvement Methodology

Based on implementing comprehensive descumm-style function naming and achieving 2/3 test case compatibility, here are the proven patterns for systematic plugin improvement toward descumm-level output quality.

### The Methodical Approach That Works

#### 1. Real-World Data-Driven Analysis
**Key Insight**: Always use actual game scripts, not synthetic test data.

```bash
# Extract all scripts for systematic analysis
python scripts/analyze_dottdemo_scripts.py
# Creates comprehensive inventory: 66 DOTTDEMO scripts categorized by complexity

# Focus on smallest scripts first for maximum impact
python scripts/analyze_simple_scripts_refactored.py 
# Identifies specific, actionable fusion opportunities
```

**Why This Works**: Real game scripts reveal patterns that synthetic tests miss. The DOTTDEMO.bsc6 file contains 66 scripts ranging from 1-byte simplicity to 463-byte complexity, providing perfect progression for improvement.

#### 2. Descumm as Ground Truth Validation
**Critical Discovery**: descumm output quality is the measurable target, not subjective "readability."

```python
# Framework for systematic comparison against descumm
@pytest.mark.parametrize("case", script_test_cases, ids=lambda c: c.test_id)
def test_script_comparison(case: ScriptComparisonTestCase, test_environment: ComparisonTestEnvironment):
    """Data-driven validation against industry standard."""
    descumm_output = run_descumm_on_bytecode(test_environment.descumm_path, bytecode)
    plugin_output = run_scumm6_disassembler_with_fusion(bytecode, script_info.start)
    
    # Quantifiable gap analysis
    compare_semantic_understanding(descumm_output, plugin_output)
```

**Measurable Results**: 
- **Before**: `stop_object_code1`, `start_script(script_id, ...)`
- **After**: `stopObjectCodeA()`, `startScript(...)`
- **Progress**: 2/3 major test cases achieve perfect compatibility

#### 3. Comprehensive Function Name Mapping Implementation
**Architecture Pattern**: Global function name mapping applied consistently across all instruction base classes.

```python
# Central mapping dictionary - single source of truth
DESCUMM_FUNCTION_NAMES = {
    "stop_object_code1": "stopObjectCodeA",
    "start_script": "startScript", 
    "room_ops.room_screen": "roomOps.setScreen",
    "get_object_x": "getObjectX",
    # 50+ mappings covering all major SCUMM operations
}

# Applied in ALL instruction render methods
class SmartIntrinsicOp(Instruction):
    def render(self) -> List[Token]:
        display_name = DESCUMM_FUNCTION_NAMES.get(self._name, self._name)
        return [TInstr(f"{display_name}(...)")]
```

**Critical Implementation Insight**: Function name mapping must be applied in 6+ different instruction base classes, not just one. Each base class (`SmartIntrinsicOp`, `SmartFusibleIntrinsic`, `SmartSemanticIntrinsicOp`, `SmartComplexOp`, `SmartUnaryOp`, `SmartBinaryOp`) handles different instruction categories.

#### 4. Iterative Test-Driven Validation
**Process**: Fix one failing test completely before moving to the next.

```bash
# Target specific failing cases systematically  
python scripts/run_pytest_direct.py "src/test_descumm_comparison.py::test_script_comparison[room2_enter_output_verification]" -v
# PASS ✓

python scripts/run_pytest_direct.py "src/test_descumm_comparison.py::test_script_comparison[room11_enter_initialization]" -v  
# PASS ✓

python scripts/run_pytest_direct.py "src/test_descumm_comparison.py::test_script_comparison[room8_scrp18_collision_detection]" -v
# 95% working, complex print_debug formatting issues remain
```

**Success Pattern**: Focus on complete solutions rather than partial improvements across multiple areas.

### Key Technical Discoveries

#### 1. Instruction Fusion + Function Naming = Descumm-Level Quality
**Insight**: Neither fusion alone nor naming alone achieves descumm quality. The combination is essential.

```
# Fusion produces clean expressions
[0000] startScript(1, 201, 0)  # Perfect semantic expression

# Function naming provides descumm compatibility  
stopObjectCodeA() vs stop_object_code1  # Industry standard vs internal naming
```

#### 2. Base Class Architecture Patterns
**Discovery**: Different instruction types require different base classes with shared naming logic.

- **Intrinsics**: `SmartIntrinsicOp` → `SmartFusibleIntrinsic` → `SmartSemanticIntrinsicOp`
- **Operations**: `SmartBinaryOp`, `SmartUnaryOp` for arithmetic
- **Complex**: `SmartComplexOp` for multi-part operations like `room_ops.room_screen`

**Implementation Rule**: Add function name mapping to the `render()` method of EVERY base class.

#### 3. Test Expectation Management Strategy
**Lesson**: Update test expectations progressively as improvements are implemented.

```python
# Wrong approach: Update all tests at once (leads to confusion)
# Right approach: Update expectations incrementally per improvement

# Update room2_enter expectations after implementing fusion
expected_disasm_fusion_output=dedent("""
    [0000] startScript(1, 201, 0)    # Was: 3 separate push/call instructions
    [000A] startScriptQuick(5, 0)    # Clean semantic expressions
    [0011] stopObjectCodeA()         # camelCase naming
""").strip()
```

#### 4. Complex Operation Edge Cases
**Challenge**: Some operations like `print_debug.msg("string")` require special handling.

**Current State**: 95% function naming works, but string parameter formatting needs investigation.
**Solution Pattern**: Handle complex operations through dedicated `SmartComplexOp` subclasses.

### Proven Development Workflow

#### Phase 1: Analysis & Planning
1. **Script Inventory**: Extract and categorize all target scripts
2. **Gap Analysis**: Run descumm comparison to identify specific issues  
3. **Priority Ranking**: Start with simplest scripts for maximum impact

#### Phase 2: Systematic Implementation  
1. **Function Name Mapping**: Implement comprehensive naming dictionary
2. **Base Class Updates**: Apply mapping across all instruction types
3. **Test Expectation Updates**: Update golden master tests incrementally

#### Phase 3: Validation & Iteration
1. **Test Case Progression**: Fix one test completely before moving to next
2. **Real-World Validation**: Test against actual game scripts
3. **Quality Measurement**: Track progress through passing test percentages

### Quantifiable Success Metrics

#### Output Quality Improvements
- **Function Names**: 50+ mappings from internal names to descumm camelCase
- **Expression Quality**: `startScript(1, 201, 0)` vs 3 separate operations  
- **Test Compatibility**: 67% test cases pass completely (2/3)
- **Code Readability**: Consistent parentheses syntax for all function calls

#### Architecture Robustness
- **Instruction Coverage**: 6 base classes updated with consistent naming
- **Fusion Integration**: Naming works seamlessly with instruction fusion
- **Test Framework**: Automated validation against 66 real game scripts
- **Error Handling**: Graceful fallbacks for unmapped function names

### Future Improvement Roadmap

#### Immediate Opportunities (High Impact, Low Effort)
1. **Fix print_debug string formatting**: Address remaining 5% of room8 test case
2. **Add variable assignment fusion**: `var_x = add(a, b)` expressions  
3. **Implement control flow fusion**: `if (condition)` constructs

#### Medium-Term Goals (Medium Impact, Medium Effort)
1. **Expression tree building**: Multi-level nested expressions
2. **Variable name resolution**: `localvar5` instead of `var_5`
3. **Resource ID resolution**: Symbolic names for scripts/objects

#### Long-Term Vision (High Impact, High Effort)  
1. **Full descumm parity**: 100% test case compatibility
2. **Control flow reconstruction**: Loops, switches, complex conditionals
3. **Semantic analysis**: Function call graph, data flow analysis

### Critical Implementation Rules

#### Always Follow These Patterns
1. **Global Naming Dictionary**: Single source of truth for all function names
2. **Comprehensive Base Class Coverage**: Apply improvements to ALL instruction types
3. **Real Data Validation**: Test against actual game scripts, not synthetic data
4. **Incremental Test Updates**: Fix expectations as improvements are made
5. **Quantifiable Progress**: Measure success through test case pass rates

#### Never Do These Things
1. **Partial Implementation**: Don't update some base classes and skip others
2. **Synthetic Testing**: Don't rely solely on hand-crafted test cases
3. **Batch Test Updates**: Don't update all expectations simultaneously
4. **Ignore Edge Cases**: Don't skip complex operations like print_debug
5. **Skip Validation**: Don't assume improvements work without testing

This methodology has proven effective for achieving measurable progress toward descumm-level output quality through systematic, data-driven improvement.

## Enabling Fusion for Intrinsic Instructions

When implementing instruction fusion for intrinsic operations that accept parameters, there's a critical configuration step that's easy to miss.

### The Problem

You may find that an intrinsic instruction like `is_script_running` doesn't fuse with push operations even though it should. The disassembly shows fusion working:

```
# Without fusion:
[0000] push_word(137)
[0003] isScriptRunning(...)

# With fusion (disassembly):
[0000] isScriptRunning(137)
```

But the LLIL still uses stack pops instead of direct parameters:

```python
# Expected LLIL with fusion:
mintrinsic('is_script_running', outputs=[TEMP0], params=[CONST.4(137)])

# Actual LLIL (fusion not working):
mintrinsic('is_script_running', outputs=[TEMP0], params=[POP.4])
```

### The Root Cause

The issue is in `src/pyscumm6/instr/factories.py`. The `create_intrinsic_instruction` function has a hardcoded list of fusible instructions:

```python
def create_intrinsic_instruction(name: str, config: IntrinsicConfig) -> Type[Instruction]:
    # List of instructions that should support fusion
    FUSIBLE_INSTRUCTIONS = {
        "draw_object",
        "start_script",
        "walk_actor_to",
        # ... other instructions
    }
    
    # Choose base class based on whether instruction should support fusion
    if name in FUSIBLE_INSTRUCTIONS:
        base_class = SmartFusibleIntrinsic  # Supports fusion
    else:
        base_class = SmartIntrinsicOp       # No fusion support
```

Instructions not in this set are created with `SmartIntrinsicOp` which doesn't support fusion. Instructions in the set use `SmartFusibleIntrinsic` which has fusion capabilities.

### The Solution

Add your intrinsic to the `FUSIBLE_INSTRUCTIONS` set:

```python
FUSIBLE_INSTRUCTIONS = {
    # ... existing instructions ...
    "is_script_running",  # Add this line
}
```

### How It Works

1. **SmartIntrinsicOp**: Basic intrinsic with no fusion support
   - Always pops parameters from stack
   - Simpler implementation

2. **SmartFusibleIntrinsic**: Enhanced intrinsic with fusion support
   - Inherits from SmartIntrinsicOp and FusibleMultiOperandMixin
   - Implements `fuse()` method to combine with push instructions
   - Overrides `lift()` to use fused operands directly
   - Reduces stack operations in generated LLIL

### Testing the Fix

After adding an intrinsic to `FUSIBLE_INSTRUCTIONS`, verify fusion works:

```python
# Test bytecode
bytecode = bytes([
    0x01, 0x89, 0x00,  # push_word(137)
    0x8B,               # is_script_running
])

# Check disassembly shows fusion
instruction = decode_with_fusion(bytecode, 0x0)
assert instruction.__class__.__name__ == "IsScriptRunning"
assert len(instruction.fused_operands) == 1
assert instruction.stack_pop_count == 0  # No stack pops needed

# Verify LLIL uses direct parameter
# Should see: params=[MockLLIL(op='CONST.4', ops=[137])]
# Not: params=[MockLLIL(op='POP.4', ops=[])]
```

### Common Fusible Intrinsics

Intrinsics that typically benefit from fusion:
- **Script operations**: `start_script`, `stop_script`, `is_script_running`
- **Object operations**: `draw_object`, `set_state`, `get_object_x`
- **Actor operations**: `walk_actor_to`, `put_actor_at_xy`, `animate_actor`
- **Room operations**: `load_room`, `set_camera_at`
- **Any intrinsic taking parameters**: If it pops values, it can likely fuse

### Performance Impact

Fusion improves both readability and performance:
- **Fewer IL operations**: Direct parameters instead of push/pop sequences
- **Better decompilation**: Binary Ninja can recognize patterns more easily
- **Cleaner output**: `isScriptRunning(137)` is clearer than separate operations

This simple configuration change enables significant improvements in IL quality for intrinsic operations.

## Variable Argument Instructions

Some SCUMM6 instructions like `startScriptQuick` have a variable number of arguments. These require special fusion handling.

### The Challenge

`startScriptQuick` has this stack structure:
```
push_word(script_id)    # Script to start
push_word(arg1)         # First argument
push_word(arg2)         # Second argument  
push_word(arg3)         # Third argument
push_word(arg_count)    # Number of arguments (3 in this case)
startScriptQuick        # Consumes all the above
```

### Custom Fusion Implementation

For variable argument instructions, create a custom class instead of relying on auto-generated classes:

```python
class StartScriptQuick(SmartSemanticIntrinsicOp):
    """StartScriptQuick with proper variable argument handling."""
    
    def fuse(self, previous: Instruction) -> Optional['StartScriptQuick']:
        """
        Custom fusion that handles:
        1. Script ID
        2. Arg count 
        3. Variable number of arguments based on arg count
        """
        # First fusion: arg_count
        if not self.fused_operands:
            if self._is_fusible_push(previous):
                fused = copy.deepcopy(self)
                fused.fused_operands = [previous]
                # Extract arg_count value
                if previous.__class__.__name__ in ['PushByte', 'PushWord']:
                    fused._arg_count = previous.op_details.body.data
                return fused
                
        # Subsequent fusions: collect arguments, then script_id
        # ... (see script_ops.py for full implementation)
```

### Key Implementation Points

1. **Track metadata**: Store `_arg_count` to know how many arguments to collect
2. **Correct ordering**: Stack is LIFO - the order is: script_id, arg1, arg2, ..., argN, arg_count
3. **Render properly**: Show as `startScriptQuick(script_id, [arg1, arg2, ...])`
4. **LLIL generation**: Don't include arg_count in LLIL params - it's implicit

### Testing Variable Argument Fusion

```python
ScriptComparisonTestCase(
    test_id="start_script_quick_multi_args",
    bytecode=bytes([
        0x01, 0x5D, 0x00,  # push_word(93) - script_id
        0x01, 0x0B, 0x00,  # push_word(11) - arg1
        0x01, 0x16, 0x00,  # push_word(22) - arg2  
        0x01, 0x21, 0x00,  # push_word(33) - arg3
        0x01, 0x03, 0x00,  # push_word(3)  - arg_count
        0x5F,              # startScriptQuick
    ]),
    expected_disasm_fusion_output="[0000] startScriptQuick(93, [11, 22, 33])"
)
```

## Complex Operation Fusion

Instructions with sub-operations (like `room_ops.room_screen`) also benefit from fusion but require special handling.

### Enabling Fusion for Complex Operations

Complex operations use the `SmartComplexOp` base class. To enable fusion:

1. **Add FusibleMultiOperandMixin** to the base class
2. **Implement fusion support** in the base class methods
3. **Fix parameter ordering** - stack operations reverse the order

### Parameter Order Preservation

**Critical**: When fusing stack operations, parameters appear in reverse order due to LIFO semantics:

```python
# Stack operations (LIFO):
push_word(0)    # First pushed
push_word(200)  # Second pushed  
room_ops.room_screen  # Pops 200 first, then 0

# Result: roomOps.setScreen(0, 200) - NOT (200, 0)
```

### Testing Complex Operation Fusion

Always verify parameter order matches descumm output:

```python
# Correct (matches descumm):
[0012] roomOps.setScreen(0, 200)

# Wrong (reversed parameters):
[0012] roomOps.setScreen(200, 0)
```

## LLIL Size Suffixes

The SCUMM6 architecture uses custom size suffixes for LLIL operations:

```python
# Configure in test files:
set_size_lookup(
    size_lookup={1: ".b", 2: ".w", 3: ".l", 4: ".4"},  # 4-byte ops use ".4"
    suffix_sz={"b": 1, "w": 2, "l": 3, "4": 4}
)
```

This prevents `.error` suffixes in LLIL output and ensures correct semantic representation.

## Testing Best Practices

### Hard-Coded Bytecode in Tests

For testing specific instruction sequences, use hard-coded bytecode:

```python
ScriptComparisonTestCase(
    test_id="specific_sequence_test",
    bytecode=bytes([...]),  # Explicit bytecode
    # script_name is optional when bytecode is provided
)
```

### Flaky Test Debugging

If tests fail intermittently:
1. **Check for dynamic addresses** in LLIL (control flow targets)
2. **Isolate the root cause** - don't just disable the test
3. **Use session fixtures** for expensive operations (building descumm)

### MyPy with Mock Binary Ninja

Always run mypy in both environments:
```bash
# Real Binary Ninja (if available)
mypy --explicit-package-bases src/

# Mock Binary Ninja (for CI/testing)
FORCE_BINJA_MOCK=1 mypy --explicit-package-bases src/
```
