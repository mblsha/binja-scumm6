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
4. **Dual Execution**: Runs both `descumm` and `Scumm6New` on identical bytecode
5. **Golden Master Testing**: Compares outputs against expected strings

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

**Scumm6New Output (Assembly-like):**
```
[0000] push_word_var(var_0)
[0003] get_object_x
[0004] push_word_var(var_1)
[0007] sub
[0008] write_word_var(var_5)
[000B] push_word_var(var_0)
[000E] get_object_y
```

### Adding New Test Cases

To add a new script comparison test:

```python
script_test_cases.append(
    ScriptComparisonTestCase(
        test_id="room11_enter_initialization",
        script_name="room11_enter", 
        expected_descumm_output=dedent("""
            [0000] (43) localvar1 = 100
            [0006] (66) stopObjectCodeB()
            END
        """).strip(),
        expected_new_disasm_output=dedent("""
            [0000] push_word(100)
            [0003] write_word_var(var_1)
            [0006] stop_object_code2
        """).strip()
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
- **Test Script**: `room8_scrp18` (463 bytes, ellipse collision detection algorithm)
- **Address**: `0x8D79D` in the original container file
- **Scripts Available**: 66 total scripts from rooms 1-12 plus global scripts

This real-world data ensures the comparison tests reflect actual game engine semantics rather than synthetic test cases.
