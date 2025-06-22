# Declarative Testing Patterns in SCUMM6

This document describes the declarative testing pattern used in the SCUMM6 project and provides guidance for converting imperative tests to the declarative style.

## Overview

The declarative testing pattern separates test **data** (the "what") from test **execution logic** (the "how"), making tests more maintainable, extensible, and readable.

### Benefits

- **Reduced Code Duplication**: ~70% reduction in test code
- **Easy Extensibility**: Adding new tests requires only adding data
- **Improved Readability**: Test intent is clearer when separated from execution
- **Consistency**: Uniform testing approach across the project
- **Automated Generation**: Test cases can be generated from analysis scripts

## Pattern Structure

### 1. Test Case Dataclass

Define a `@dataclass` that captures all test parameters:

```python
@dataclass
class FusionTestCase:
    """Declarative test case for instruction fusion."""
    test_id: str
    bytecode: bytes
    expected_fused_class: str
    expected_fused_operands: int
    expected_stack_pops: int
    expected_render_text: str
    addr: int = 0x1000
    description: Optional[str] = None
```

### 2. Test Runner Function

Create a centralized function that executes test logic:

```python
def run_fusion_test(case: FusionTestCase) -> None:
    """Executes a single fusion test case and asserts its correctness."""
    instruction = decode_with_fusion(case.bytecode, case.addr)
    
    assert instruction is not None, f"Fusion decoding failed for {case.test_id}"
    assert instruction.__class__.__name__ == case.expected_fused_class
    assert len(instruction.fused_operands) == case.expected_fused_operands
    assert instruction.stack_pop_count == case.expected_stack_pops
    
    tokens = instruction.render()
    token_text = ''.join(str(token.text if hasattr(token, 'text') else token) for token in tokens)
    assert case.expected_render_text in token_text
```

### 3. Test Data

Define test cases as data structures:

```python
fusion_test_cases = [
    FusionTestCase(
        test_id="add_double_operand",
        bytecode=bytes([0x00, 0x0A, 0x00, 0x05, 0x14]),
        expected_fused_class="Add",
        expected_fused_operands=2,
        expected_stack_pops=0,
        expected_render_text="add(10, 5)",
        description="Complete fusion: both operands fused"
    ),
    # ... more test cases
]
```

### 4. Parametrized Test Function

Use pytest parametrization to execute all test cases:

```python
@pytest.mark.parametrize("case", fusion_test_cases, ids=lambda c: c.test_id)
def test_instruction_fusion(case: FusionTestCase) -> None:
    """Data-driven test for all instruction fusion scenarios."""
    run_fusion_test(case)
```

## Migration Guide

### Converting Imperative Tests

**Before (Imperative Style):**
```python
class TestInstructionFusion:
    def test_double_operand_fusion(self) -> None:
        """Test fusion of push_byte + push_byte + add (complete fusion)."""
        bytecode = bytes([0x00, 0x0A, 0x00, 0x05, 0x14])
        
        instruction = decode_with_fusion(bytecode, 0x1000)
        assert instruction is not None
        assert instruction.__class__.__name__ == "Add"
        assert len(instruction.fused_operands) == 2
        assert instruction.stack_pop_count == 0
        
        tokens = instruction.render()
        token_text = ''.join(str(t.text if hasattr(t, 'text') else t) for t in tokens)
        assert "add(10, 5)" in token_text
```

**After (Declarative Style):**
```python
fusion_test_cases = [
    FusionTestCase(
        test_id="add_double_operand",
        bytecode=bytes([0x00, 0x0A, 0x00, 0x05, 0x14]),
        expected_fused_class="Add",
        expected_fused_operands=2,
        expected_stack_pops=0,
        expected_render_text="add(10, 5)"
    ),
]

@pytest.mark.parametrize("case", fusion_test_cases, ids=lambda c: c.test_id)
def test_instruction_fusion(case: FusionTestCase) -> None:
    run_fusion_test(case)
```

### Step-by-Step Migration Process

1. **Analyze Existing Tests**: Identify common patterns and assertions
2. **Design Dataclass**: Create a dataclass that captures all test parameters
3. **Extract Test Data**: Convert each test function into a dataclass instance
4. **Create Test Runner**: Write a centralized function for test execution
5. **Parametrize**: Replace individual test functions with parametrized tests
6. **Validate**: Ensure new tests have identical behavior to originals

## Pattern Variations

### Loop Recognition Tests

```python
@dataclass
class LoopRecognitionTestCase:
    test_id: str
    bytecode: bytes
    expected_loop_type: str
    expected_body_size: int
    expected_condition_type: str
    expected_render_text: str
    addr: int = 0x1000
```

### Instruction Info Tests

```python
@dataclass
class InstructionInfoTestCase:
    test_id: str
    bytecode: bytes
    expected_length: int
    expected_branches: List[Tuple[BranchType, int]]
    addr: int = 0x1000
```

### Multi-Level Tests

```python
@dataclass
class MultiLevelTestCase:
    test_id: str
    bytecode: bytes
    expected_expression_depth: int
    expected_simplified_form: str
    expected_llil_operations: List[str]
    addr: int = 0x1000
```

## Advanced Patterns

### Inheritance for Specialized Tests

```python
@dataclass
class FusionTestCase:
    """Base class for all fusion tests."""
    test_id: str
    bytecode: bytes
    expected_fused_class: str
    # ... common fields

@dataclass
class VariableWriteFusionTestCase(FusionTestCase):
    """Specialized for variable write fusion."""
    expected_variable_name: Optional[str] = None
    expected_assignment_value: Optional[Union[int, str]] = None
```

### Category-Based Organization

```python
# Organize test cases by category
instruction_fusion_cases = [...]
variable_write_cases = [...]
array_write_cases = [...]

# Separate parametrized tests for each category
@pytest.mark.parametrize("case", instruction_fusion_cases, ids=lambda c: c.test_id)
def test_instruction_fusion(case: FusionTestCase) -> None:
    run_fusion_test(case)

@pytest.mark.parametrize("case", variable_write_cases, ids=lambda c: c.test_id)
def test_variable_write_fusion(case: VariableWriteFusionTestCase) -> None:
    run_fusion_test(case)
```

## Best Practices

### Test Case Design

1. **Descriptive IDs**: Use clear, descriptive test_id values
2. **Comprehensive Coverage**: Include both positive and negative test cases
3. **Edge Cases**: Test boundary conditions and error scenarios
4. **Documentation**: Add description fields for complex test cases

### Test Runner Design

1. **Clear Error Messages**: Include test_id in assertion messages
2. **Modular Assertions**: Break complex assertions into smaller, focused checks
3. **Category Handling**: Use polymorphism for different test case types
4. **Debugging Support**: Include helpful debug output for failures

### Organization

1. **Logical Grouping**: Group related test cases together
2. **Consistent Naming**: Use consistent naming conventions across files
3. **Separate Concerns**: Keep different test types in separate modules when appropriate
4. **Shared Utilities**: Extract common test utilities to shared modules

## Examples in the Codebase

- **`test_descumm_comparison.py`**: Original declarative pattern implementation
- **`test_fusion_declarative.py`**: Basic fusion test refactoring
- **`test_fusion_comprehensive.py`**: Advanced multi-category fusion tests
- **`test_instruction_info_consolidated.py`**: Semi-declarative pattern (to be fully migrated)

## Migration Checklist

- [ ] Identify repetitive test patterns
- [ ] Design appropriate dataclass structure
- [ ] Extract test data from imperative functions
- [ ] Create centralized test runner
- [ ] Implement parametrized test function
- [ ] Validate test equivalence
- [ ] Update documentation
- [ ] Remove old imperative tests

## Future Enhancements

- **Automated Test Generation**: Generate test cases from analysis scripts
- **Test Case Validation**: Validate test case completeness and consistency
- **Performance Testing**: Extend pattern to performance and benchmark tests
- **Integration Testing**: Apply pattern to integration and end-to-end tests

