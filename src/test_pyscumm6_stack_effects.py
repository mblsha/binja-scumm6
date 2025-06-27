"""Tests for stack effect analysis of SCUMM6 instructions."""

import pytest
from typing import Dict, Any

from .scumm6_opcodes import Scumm6Opcodes  # type: ignore[attr-defined]
from .pyscumm6.instr.opcode_table import OPCODE_MAP

# Test cases: (OpType, expected_pop_count)
stack_pop_count_test_cases: Dict[Scumm6Opcodes.OpType, int] = {
    # Simple ops
    Scumm6Opcodes.OpType.push_byte: 0,
    Scumm6Opcodes.OpType.push_word: 0,
    Scumm6Opcodes.OpType.dup: 1,
    Scumm6Opcodes.OpType.pop1: 1,

    # Stack ops
    Scumm6Opcodes.OpType.add: 2,
    Scumm6Opcodes.OpType.sub: 2,
    Scumm6Opcodes.OpType.mul: 2,
    Scumm6Opcodes.OpType.div: 2,
    Scumm6Opcodes.OpType.nott: 1,
    Scumm6Opcodes.OpType.eq: 2,
    Scumm6Opcodes.OpType.gt: 2,
    Scumm6Opcodes.OpType.abs: 1,

    # Variable ops
    Scumm6Opcodes.OpType.push_byte_var: 0,
    Scumm6Opcodes.OpType.write_byte_var: 1,
    Scumm6Opcodes.OpType.byte_var_inc: 0,

    # Array ops
    Scumm6Opcodes.OpType.byte_array_read: 1,
    Scumm6Opcodes.OpType.byte_array_indexed_read: 2,
    Scumm6Opcodes.OpType.byte_array_write: 2,
    Scumm6Opcodes.OpType.byte_array_indexed_write: 3,

    # Control flow
    Scumm6Opcodes.OpType.iff: 1,
    Scumm6Opcodes.OpType.if_not: 1,
    Scumm6Opcodes.OpType.jump: 0,

    # Intrinsics
    Scumm6Opcodes.OpType.draw_object: 2,
    Scumm6Opcodes.OpType.stop_music: 0,
    Scumm6Opcodes.OpType.get_state: 1,
    
    # Semantic Intrinsics (variable args)
    Scumm6Opcodes.OpType.start_script: -1,
    Scumm6Opcodes.OpType.start_script_quick: -1,
}

# Parametrize the test function
@pytest.mark.parametrize("op_type, expected_count", stack_pop_count_test_cases.items(), ids=lambda x: x.name if isinstance(x, Scumm6Opcodes.OpType) else str(x))
def test_instruction_stack_pop_count(op_type: Scumm6Opcodes.OpType, expected_count: int) -> None:
    """Tests that instructions report the correct stack pop count."""
    
    InstructionClass = OPCODE_MAP.get(op_type)
    assert InstructionClass is not None, f"No instruction class found for OpType {op_type.name}"

    # We need to instantiate the class with a mock Kaitai object.
    # The structure of the mock object doesn't matter for this test, as long as it exists.
    class MockKaitaiOp:
        def __init__(self) -> None:
            self.id = op_type
            # Some instructions inspect body, so provide a dummy.
            self.body = type('MockBody', (object,), {'pop_count': 0, 'push_count': 0, 'data': 0, 'subop': type('MockSubop', (object,), {'name': 'test'})()})()
    
    mock_kaitai_op = MockKaitaiOp()
    
    # Instantiate the instruction. Length doesn't matter for this test.
    instruction = InstructionClass(kaitai_op=mock_kaitai_op, length=1)
    
    assert instruction.stack_pop_count == expected_count, \
        f"Incorrect stack pop count for {op_type.name}. " \
        f"Expected {expected_count}, got {instruction.stack_pop_count}."

def test_if_class_of_is_stack_pop_count() -> None:
    """Specific test for if_class_of_is which is not in the main map but has a custom class."""
    from .pyscumm6.instr.instructions import IfClassOfIs
    class MockKaitaiOp:
        def __init__(self) -> None:
            self.id = Scumm6Opcodes.OpType.if_class_of_is
            self.body = type('MockBody', (object,), {})()
    
    instruction = IfClassOfIs(kaitai_op=MockKaitaiOp(), length=1)
    assert instruction.stack_pop_count == 3, \
        "if_class_of_is should pop 3 values (object, class, count)."

def test_cutscene_stack_pop_count() -> None:
    """Test cutscene's dynamic pop count."""
    op_type = Scumm6Opcodes.OpType.cutscene
    InstructionClass = OPCODE_MAP.get(op_type)
    assert InstructionClass is not None
    
    class MockKaitaiOp:
        def __init__(self, args_list: Any) -> None:
            self.id = op_type
            self.body = type('MockBody', (object,), {'args': args_list})()

    # Test with 3 args
    instruction_3_args = InstructionClass(kaitai_op=MockKaitaiOp([1, 2, 3]), length=1)
    assert instruction_3_args.stack_pop_count == 3
    
    # Test with 0 args
    instruction_0_args = InstructionClass(kaitai_op=MockKaitaiOp([]), length=1)
    assert instruction_0_args.stack_pop_count == 0
