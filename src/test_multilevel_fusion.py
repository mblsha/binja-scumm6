"""Test multi-level expression building functionality."""

import os
os.environ["FORCE_BINJA_MOCK"] = "1"

from binja_test_mocks import binja_api  # noqa: F401

from src.pyscumm6.disasm import decode, decode_with_fusion


def test_simple_binary_expression_fusion() -> None:
    """Test fusion of push + push + binary operation."""
    bytecode = bytes([
        0x00, 0x0A,  # push_byte(10)
        0x00, 0x05,  # push_byte(5)
        0x14         # add
    ])
    
    # Test normal decoding
    normal = decode(bytecode, 0x1000)
    assert normal.__class__.__name__ == "PushByte"
    
    # Test fusion decoding
    fused = decode_with_fusion(bytecode, 0x1000)
    assert fused is not None
    assert fused.__class__.__name__ == "Add"
    assert len(fused.fused_operands) == 2
    assert fused.stack_pop_count == 0
    assert fused.produces_result()
    
    # Test rendering
    tokens = fused.render()
    text = ''.join(str(t.text if hasattr(t, 'text') else t) for t in tokens)
    assert text == "(10 + 5)"


def test_multi_level_arithmetic_expression() -> None:
    """Test complex multi-level expression: (a + b) * c"""
    bytecode = bytes([
        0x02, 0x05,  # push_byte_var(var_5)  -> a
        0x02, 0x07,  # push_byte_var(var_7)  -> b  
        0x14,        # add                   -> (a + b)
        0x02, 0x03,  # push_byte_var(var_3)  -> c
        0x16         # mul                   -> (a + b) * c
    ])
    
    fused = decode_with_fusion(bytecode, 0x1000)
    assert fused is not None
    assert fused.__class__.__name__ == "Mul"
    assert len(fused.fused_operands) == 2
    assert fused.stack_pop_count == 0
    
    # The second operand should be var_3, the first should be a fused Add
    first_operand = fused.fused_operands[0]  # The fused Add instruction
    second_operand = fused.fused_operands[1]  # push_byte_var(var_3)
    
    assert first_operand.__class__.__name__ == "Add"
    assert first_operand.produces_result()
    assert len(first_operand.fused_operands) == 2
    
    assert second_operand.__class__.__name__ == "PushByteVar"
    
    # Test rendering - should show nested expression
    tokens = fused.render()
    text = ''.join(str(t.text if hasattr(t, 'text') else t) for t in tokens)
    # Expected with infix notation: (((var_5 + var_7)) * var_3)
    assert "*" in text and "+" in text and "VAR_OVERRIDE" in text and "VAR_ME" in text and "VAR_HAVE_MSG" in text
    assert text == "(VAR_OVERRIDE + VAR_ME * VAR_HAVE_MSG)"


def test_three_level_expression() -> None:
    """Test three-level expression: ((a + b) * c) - d"""
    bytecode = bytes([
        0x00, 0x0A,  # push_byte(10)         -> a
        0x00, 0x05,  # push_byte(5)          -> b
        0x14,        # add                   -> (a + b)
        0x00, 0x03,  # push_byte(3)          -> c  
        0x16,        # mul                   -> (a + b) * c
        0x00, 0x02,  # push_byte(2)          -> d
        0x15         # sub                   -> ((a + b) * c) - d
    ])
    
    fused = decode_with_fusion(bytecode, 0x1000)
    assert fused is not None
    assert fused.__class__.__name__ == "Sub"
    assert len(fused.fused_operands) == 2
    
    # First operand should be the fused multiplication
    mul_operand = fused.fused_operands[0]
    assert mul_operand.__class__.__name__ == "Mul"
    assert mul_operand.produces_result()
    
    # The mul operand should have a fused add as its first operand
    add_operand = mul_operand.fused_operands[0]
    assert add_operand.__class__.__name__ == "Add"
    assert add_operand.produces_result()
    
    # Test rendering - should show deeply nested expression
    tokens = fused.render()
    text = ''.join(str(t.text if hasattr(t, 'text') else t) for t in tokens)
    # Expected with infix notation: (((((10 + 5)) * 3)) - 2)
    assert "-" in text and "*" in text and "+" in text
    assert text == "((10 + 5 * 3) - 2)"


def test_comparison_in_expression() -> None:
    """Test comparison operation as part of larger expression."""
    bytecode = bytes([
        0x02, 0x05,  # push_byte_var(var_5)
        0x00, 0x0A,  # push_byte(10)
        0x10,        # gt -> (var_5 > 10)
        0x02, 0x03,  # push_byte_var(var_3)  
        0x18         # land -> (var_5 > 10) && var_3
    ])
    
    fused = decode_with_fusion(bytecode, 0x1000)
    assert fused is not None
    assert fused.__class__.__name__ == "Land"
    assert len(fused.fused_operands) == 2
    
    # First operand should be the fused comparison
    gt_operand = fused.fused_operands[0]
    assert gt_operand.__class__.__name__ == "Gt"
    assert gt_operand.produces_result()
    
    # Test rendering
    tokens = fused.render()
    text = ''.join(str(t.text if hasattr(t, 'text') else t) for t in tokens)
    # Should include both the comparison and the logical operation (with infix notation)
    assert "&&" in text and ">" in text and "VAR_OVERRIDE" in text and "10" in text and "VAR_HAVE_MSG" in text
    assert text == "(VAR_OVERRIDE > 10 && VAR_HAVE_MSG)"


def test_mixed_variable_and_constant_fusion() -> None:
    """Test mixing variables and constants in multi-level expressions."""
    bytecode = bytes([
        0x02, 0x08,  # push_byte_var(var_8)
        0x00, 0x14,  # push_byte(20)
        0x14,        # add -> (var_8 + 20)
        0x00, 0x02,  # push_byte(2)
        0x17         # div -> (var_8 + 20) / 2
    ])
    
    fused = decode_with_fusion(bytecode, 0x1000)
    assert fused is not None
    assert fused.__class__.__name__ == "Div"
    assert len(fused.fused_operands) == 2
    
    # First operand should be fused addition
    add_operand = fused.fused_operands[0]
    assert add_operand.__class__.__name__ == "Add"
    assert len(add_operand.fused_operands) == 2
    
    # Test rendering
    tokens = fused.render()
    text = ''.join(str(t.text if hasattr(t, 'text') else t) for t in tokens)
    # Expected with infix notation: (VAR_NUM_ACTOR + 20 / 2)
    assert "/" in text and "+" in text and "VAR_NUM_ACTOR" in text and "20" in text and "2" in text
    assert text == "(VAR_NUM_ACTOR + 20 / 2)"


def test_partial_fusion_with_multilevel() -> None:
    """Test that partial fusion still works with multi-level expressions."""
    bytecode = bytes([
        0x00, 0x07,  # push_byte(7)
        0x14         # add (only one operand provided)
    ])
    
    fused = decode_with_fusion(bytecode, 0x1000)
    assert fused is not None
    assert fused.__class__.__name__ == "Add"
    assert len(fused.fused_operands) == 1
    assert fused.stack_pop_count == 1  # Still needs one from stack
    
    # Test rendering - should use function-call style
    tokens = fused.render()
    text = ''.join(str(t.text if hasattr(t, 'text') else t) for t in tokens)
    assert text == "add(7, ...)"

