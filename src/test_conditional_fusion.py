"""Test conditional expression fusion functionality."""

import os
os.environ["FORCE_BINJA_MOCK"] = "1"

from binja_helpers import binja_api  # noqa: F401

from src.pyscumm6.disasm import decode, decode_with_fusion


def test_comparison_fusion_with_constants() -> None:
    """Test fusion of push constants with comparison operations."""
    bytecode = bytes([
        0x00, 0x0A,  # push_byte(10)
        0x00, 0x05,  # push_byte(5)  
        0x10         # gt (opcode for greater than)
    ])
    
    # Test normal decoding
    normal = decode(bytecode, 0x1000)
    assert normal.__class__.__name__ == "PushByte"
    
    # Test fusion decoding
    fused = decode_with_fusion(bytecode, 0x1000)
    assert fused is not None
    assert fused.__class__.__name__ == "Gt"
    assert len(fused.fused_operands) == 2
    assert fused.stack_pop_count == 0
    
    # Test rendering
    tokens = fused.render()
    text = ''.join(str(t.text if hasattr(t, 'text') else t) for t in tokens)
    assert text == "10 > 5"


def test_comparison_fusion_with_variables() -> None:
    """Test fusion of variable pushes with comparison operations."""
    bytecode = bytes([
        0x02, 0x0A,  # push_byte_var(var_10)
        0x00, 0x14,  # push_byte(20)
        0x11         # lt (opcode for less than)
    ])
    
    fused = decode_with_fusion(bytecode, 0x1000)
    assert fused is not None
    assert fused.__class__.__name__ == "Lt"
    assert len(fused.fused_operands) == 2
    
    # Test rendering
    tokens = fused.render()
    text = ''.join(str(t.text if hasattr(t, 'text') else t) for t in tokens)
    assert text == "var_10 < 20"


def test_conditional_jump_fusion_with_if_not() -> None:
    """Test fusion of comparison with if_not conditional jump."""
    bytecode = bytes([
        0x02, 0x05,  # push_byte_var(var_5)
        0x00, 0x0A,  # push_byte(10)
        0x10,        # gt (greater than)
        0x5D, 0x14, 0x00  # if_not goto +20
    ])
    
    fused = decode_with_fusion(bytecode, 0x1000)
    assert fused is not None
    assert fused.__class__.__name__ == "SmartIfNot"
    assert len(fused.fused_operands) == 1
    assert fused.stack_pop_count == 0
    
    # Test rendering - should show inverted condition for readability
    tokens = fused.render()
    text = ''.join(str(t.text if hasattr(t, 'text') else t) for t in tokens)
    assert "if" in text and "var_5" in text and "<=" in text and "+20" in text


def test_conditional_jump_fusion_with_iff() -> None:
    """Test fusion of comparison with iff conditional jump."""
    bytecode = bytes([
        0x00, 0x32,  # push_byte(50)
        0x02, 0x0F,  # push_byte_var(var_15)
        0x0E,        # eq (equal)
        0x5C, 0x0C, 0x00  # iff goto +12
    ])
    
    fused = decode_with_fusion(bytecode, 0x1000)
    assert fused is not None
    assert fused.__class__.__name__ == "SmartIff"
    assert len(fused.fused_operands) == 1
    assert fused.stack_pop_count == 0
    
    # Test rendering
    tokens = fused.render()
    text = ''.join(str(t.text if hasattr(t, 'text') else t) for t in tokens)
    assert "if" in text and "50" in text and "var_15" in text and "==" in text


def test_partial_fusion_comparison() -> None:
    """Test comparison with only one operand fused."""
    bytecode = bytes([
        0x00, 0x0F,  # push_byte(15)
        0x10         # gt (but only one operand)
    ])
    
    fused = decode_with_fusion(bytecode, 0x1000)
    assert fused is not None
    assert fused.__class__.__name__ == "Gt"
    assert len(fused.fused_operands) == 1
    
    # Test rendering - should use function-call style
    tokens = fused.render()
    text = ''.join(str(t.text if hasattr(t, 'text') else t) for t in tokens)
    assert text == "gt(15)"


def test_complex_conditional_with_neq() -> None:
    """Test not-equal comparison with conditional jump."""
    bytecode = bytes([
        0x00, 0x00,  # push_byte(0)
        0x02, 0x03,  # push_byte_var(var_3)
        0x0F,        # neq (not equal)
        0x5D, 0x08, 0x00  # if_not goto +8
    ])
    
    fused = decode_with_fusion(bytecode, 0x1000)
    assert fused is not None
    assert fused.__class__.__name__ == "SmartIfNot"
    
    # Test rendering - if_not with neq should become ==
    tokens = fused.render()
    text = ''.join(str(t.text if hasattr(t, 'text') else t) for t in tokens)
    assert "if" in text and "0" in text and "var_3" in text and "==" in text


def test_le_ge_comparisons() -> None:
    """Test less-equal and greater-equal comparisons."""
    # Test le (less than or equal)
    bytecode_le = bytes([
        0x02, 0x08,  # push_byte_var(var_8)
        0x00, 0x64,  # push_byte(100)
        0x12         # le
    ])
    
    fused_le = decode_with_fusion(bytecode_le, 0x1000)
    assert fused_le is not None
    assert fused_le.__class__.__name__ == "Le"
    tokens_le = fused_le.render()
    text_le = ''.join(str(t.text if hasattr(t, 'text') else t) for t in tokens_le)
    assert text_le == "var_8 <= 100"
    
    # Test ge (greater than or equal)
    bytecode_ge = bytes([
        0x00, 0x32,  # push_byte(50)
        0x02, 0x07,  # push_byte_var(var_7)
        0x13         # ge
    ])
    
    fused_ge = decode_with_fusion(bytecode_ge, 0x1000)
    assert fused_ge is not None
    assert fused_ge.__class__.__name__ == "Ge"
    tokens_ge = fused_ge.render()
    text_ge = ''.join(str(t.text if hasattr(t, 'text') else t) for t in tokens_ge)
    assert text_ge == "50 >= var_7"


def test_no_fusion_when_not_comparison() -> None:
    """Test that conditional jumps don't fuse with non-comparison operations."""
    bytecode = bytes([
        0x00, 0x05,  # push_byte(5)
        0x00, 0x03,  # push_byte(3)
        0x14,        # add (not a comparison)
        0x5D, 0x10, 0x00  # if_not goto +16
    ])
    
    # The conditional should not fuse with add operation
    fused = decode_with_fusion(bytecode, 0x1000)
    assert fused is not None
    assert fused.__class__.__name__ == "SmartIfNot"
    assert len(fused.fused_operands) == 0  # No fusion
    assert fused.stack_pop_count == 1  # Normal stack operation


if __name__ == "__main__":
    test_comparison_fusion_with_constants()
    test_comparison_fusion_with_variables()
    test_conditional_jump_fusion_with_if_not()
    test_conditional_jump_fusion_with_iff()
    test_partial_fusion_comparison()
    test_complex_conditional_with_neq()
    test_le_ge_comparisons()
    test_no_fusion_when_not_comparison()
    print("All conditional fusion tests passed!")