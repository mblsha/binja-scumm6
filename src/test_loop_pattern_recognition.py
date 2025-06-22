"""Test loop pattern recognition functionality."""

import os
os.environ["FORCE_BINJA_MOCK"] = "1"

from binja_helpers import binja_api  # noqa: F401

from src.pyscumm6.disasm import decode, decode_with_fusion
from src.pyscumm6.instr.smart_bases import SmartLoopConditionalJump


def test_simple_backward_jump_detection() -> None:
    """Test detection of simple backward jump (basic loop pattern)."""
    bytecode = bytes([
        0x02, 0x0C,  # push_byte_var(var_12)
        0x5D, 0x9E, 0xFF  # unless goto -98 (backward jump - loop!)
    ])
    
    # Test normal decoding
    normal = decode(bytecode, 0x1000)
    assert normal.__class__.__name__ == "PushByteVar"
    
    # Test fusion with loop detection
    fused = decode_with_fusion(bytecode, 0x1000)
    assert fused is not None
    assert isinstance(fused, SmartLoopConditionalJump)
    assert fused.__class__.__name__ == "SmartLoopIfNot"
    
    # Verify loop detection worked
    assert fused.detected_loop is not None
    assert fused.detected_loop.loop_type == "while"
    
    # Test rendering shows loop pattern
    tokens = fused.render()
    text = ''.join(str(t.text if hasattr(t, 'text') else t) for t in tokens)
    assert "while" in text
    assert "var_12" in text


def test_for_loop_pattern_detection() -> None:
    """Test detection of for-loop pattern (variable < constant)."""
    bytecode = bytes([
        0x02, 0x05,  # push_byte_var(var_5) - iterator
        0x00, 0x0A,  # push_byte(10)         - limit
        0x11,        # lt                    - comparison
        0x5D, 0xEC, 0xFF  # unless goto -20 (backward jump)
    ])
    
    fused = decode_with_fusion(bytecode, 0x1000)
    assert fused is not None
    assert isinstance(fused, SmartLoopConditionalJump)
    assert fused.__class__.__name__ == "SmartLoopIfNot"
    
    # Should detect as for-loop due to variable < constant pattern
    assert fused.detected_loop is not None
    assert fused.detected_loop.loop_type == "for"
    assert fused.detected_loop.iterator_var == 5
    
    # Test rendering shows for-loop style
    tokens = fused.render()
    text = ''.join(str(t.text if hasattr(t, 'text') else t) for t in tokens)
    assert "for" in text
    assert "var_5" in text


def test_while_loop_pattern_detection() -> None:
    """Test detection of while-loop pattern (general condition)."""
    bytecode = bytes([
        0x02, 0x08,  # push_byte_var(var_8)
        0x02, 0x09,  # push_byte_var(var_9)
        0x0E,        # eq (equal comparison)
        0x5D, 0xF5, 0xFF  # unless goto -11 (backward jump)
    ])
    
    fused = decode_with_fusion(bytecode, 0x1000)
    assert fused is not None
    assert isinstance(fused, SmartLoopConditionalJump)
    assert fused.__class__.__name__ == "SmartLoopIfNot"
    
    # Should detect as while-loop due to variable == variable pattern
    assert fused.detected_loop is not None
    assert fused.detected_loop.loop_type == "while"
    
    # Test rendering shows while-loop style
    tokens = fused.render()
    text = ''.join(str(t.text if hasattr(t, 'text') else t) for t in tokens)
    assert "while" in text
    assert "var_8" in text
    assert "var_9" in text


def test_forward_jump_no_loop_detection() -> None:
    """Test that forward jumps are not detected as loops."""
    bytecode = bytes([
        0x02, 0x05,  # push_byte_var(var_5)
        0x00, 0x0A,  # push_byte(10)
        0x11,        # lt
        0x5D, 0x14, 0x00  # unless goto +20 (forward jump - not a loop)
    ])
    
    fused = decode_with_fusion(bytecode, 0x1000)
    assert fused is not None
    assert fused.__class__.__name__ == "SmartIfNot"  # Not SmartLoopIfNot
    
    # Should not have loop detection
    assert not hasattr(fused, 'detected_loop') or fused.detected_loop is None


def test_iff_loop_detection() -> None:
    """Test loop detection with 'iff' (if) instruction."""
    bytecode = bytes([
        0x00, 0x00,  # push_byte(0)
        0x02, 0x03,  # push_byte_var(var_3)
        0x0F,        # neq (not equal)
        0x5C, 0xF8, 0xFF  # iff goto -8 (backward jump with iff)
    ])
    
    fused = decode_with_fusion(bytecode, 0x1000)
    assert fused is not None
    assert isinstance(fused, SmartLoopConditionalJump)
    assert fused.__class__.__name__ == "SmartLoopIff"
    
    # Should detect loop
    assert fused.detected_loop is not None
    assert fused.detected_loop.loop_type == "while"
    
    tokens = fused.render()
    text = ''.join(str(t.text if hasattr(t, 'text') else t) for t in tokens)
    assert "while" in text


def test_loop_body_size_calculation() -> None:
    """Test that loop body size is calculated correctly."""
    bytecode = bytes([
        0x02, 0x0A,  # push_byte_var(var_10)
        0x5D, 0x9A, 0xFF  # unless goto -102
    ])
    
    fused = decode_with_fusion(bytecode, 0x1005)  # Address 0x1005
    assert fused is not None
    assert isinstance(fused, SmartLoopConditionalJump)
    assert fused.detected_loop is not None
    
    # Body size should be 97 bytes (jump offset is -102, but instruction is 5 bytes)
    body_size = fused.detected_loop.body_end - fused.detected_loop.body_start
    assert body_size == 97
    
    # Should be mentioned in rendering
    tokens = fused.render()
    text = ''.join(str(t.text if hasattr(t, 'text') else t) for t in tokens)
    assert "97" in text


def test_partial_fusion_with_loop() -> None:
    """Test loop detection with partial fusion (unfused condition)."""
    bytecode = bytes([
        0x5D, 0xF0, 0xFF  # unless goto -16 (only conditional jump, no fused condition)
    ])
    
    fused = decode_with_fusion(bytecode, 0x1000)
    assert fused is not None
    assert isinstance(fused, SmartLoopConditionalJump)
    assert fused.__class__.__name__ == "SmartLoopIfNot"
    
    # Should still detect as loop even without fused condition
    assert fused.detected_loop is not None
    assert fused.detected_loop.loop_type == "while"
    assert fused.detected_loop.condition is None  # No fused condition
    
    tokens = fused.render()
    text = ''.join(str(t.text if hasattr(t, 'text') else t) for t in tokens)
    assert "while" in text
    assert "condition" in text  # Should show generic condition


def test_complex_comparison_loop() -> None:
    """Test loop with greater-than-or-equal comparison."""
    bytecode = bytes([
        0x00, 0x0A,  # push_byte(10)   - positive scaling target
        0x02, 0x00,  # push_byte_var(var_0) - current scale
        0x13,        # ge (greater or equal)
        0x5D, 0xB9, 0xFF  # unless goto -71 (from room8_local200 analysis)
    ])
    
    fused = decode_with_fusion(bytecode, 0x1000)
    assert fused is not None
    assert isinstance(fused, SmartLoopConditionalJump)
    assert fused.__class__.__name__ == "SmartLoopIfNot"
    
    # Should detect as for-loop (constant >= variable pattern)
    assert fused.detected_loop is not None
    assert fused.detected_loop.loop_type == "for"
    assert fused.detected_loop.iterator_var == 0
    
    tokens = fused.render()
    text = ''.join(str(t.text if hasattr(t, 'text') else t) for t in tokens)
    assert "for" in text
    assert "var_0" in text
    assert "10" in text


def test_no_fusion_preserves_normal_behavior() -> None:
    """Test that instructions without fusion still work normally."""
    bytecode = bytes([
        0x00, 0x05  # push_byte(5) - single instruction, no fusion possible
    ])
    
    normal = decode(bytecode, 0x1000)
    fused = decode_with_fusion(bytecode, 0x1000)
    
    # Both should be the same since no fusion is possible
    assert normal.__class__.__name__ == fused.__class__.__name__
    assert normal.__class__.__name__ == "PushByte"

