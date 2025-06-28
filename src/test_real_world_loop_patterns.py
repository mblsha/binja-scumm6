"""Test loop pattern recognition on real-world SCUMM6 bytecode patterns."""

import os
os.environ["FORCE_BINJA_MOCK"] = "1"

from binja_helpers import binja_api  # noqa: F401

from src.pyscumm6.disasm import decode, decode_with_fusion
from src.pyscumm6.instr.smart_bases import SmartLoopConditionalJump


def test_room8_scrp18_loop_pattern() -> None:
    """Test loop detection on the actual room8_scrp18 collision detection pattern."""
    # This is the actual bytecode pattern from room8_scrp18 at offset 0x130
    # push_word_var(var_12) + unless goto -98
    bytecode = bytes([
        0x03, 0x0C, 0x00,  # push_word_var(var_12) - 3 bytes
        0x5D, 0x9E, 0xFF   # unless goto -98 - 3 bytes  
    ])
    
    # Test that normal decode just gets the first instruction
    normal = decode(bytecode, 0x2130)  # Simulating the real address
    assert normal is not None
    assert normal.__class__.__name__ == "PushWordVar"
    
    # Test that fusion with loop detection works
    fused = decode_with_fusion(bytecode, 0x2130)
    assert fused is not None
    assert isinstance(fused, SmartLoopConditionalJump)
    assert fused.__class__.__name__ == "SmartLoopIfNot"
    
    # Verify loop detection
    assert fused.detected_loop is not None
    assert fused.detected_loop.loop_type == "while"
    
    # Check loop body size matches the real pattern
    body_size = fused.detected_loop.body_end - fused.detected_loop.body_start
    assert body_size == 92  # -98 offset + 6 bytes instruction length
    
    # Test rendering shows the loop pattern
    tokens = fused.render()
    text = ''.join(str(t.text if hasattr(t, 'text') else t) for t in tokens)
    assert "while" in text
    assert "!VAR_TMR_2" in text  # Should show the negated condition for if_not
    assert "92 bytes" in text


def test_room8_local200_scaling_loop() -> None:
    """Test the animation scaling loop pattern from room8_local200."""
    # Pattern: push_word_var(var_0) + push_word(255) + eq + unless goto -71
    bytecode = bytes([
        0x03, 0x00, 0x00,  # push_word_var(var_0) - scaling variable
        0x01, 0xFF, 0x00,  # push_word(255) - target scale
        0x0E,              # eq - comparison
        0x5D, 0xB9, 0xFF   # unless goto -71
    ])
    
    fused = decode_with_fusion(bytecode, 0x20A9)  # Simulating real address
    assert fused is not None
    assert isinstance(fused, SmartLoopConditionalJump)
    assert fused.__class__.__name__ == "SmartLoopIfNot"
    
    # Should detect as while-loop since eq comparison is wait-until pattern, not counter
    assert fused.detected_loop is not None
    assert fused.detected_loop.loop_type == "while"
    # Variable is still identified for potential analysis
    assert fused.detected_loop.iterator_var == 0
    
    # Test rendering
    tokens = fused.render()
    text = ''.join(str(t.text if hasattr(t, 'text') else t) for t in tokens)
    assert "while" in text
    assert "VAR_KEYPRESS" in text


def test_multiple_backward_jumps_pattern() -> None:
    """Test detection of multiple small backward jumps (room8_scrp3 pattern)."""
    # Pattern: unless goto -7 (small loop)
    bytecode = bytes([
        0x02, 0x05,        # push_byte_var(var_5) - loop condition
        0x5D, 0xF9, 0xFF   # unless goto -7
    ])
    
    fused = decode_with_fusion(bytecode, 0x1026)
    assert fused is not None
    assert isinstance(fused, SmartLoopConditionalJump)
    assert fused.__class__.__name__ == "SmartLoopIfNot"
    
    # Should detect loop
    assert fused.detected_loop is not None
    assert fused.detected_loop.loop_type == "while"
    
    # Small loop body
    body_size = fused.detected_loop.body_end - fused.detected_loop.body_start
    assert body_size == 2  # -7 offset + 5 bytes instruction length
    
    tokens = fused.render()
    text = ''.join(str(t.text if hasattr(t, 'text') else t) for t in tokens)
    assert "while" in text
    assert "2 bytes" in text


def test_complex_loop_with_nested_jumps() -> None:
    """Test detection of complex loop from room8_scrp24 pattern."""
    # Pattern: complex conditional with larger backward jump
    bytecode = bytes([
        0x02, 0x08,        # push_byte_var(var_8) - condition variable
        0x00, 0x0A,        # push_byte(10) - limit
        0x11,              # lt - less than comparison
        0x5D, 0xA3, 0xFF   # unless goto -93 (larger loop body)
    ])
    
    fused = decode_with_fusion(bytecode, 0x234A)
    assert fused is not None
    assert isinstance(fused, SmartLoopConditionalJump)
    assert fused.__class__.__name__ == "SmartLoopIfNot"
    
    # Should detect as for-loop
    assert fused.detected_loop is not None
    assert fused.detected_loop.loop_type == "for"
    assert fused.detected_loop.iterator_var == 8
    
    # Large loop body
    body_size = fused.detected_loop.body_end - fused.detected_loop.body_start
    assert body_size == 85  # Actual calculated size
    
    tokens = fused.render()
    text = ''.join(str(t.text if hasattr(t, 'text') else t) for t in tokens)
    assert "for" in text
    assert "var_8" in text
    assert "< 10" in text  # Should show inverted condition (unless becomes <)


def test_iff_loop_pattern() -> None:
    """Test loop detection with 'iff' (positive conditional) instruction."""
    # Pattern: condition + iff goto -N (loop continues when condition is TRUE)
    bytecode = bytes([
        0x02, 0x03,        # push_byte_var(var_3) - condition
        0x00, 0x00,        # push_byte(0) - comparison value
        0x0F,              # neq - not equal
        0x5C, 0xF8, 0xFF   # iff goto -8 (continue if var_3 != 0)
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
    assert "VAR_HAVE_MSG" in text


def test_no_loop_detection_for_regular_conditionals() -> None:
    """Test that regular forward conditionals are not detected as loops."""
    # Regular if-then pattern with forward jump
    bytecode = bytes([
        0x02, 0x05,        # push_byte_var(var_5)
        0x00, 0x0A,        # push_byte(10)
        0x10,              # gt - greater than
        0x5D, 0x20, 0x00   # unless goto +32 (forward jump - NOT a loop)
    ])
    
    fused = decode_with_fusion(bytecode, 0x1000)
    assert fused is not None
    
    # Should be regular conditional, not loop
    assert fused.__class__.__name__ == "SmartIfNot"  # Not SmartLoopIfNot
    assert not hasattr(fused, 'detected_loop') or fused.detected_loop is None
    
    tokens = fused.render()
    text = ''.join(str(t.text if hasattr(t, 'text') else t) for t in tokens)
    assert "if" in text
    assert "while" not in text
    assert "for" not in text


def test_descumm_style_output_comparison() -> None:
    """Test that our loop output approaches descumm-style semantic rendering."""
    # Simple loop pattern
    bytecode = bytes([
        0x02, 0x0C,        # push_byte_var(var_12)
        0x5D, 0x9E, 0xFF   # unless goto -98
    ])
    
    # Our output
    fused = decode_with_fusion(bytecode, 0x1000)
    assert fused is not None
    tokens = fused.render()
    our_output = ''.join(str(t.text if hasattr(t, 'text') else t) for t in tokens)
    
    # Our output should be more semantic than raw bytecode
    assert "while (!VAR_TMR_2)" in our_output
    assert "bytes" in our_output  # Should include loop body size info
    
    # Compared to what raw disassembly would show:
    normal = decode(bytecode, 0x1000)
    assert normal is not None
    normal_tokens = normal.render()
    raw_output = ''.join(str(t.text if hasattr(t, 'text') else t) for t in normal_tokens)
    
    # Our loop output should be more descriptive than raw instruction names
    assert len(our_output) > len(raw_output)  # More informative
    print(f"Raw output: {raw_output}")
    print(f"Loop output: {our_output}")

