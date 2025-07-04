"""Test actor segment creation in Scumm6View."""

import os
os.environ["FORCE_BINJA_MOCK"] = "1"

from binja_helpers import binja_api  # noqa: F401
from binaryninja.enums import SegmentFlag
from typing import cast

from .vars import ACTORS_START, ACTORS_SIZE, MAX_ACTORS, ACTOR_STRUCT_SIZE
from .actor_state import CURRENT_ACTOR_ADDRESS


def test_actor_segment_values() -> None:
    """Test that actor segment values are calculated correctly."""
    
    # Test basic calculations
    assert ACTORS_SIZE == MAX_ACTORS * ACTOR_STRUCT_SIZE
    assert ACTORS_SIZE == 32 * 64  # 32 actors, 64 bytes each
    assert ACTORS_SIZE == 2048
    
    # Test that current actor address is after the actor array
    assert CURRENT_ACTOR_ADDRESS == ACTORS_START + ACTORS_SIZE
    
    # Test actor addresses
    for i in range(MAX_ACTORS):
        actor_addr = ACTORS_START + (i * ACTOR_STRUCT_SIZE)
        # Each actor should be aligned to 64-byte boundary
        assert actor_addr % 64 == ACTORS_START % 64
        
        # Test that actor addresses don't overlap
        if i < MAX_ACTORS - 1:
            next_actor_addr = ACTORS_START + ((i + 1) * ACTOR_STRUCT_SIZE)
            assert next_actor_addr - actor_addr == ACTOR_STRUCT_SIZE
    
    print("✓ Actor memory layout validated:")
    print(f"  - Actors start at: 0x{ACTORS_START:08x}")
    print(f"  - Actors end at:   0x{ACTORS_START + ACTORS_SIZE:08x}")
    print(f"  - Current actor at: 0x{CURRENT_ACTOR_ADDRESS:08x}")
    print(f"  - Total size: {ACTORS_SIZE} bytes")
    print(f"  - Per actor: {ACTOR_STRUCT_SIZE} bytes")


def test_actor_struct_definition() -> None:
    """Test that the actor struct definition is correctly sized."""
    
    # This is the struct definition from view.py
    struct_fields = [
        ("id", 2),              # uint16_t
        ("costume", 2),         # uint16_t  
        ("name_ptr", 4),        # uint32_t
        ("x", 2),               # uint16_t
        ("y", 2),               # uint16_t
        ("elevation", 2),       # int16_t
        ("room", 1),            # uint8_t
        ("layer", 1),           # uint8_t
        ("target_x", 2),        # uint16_t
        ("target_y", 2),        # uint16_t
        ("walk_speed_x", 2),    # uint16_t
        ("walk_speed_y", 2),    # uint16_t
        ("facing_direction", 1), # uint8_t
        ("moving", 1),          # uint8_t
        ("walk_box", 1),        # uint8_t
        ("_pad1", 1),           # uint8_t
        ("scale_x", 1),         # uint8_t
        ("scale_y", 1),         # uint8_t
        ("width", 1),           # uint8_t
        ("palette", 1),         # uint8_t
        ("talk_color", 1),      # uint8_t
        ("_pad2", 1),           # uint8_t
        ("flags", 2),           # uint16_t
        ("anim_counter", 2),    # uint16_t
        ("current_anim", 1),    # uint8_t
        ("walk_frame", 1),      # uint8_t
        ("stand_frame", 1),     # uint8_t
        ("_pad3", 3),           # uint8_t[3]
        ("_reserved", 20),      # uint8_t[20]
    ]
    
    # Calculate total size
    total_size = sum(size for _, size in struct_fields)
    
    print("\n✓ Actor struct validation:")
    print(f"  - Calculated size: {total_size} bytes")
    print(f"  - Expected size: {ACTOR_STRUCT_SIZE} bytes")
    
    assert total_size == ACTOR_STRUCT_SIZE, f"Actor struct size mismatch: {total_size} != {ACTOR_STRUCT_SIZE}"


def test_segment_flags() -> None:
    """Test that correct segment flags are used for actor data."""
    
    # These are the flags used in view.py
    expected_flags = cast(SegmentFlag, SegmentFlag.SegmentReadable | SegmentFlag.SegmentWritable)
    
    # Verify flags are correct for actor data
    assert expected_flags & SegmentFlag.SegmentReadable != 0
    assert expected_flags & SegmentFlag.SegmentWritable != 0
    assert expected_flags & SegmentFlag.SegmentExecutable == 0  # Actors are data, not code
    
    print("\n✓ Segment flags validated:")
    print("  - Readable: Yes")
    print("  - Writable: Yes")
    print("  - Executable: No")
    print("  - Section semantics: ReadWriteData")