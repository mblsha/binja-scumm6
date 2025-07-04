#!/usr/bin/env python3
"""Debug script to analyze actor_ops bytecode decoding issue."""

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.pyscumm6.disasm import decode, decode_with_fusion

# Full bytecode from the test
full_bytecode = bytes([
    # getActorAnimCounter(1) - offset 0x00
    0x00, 0x01,              # push_byte(1)
    0x71,                    # get_actor_anim_counter
    # getActorCostume(2) - offset 0x03
    0x00, 0x02,              # push_byte(2)
    0x76,                    # get_actor_costume
    # getActorElevation(3) - offset 0x06
    0x00, 0x03,              # push_byte(3)
    0x83,                    # get_actor_elevation
    # getActorFacing(4) - offset 0x09
    0x00, 0x04,              # push_byte(4)
    0x7C,                    # get_actor_facing
    # getActorMoving(5) - offset 0x0C
    0x00, 0x05,              # push_byte(5)
    0x85,                    # get_actor_moving
    # getActorRoom(6) - offset 0x0F
    0x00, 0x06,              # push_byte(6)
    0x80,                    # get_actor_room
    # getActorScaleX(7) - offset 0x12
    0x00, 0x07,              # push_byte(7)
    0x87,                    # get_actor_scale_x
    # getActorScaleY(8) - offset 0x15
    0x00, 0x08,              # push_byte(8)
    0x55,                    # get_actor_scale_y
    # getActorWalkbox(9) - offset 0x18
    0x00, 0x09,              # push_byte(9)
    0x82,                    # get_actor_walkbox
    # getActorWidth(10) - offset 0x1B
    0x00, 0x0A,              # push_byte(10)
    0x86,                    # get_actor_width
    # getActorX(1) - offset 0x1E
    0x00, 0x01,              # push_byte(1)
    0x72,                    # get_actor_x
    # getActorY(2) - offset 0x21
    0x00, 0x02,              # push_byte(2)
    0x73,                    # get_actor_y
    # isSoundRunning(100) - offset 0x24
    0x00, 0x64,              # push_byte(100)
    0x89,                    # is_sound_running
    # getDistObjObj(1, 2) - offset 0x27
    0x00, 0x01,              # push_byte(1)
    0x00, 0x02,              # push_byte(2)
    0x74,                    # get_dist_obj_obj
    # actorOps.setWalkSpeed(1, 10, 5) - offset 0x2C
    0x00, 0x01,              # push_byte(1) - actor
    0x00, 0x0A,              # push_byte(10) - x_speed
    0x00, 0x05,              # push_byte(5) - y_speed
    0x8E,                    # actor_ops
    0x10,                    # ACTOR_SET_WALK_SPEED sub-op
    0xFF,                    # end marker
    # Offset 0x36: 5 bytes before 0x3B
    0x00, 0x32,              # push_byte(50)
    0x8E,                    # actor_ops
    0x15,                    # ACTOR_SET_WIDTH sub-op - This is at 0x39
    0xFF,                    # end marker - This is at 0x3A
    # putActorAtXY(2, 100, 200, 0) - offset 0x3B
    0x00, 0x02,              # push_byte(2) - actor
    0x01, 0x64, 0x00,        # push_word(100) - x
    0x01, 0xC8, 0x00,        # push_word(200) - y
    0x00, 0x00,              # push_byte(0) - room
    0x7F,                    # put_actor_at_xy
    # animateActor(3, 5) - offset 0x47
    0x00, 0x03,              # push_byte(3)
    0x00, 0x05,              # push_byte(5)
    0x84,                    # animate_actor
])

print("=== ACTOR OPS BYTECODE DEBUG ===")
print(f"Total bytecode length: {len(full_bytecode)} bytes")
print()

# Analyze the area around offset 0x3B
print("=== BYTECODE AROUND OFFSET 0x3B ===")
start_offset = 0x35
end_offset = 0x50
for i in range(start_offset, min(end_offset, len(full_bytecode))):
    byte_val = full_bytecode[i]
    print(f"[{i:04X}] 0x{byte_val:02X} ({byte_val:3d}) - ", end="")
    if i == 0x3B:
        print("<<< Expected putActorAtXY start")
    elif i == 0x47:
        print("<<< Expected animateActor start")
    else:
        print()

print("\n=== DECODING FROM OFFSET 0x3B ===")
# Try decoding from offset 0x3B
offset = 0x3B
bytes_remaining = full_bytecode[offset:]
print(f"Bytes from 0x3B: {' '.join(f'{b:02X}' for b in bytes_remaining[:20])}...")

# Decode instructions starting from 0x3B
print("\n=== SEQUENTIAL DECODE FROM 0x3B ===")
current_offset = 0x3B
instructions_found = []
while current_offset < len(full_bytecode) and len(instructions_found) < 5:
    try:
        instr = decode(full_bytecode, current_offset)
        if instr:
            print(f"[{current_offset:04X}] {instr.__class__.__name__}: {instr.render()}")
            instructions_found.append((current_offset, instr))
            current_offset += instr.length()
        else:
            print(f"[{current_offset:04X}] Failed to decode instruction")
            break
    except Exception as e:
        print(f"[{current_offset:04X}] Exception: {e}")
        break

print("\n=== FUSION DECODE FROM 0x3B ===")
current_offset = 0x3B
fusion_instructions = []
while current_offset < len(full_bytecode) and len(fusion_instructions) < 2:
    try:
        instr = decode_with_fusion(full_bytecode, current_offset)
        if instr:
            tokens = instr.render()
            text = ''.join(str(t.text if hasattr(t, 'text') else t) for t in tokens)
            print(f"[{current_offset:04X}] {instr.__class__.__name__}: {text}")
            fusion_instructions.append((current_offset, instr))
            current_offset += instr.length()
        else:
            print(f"[{current_offset:04X}] Failed to decode instruction")
            break
    except Exception as e:
        print(f"[{current_offset:04X}] Exception: {e}")
        break

# Let's also check what happens if we decode from earlier
print("\n=== CHECKING DECODE FROM 0x36 (actorOps.setWidth) ===")
current_offset = 0x36
for i in range(3):
    try:
        instr = decode(full_bytecode, current_offset)
        if instr:
            print(f"[{current_offset:04X}] {instr.__class__.__name__}: {instr.render()}")
            current_offset += instr.length()
        else:
            print(f"[{current_offset:04X}] Failed to decode")
            break
    except Exception as e:
        print(f"[{current_offset:04X}] Exception: {e}")
        break

# Let's manually check the expected putActorAtXY bytecode
print("\n=== MANUAL PUTACTORATXY BYTECODE CHECK ===")
expected_put_actor = [
    (0x3B, 0x00, "push_byte"),
    (0x3C, 0x02, "value: 2"),
    (0x3D, 0x01, "push_word"),
    (0x3E, 0x64, "value low: 100"),
    (0x3F, 0x00, "value high"),
    (0x40, 0x01, "push_word"),
    (0x41, 0xC8, "value low: 200"),
    (0x42, 0x00, "value high"),
    (0x43, 0x00, "push_byte"),
    (0x44, 0x00, "value: 0"),
    (0x45, 0x7F, "put_actor_at_xy opcode"),
]

print("Expected sequence:")
for offset, byte_val, desc in expected_put_actor:
    actual = full_bytecode[offset] if offset < len(full_bytecode) else None
    match = "✓" if actual == byte_val else "✗"
    print(f"  [{offset:04X}] Expected: 0x{byte_val:02X} ({desc}), Actual: 0x{actual:02X} {match}")

# Check what opcode 0x7F actually decodes to
print("\n=== OPCODE 0x7F DECODE TEST ===")
test_bytecode = bytes([0x7F])
try:
    instr = decode(test_bytecode, 0)
    print(f"Opcode 0x7F decodes to: {instr.__class__.__name__}")
except Exception as e:
    print(f"Failed to decode 0x7F: {e}")

# Try decoding the exact putActorAtXY sequence
print("\n=== ISOLATED PUTACTORATXY DECODE ===")
put_actor_bytes = bytes([
    0x00, 0x02,              # push_byte(2)
    0x01, 0x64, 0x00,        # push_word(100)
    0x01, 0xC8, 0x00,        # push_word(200)
    0x00, 0x00,              # push_byte(0)
    0x7F,                    # put_actor_at_xy
])

offset = 0
while offset < len(put_actor_bytes):
    instr = decode(put_actor_bytes, offset)
    if instr:
        print(f"[{offset:04X}] {instr.__class__.__name__}: {instr.render()}")
        offset += instr.length()
    else:
        print(f"[{offset:04X}] Failed to decode")
        break

# Try with fusion
print("\nWith fusion:")
instr = decode_with_fusion(put_actor_bytes, 0)
if instr:
    tokens = instr.render()
    text = ''.join(str(t.text if hasattr(t, 'text') else t) for t in tokens)
    print(f"[0000] {instr.__class__.__name__}: {text}")