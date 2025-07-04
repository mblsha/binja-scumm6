#!/usr/bin/env python3
"""Debug script to find the bytecode alignment issue."""

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.pyscumm6.disasm import decode, decode_with_fusion

# Let's check the actorOps.setWidth instruction format
print("=== TESTING ACTOROP SET WIDTH FORMAT ===")

# Expected format for actorOps.setWidth(actor, width)
test_sequences = [
    # Format 1: actor_ops with actor as parameter
    ("Format 1: push actor, push width, actor_ops", bytes([
        0x00, 0x01,    # push_byte(1) - actor
        0x00, 0x32,    # push_byte(50) - width
        0x8E,          # actor_ops
        0x15,          # ACTOR_SET_WIDTH
        0xFF,          # end
    ])),
    # Format 2: just push width, actor_ops (actor in op_details)
    ("Format 2: push width, actor_ops", bytes([
        0x00, 0x32,    # push_byte(50) - width
        0x8E,          # actor_ops
        0x15,          # ACTOR_SET_WIDTH
        0xFF,          # end
    ])),
    # Format 3: Check if actor_ops has additional data
    ("Format 3: push width, actor_ops with actor byte", bytes([
        0x00, 0x32,    # push_byte(50) - width  
        0x8E,          # actor_ops
        0x01,          # actor id
        0x15,          # ACTOR_SET_WIDTH
        0xFF,          # end
    ])),
]

for desc, bytecode in test_sequences:
    print(f"\n{desc}:")
    print(f"Bytecode: {' '.join(f'{b:02X}' for b in bytecode)}")
    
    # Try decoding
    offset = 0
    instructions = []
    while offset < len(bytecode):
        try:
            instr = decode(bytecode, offset)
            if instr:
                instructions.append((offset, instr))
                print(f"  [{offset:04X}] {instr.__class__.__name__}: {instr.render()}")
                offset += instr.length()
            else:
                print(f"  [{offset:04X}] Failed to decode")
                break
        except Exception as e:
            print(f"  [{offset:04X}] Exception: {e}")
            break
    
    # Try with fusion
    print("  With fusion:")
    try:
        instr = decode_with_fusion(bytecode, 0)
        if instr:
            tokens = instr.render()
            text = ''.join(str(t.text if hasattr(t, 'text') else t) for t in tokens)
            print(f"    {instr.__class__.__name__}: {text}")
            print(f"    Length: {instr.length()} bytes")
    except Exception as e:
        print(f"    Exception: {e}")

# Now let's check what the test bytecode actually has
print("\n\n=== ANALYZING TEST BYTECODE ===")
full_bytecode = bytes([
    # ... (earlier bytes)
    # actorOps.setWalkSpeed(1, 10, 5) - offset 0x2C
    0x00, 0x01,              # push_byte(1) - actor
    0x00, 0x0A,              # push_byte(10) - x_speed
    0x00, 0x05,              # push_byte(5) - y_speed
    0x8E,                    # actor_ops
    0x10,                    # ACTOR_SET_WALK_SPEED sub-op
    0xFF,                    # end marker
    # This should be actorOps.setWidth
    0x00, 0x32,              # push_byte(50) - width
    0x8E,                    # actor_ops
    0x15,                    # ACTOR_SET_WIDTH sub-op
    0xFF,                    # end marker
])

print("Decoding from walk speed:")
offset = 0
while offset < len(full_bytecode):
    instr = decode(full_bytecode, offset)
    if instr:
        print(f"[{offset:04X}] {instr.__class__.__name__} (len={instr.length()}): {instr.render()}")
        offset += instr.length()
    else:
        print(f"[{offset:04X}] Failed to decode")
        break

# Calculate expected offsets
print("\n=== OFFSET CALCULATION ===")
print("actorOps.setWalkSpeed starts at: 0x2C")
print("  push_byte(1): 2 bytes")
print("  push_byte(10): 2 bytes")
print("  push_byte(5): 2 bytes")
print("  actor_ops + subop + end: 3 bytes")
print("  Total: 9 bytes")
print("  Next instruction should be at: 0x2C + 9 = 0x35")
print()
print("actorOps.setWidth should start at: 0x35")
print("  push_byte(50): 2 bytes")
print("  actor_ops + subop + end: 3 bytes")
print("  Total: 5 bytes")
print("  Next instruction should be at: 0x35 + 5 = 0x3A")
print()
print("putActorAtXY should start at: 0x3A (not 0x3B!)")