#!/usr/bin/env python3
"""Calculate the actual offsets in the actor_ops test bytecode."""

# Test bytecode with offset calculations
bytecode_parts = [
    # actorOps.setCurActor(1)
    (0x00, 0x01, "push_byte(1)"),              # 2 bytes
    (0x9D, "actor_ops"),                       # 1 byte
    (0xC5, "set_current_actor subop"),         # 1 byte
    # Need 0xFF end marker?                    # +1 byte?
    
    # actorOps.init()
    (0x9D, "actor_ops"),                       # 1 byte
    (0x53, "init subop"),                      # 1 byte
    # Need 0xFF end marker?                    # +1 byte?
    
    # actorOps.setCostume(5)
    (0x00, 0x05, "push_byte(5)"),              # 2 bytes
    (0x9D, "actor_ops"),                       # 1 byte
    (0x4C, "set_costume subop"),               # 1 byte
    # Need 0xFF end marker?                    # +1 byte?
]

print("=== OFFSET CALCULATION ===")
print("Calculating offsets for actor_ops test bytecode...")
print()

# Count bytes in the test up to the failing point
test_sections = [
    ("actorOps.setCurActor(1)", 4),           # push_byte(2) + actor_ops + subop
    ("actorOps.init()", 2),                    # actor_ops + subop
    ("actorOps.setCostume(5)", 4),            # push_byte(2) + actor_ops + subop
    ("actorOps.setIgnoreBoxes()", 2),         # actor_ops + subop
    ("actorOps.setNeverZClip()", 2),          # actor_ops + subop
    ("actorOps.setElevation(20)", 4),         # push_byte(2) + actor_ops + subop
    ("actorOps.setScale(255)", 4),            # push_byte(2) + actor_ops + subop
    ("actorOps.setTalkPos(-25, -98)", 6),     # push_byte(2) + push_byte(2) + actor_ops + subop
    ("actorOps.setWidth(30)", 4),             # push_byte(2) + actor_ops + subop
    ("actorOps.setWalkFrame(2)", 4),          # push_byte(2) + actor_ops + subop
    ("actorOps.setStandFrame(8)", 4),         # push_byte(2) + actor_ops + subop
    ("actorOps.setTalkFrame(6, 9)", 6),       # push_byte(2) + push_byte(2) + actor_ops + subop
    ("actorOps.setTalkColor(15)", 4),         # push_byte(2) + actor_ops + subop
    ("actorOps.setPalette(3)", 4),            # push_byte(2) + actor_ops + subop
    ("actorOps.setWalkSpeed(10, 5)", 6),      # push_byte(2) + push_byte(2) + actor_ops + subop
]

# Add up all offsets
current_offset = 0
for section, size in test_sections:
    print(f"[{current_offset:04X}] {section} - {size} bytes")
    current_offset += size

print(f"\nTotal before actorOps.setName: {current_offset} bytes (0x{current_offset:02X})")
print()

# Check if actor_ops needs end markers
print("=== CHECKING ACTOR_OPS FORMAT ===")
print("According to the Kaitai struct, actor_ops has:")
print("- subop (1 byte)")
print("- body (variable based on subop)")
print()
print("The body type depends on the subop. Most are call_func_popN types.")
print("These do NOT require 0xFF end markers.")
print()
print("However, some subops like actor_name might have string data that")
print("requires special handling or termination.")

# Calculate the actual offset where putActorAtXY should be
print("\n=== EXPECTED VS ACTUAL ===")
print("Expected putActorAtXY at: 0x3B (59 decimal)")
print(f"Actual offset after setWalkSpeed: 0x{current_offset:02X} ({current_offset} decimal)")
print(f"Difference: {0x3B - current_offset} bytes")

# The setName instruction is complex - it likely has string data
print("\n=== ACTOR_NAME INSTRUCTION ===")
print("The actorOps.setName instruction at offset 0x38 has:")
print("- 0x9D (actor_ops)")
print("- 0x58 (actor_name subop)")
print("- String data (format unknown)")
print()
print("This is likely where the offset calculation goes wrong.")
print("The test comment says 'String data would follow but format is complex'")
print("But the test doesn't include any string data!")

# Check the actual test bytecode
test_bytecode = bytes([
    # ... (first part of test)
    # actorOps.setWalkSpeed(10, 5) 
    0x00, 0x0A,             # push_byte(10)
    0x00, 0x05,             # push_byte(5)
    0x9D,                   # actor_ops (0x9D)
    0x4D,                   # step_dist subop (77)
    
    # actorOps.setName("Hero")
    0x9D,                   # actor_ops (0x9D)
    0x58,                   # actor_name subop (88)
    # String data would follow but format is complex
    
    # Now test non-actorOps functions that take actor index
    # putActorAtXY(2, 100, 200, room=0)
    0x00, 0x02,             # push_byte(2) - actor index
    0x00, 0x64,             # push_byte(100) - x position
    0x00, 0xC8,             # push_byte(200) - y position  
    0x00, 0x00,             # push_byte(0) - room
    0x7F,                   # put_actor_at_xy opcode (127)
])

print("\n=== ACTUAL BYTECODE ===")
print("Bytes around the setName/putActorAtXY boundary:")
for i in range(len(test_bytecode)):
    if i % 8 == 0:
        print(f"\n[{0x34+i:04X}] ", end="")
    print(f"{test_bytecode[i]:02X} ", end="")