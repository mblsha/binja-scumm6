#!/usr/bin/env python3
"""Debug script to understand ActorOps decoding issue."""

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.scumm6_opcodes import Scumm6Opcodes
from src.pyscumm6.disasm import decode

# Test decoding of 0x8E (actor_ops)
print("=== TESTING ACTOR_OPS DECODING ===")

# Simple test case
test_bytecode = bytes([0x8E, 0x10, 0xFF])  # actor_ops, ACTOR_SET_WALK_SPEED, end
print(f"Test bytecode: {' '.join(f'{b:02X}' for b in test_bytecode)}")

# Try to decode using the low-level decoder
print("\n=== KAITAI DECODING ===")
try:
    kaitai_op = Scumm6Opcodes.from_bytes(test_bytecode)
    print(f"Kaitai op type: {kaitai_op.opcode}")
    print(f"Kaitai op enum: {type(kaitai_op.opcode)}")
    print(f"Op details: {kaitai_op.op_details}")
    if hasattr(kaitai_op.op_details, 'body'):
        print(f"Op body: {kaitai_op.op_details.body}")
        if hasattr(kaitai_op.op_details.body, 'subop'):
            print(f"Subop: {kaitai_op.op_details.body.subop}")
        if hasattr(kaitai_op.op_details.body, 'body'):
            print(f"Subop body: {kaitai_op.op_details.body.body}")
except Exception as e:
    print(f"Kaitai decoding failed: {e}")
    import traceback
    traceback.print_exc()

# Test the specific failing bytecode pattern
print("\n\n=== TESTING FAILING PATTERN ===")
# actorOps.setWidth pattern from the test
failing_bytecode = bytes([
    0x00, 0x32,  # push_byte(50)
    0x8E,        # actor_ops
    0x15,        # ACTOR_SET_WIDTH
    0xFF,        # end
])

print(f"Failing bytecode: {' '.join(f'{b:02X}' for b in failing_bytecode)}")

# Try to decode byte by byte
print("\nByte-by-byte decoding:")
for i in range(len(failing_bytecode)):
    try:
        kaitai_op = Scumm6Opcodes.from_bytes(failing_bytecode[i:])
        op_enum = kaitai_op.opcode
        if isinstance(op_enum, Scumm6Opcodes.OpType):
            print(f"  [{i:02X}] 0x{failing_bytecode[i]:02X} -> {op_enum.name}")
        else:
            print(f"  [{i:02X}] 0x{failing_bytecode[i]:02X} -> {op_enum} (raw)")
    except Exception as e:
        print(f"  [{i:02X}] 0x{failing_bytecode[i]:02X} -> Error: {e}")

# Check if 0x8E is in the OpType enum
print("\n=== CHECKING OPTYPE ENUM ===")
print(f"OpType.actor_ops value: {Scumm6Opcodes.OpType.actor_ops.value if hasattr(Scumm6Opcodes.OpType, 'actor_ops') else 'NOT FOUND'}")

# List all OpType values around 0x8E
print("\nOpType values near 0x8E:")
for attr_name in dir(Scumm6Opcodes.OpType):
    if not attr_name.startswith('_'):
        try:
            attr_val = getattr(Scumm6Opcodes.OpType, attr_name)
            if hasattr(attr_val, 'value') and 0x88 <= attr_val.value <= 0x94:
                print(f"  {attr_name}: 0x{attr_val.value:02X}")
        except Exception:
            pass

# Direct check of what 0x8E maps to
print("\n=== DIRECT ENUM CHECK ===")
try:
    op_8e = Scumm6Opcodes.OpType(0x8E)
    print(f"0x8E maps to: {op_8e.name}")
except ValueError as e:
    print(f"0x8E is not a valid OpType: {e}")

# Check the actual bytecode structure from position 0x36
print("\n\n=== CHECKING ACTUAL TEST BYTECODE ===")
actual_test_bytes = bytes([
    # From offset 0x36 in the test
    0x00, 0x32,              # push_byte(50)
    0x8E,                    # actor_ops
    0x15,                    # ACTOR_SET_WIDTH sub-op
    0xFF,                    # end marker
    # putActorAtXY starts here (offset 0x3B in original)
    0x00, 0x02,              # push_byte(2)
    0x01, 0x64, 0x00,        # push_word(100)
    0x01, 0xC8, 0x00,        # push_word(200)
    0x00, 0x00,              # push_byte(0)
    0x7F,                    # put_actor_at_xy
])

print(f"Actual test bytes: {' '.join(f'{b:02X}' for b in actual_test_bytes[:10])}")

# Now use the high-level decoder
print("\n=== HIGH-LEVEL DECODE ===")
offset = 0
while offset < len(actual_test_bytes):
    try:
        instr = decode(actual_test_bytes, offset)
        if instr:
            print(f"[{offset:04X}] {instr.__class__.__name__} (opcode at {offset:04X})")
            print(f"       Length: {instr.length()}")
            print(f"       Render: {instr.render()}")
            
            # Check if it's consuming the right bytes
            consumed_bytes = actual_test_bytes[offset:offset+instr.length()]
            print(f"       Consumed: {' '.join(f'{b:02X}' for b in consumed_bytes)}")
            
            offset += instr.length()
        else:
            print(f"[{offset:04X}] Failed to decode")
            break
    except Exception as e:
        print(f"[{offset:04X}] Exception: {e}")
        import traceback
        traceback.print_exc()
        break