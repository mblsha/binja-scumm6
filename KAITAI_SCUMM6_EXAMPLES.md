# Concrete Examples: Kaitai Struct vs Descumm for SCUMM6

## Overview

This document provides concrete examples of SCUMM6 instructions where Kaitai Struct's current implementation falls short compared to descumm's capabilities.

## 1. Variable Argument Instructions

### `startScript` (0x5E)

**Descumm Output**:
```c
startScript(108, [7, 15, 23])
```

**Current Kaitai Limitation**:
```yaml
# Can only mark that it uses variable args, not parse them
start_script:
  instances:
    pop_list: true
```

**What's Missing**:
- Cannot determine argument count (comes from previous push)
- Cannot extract actual argument values
- Cannot represent the semantic meaning

**Ideal Kaitai**:
```yaml
start_script:
  seq:
    - id: arg_count
      type: stack_pop
    - id: script_id  
      type: stack_pop
    - id: flags
      type: stack_pop
      if: _parent.op_type == op_type::start_script
    - id: args
      type: stack_pop
      repeat: expr
      repeat-expr: arg_count.value
```

## 2. Complex Sub-Operations

### `actorOps` (0x85)

**Descumm Output**:
```c
Actor[3].costume(25)
Actor[3].talkColor(15)
Actor[3].walkSpeed(3, 2)
Actor[3].initAnimation(4)
```

**Current Kaitai**:
```yaml
actor_ops:
  seq:
    - id: sub_op
      type: u1
    - id: data
      switch-on: sub_op
      cases:
        # 50+ cases with different structures
```

**What's Missing**:
- No semantic grouping of related operations
- No type safety for parameters
- No documentation of side effects
- Flat structure doesn't represent logical hierarchy

**Ideal Kaitai**:
```yaml
actor_ops:
  seq:
    - id: actor_id
      type: stack_pop
    - id: operation
      type: actor_operation
      
types:
  actor_operation:
    seq:
      - id: type
        type: u1
        enum: actor_op_type
      - id: params
        type:
          switch-on: type
          cases:
            'actor_op_type::costume': costume_params
            'actor_op_type::walk_speed': walk_speed_params
            
  costume_params:
    meta:
      semantic: "Sets actor costume and resets animation"
    seq:
      - id: costume_id
        type: stack_pop
        doc: "Costume resource ID"
        
  walk_speed_params:
    meta:
      semantic: "Sets actor movement speed"
    seq:
      - id: x_speed
        type: stack_pop
      - id: y_speed
        type: stack_pop
```

## 3. Message Parsing

### `printActor` (0xD8)

**Descumm Output**:
```c
printActor("Hello, my name is %s{name} and I have %d{gold} gold coins.")
```

**Current Kaitai**:
```yaml
message:
  seq:
    - id: data
      type: u1
      repeat: until
      repeat-until: _ == 0
```

**What's Missing**:
- No parsing of escape sequences
- No extraction of variable references
- No understanding of format specifiers
- Just returns raw bytes

**Ideal Kaitai**:
```yaml
scumm_message:
  seq:
    - id: segments
      type: message_segment
      repeat: until
      repeat-until: _.is_terminator
      
types:
  message_segment:
    seq:
      - id: marker
        type: u1
      - id: content
        switch-on: marker
        cases:
          0xFF: var_reference      # Variable substitution
          0xFE: verb_reference     # Verb substitution  
          0xFD: format_specifier   # Format code
          0x00: terminator
          _: text_chunk
          
  var_reference:
    seq:
      - id: var_type
        type: u1
        enum: var_type
      - id: var_id
        type: u2le
    instances:
      display_name:
        value: |
          var_type == var_type::string ? "%s" :
          var_type == var_type::int ? "%d" : "%x"
```

## 4. Control Flow with Context

### `if...goto` Pattern

**Descumm Output**:
```c
if (VAR_ROOM == 10) {
    startScript(50, []);
} else {
    startScript(51, []);
}
```

**Current Kaitai**: Can only see individual instructions:
```
push_word_var(VAR_ROOM)
push_byte(10)  
eq
if_not(+10)
push_byte(50)
push_byte(0)
start_script_quick
jump(+8)
push_byte(51)
push_byte(0)
start_script_quick
```

**What's Missing**:
- No understanding of control flow patterns
- No basic block analysis
- No pattern recognition
- No semantic grouping

**Ideal Kaitai with Patterns**:
```yaml
patterns:
  if_else_pattern:
    match:
      - push_var
      - push_const
      - comparison_op
      - conditional_jump
    transform: if_else_block
    
types:
  if_else_block:
    meta:
      control_flow: conditional
    seq:
      - id: condition
        type: condition_expression
      - id: true_branch
        type: instruction_block
      - id: false_branch
        type: instruction_block
        if: has_else_branch
```

## 5. Resource References

### `drawObject` (0x61)

**Descumm Output**:
```c
drawObject(OBJ_DOOR, 3)  // Draw door object in state 3
```

**Current Kaitai**:
```yaml
draw_object:
  instances:
    pop_count: 2
```

**What's Missing**:
- No resource name resolution
- No semantic understanding of object states
- No cross-references to resource data

**Ideal Kaitai**:
```yaml
draw_object:
  seq:
    - id: object_id
      type: stack_pop
    - id: state
      type: stack_pop
  instances:
    object_name:
      io: _root.resource_table.objects[object_id.value].name_stream
      type: str
      encoding: ASCII
    semantic_desc:
      value: '"Draw " + object_name + " in state " + state.value.to_s'
```

## 6. Stack Machine Semantics

### Complex Expression

**Descumm Output**:
```c
VAR_RESULT = (VAR_X * 3 + VAR_Y) / 2
```

**Current Kaitai Bytecode**:
```
push_word_var(VAR_X)
push_byte(3)
mul
push_word_var(VAR_Y)
add
push_byte(2)
div
write_word_var(VAR_RESULT)
```

**What's Missing**:
- No expression tree building
- No stack effect tracking
- No semantic grouping of operations

**Ideal Kaitai with Stack Tracking**:
```yaml
meta:
  stack_machine: true
  
instances:
  stack_state:
    type: stack_tracker
    
types:
  instruction:
    seq:
      - id: opcode
        type: u1
      - id: operation
        type: operation(opcode)
    instances:
      stack_before:
        value: _parent.stack_state.before(this)
      stack_after:
        value: _parent.stack_state.after(this)
      expression:
        value: _parent.expression_builder.build(this)
```

## Key Patterns Kaitai Can't Handle

### 1. **Runtime Stack Dependencies**
```c
// Descumm understands this pushes N values then pops N+1
pickOneOf([choice1, choice2, choice3])
```

### 2. **Cross-Instruction Semantics**
```c
// Descumm knows these form a single logical operation
setCameraAt(getObjectX(OBJ_PLAYER))
```

### 3. **Resource Cross-References**
```c
// Descumm can resolve resource names and types
playSound(SND_DOOR_OPEN)
loadRoom(ROOM_LIBRARY)
```

### 4. **State Machine Patterns**
```c
// Descumm recognizes state machine implementations
switch (VAR_GAME_STATE) {
    case STATE_MENU:
        // ...
    case STATE_PLAYING:
        // ...
}
```

## Conclusion

These examples demonstrate that while Kaitai Struct can parse the binary format of SCUMM6 instructions, it lacks the semantic understanding that makes descumm valuable for reverse engineering. The proposed improvements would bridge this gap, enabling Kaitai to produce output comparable to descumm while maintaining its declarative nature.