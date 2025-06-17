# Kaitai Struct Improvements for SCUMM6 Script Parsing

## Executive Summary

Kaitai Struct, while excellent for binary format parsing, has fundamental limitations when dealing with complex scripting languages like SCUMM6. This document outlines the specific challenges and proposes improvements to achieve parity with descumm's capabilities.

## Current Kaitai Struct Limitations for SCUMM6

### 1. **Variable-Length Argument Lists**

**Problem**: SCUMM6 has numerous instructions that consume a variable number of arguments from the stack. The count is determined at runtime by a previously pushed value.

**Current Kaitai Approach**:
```yaml
call_func_list:
  seq:
    - id: call_func
      size: 0
  instances:
    pop_list:
      value: true
    pop_list_first:
      value: true
```

**Why It's Bad**: 
- Kaitai can't parse the actual arguments
- No way to know how many values will be popped at parse time
- Results in incomplete instruction representation
- Forces runtime interpretation outside of Kaitai

**Examples Affected**:
- `start_script` - Variable script arguments
- `sound_kludge` - Variable sound parameters
- `cutscene` - Variable cutscene commands
- `draw_blast_object` - Complex parameter lists

### 2. **Context-Dependent Parsing**

**Problem**: Many SCUMM6 instructions require knowledge of previous instructions to parse correctly.

**Examples**:
- Array operations need the array ID from a previous push
- Script calls need the script ID from stack
- Variable assignments need the variable ID

**Current Limitation**: Kaitai is stateless - each instruction is parsed in isolation without access to execution context.

### 3. **Complex Message/String Structures**

**Problem**: SCUMM6 messages contain escape sequences, variable substitutions, and complex formatting that Kaitai struggles with.

**Current Approach**:
```yaml
message:
  seq:
    - id: data
      type: u1
      repeat: until
      repeat-until: _ == 0
```

**Why It's Bad**:
- No semantic parsing of escape sequences
- Can't handle variable substitutions
- No support for formatting codes
- Results in raw byte arrays instead of structured data

### 4. **Sub-Operation Complexity**

**Problem**: Many SCUMM6 opcodes have sub-operations that completely change their behavior and parameter structure.

**Examples**:
- `actor_ops` - 50+ sub-operations with different parameters
- `verb_ops` - Different verb manipulations
- `system_ops` - Various system functions
- `room_ops` - Room manipulations

**Current Limitation**: Kaitai handles this with massive switch statements, but can't elegantly represent the semantic differences.

### 5. **Control Flow Analysis**

**Problem**: Kaitai can identify jump offsets but can't build control flow understanding.

**Limitations**:
- Can't resolve jump targets to actual addresses
- No concept of basic blocks or control flow graphs
- Can't track script entry points
- No understanding of conditional vs unconditional branches

### 6. **Intrinsic Operations**

**Problem**: Many SCUMM6 operations are engine intrinsics that have side effects beyond data manipulation.

**Examples**:
- Drawing operations
- Sound/music control
- Game state changes
- Actor manipulations

**Current Limitation**: Kaitai can only identify these as opcodes, not understand their semantics.

## Proposed Improvements

### 1. **Enhanced Variable Argument Support**

**Proposal**: Add a "runtime-determined repeat" feature to Kaitai.

```yaml
# Proposed syntax
start_script:
  seq:
    - id: num_args
      type: runtime_stack_value  # New: Reference to runtime value
    - id: args
      type: argument
      repeat: expr
      repeat-expr: num_args  # Uses runtime value
```

**Benefits**:
- Accurate representation of variable-length instructions
- Better documentation of instruction behavior
- Enables proper disassembly

### 2. **Context-Aware Parsing**

**Proposal**: Add execution context to Kaitai parsing.

```yaml
# Proposed context system
context:
  stack:
    type: value_stack
    max_depth: 100
  
  variables:
    type: variable_map
    
  arrays:
    type: array_registry

types:
  array_write:
    seq:
      - id: array_id
        type: context_stack_pop  # Gets value from context
      - id: index
        type: context_stack_pop
      - id: value
        type: context_stack_pop
```

**Benefits**:
- Accurate parameter extraction
- Better semantic understanding
- Enables cross-reference analysis

### 3. **Semantic String Parsing**

**Proposal**: Add structured string parsing with escape sequence support.

```yaml
# Proposed message structure
scumm_message:
  seq:
    - id: parts
      type: message_part
      repeat: until
      repeat-until: _.type == message_part_type::end
      
types:
  message_part:
    seq:
      - id: type
        type: u1
        enum: message_part_type
      - id: content
        switch-on: type
        cases:
          'message_part_type::text': text_content
          'message_part_type::variable': variable_reference
          'message_part_type::verb': verb_reference
          'message_part_type::format': format_code
          
  variable_reference:
    seq:
      - id: var_type
        type: u1
      - id: var_id
        type: u2le
```

**Benefits**:
- Structured representation of messages
- Easy extraction of variable references
- Better internationalization support

### 4. **Semantic Sub-Operation System**

**Proposal**: Replace flat switch with hierarchical operation definitions.

```yaml
# Proposed semantic operation structure
actor_ops:
  seq:
    - id: sub_op
      type: u1
      enum: actor_sub_op
    - id: params
      type: actor_op_params(sub_op)
      
types:
  actor_op_params:
    params:
      - id: sub_op
        type: u1
    seq:
      - id: data
        switch-on: sub_op
        cases:
          'actor_sub_op::costume':
            type: costume_params
          'actor_sub_op::walk_speed':
            type: walk_speed_params
            
  costume_params:
    doc: "Sets actor costume with animation reset"
    seq:
      - id: costume_id
        type: u2le
      - id: reset_anim
        type: b1
```

**Benefits**:
- Self-documenting sub-operations
- Type-safe parameter parsing
- Better code generation

### 5. **Control Flow Annotations**

**Proposal**: Add control flow metadata to Kaitai.

```yaml
# Proposed control flow annotations
types:
  jump_instruction:
    seq:
      - id: offset
        type: s2le
    instances:
      target_address:
        value: _parent._parent.address + 3 + offset
      is_forward:
        value: offset > 0
      is_loop:
        value: offset < 0 and target_address < _parent._parent.address
    meta:
      control_flow:
        type: unconditional_branch
        target: target_address
        
  conditional_jump:
    meta:
      control_flow:
        type: conditional_branch
        true_target: target_address
        false_target: _parent._parent.address + 3
```

**Benefits**:
- Enables CFG construction
- Better navigation in disassemblers
- Supports decompilation

### 6. **Semantic Intrinsic Definitions**

**Proposal**: Add semantic metadata for intrinsic operations.

```yaml
# Proposed intrinsic metadata
draw_object:
  meta:
    semantic:
      category: graphics
      side_effects:
        - modifies: screen_buffer
        - invalidates: screen_region
      parameters:
        - name: object_id
          type: game_object_ref
        - name: state
          type: object_state
      description: "Draws game object at current position with specified state"
```

**Benefits**:
- Rich documentation in the format
- Better reverse engineering support
- Enables semantic analysis tools

## Implementation Strategy

### Phase 1: Core Improvements
1. Implement runtime-determined repeat for variable arguments
2. Add basic context system for stack tracking
3. Enhance message parsing with escape sequences

### Phase 2: Semantic Enhancements
1. Add hierarchical sub-operation support
2. Implement control flow annotations
3. Add semantic metadata system

### Phase 3: Advanced Features
1. Full execution context modeling
2. Cross-reference generation
3. Decompilation support

## Benefits of These Improvements

### For SCUMM6 Specifically:
- Complete instruction representation
- Accurate parameter extraction
- Proper control flow analysis
- Semantic understanding of operations

### For Kaitai Struct Generally:
- Better support for stack-based VMs
- Enhanced scripting language parsing
- Improved reverse engineering capabilities
- Richer semantic representations

## Alternative Approaches

### 1. **Hybrid Parsing**
Use Kaitai for basic structure, then post-process with semantic analyzer.

### 2. **Code Generation**
Generate specialized parsers from Kaitai definitions with added semantics.

### 3. **Extension System**
Add plugin system to Kaitai for custom parsing logic.

## Conclusion

While Kaitai Struct excels at parsing fixed binary formats, SCUMM6's dynamic scripting language pushes its boundaries. The proposed improvements would make Kaitai suitable for complex VM instruction sets while maintaining its declarative nature. These enhancements would benefit not just SCUMM6 but any stack-based virtual machine format.