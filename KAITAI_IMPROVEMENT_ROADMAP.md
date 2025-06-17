# Technical Roadmap: Implementing SCUMM6 Semantic Parsing

## Overview

Since Kaitai Struct's core architecture may not change quickly enough to support SCUMM6's complex requirements, this roadmap outlines both ideal Kaitai improvements and practical workarounds available today.

## Approach 1: Kaitai Post-Processing Layer

### Architecture

```
┌─────────────────┐     ┌──────────────────┐     ┌─────────────────┐
│  SCUMM6 Binary  │ --> │  Kaitai Parser   │ --> │ Semantic Layer  │
│      Data       │     │ (Current .ksy)   │     │ (Python/Ruby)   │
└─────────────────┘     └──────────────────┘     └─────────────────┘
                                                           |
                                                           v
                                                  ┌─────────────────┐
                                                  │ Descumm-style   │
                                                  │     Output      │
                                                  └─────────────────┘
```

### Implementation Plan

#### Phase 1: Stack Simulator (Week 1-2)
```python
class StackSimulator:
    """Simulates SCUMM6 stack during parsing."""
    
    def __init__(self):
        self.stack = []
        self.instruction_queue = []
        
    def simulate_instruction(self, instr):
        if instr.op.id == OpType.push_byte:
            self.stack.append(instr.op.body.data)
        elif instr.op.id == OpType.push_word:
            self.stack.append(instr.op.body.data)
        elif instr.needs_stack_args:
            # Extract arguments for variable-arg instructions
            arg_count = self.stack.pop() if instr.has_var_args else instr.fixed_arg_count
            args = [self.stack.pop() for _ in range(arg_count)]
            instr.resolved_args = args
```

#### Phase 2: Semantic Analyzer (Week 3-4)
```python
class SemanticAnalyzer:
    """Adds semantic understanding to parsed instructions."""
    
    def analyze_script(self, instructions):
        # Pattern matching for control flow
        self.identify_control_structures(instructions)
        
        # Resource name resolution
        self.resolve_resource_references(instructions)
        
        # Expression tree building
        self.build_expression_trees(instructions)
        
        # Message parsing
        self.parse_messages(instructions)
```

#### Phase 3: Descumm Output Generator (Week 5-6)
```python
class DescummFormatter:
    """Generates descumm-style output."""
    
    def format_instruction(self, instr):
        if instr.semantic_type == 'function_call':
            return f"{instr.function_name}({', '.join(map(str, instr.args))})"
        elif instr.semantic_type == 'control_flow':
            return self.format_control_flow(instr)
        elif instr.semantic_type == 'expression':
            return self.format_expression(instr)
```

## Approach 2: Extended Kaitai Format

### Custom YAML Preprocessor

Create a preprocessor that extends Kaitai's YAML with SCUMM6-specific features:

```yaml
# scumm6_extended.ksy
meta:
  id: scumm6_opcodes_extended
  extends: kaitai  # Custom extension
  features:
    - stack_tracking
    - variable_repeat
    - semantic_annotations

types:
  start_script:
    stack_input:
      - name: arg_count
        type: u1
      - name: script_id
        type: u2
      - name: args
        type: u4
        repeat: stack[arg_count]  # Extended syntax
    semantic:
      type: script_invocation
      cross_ref: scripts[script_id]
```

### Preprocessor Implementation
```python
class KaitaiExtensionPreprocessor:
    """Converts extended .ksy to standard Kaitai + metadata."""
    
    def process(self, extended_ksy):
        # Extract extended features
        stack_tracking = self.extract_stack_features(extended_ksy)
        semantic_info = self.extract_semantic_annotations(extended_ksy)
        
        # Generate standard Kaitai
        standard_ksy = self.to_standard_kaitai(extended_ksy)
        
        # Generate companion metadata
        metadata = {
            'stack_effects': stack_tracking,
            'semantics': semantic_info
        }
        
        return standard_ksy, metadata
```

## Approach 3: Hybrid Parser Generator

### Code Generation Strategy

Generate specialized parsers that combine Kaitai's structure with semantic understanding:

```python
# Generated from scumm6.ksy + semantic rules
class Scumm6Parser:
    def __init__(self, stream):
        self.stream = stream
        self.stack = StackMachine()
        self.resources = ResourceTable()
        
    def parse_start_script(self):
        # Generated from Kaitai structure
        base = self._parse_base_structure()
        
        # Added semantic layer
        arg_count = self.stack.pop()
        script_id = self.stack.pop()
        args = [self.stack.pop() for _ in range(arg_count)]
        
        return StartScriptInstruction(
            script_id=script_id,
            args=args,
            semantic_name=self.resources.get_script_name(script_id)
        )
```

### Generator Implementation Plan

1. **Parser Generator Core** (Week 1-2)
   - Template engine for code generation
   - Kaitai structure reader
   - Semantic rule system

2. **SCUMM6-Specific Rules** (Week 3-4)
   - Stack operation rules
   - Resource resolution rules
   - Control flow patterns

3. **Integration Layer** (Week 5)
   - Binary Ninja plugin adaptation
   - Testing framework

## Practical Implementation Timeline

### Month 1: Foundation
- Week 1-2: Implement basic stack simulator
- Week 3-4: Add pattern recognition for common constructs

### Month 2: Semantic Layer
- Week 1-2: Message and string parsing
- Week 3-4: Control flow analysis

### Month 3: Output Generation
- Week 1-2: Descumm-compatible formatter
- Week 3-4: Binary Ninja integration

## Recommended Approach

For immediate results, implement **Approach 1** (Post-Processing Layer):

### Advantages:
- Works with existing Kaitai definitions
- Can be implemented incrementally
- No changes to Kaitai Struct needed
- Full control over semantic analysis

### Implementation Steps:

1. **Create Stack Tracker**
```python
class Scumm6StackTracker:
    def track_instruction_effects(self, instr):
        # Track push/pop operations
        # Resolve variable arguments
        # Build expression trees
```

2. **Add Semantic Patterns**
```python
class Scumm6Patterns:
    patterns = [
        IfElsePattern(),
        WhileLoopPattern(),
        SwitchCasePattern(),
        FunctionCallPattern()
    ]
```

3. **Generate Rich Output**
```python
class Scumm6Decompiler:
    def decompile(self, instructions):
        # Apply patterns
        # Build AST
        # Generate descumm-style output
```

## Future Kaitai Improvements

Submit proposals to Kaitai project for:

1. **Stack machine support**
```yaml
meta:
  machine: stack
  stack_size: 256
```

2. **Runtime repeat expressions**
```yaml
repeat: runtime
repeat-source: stack[-1]
```

3. **Cross-instruction context**
```yaml
context:
  maintain: stack
  track: [variables, arrays]
```

4. **Semantic annotations**
```yaml
semantic:
  category: control_flow
  pattern: if_else
  side_effects: [modifies_game_state]
```

## Conclusion

While Kaitai Struct has limitations for SCUMM6's complex scripting language, a post-processing layer can provide full descumm compatibility today. This practical approach allows incremental implementation while maintaining clean separation between binary parsing (Kaitai's strength) and semantic analysis (our added value).

The long-term goal remains enhancing Kaitai itself, but the immediate solution delivers results without waiting for upstream changes.