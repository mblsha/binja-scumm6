# Instruction Fusion Roadmap

This document outlines the future enhancements and implementation strategies for extending the instruction fusion system in the SCUMM6 Binary Ninja plugin.

## Phase 1: Basic Consumer Instruction Fusion

### 1.1 Variable Write Operations ✅ Priority: High

Implement fusion for variable assignment instructions to transform stack operations into readable assignments.

#### WriteByteVar / WriteWordVar
```python
# Current output:
push_byte(5)
write_byte_var(var_10)

# With fusion:
var_10 = 5
```

**Implementation Notes:**
- Single operand fusion (value to assign)
- Update `lift()` to use `il.set_reg()` directly
- Consider showing type hints: `var_10: byte = 5`

### 1.2 Array Write Operations ✅ Priority: High

Array operations consume both index and value from the stack.

#### ByteArrayWrite / WordArrayWrite
```python
# Current output:
push_byte(3)      # index
push_byte(10)     # value
byte_array_write(array_5)

# With fusion:
array_5[3] = 10
```

**Implementation Notes:**
- Two operand fusion (index, value)
- Maintain proper operand order (first push = index)
- Handle both byte and word array variants

### 1.3 Function Calls with Arguments ✅ Priority: High

Many SCUMM functions consume multiple stack arguments.

#### DrawObject
```python
# Current output:
push_word(100)    # object_id
push_word(200)    # x
push_word(150)    # y
draw_object

# With fusion:
draw_object(100, 200, 150)
# Or with parameter names:
draw_object(obj_id=100, x=200, y=150)
```

#### StartScript / StartScriptQuick
```python
# Current output:
push_word(93)     # script_id
push_byte(1)      # arg1
push_byte(2)      # arg2
start_script_quick

# With fusion:
start_script_quick(93, [1, 2])
```

**Implementation Notes:**
- Variable argument counts per instruction
- Consider showing parameter names for clarity
- Handle both regular and "quick" variants

## Phase 2: Control Flow Fusion

### 2.1 Conditional Expression Fusion ✅ Priority: High

Fuse comparison operations with conditional jumps to create readable if statements.

```python
# Current output:
push_word_var(var_5)
push_word(10)
gt
if_not(+20)

# With fusion:
if (var_5 <= 10) goto +20
# Or better:
unless (var_5 > 10) goto +20
```

### 2.2 Complex Boolean Expressions

Handle compound conditions with logical operators.

```python
# Current output:
push_var(x)
push_byte(10)
gt
push_var(y)
push_byte(20)
lt
land
if_not(+30)

# With fusion:
if (!(x > 10 && y < 20)) goto +30
# Or:
unless (x > 10 && y < 20) goto +30
```

**Implementation Notes:**
- Track boolean expression trees
- Handle operator precedence
- Consider De Morgan's law for negations

## Phase 3: Expression Tree Building

### 3.1 Multi-Level Arithmetic Expressions

Build complete expression trees from nested operations.

```python
# Current output:
push_var(a)
push_var(b)
add
push_var(c)
mul
push_var(d)
sub
write_var(x)

# With fusion:
var_x = (a + b) * c - d
```

### 3.2 Function Return Value Handling

Many SCUMM functions push results onto the stack.

```python
# Current output:
push_var(obj)
get_object_x
push_byte(10)
add
write_var(new_x)

# With fusion:
var_new_x = get_object_x(obj) + 10
```

**Implementation Strategy:**
- Mark instructions that push results
- Allow them to participate in expression building
- Track data flow through the stack

## Phase 4: Advanced Semantic Analysis

### 4.1 Pattern Recognition

Identify common programming patterns and transform them into high-level constructs.

#### Loop Detection
```python
# Current bytecode pattern:
label_1:
  push_var(i)
  push_byte(10)
  lt
  if_not(label_2)
  # loop body
  push_var(i)
  inc
  write_var(i)
  jump(label_1)
label_2:

# Recognize as:
for (i = 0; i < 10; i++) {
  // loop body
}
```

#### Switch Statement Recognition
```python
# Pattern of multiple comparisons on same variable
# Transform to switch/case structure
```

### 4.2 Variable Type Inference

Use context to infer variable types and provide better names.

```python
# If var_93 is always used with actor functions:
var_93 → actor_id

# If var_45 is used with object coordinates:
var_45 → obj_x_pos
```

### 4.3 Function Signature Database

Build a comprehensive database of SCUMM function signatures.

```yaml
draw_object:
  params:
    - name: object_id
      type: word
    - name: x_pos
      type: word
    - name: y_pos
      type: word
  returns: void
  
get_object_x:
  params:
    - name: object_id
      type: word
  returns: word
  pushes_result: true
```

## Phase 5: Cross-Block and Interprocedural Analysis

### 5.1 Cross-Block Fusion

Handle fusion across basic block boundaries safely.

**Challenges:**
- Control flow convergence
- Multiple predecessors
- Exception handling

**Solution:**
- Use data flow analysis
- Track stack state at block boundaries
- Conservative fusion only when safe

### 5.2 Interprocedural Stack Analysis

Track stack effects across function calls.

```python
# Function A pushes values
# Function B consumes them
# Analyze together for complete picture
```

## Implementation Priorities

### High Priority (Immediate Impact)
1. Variable write operations (var_x = 5)
2. Array write operations (array[i] = val)
3. Common function calls (draw_object, start_script)
4. Basic conditional fusion (if var > 10)

### Medium Priority (Significant Enhancement)
1. Multi-level expression building
2. Boolean expression fusion
3. Loop pattern detection
4. Function return value handling

### Low Priority (Advanced Features)
1. Full AST construction
2. Type inference system
3. Cross-block analysis
4. Custom pattern matching DSL

## Technical Considerations

### Performance Impact
- Fusion adds decoding overhead
- Consider caching fused instructions
- Profile on large scripts
- Add fusion level settings

### Correctness Guarantees
- Extensive test coverage required
- Property-based testing for complex patterns
- Comparison with descumm output
- Formal verification of transformations

### Binary Ninja Integration
- Ensure IL generation remains correct
- Update data flow analysis
- Consider impact on decompiler
- Maintain debugging information

### Extensibility
- Plugin system for custom fusion rules
- Configuration file for patterns
- User-defined transformations
- Export/import fusion rules

## Success Metrics

1. **Readability**: Output should approach descumm quality
2. **Correctness**: No semantic changes from fusion
3. **Performance**: <10% overhead on typical scripts
4. **Coverage**: 80%+ of common patterns fused
5. **Maintainability**: Clear, documented fusion rules

## Research Directions

### Machine Learning Approaches
- Train models on descumm output
- Learn common patterns automatically
- Predict variable purposes

### Formal Methods
- Prove fusion correctness
- Generate fusion rules from specifications
- Verify stack state transformations

### Integration with Decompilers
- Feed fused IL to decompiler
- Custom decompiler passes
- Round-trip engineering support

## Next Steps

1. **Implement Phase 1.1**: Variable write fusion
2. **Create fusion benchmark suite**: Measure improvements
3. **Build pattern library**: Common SCUMM idioms
4. **Design configuration system**: User preferences
5. **Document fusion API**: For extensions

This roadmap will evolve as we gain experience with the fusion system and receive user feedback.