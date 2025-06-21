# Simple Script Analysis Report

## Overview
Analyzed 8 simple scripts from DOTTDEMO.bsc6

## Fusion Gaps Identified
- descumm cannot process this script (too small)

## Detailed Script Analysis

### room1_exit
**Bytecode**: `65`

**Descumm Output:**
```
Error: ERROR: 2File too small to be a script!
```

**Current Fusion Output:**
```
[0000] stop_object_code1
```

**Gaps:**
- descumm cannot process this script (too small)


### room1_enter
**Bytecode**: `65`

**Descumm Output:**
```
Error: ERROR: 2File too small to be a script!
```

**Current Fusion Output:**
```
[0000] stop_object_code1
```

**Gaps:**
- descumm cannot process this script (too small)


### room5_exit
**Bytecode**: `65`

**Descumm Output:**
```
Error: ERROR: 2File too small to be a script!
```

**Current Fusion Output:**
```
[0000] stop_object_code1
```

**Gaps:**
- descumm cannot process this script (too small)


### room2_exit
**Bytecode**: `0105007c65`

**Descumm Output:**
```
Error: ERROR: 2File too small to be a script!
```

**Current Fusion Output:**
```
[0000] stop_object_code1
[0001] stop_object_code1
[0002] stop_object_code1
[0003] stop_object_code1
[0004] stop_object_code1
```

**Gaps:**
- descumm cannot process this script (too small)


### room9_enter
**Bytecode**: `01000001c8009cae65`

**Descumm Output:**
```
Error: ERROR: 1Unknown script type!
```

**Current Fusion Output:**
```
[0000] stop_object_code1
[0001] stop_object_code1
[0002] stop_object_code1
[0003] stop_object_code1
[0004] stop_object_code1
[0005] stop_object_code1
[0006] stop_object_code1
[0007] stop_object_code1
[0008] stop_object_code1
```

**Gaps:**
- descumm cannot process this script (too small)


### room7_enter
**Bytecode**: `01000001c8000100005e65`

**Descumm Output:**
```
Error: ERROR: 1Unknown script type!
```

**Current Fusion Output:**
```
[0000] stop_object_code1
[0001] stop_object_code1
[0002] stop_object_code1
[0003] stop_object_code1
[0004] stop_object_code1
[0005] stop_object_code1
[0006] stop_object_code1
[0007] stop_object_code1
[0008] stop_object_code1
[0009] stop_object_code1
[000A] stop_object_code1
```

**Gaps:**
- descumm cannot process this script (too small)


### room10_exit
**Bytecode**: `0107008b5d08000100000190009cae65`

**Descumm Output:**
```
Error: ERROR: 1Unknown script type!
```

**Current Fusion Output:**
```
[0000] stop_object_code1
[0001] stop_object_code1
[0002] stop_object_code1
[0003] stop_object_code1
[0004] stop_object_code1
[0005] stop_object_code1
[0006] stop_object_code1
[0007] stop_object_code1
[0008] stop_object_code1
[0009] stop_object_code1
[000A] stop_object_code1
[000B] stop_object_code1
[000C] stop_object_code1
[000D] stop_object_code1
[000E] stop_object_code1
[000F] stop_object_code1
```

**Gaps:**
- descumm cannot process this script (too small)


### room2_enter
**Bytecode**: `01010001c9000100005e0105000100005f65`

**Descumm Output:**
```
Error: ERROR: 1Unknown script type!
```

**Current Fusion Output:**
```
[0000] stop_object_code1
[0001] stop_object_code1
[0002] stop_object_code1
[0003] stop_object_code1
[0004] stop_object_code1
[0005] stop_object_code1
[0006] stop_object_code1
[0007] stop_object_code1
[0008] stop_object_code1
[0009] stop_object_code1
[000A] stop_object_code1
[000B] stop_object_code1
[000C] stop_object_code1
[000D] stop_object_code1
[000E] stop_object_code1
[000F] stop_object_code1
[0010] stop_object_code1
[0011] stop_object_code1
```

**Gaps:**
- descumm cannot process this script (too small)

## Fusion Patterns

### Simple function call formatting
**Description**: Single-byte opcodes should render as function calls

**Example Bytecode**: `65`

**Current Output**: `stop_object_code`

**Ideal Output**: `stopObjectCodeA()`

**Implementation Notes:**
1. Add a function name mapping table
2. Render with parentheses for consistency
3. Match descumm's exact function names

## Generated Test Cases
Add these test cases to validate fusion improvements:

### Test for room1_exit
```python

def test_room1_exit_fusion():
    """Test fusion for room1_exit."""
    bytecode = bytes.fromhex("65")
    
    # Test with fusion
    instr = decode_with_fusion(bytecode, 0)
    tokens = instr.render()
    text = ''.join(t.text for t in tokens)
    
    # Expected output (from descumm)
    expected_lines = ['Error: ERROR: 2File too small to be a script!']
    
    # Compare key elements
    # TODO: Add specific assertions based on expected output

```

### Test for room1_enter
```python

def test_room1_enter_fusion():
    """Test fusion for room1_enter."""
    bytecode = bytes.fromhex("65")
    
    # Test with fusion
    instr = decode_with_fusion(bytecode, 0)
    tokens = instr.render()
    text = ''.join(t.text for t in tokens)
    
    # Expected output (from descumm)
    expected_lines = ['Error: ERROR: 2File too small to be a script!']
    
    # Compare key elements
    # TODO: Add specific assertions based on expected output

```

### Test for room5_exit
```python

def test_room5_exit_fusion():
    """Test fusion for room5_exit."""
    bytecode = bytes.fromhex("65")
    
    # Test with fusion
    instr = decode_with_fusion(bytecode, 0)
    tokens = instr.render()
    text = ''.join(t.text for t in tokens)
    
    # Expected output (from descumm)
    expected_lines = ['Error: ERROR: 2File too small to be a script!']
    
    # Compare key elements
    # TODO: Add specific assertions based on expected output

```

### Test for room2_exit
```python

def test_room2_exit_fusion():
    """Test fusion for room2_exit."""
    bytecode = bytes.fromhex("0105007c65")
    
    # Test with fusion
    instr = decode_with_fusion(bytecode, 0)
    tokens = instr.render()
    text = ''.join(t.text for t in tokens)
    
    # Expected output (from descumm)
    expected_lines = ['Error: ERROR: 2File too small to be a script!']
    
    # Compare key elements
    # TODO: Add specific assertions based on expected output

```

### Test for room9_enter
```python

def test_room9_enter_fusion():
    """Test fusion for room9_enter."""
    bytecode = bytes.fromhex("01000001c8009cae65")
    
    # Test with fusion
    instr = decode_with_fusion(bytecode, 0)
    tokens = instr.render()
    text = ''.join(t.text for t in tokens)
    
    # Expected output (from descumm)
    expected_lines = ['Error: ERROR: 1Unknown script type!']
    
    # Compare key elements
    # TODO: Add specific assertions based on expected output

```

### Test for room7_enter
```python

def test_room7_enter_fusion():
    """Test fusion for room7_enter."""
    bytecode = bytes.fromhex("01000001c8000100005e65")
    
    # Test with fusion
    instr = decode_with_fusion(bytecode, 0)
    tokens = instr.render()
    text = ''.join(t.text for t in tokens)
    
    # Expected output (from descumm)
    expected_lines = ['Error: ERROR: 1Unknown script type!']
    
    # Compare key elements
    # TODO: Add specific assertions based on expected output

```

### Test for room10_exit
```python

def test_room10_exit_fusion():
    """Test fusion for room10_exit."""
    bytecode = bytes.fromhex("0107008b5d08000100000190009cae65")
    
    # Test with fusion
    instr = decode_with_fusion(bytecode, 0)
    tokens = instr.render()
    text = ''.join(t.text for t in tokens)
    
    # Expected output (from descumm)
    expected_lines = ['Error: ERROR: 1Unknown script type!']
    
    # Compare key elements
    # TODO: Add specific assertions based on expected output

```

### Test for room2_enter
```python

def test_room2_enter_fusion():
    """Test fusion for room2_enter."""
    bytecode = bytes.fromhex("01010001c9000100005e0105000100005f65")
    
    # Test with fusion
    instr = decode_with_fusion(bytecode, 0)
    tokens = instr.render()
    text = ''.join(t.text for t in tokens)
    
    # Expected output (from descumm)
    expected_lines = ['Error: ERROR: 1Unknown script type!']
    
    # Compare key elements
    # TODO: Add specific assertions based on expected output

```
