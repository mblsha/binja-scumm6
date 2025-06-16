# SCUMM6 Architecture Decoder Selection

## Overview

The SCUMM6 Binary Ninja plugin now supports two different decoders:

1. **Legacy Decoder** - The original implementation with technical bytecode representation
2. **New Decoder** - Object-oriented implementation with semantic, descumm-style representations

## Usage

### Default Architecture (Legacy)
```python
# Uses legacy decoder by default
arch = Scumm6()
```

### Explicit Legacy Architecture
```python
# Explicitly use legacy decoder
arch = Scumm6Legacy()
```

### New Semantic Architecture
```python
# Use new decoder with semantic representations
arch = Scumm6New()
```

## Key Differences

### Legacy Decoder Output
- Technical bytecode representation
- Shows internal details
- Example outputs:
  - `iff(src.scumm6_opcodes, 20)`
  - `push_byte(src.scumm6_opcodes, 18)`
  - `add(src.scumm6_opcodes)`

### New Decoder Output
- Semantic, human-readable representation
- Follows descumm philosophy
- Example outputs:
  - `if goto +20`
  - `push_byte(18)`
  - `add`

## Implementation Details

### Architecture Configuration
The base `Scumm6` class now accepts a `use_new_decoder` parameter:
```python
def __init__(self, use_new_decoder: bool = False) -> None:
    Architecture.__init__(self)
    self.disasm = Scumm6Disasm()
    self.use_new_decoder = use_new_decoder
```

### Methods Supporting Both Decoders
- `decode_instruction()` - Switches between decoders based on configuration
- `get_instruction_text()` - Uses appropriate decoder for disassembly
- `get_instruction_low_level_il()` - Generates LLIL using selected decoder

### Compatibility Layer
The new decoder output is converted to legacy format when needed through `_convert_new_to_legacy()` method, ensuring backward compatibility with existing code that expects the legacy instruction format.

## Testing

Run the test script to verify both decoders work correctly:
```bash
python test_decoder_selection.py
```

## Architecture Registration

In Binary Ninja, you'll see three SCUMM6 architecture options:
- `SCUMM6` - Default (legacy decoder)
- `SCUMM6-Legacy` - Explicit legacy decoder
- `SCUMM6-New` - New semantic decoder

## Benefits

### For Reverse Engineers
- Choose between technical detail (legacy) or semantic clarity (new)
- New decoder makes game logic more apparent
- Control flow instructions are more readable

### For Developers
- Maintains full backward compatibility
- Easy to switch between implementations
- Enables gradual migration to new decoder

## Future Work
- Additional semantic improvements to new decoder
- Performance optimizations
- Extended configuration options