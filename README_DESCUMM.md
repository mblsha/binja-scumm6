# Descumm Tool Setup and Testing

This directory contains scripts to set up and test the `descumm` tool from scummvm-tools for decompiling SCUMM6 scripts.

## Files

- **`setup_descumm.py`** - Main setup script that handles everything automatically
- **`test_descumm.py`** - Comprehensive test suite and demonstration
- **`README_DESCUMM.md`** - This file

## Quick Start

### Automatic Setup

Run the setup script to automatically configure everything:

```bash
python setup_descumm.py
```

This will:
1. Initialize git submodules (including scummvm-tools)
2. Configure and compile the scummvm-tools
3. Download the Day of the Tentacle demo files
4. Convert demo files to .bsc6 format
5. Extract a test script from the demo
6. Test the descumm tool with the extracted script

### Manual Usage

Once set up, you can use the descumm tool directly:

```bash
# Decompile a SCUMM6 script (unblocked format)
./scummvm-tools/descumm -6 -u script-file.bin

# Show offsets in output
./scummvm-tools/descumm -6 -u -o script-file.bin

# For other SCUMM versions, change the version number
./scummvm-tools/descumm -5 -u script-file.bin
```

### Python Interface

Use the Python classes for programmatic access:

```python
from setup_descumm import DescummSetup
from test_descumm import DescummRunner, ScriptExtractor

# Set up the tool
setup = DescummSetup()
setup.setup()

# Extract scripts from a BSC6 file
extractor = ScriptExtractor("dottdemo.bsc6")
scripts = extractor.extract_all_scripts("output_dir")

# Decompile scripts
runner = DescummRunner()
for script_name, script_path in scripts:
    output = runner.decompile_script(str(script_path))
    print(f"=== {script_name} ===")
    print(output)
```

## Testing

### Run the Demo

See the tool in action with extracted scripts from the Day of the Tentacle demo:

```bash
python test_descumm.py --demo
```

### Run Unit Tests

Run the comprehensive test suite:

```bash
python test_descumm.py --test
```

### Run All Tests

```bash
python test_descumm.py
```

## Command Line Options for descumm

The descumm tool supports various options:

- **`-0` to `-8`** - SCUMM version (0-8)
- **`-gNNN`** - HE version NNN
- **`-u`** - Script is unblocked/has no header
- **`-o`** - Always show offsets
- **`-i`** - Don't output ifs
- **`-e`** - Don't output else
- **`-f`** - Don't output else-if
- **`-w`** - Don't output while
- **`-b`** - Don't output breaks
- **`-c`** - Don't show opcode
- **`-x`** - Don't show offsets
- **`-h`** - Halt on error

## Example Output

When you run `descumm -6 -u script-portion-of-dott-demo`, you'll see output like:

```
[0000] (AC) soundKludge([264,4,0,47,0])
[0013] (AC) soundKludge([270,4,3])
[0020] (AC) soundKludge([271,262,4,0])
[0030] (AC) soundKludge([271,-1])
[003A] (AC) soundKludge([-1])
[0041] (43) bitvar93 = 0
[0047] (9D) actorOps.setCurActor(7)
[004C] (9D) actorOps.init()
[004E] (9D) actorOps.setCostume(6)
[0053] (9D) actorOps.setTalkColor(13)
[0058] (9D) actorOps.setName("Purple Tentacle")
...
END
```

## Dependencies

The setup script will check for these dependencies:

- **git** - For submodule management
- **make** - For building scummvm-tools
- **g++** - C++ compiler
- **python3** - For the converter and test scripts

Additional Python packages (installed automatically):
- **kaitaistruct** - For parsing BSC6 files
- **pytest** - For running tests

## Troubleshooting

### Build Issues

If compilation fails:
1. Make sure you have build-essential installed: `sudo apt-get install build-essential`
2. Check that git submodules are initialized: `git submodule update --init --recursive`
3. Try cleaning and rebuilding: `cd scummvm-tools && make clean && make`

### Script Extraction Issues

If script extraction fails:
1. Make sure the BSC6 file was created successfully
2. Check that Python dependencies are installed: `pip install -e .[dev]`
3. Verify the demo files were downloaded correctly

### Descumm Errors

Some scripts may fail to decompile due to:
- Corrupted or invalid script data
- Unsupported SCUMM opcodes
- Scripts that aren't actually SCUMM6 format

This is normal - not all extracted data will be valid scripts.

## Integration with Binary Ninja

This tool is designed to work with the SCUMM6 Binary Ninja plugin. The extracted and decompiled scripts can help understand the game's logic and assist in reverse engineering SCUMM6 games.

## License

This setup uses scummvm-tools which is licensed under GPL. See the scummvm-tools directory for license information.

