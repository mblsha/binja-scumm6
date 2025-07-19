# SCUMM6 Scripts

This directory contains utility scripts specific to the SCUMM6 Binary Ninja plugin, as well as symlinks to shared Binary Ninja utilities.

## Shared Binary Ninja Scripts (Symlinks)

The following scripts are symlinks to shared utilities in the binary_ninja_mcp plugin:

### binja-restart.py
Advanced Binary Ninja restart utility (symlink to `../../binary_ninja_mcp/scripts/binja-restart.py`).
See the [shared scripts README](../../binary_ninja_mcp/scripts/README.md) for full documentation.

### binja-cli.py
Binary Ninja MCP command-line interface (symlink to `../../binary_ninja_mcp/scripts/binja-cli.py`).
See the [shared scripts README](../../binary_ninja_mcp/scripts/README.md) for full documentation.

## SCUMM6-Specific Scripts

### ensure_descumm.py
[Description needed]

### show_instruction_info.py
Display instruction info at specific addresses. Meant to be run from Binary Ninja's Python console.

### Other Scripts
- `list-project-files.fish` - Fish shell script for listing project files
- `run_mypy.py` / `run_mypy.sh` - Type checking scripts
- `run_pytest_direct.py` - Direct pytest runner
- `setup.py` - Setup script

## Legacy Documentation

**Note:** The Binary Ninja restart script (`binja_restart_advanced.py`) has been moved to the shared scripts directory.
For usage information, see [binary_ninja_mcp/scripts/README.md](../../binary_ninja_mcp/scripts/README.md).

The following documentation is preserved for reference:

**Usage:**
```bash
./binja_restart_advanced.py [OPTIONS] [file_path]
```

**Options:**
- `-h, --help` - Show help message
- `-t, --timeout SECONDS` - Overall timeout (default: 60)
- `-b, --binja-path PATH` - Path to Binary Ninja.app (default: /Applications/Binary Ninja.app)
- `-w, --window-wait SECONDS` - Timeout for window detection (default: 30)
- `-s, --stabilization-time SECONDS` - Additional wait time after window appears (default: 5)
- `-f, --force` - Force kill without graceful quit
- `-v, --verbose` - Enable verbose output with timestamps
- `--monitor-interval SECONDS` - Interval between checks (default: 0.5)
- `--startup-script` - Create startup script (experimental, currently disabled)

**Examples:**
```bash
# Open Binary Ninja without file
./binja_restart_advanced.py

# Custom Binary Ninja location
./binja_restart_advanced.py -b "/Applications/Binary Ninja Beta.app" myfile.bin

# Extended timeouts with verbose logging
./binja_restart_advanced.py -v -t 120 -w 60 myfile.bin

# Fast monitoring with short intervals
./binja_restart_advanced.py --monitor-interval 0.1 -s 10 myfile.bin
```

**Features:**
- Two-phase monitoring (window detection + stabilization wait)
- Configurable monitoring intervals
- Automatic handling of "Save changes?" dialogs (clicks "Don't Save")
- Enhanced logging with timestamps and levels
- Elapsed time reporting
- Preparation for Binary Ninja API integration
- Temporary script creation capability (for future use)

## File Handling

When no file path is provided, the script will:
- Kill any existing Binary Ninja instances
- Launch Binary Ninja without opening any file
- Wait for the main window to appear

This is useful for:
- Starting fresh Binary Ninja sessions
- Clearing memory after crashes
- Automation workflows where files are opened later

## Quick Start

For simple use cases similar to the removed monitor script, you can use these aliases:

```bash
# Simple restart with default settings
alias binja-restart='./binja_restart_advanced.py -b "/Applications/Binary Ninja.app"'

# Simple restart with file
alias binja-restart-file='./binja_restart_advanced.py -b "/Applications/Binary Ninja.app" -s 3'
```

## Key Features

| Feature | Description |
|---------|-----------------|
| Wait Strategy | Configurable stabilization time |
| Logging | Timestamped with multiple levels |
| Configuration | Extensive customization options |
| Monitoring | Two-phase with intervals |
| Error Handling | Graceful quit with dialog handling |

## Troubleshooting

### "osascript is not allowed assistive access"
Grant Terminal/iTerm accessibility permissions:
1. System Preferences → Security & Privacy → Privacy → Accessibility
2. Add and enable Terminal or iTerm2

### Window detection fails
- Ensure Binary Ninja is installed at the expected location
- Check that the file path is correct
- Try increasing timeout values

### File not fully loaded
- Use `-s` or `--stabilization-time` to increase wait time after window appears
- This wait time ensures Binary Ninja has time to fully load files

### Process won't quit
- Use `-f` or `--force` flag to skip graceful quit
- Check Activity Monitor for stuck processes

## Version Information

- Advanced Script: 2.0.0

The script is actively maintained and tested with Binary Ninja Personal 5.1.x on macOS.