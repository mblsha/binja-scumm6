# Binary Ninja Restart Scripts

This directory contains Python scripts for restarting Binary Ninja and loading files with process monitoring capabilities. Both scripts use Plumbum CLI for clean argument handling.

## Requirements

- Python 3.6+
- Plumbum: `pip install plumbum`
- macOS with Binary Ninja installed
- Accessibility permissions for Terminal/iTerm (for window detection)

## Available Scripts

### 1. **binja_restart_monitor.py** - Process Monitor

A reliable script with process monitoring and CPU usage detection to ensure files are fully loaded.

**Usage:**
```bash
./binja_restart_monitor.py [OPTIONS] [file_path]
```

**Options:**
- `-h, --help` - Show help message
- `-t, --timeout SECONDS` - Timeout for window detection (default: 30)
- `-g, --graceful-timeout SECONDS` - Timeout for graceful quit (default: 5)
- `-w, --wait SECONDS` - Extra wait time after window appears (default: 3)
- `-f, --force` - Skip graceful quit and force kill immediately
- `-v, --verbose` - Enable verbose output

**Examples:**
```bash
# Open Binary Ninja without file
./binja_restart_monitor.py

# Open specific file with verbose output
./binja_restart_monitor.py -v ~/Downloads/program.bin

# Force kill with extended timeout
./binja_restart_monitor.py -f -t 60 myfile.bin
```

**Features:**
- Process existence checking
- Graceful quit with configurable timeout
- Automatic handling of "Save changes?" dialogs (clicks "Don't Save")
- Window detection and verification
- Progress indicators
- Detailed error reporting

### 2. **binja_restart_advanced.py** - Advanced Controller

An advanced controller with enhanced monitoring capabilities and preparation for future Binary Ninja API integration.

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

When no file path is provided, both scripts will:
- Kill any existing Binary Ninja instances
- Launch Binary Ninja without opening any file
- Wait for the main window to appear

This is useful for:
- Starting fresh Binary Ninja sessions
- Clearing memory after crashes
- Automation workflows where files are opened later

## Key Differences

| Feature | Monitor Script | Advanced Script |
|---------|---------------|-----------------|
| Complexity | Simple, focused | Feature-rich |
| Wait Strategy | Fixed wait time | Configurable stabilization |
| Logging | Basic | Timestamped with levels |
| Configuration | Essential options | Extensive customization |
| Use Case | Quick restarts | Complex workflows |

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
- Increase `-w` or `--wait` time for monitor script
- Use `-s` or `--stabilization-time` for advanced script
- These wait times ensure Binary Ninja has time to load files

### Process won't quit
- Use `-f` or `--force` flag to skip graceful quit
- Check Activity Monitor for stuck processes

## Version Information

- Monitor Script: 1.0.0
- Advanced Script: 2.0.0

Both scripts are actively maintained and tested with Binary Ninja Personal 5.1.x on macOS.