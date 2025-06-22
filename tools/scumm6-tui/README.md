# SCUMM6 Disassembly Comparison Tool

A terminal user interface (TUI) and command-line tool for comparing disassembly output between the industry-standard `descumm` tool and the `pyscumm6` Binary Ninja plugin.

## Features

- **Interactive TUI**: Browse all scripts with real-time search and filtering
- **Progress indicator**: Shows analysis progress for each script during startup
- **Three-way comparison**: View descumm, pyscumm6 (fused), and pyscumm6 (raw) outputs side-by-side
- **Fuzzy matching**: Smart comparison that handles formatting differences
- **CLI mode**: Scriptable interface for automation and testing
- **JSON export**: Machine-readable comparison results

## Installation

```bash
cd tools/scumm6-tui
pip install -r requirements.txt
```

Note: The TUI requires the Textual library. If you get import errors, make sure to install the requirements.

## Usage

### Interactive TUI Mode (Default)

```bash
./run.sh
```

Or from the plugin root:
```bash
python tools/scumm6-tui/scumm6_compare.py
```

### CLI Mode

#### List all scripts
```bash
./run.sh --list
./run.sh --list --filter room8  # Filter by pattern
```

#### Compare specific script
```bash
./run.sh --compare room8_scrp18  # JSON output
./run.sh --compare room8_scrp18 --diff  # Human-readable diff
./run.sh --compare room8_scrp18 --output results.json  # Save to file
```

#### Override file paths
```bash
./run.sh --bsc6-path /path/to/DOTTDEMO.bsc6 --descumm-path /path/to/descumm
```

## TUI Navigation

### Main Screen
- **Arrow keys**: Navigate script list
- **Enter**: Open detailed comparison view
- **ESC**: Cancel search
- **/**: Search scripts by name
- **q**: Quit application
- **r**: Refresh all comparisons

### Diff View
- **ESC**: Return to script list
- **h**: Toggle difference highlighting
- **s**: Toggle synchronized scrolling
- **Arrow keys / Page Up/Down**: Scroll through diff

## Advanced Diff Features

### Synchronized Scrolling
All three panels scroll together, making it easy to compare the same section across different disassemblers.

### Difference Highlighting
- **Green**: Lines added in pyscumm6
- **Red**: Lines with major differences
- **Yellow**: Lines with moderate differences
- **Cyan**: Lines with minor differences
- **White**: Matching lines

### Line Alignment
The diff view automatically aligns corresponding lines across panels, inserting blank lines where needed to maintain visual correspondence.

## Understanding the Results

### Match Status
- **✓** (Green): Outputs are semantically equivalent
- **✗** (Red): Significant differences detected

### Match Score
Percentage of lines that match after normalization (variable names, spacing, etc.)

### Comparison View
- **Left panel**: descumm output (target/reference)
- **Middle panel**: pyscumm6 with instruction fusion
- **Right panel**: pyscumm6 without fusion (raw)

## Testing

Run the CLI test suite:
```bash
python test_cli.py
```

## Requirements

- Python 3.8+
- DOTTDEMO.bsc6 file (Day of the Tentacle demo)
- descumm executable (built from scummvm-tools)

The tool will search common locations for these files, or you can specify paths explicitly.