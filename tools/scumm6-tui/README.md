# SCUMM6 Disassembly Comparison Tool

A terminal user interface (TUI) and command-line tool for comparing disassembly output between the industry-standard `descumm` tool and the `pyscumm6` Binary Ninja plugin.

## Features

- **Interactive TUI**: Browse all scripts with real-time search and filtering
- **Three-way comparison**: View descumm, pyscumm6 (fused), and pyscumm6 (raw) outputs side-by-side
- **Fuzzy matching**: Smart comparison that handles formatting differences
- **CLI mode**: Scriptable interface for automation and testing
- **JSON export**: Machine-readable comparison results

## Installation

```bash
pip install -r requirements.txt
```

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

- **Arrow keys**: Navigate script list
- **Enter**: Open detailed comparison view
- **ESC**: Go back / Cancel search
- **/**: Search scripts by name
- **q**: Quit application
- **r**: Refresh all comparisons

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