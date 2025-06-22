#!/bin/bash
# Run the SCUMM6 comparison TUI

# Get the directory of this script
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"

# Change to the plugin root directory
cd "$SCRIPT_DIR/../.."

# Run the TUI
python tools/scumm6-tui/scumm6_compare.py "$@"