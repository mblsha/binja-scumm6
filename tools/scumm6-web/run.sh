#!/bin/bash
# Run the SCUMM6 comparison web app

# Get the directory of this script
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"

# Change to the plugin root directory
cd "$SCRIPT_DIR/../.."

# Run the web app
python tools/scumm6-web/app.py "$@"