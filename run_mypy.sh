#!/usr/bin/env bash
# Run mypy from the repository root even if this script is invoked via an
# absolute path from another directory.  ``BASH_SOURCE[0]`` resolves to the
# path of this script.  Using it allows the script to locate ``run_mypy.py``
# relative to its own location instead of the current working directory.
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR" || exit
python scripts/run_mypy.py
