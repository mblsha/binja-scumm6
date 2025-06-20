#!/usr/bin/env python3
"""
Subprocess-based pytest runner that forces the use of mocked Binary Ninja modules.
Note: run_pytest_direct.py is preferred as it avoids subprocess complexity.
"""

import os
import sys
import subprocess
from pathlib import Path
from scripts.setup import setup_test_environment

if __name__ == "__main__":
    # Set up the test environment in the current process
    setup_test_environment()
    print("Using binja_helpers stubs for testing")
    
    # Get repo root for subprocess
    repo_root = Path(__file__).resolve().parent.parent
    helper_dir = repo_root / "binja_helpers_tmp"
    
    # Set environment for pytest subprocess to find the modules, excluding Binary Ninja
    existing_pythonpath = os.environ.get("PYTHONPATH", "")
    pythonpath_parts = [str(helper_dir), str(repo_root)]
    
    # Add existing PYTHONPATH parts that are not Binary Ninja paths
    if existing_pythonpath:
        for part in existing_pythonpath.split(":"):
            if part and "Binary Ninja" not in part and part not in pythonpath_parts:
                pythonpath_parts.append(part)
    
    # Create environment for subprocess
    env = os.environ.copy()
    env["PYTHONPATH"] = ":".join(pythonpath_parts)
    env["FORCE_BINJA_MOCK"] = "1"
    
    # Run pytest with the arguments passed to this script
    cmd = ["pytest"] + sys.argv[1:]
    result = subprocess.run(cmd, cwd=repo_root, env=env)
    sys.exit(result.returncode)
