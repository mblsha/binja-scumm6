#!/usr/bin/env python3
"""
Direct pytest runner that forces the use of mocked Binary Ninja modules.
This avoids issues with subprocess environment inheritance.
"""

import os
import sys
from pathlib import Path

# Force use of mock
os.environ["FORCE_BINJA_MOCK"] = "1"

# Ensure repository root is in sys.path
repo_root = Path(__file__).resolve().parent
sys.path.insert(0, str(repo_root))

# Add binja_helpers to path FIRST
helper_dir = repo_root / "binja_helpers_tmp"
if helper_dir.is_dir():
    sys.path.insert(0, str(helper_dir))

# Import mock BEFORE any real Binary Ninja modules can be loaded
from binja_helpers import binja_api  # noqa: F401

# Remove any real Binary Ninja paths that might have been added
bn_path = os.path.expanduser("~/Applications/Binary Ninja.app/Contents/Resources/python/")
if bn_path in sys.path:
    sys.path.remove(bn_path)

# Import pytest and run
import pytest

# Run pytest with the provided arguments
if __name__ == "__main__":
    sys.exit(pytest.main([
        "--cov=src", 
        "--cov-report=xml", 
        "--cov-report=term"
    ] + sys.argv[1:]))