#!/usr/bin/env python3
"""
Direct pytest runner that forces the use of mocked Binary Ninja modules.
This avoids issues with subprocess environment inheritance.
"""

import sys
from pathlib import Path
import pytest

# Add repository root to Python path so we can import scripts.setup
repo_root = Path(__file__).resolve().parent.parent
if str(repo_root) not in sys.path:
    sys.path.insert(0, str(repo_root))

from scripts.setup import setup_test_environment  # noqa: E402

if __name__ == "__main__":
    setup_test_environment()
    sys.exit(pytest.main(sys.argv[1:]))

    # sys.exit(pytest.main([
    #     "--cov=src",
    #     "--cov-report=xml",
    #     "--cov-report=term"
    # ] + sys.argv[1:]))
