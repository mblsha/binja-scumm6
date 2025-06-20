#!/usr/bin/env python3
"""
Direct pytest runner that forces the use of mocked Binary Ninja modules.
This avoids issues with subprocess environment inheritance.
"""

import sys
import pytest
from scripts.setup import setup_test_environment

if __name__ == "__main__":
    setup_test_environment()
    sys.exit(pytest.main(sys.argv[1:]))

    # sys.exit(pytest.main([
    #     "--cov=src",
    #     "--cov-report=xml",
    #     "--cov-report=term"
    # ] + sys.argv[1:]))
