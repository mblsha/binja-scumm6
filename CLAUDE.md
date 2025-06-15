# SCUMM6 Binary Ninja Plugin - Development Guide

## Running Tests

To run tests correctly, use one of these methods:

### Method 1: Use the test runner script (Recommended)
```bash
./run-tests.fish --once
```

This script automatically:
- Sets up the proper mocking environment
- Runs ruff, mypy, and pytest
- Watches for file changes (unless `--once` is used)

### Method 2: Run pytest directly with proper environment
```bash
python scripts/run_pytest_direct.py
```

This ensures the `FORCE_BINJA_MOCK=1` environment variable is set and loads the mocked Binary Ninja API.

## Why the Special Test Setup?

This plugin requires Binary Ninja to be installed and licensed. For testing without a license, we use a mocked version of the Binary Ninja API. The key requirements are:

1. Set `FORCE_BINJA_MOCK=1` environment variable
2. Import `binja_helpers.binja_api` before any real Binary Ninja modules
3. Ensure `binja_helpers_tmp` is in the Python path

## Test Structure

- Individual test files can set up mocking by importing `os` and setting `os.environ["FORCE_BINJA_MOCK"] = "1"` at the top
- All tests should import `from binja_helpers import binja_api  # noqa: F401` to ensure proper mocking

## Common Issues

- **License errors**: If you see `RuntimeError: License is not valid. Please supply a valid license.` when running tests or mypy, you need to force the use of mock Binary Ninja functions. Make sure to use the proper test runner or set `FORCE_BINJA_MOCK=1` environment variable before running any commands that import Binary Ninja modules.
- **Import errors**: The mocked API may not have all the same imports as the real Binary Ninja API

## Binary Ninja License Issues

When working with this plugin without a valid Binary Ninja license, you'll encounter license validation errors. This happens because:

1. The plugin imports real Binary Ninja modules (`binaryninja.architecture`, `binaryninja.binaryview`, etc.)
2. Binary Ninja validates its license when these modules are loaded
3. Without a valid license, operations fail with `RuntimeError: License is not valid`

**Solution**: Always use `FORCE_BINJA_MOCK=1` when:
- Running tests (`FORCE_BINJA_MOCK=1 python -m pytest`)
- Running mypy (`FORCE_BINJA_MOCK=1 mypy src/`)
- Running any Python script that imports from this plugin
- Working in development environments without Binary Ninja license

The mock system provides stub implementations of all Binary Ninja classes and functions needed for development and testing.
