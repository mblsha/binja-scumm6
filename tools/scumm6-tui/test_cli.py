#!/usr/bin/env python3
"""
Test script for SCUMM6 comparison CLI.

This demonstrates how the CLI can be used for unit testing.
"""

import subprocess
import json
import sys
from pathlib import Path


def test_list_scripts():
    """Test listing all scripts."""
    print("Testing --list option...")
    result = subprocess.run(
        [sys.executable, "scumm6_compare.py", "--list"],
        capture_output=True,
        text=True,
        cwd=Path(__file__).parent
    )
    
    if result.returncode != 0:
        print(f"Error: {result.stderr}")
        return False
    
    lines = result.stdout.strip().split('\n')
    print(f"Found {len(lines)} scripts")
    
    # Check for known scripts
    script_names = [line.split()[0] for line in lines]
    assert "room8_scrp18" in script_names
    assert "room11_enter" in script_names
    print("✓ List scripts test passed")
    return True


def test_compare_script():
    """Test comparing a specific script."""
    print("\nTesting --compare option...")
    result = subprocess.run(
        [sys.executable, "scumm6_compare.py", "--compare", "room11_enter"],
        capture_output=True,
        text=True,
        cwd=Path(__file__).parent
    )
    
    if result.returncode != 0:
        print(f"Error: {result.stderr}")
        return False
    
    # Parse JSON output
    try:
        data = json.loads(result.stdout)
    except json.JSONDecodeError as e:
        print(f"Failed to parse JSON: {e}")
        print(f"Output: {result.stdout}")
        return False
    
    # Verify structure
    assert "name" in data
    assert "is_match" in data
    assert "match_score" in data
    assert "descumm_output" in data
    assert "fused_output" in data
    assert "raw_output" in data
    
    print(f"Script: {data['name']}")
    print(f"Match: {data['is_match']}")
    print(f"Score: {data['match_score']:.1%}")
    print("✓ Compare script test passed")
    return True


def test_diff_output():
    """Test diff output format."""
    print("\nTesting --compare --diff option...")
    result = subprocess.run(
        [sys.executable, "scumm6_compare.py", "--compare", "room11_enter", "--diff"],
        capture_output=True,
        text=True,
        cwd=Path(__file__).parent
    )
    
    if result.returncode != 0:
        print(f"Error: {result.stderr}")
        return False
    
    # Check output contains expected sections
    output = result.stdout
    assert "=== Script: room11_enter ===" in output
    assert "Match Score:" in output
    assert "descumm" in output
    assert "pyscumm6 (fused)" in output
    
    print("✓ Diff output test passed")
    return True


def test_invalid_script():
    """Test error handling for invalid script name."""
    print("\nTesting invalid script name...")
    result = subprocess.run(
        [sys.executable, "scumm6_compare.py", "--compare", "invalid_script_name"],
        capture_output=True,
        text=True,
        cwd=Path(__file__).parent
    )
    
    # Should return error
    assert result.returncode != 0
    assert "not found" in result.stderr
    print("✓ Error handling test passed")
    return True


def main():
    """Run all tests."""
    print("Running SCUMM6 comparison CLI tests...\n")
    
    tests = [
        test_list_scripts,
        test_compare_script,
        test_diff_output,
        test_invalid_script
    ]
    
    passed = 0
    for test in tests:
        try:
            if test():
                passed += 1
        except Exception as e:
            print(f"✗ {test.__name__} failed: {e}")
    
    print(f"\n{passed}/{len(tests)} tests passed")
    return 0 if passed == len(tests) else 1


if __name__ == "__main__":
    sys.exit(main())