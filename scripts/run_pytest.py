import os
import sys
from pathlib import Path
import subprocess

# Remove any Binary Ninja paths from sys.path to force use of mock
bn_path = os.path.expanduser("~/Applications/Binary Ninja.app/Contents/Resources/python/")
if bn_path in sys.path:
    sys.path.remove(bn_path)

# Ensure repository root is in sys.path so sc62015 can be imported when the
# script is run from the 'scripts' directory.
repo_root = Path(__file__).resolve().parent.parent
sys.path.append(str(repo_root))
helper_dir = repo_root / "binja_helpers_tmp"
if helper_dir.is_dir() and str(helper_dir) not in sys.path:
    sys.path.insert(0, str(helper_dir))

# Always use mock for tests to avoid Binary Ninja API compatibility issues
# Import the mock BEFORE adding Binary Ninja path to prevent real Binary Ninja from loading
from binja_helpers import binja_api  # noqa: F401
print("Using binja_helpers stubs for testing")

# Set environment for pytest to find the modules, excluding Binary Ninja
existing_pythonpath = os.environ.get("PYTHONPATH", "")
pythonpath_parts = [str(helper_dir), str(repo_root)]

# Add existing PYTHONPATH parts that are not Binary Ninja paths
if existing_pythonpath:
    for part in existing_pythonpath.split(":"):
        if part and "Binary Ninja" not in part and part not in pythonpath_parts:
            pythonpath_parts.append(part)

os.environ["PYTHONPATH"] = ":".join(pythonpath_parts)

# Make sure pytest runs in an environment without Binary Ninja paths
env = os.environ.copy()

# Run pytest with the arguments passed to this script
cmd = ["pytest"] + sys.argv[1:]
result = subprocess.run(cmd, cwd=repo_root, env=env)
sys.exit(result.returncode)