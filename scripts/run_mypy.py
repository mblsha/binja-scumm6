import sys
from pathlib import Path
from mypy import api

# Add repository root to Python path so we can import scripts.setup
repo_root = Path(__file__).resolve().parent.parent
if str(repo_root) not in sys.path:
    sys.path.insert(0, str(repo_root))

from scripts.setup import setup_mypy_environment  # noqa: E402

# Set up the environment for mypy
setup_mypy_environment()

stdout, stderr, exit_status = api.run(["--explicit-package-bases", "src", "converter"])
print(stdout, end="")
print(stderr, end="", file=sys.stderr)
sys.exit(exit_status)
