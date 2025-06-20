import sys
from mypy import api
from scripts.setup import setup_mypy_environment

# Set up the environment for mypy
setup_mypy_environment()

stdout, stderr, exit_status = api.run(["--explicit-package-bases", "src", "converter"])
print(stdout, end="")
print(stderr, end="", file=sys.stderr)
sys.exit(exit_status)
