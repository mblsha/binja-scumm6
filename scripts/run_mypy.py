import os
import sys
from pathlib import Path
from mypy import api

# Ensure repository root is in sys.path so sc62015 can be imported when the
# script is run from the 'scripts' directory.
repo_root = Path(__file__).resolve().parent.parent
# Prepend the repository root so our in-tree packages are always preferred
if str(repo_root) not in sys.path:
    sys.path.insert(0, str(repo_root))

# ``binja_helpers`` itself contains a nested package with the same name.
# Add that directory explicitly to handle relative imports when the package
# isn't installed system-wide.
helper_dir = repo_root / "binja_helpers" / "binja_helpers"
if helper_dir.is_dir() and str(helper_dir) not in sys.path:
    sys.path.insert(1, str(helper_dir))

bn_path = os.path.expanduser(
    "~/Applications/Binary Ninja.app/Contents/Resources/python/"
)
if os.path.isdir(bn_path) and bn_path not in sys.path:
    sys.path.append(bn_path)

try:
    import binaryninja  # noqa: F401
    has_binja = True
except ImportError:
    has_binja = False

if not has_binja:
    from binja_helpers.binja_helpers import binja_api  # noqa: F401
    stub_dir = os.path.join(os.path.dirname(__file__), "..", "binja_helpers", "stubs")
    os.environ["MYPYPATH"] = os.path.abspath(stub_dir)
    print(f"Using stubs from {os.environ['MYPYPATH']}")
else:
    os.environ["MYPYPATH"] = bn_path
    print(f"Using Binary Ninja from {bn_path}")

# When this script is executed from outside the repository root the current
# working directory may not contain the ``src`` and ``converter`` directories.
# Use absolute paths so ``mypy`` can always locate the sources.
source_dirs = [repo_root / "src", repo_root / "converter"]
stdout, stderr, exit_status = api.run(["--explicit-package-bases", *(str(p) for p in source_dirs)])
print(stdout, end="")
print(stderr, end="", file=sys.stderr)
sys.exit(exit_status)
