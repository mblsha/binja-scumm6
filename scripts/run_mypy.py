import os
import sys
from pathlib import Path
from mypy import api

# Ensure repository root is in sys.path so sc62015 can be imported when the
# script is run from the 'scripts' directory.
repo_root = Path(__file__).resolve().parent.parent
sys.path.append(str(repo_root))
helper_dir = repo_root / "binja_helpers_tmp"
if helper_dir.is_dir() and str(helper_dir) not in sys.path:
    sys.path.insert(0, str(helper_dir))

bn_path = os.path.expanduser(
    "~/Applications/Binary Ninja.app/Contents/Resources/python/"
)
if os.path.isdir(bn_path) and bn_path not in sys.path:
    sys.path.append(bn_path)

# Check if we should force mock usage
force_mock = os.environ.get('FORCE_BINJA_MOCK', '').lower() in ('1', 'true', 'yes')

if force_mock:
    # Remove Binary Ninja from sys.path to force mock usage
    if bn_path in sys.path:
        sys.path.remove(bn_path)
    has_binja = False
    print("Forcing use of mock API due to FORCE_BINJA_MOCK environment variable")
else:
    try:
        import binaryninja  # noqa: F401
        has_binja = True
    except ImportError:
        has_binja = False

mypath = []
stub_dir = os.path.join(os.path.dirname(__file__), "..", "binja_helpers_tmp", "stubs")
if os.path.exists(stub_dir):
    mypath.append(os.path.abspath(stub_dir))
    print(f"Using stubs from {mypath[0]}")
else:
    print("Warning: Stub directory not found, mypy may fail")

if not has_binja:
    from binja_helpers import binja_api  # noqa: F401
else:
    mypath.append(bn_path)
    print(f"Using Binary Ninja from {bn_path}")

os.environ["MYPYPATH"] = os.pathsep.join(mypath)

stdout, stderr, exit_status = api.run(["--explicit-package-bases", "src", "converter"])
print(stdout, end="")
print(stderr, end="", file=sys.stderr)
sys.exit(exit_status)
