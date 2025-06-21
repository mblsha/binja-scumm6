from pathlib import Path
import sys

# Add plugin directory to sys.path for relative imports
_scumm6_dir = Path(__file__).resolve().parent
if str(_scumm6_dir) not in sys.path:
    sys.path.insert(0, str(_scumm6_dir))

# Add the vendored binja_helpers directory to sys.path to resolve its internal imports.
_helpers_dir = _scumm6_dir / "binja_helpers_tmp"
if _helpers_dir.is_dir() and str(_helpers_dir) not in sys.path:
    sys.path.insert(0, str(_helpers_dir))

# With the new path, we import directly from the 'binja_helpers' library package.
# The original 'from binja_helpers.binja_helpers import binja_api' will no longer work.
from binja_helpers import binja_api  # noqa: E402,F401

try:
    from binaryninja import core_ui_enabled
except Exception:
    def core_ui_enabled() -> bool:
        return False


if core_ui_enabled():
    from .src.scumm6 import Scumm6

    Scumm6.register()

    from .src.view import Scumm6View

    Scumm6View.register()

    from binaryninja import Architecture, CallingConvention

    class ParametersInRegistersCallingConvention(CallingConvention):  # type: ignore
        name = "ParametersInRegisters"

    arch = Architecture["SCUMM6"]
    arch.register_calling_convention(
        ParametersInRegistersCallingConvention(arch, "default")
    )
