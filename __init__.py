from pathlib import Path
import sys

_plugin_dir = str(Path(__file__).resolve().parent)
if _plugin_dir not in sys.path:
    sys.path.insert(0, _plugin_dir)

from binja_helpers.binja_helpers import binja_api  # noqa: E402,F401
try:  # pragma: no cover - optional Binary Ninja dependency
    from binaryninja import core_ui_enabled
except Exception:  # pragma: no cover - Binary Ninja not available
    def core_ui_enabled() -> bool:
        return False

try:
    from .src.scumm6 import Scumm6
except Exception:
    try:  # pragma: no cover - fallback when package layout differs
        from src.scumm6 import Scumm6
    except Exception:
        Scumm6 = None  # type: ignore[misc]

if Scumm6 is not None and core_ui_enabled():
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
