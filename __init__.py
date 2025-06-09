if __package__:
    from .src import binja_api  # noqa: F401
else:  # pragma: no cover - allow running tests without package context
    from src import binja_api  # type: ignore
try:
    from binaryninja import core_ui_enabled
except ImportError:  # pragma: no cover - Binary Ninja not available during tests
    def core_ui_enabled() -> bool:
        return False

if core_ui_enabled():
    if __package__:
        from .src.scumm6 import Scumm6
        from .src.view import Scumm6View
    else:  # pragma: no cover - tests
        from src.scumm6 import Scumm6
        from src.view import Scumm6View

    Scumm6.register()
    Scumm6View.register()

    from binaryninja import Architecture, CallingConvention

    class ParametersInRegistersCallingConvention(CallingConvention):  # type: ignore
        name = "ParametersInRegisters"

    arch = Architecture["SCUMM6"]
    arch.register_calling_convention(
        ParametersInRegistersCallingConvention(arch, "default")
    )
