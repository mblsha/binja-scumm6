import sys
import os

from .src import binja_api
from binaryninja import core_ui_enabled

from .src.scumm6 import Scumm6

if core_ui_enabled():
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
