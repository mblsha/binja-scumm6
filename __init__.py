import sys
import os

from . import binja_api
from binaryninja import core_ui_enabled

from .scumm6 import Scumm6

if core_ui_enabled():
    Scumm6.register()

    from .view import *

    Scumm6View.register()

    from binaryninja import Architecture, CallingConvention


    class ParametersInRegistersCallingConvention(CallingConvention):
        name = "ParametersInRegisters"


    arch = Architecture["SCUMM6"]
    arch.register_calling_convention(
        ParametersInRegistersCallingConvention(arch, "default")
    )
