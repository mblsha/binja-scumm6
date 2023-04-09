import sys
import os
import binaryninja

from .scumm6 import Scumm6
Scumm6.register()

from .view import *
Scumm6View.register()

from binaryninja import Architecture, CallingConvention
class ParametersInRegistersCallingConvention(CallingConvention):
    name = "ParametersInRegisters"

arch = Architecture['SCUMM6']
arch.register_calling_convention(ParametersInRegistersCallingConvention(arch, 'default'))
