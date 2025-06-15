# SCUMM6 Architecture for Binary Ninja

This plugin aims to provide a comprehensive view to how SCUMM6-based games work
internally.

[descumm-tool](https://github.com/scummvm/scummvm-tools/blob/master/engines/scumm/descumm-tool.cpp)
can already decompile single SCUMM6 scripts, but it doesn't show related
scripts, nor the shared memory access.

Before opening the files, the .000 + .001 files from the game need to be
converted to the .bsc6 format that de-xors them, squashes them together and
extracts all the strings to a separate section. The demo files can be obtained
from
[archive.org](https://archive.org/download/DayOfTheTentacleDemo/DOTTDEMO.ZIP).

```
$ python converter/cli.py DOTTDEMO.000 DOTTDEMO.001 -o dottdemo.bsc6
```

# Running tests

## Quick test run

Run all linting, type checking, and unit tests once:

```bash
$ ./run-tests.fish
```

# Limitations

* Array reads/writes aren't properly (need to create a separate segment for them, and do lifting)
* Message Parts (newlines, waits, etc) aren't currently shown in talk_actor() calls.

# Peculiarities

Binary Ninja architecture plugins are designed to be stateless. However, correctly analyzing SCUMM6 bytecode requires global context that is not available within a single instruction's bytes. This plugin works around this limitation by persisting a global `State` object on the `BinaryView` for several key reasons:

*   **Resolving Script Calls:** Opcodes like `start_script` take a numeric script ID as an argument, not a direct address. To resolve this ID to a callable address, the plugin must look up the ID in metadata tables (`DSCR` and `LOFF` blocks) parsed from the entire file's structure. Storing this information allows the plugin to generate proper `call` instructions in the Low-Level IL, which is essential for building an accurate Control-Flow Graph (CFG) and enabling cross-references.

*   **Resolving String References:** For improved analysis, the converter utility extracts all dialogue and text into a separate `Bstr` section. When an instruction like `talk_actor` is lifted, the plugin needs to find the address of its corresponding string within this section to create a valid pointer. This requires a pre-computed map of strings to their addresses, which is maintained in the global state.

The `Scumm6View` is responsible for creating and holding this state upon loading a file. The `Scumm6` architecture then accesses it via a helper (`LastBV`) to perform context-aware instruction lifting.
