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

Binary Ninja doesn't normally support state in Architectures, but we need it in
order to properly mark function calls and some other stuff.

In order to decoded text strings outside of Disassembler view we need to extract
them to a separate segment, otherwise they'd be considered part of the decoded
instructions, and the text won't be visible.

