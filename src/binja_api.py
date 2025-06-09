"""Helper module to load the Binary Ninja stubs from ``binja_helpers``.

This mirrors the behaviour of ``binja_helpers.binja_api`` which attempts to use a
real Binary Ninja installation if present and otherwise installs lightweight
stubs.  Importing this module before anything from ``binaryninja`` ensures that
our unit tests run without requiring Binary Ninja to be installed.
"""

from __future__ import annotations

import sys
from pathlib import Path

_helper_dir = Path(__file__).resolve().parent.parent / "binja_helpers" / "binja_helpers"
if _helper_dir.is_dir() and str(_helper_dir) not in sys.path:
    # Prepend the helpers package so ``import binja_helpers`` resolves to the
    # stub implementation rather than the plugin package of the same name.
    sys.path.insert(0, str(_helper_dir))

# Import for side effects.  Expose as ``binja_helpers.binja_api`` for callers
# that might expect to access it via this module.
# noqa: E402 because this import must occur after modifying ``sys.path`` above.
from binja_helpers import binja_api  # type: ignore[attr-defined]  # noqa: E402,F401


