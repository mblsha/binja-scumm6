"""SCUMM6-specific mock classes for testing."""

import threading
from typing import Optional, Dict, Any
from binja_test_mocks.mock_binaryview import MockBinaryView


class MockScumm6BinaryView(MockBinaryView):
    """Enhanced mock BinaryView for SCUMM6 state testing."""
    
    def __init__(self, state: Optional[Any] = None, filename: str = "test.bsc6"):
        super().__init__(filename)
        self.state = state
    
    def perform_get_address_size(self) -> int:
        """Return the address size for SCUMM6 architecture."""
        return 4  # SCUMM6 uses 4-byte addresses


# Global registry for mock views
_mock_views: Dict[str, MockScumm6BinaryView] = {}


def register_mock_view(name: str, view: MockScumm6BinaryView) -> None:
    """Register a named mock view for testing."""
    _mock_views[name] = view


def get_mock_view(name: str) -> Optional[MockScumm6BinaryView]:
    """Get a registered mock view by name."""
    return _mock_views.get(name)


def clear_mock_views() -> None:
    """Clear all registered mock views."""
    _mock_views.clear()


# Patch the LastBV class for testing

class MockLastBV:
    """Mock LastBV for testing state-dependent operations."""
    
    _current_view: Optional[MockScumm6BinaryView] = None
    _lock = threading.Lock()
    
    @classmethod
    def get(cls) -> Optional[MockScumm6BinaryView]:
        """Get the current mock view."""
        with cls._lock:
            return cls._current_view
    
    @classmethod
    def set(cls, view: Optional[MockScumm6BinaryView]) -> None:
        """Set the current mock view."""
        with cls._lock:
            cls._current_view = view
