# scripts/setup.py

import os
import sys
from pathlib import Path


def setup_test_environment() -> None:
    """Sets the environment for running tests without a real Binary Ninja license."""
    os.environ["FORCE_BINJA_MOCK"] = "1"
    repo_root = Path(__file__).resolve().parent.parent
    
    # Ensure repository root is in sys.path
    if str(repo_root) not in sys.path:
        sys.path.insert(0, str(repo_root))
    
    # Remove any real Binary Ninja paths that might have been added
    bn_path = os.path.expanduser("~/Applications/Binary Ninja.app/Contents/Resources/python/")
    if bn_path in sys.path:
        sys.path.remove(bn_path)
    
    # Import the mock API to ensure it's loaded first
    from binja_test_mocks import binja_api  # noqa: F401


def setup_mypy_environment(force_mock: bool = False) -> bool:
    """Sets up environment for mypy with optional mock forcing."""
    repo_root = Path(__file__).resolve().parent.parent
    
    # Ensure repository root is in sys.path
    if str(repo_root) not in sys.path:
        sys.path.append(str(repo_root))
    
    bn_path = os.path.expanduser("~/Applications/Binary Ninja.app/Contents/Resources/python/")
    
    # Check if we should force mock usage
    force_mock = force_mock or os.environ.get('FORCE_BINJA_MOCK', '').lower() in ('1', 'true', 'yes')
    
    if force_mock:
        # Remove Binary Ninja from sys.path to force mock usage
        if bn_path in sys.path:
            sys.path.remove(bn_path)
        has_binja = False
        print("Forcing use of mock API due to FORCE_BINJA_MOCK environment variable")
    else:
        # Add Binary Ninja path if it exists
        if os.path.isdir(bn_path) and bn_path not in sys.path:
            sys.path.append(bn_path)
        
        try:
            import binaryninja  # noqa: F401
            has_binja = True
        except ImportError:
            has_binja = False
    
    # Set up MYPYPATH - for now, stubs are included in binja-test-mocks package
    mypath = []
    print("Using stubs from binja-test-mocks package")
    
    if not has_binja:
        from binja_test_mocks import binja_api  # noqa: F401
    else:
        mypath.append(bn_path)
        print(f"Using Binary Ninja from {bn_path}")
    
    if mypath:
        os.environ["MYPYPATH"] = os.pathsep.join(mypath)
    
    return has_binja
