import os
import pytest
from . import converter

# Determine file availability for DOTT demo files .001 and .000
dott_env_available_str = os.environ.get("DOTT_FILES_AVAILABLE", "false")
dott_env_available = dott_env_available_str.lower() == "true"

expected_lecf_path = os.path.join("dott_demo_files", "DOTTDEMO.001")
expected_rnam_path = os.path.join("dott_demo_files", "DOTTDEMO.000")

files_actually_present = (
    dott_env_available
    and os.path.exists(expected_lecf_path)
    and os.path.exists(expected_rnam_path)
)

if not files_actually_present:
    pytest.skip(
        "DOTT demo files (.001, .000) not available or not found in dott_demo_files. "
        "Skipping all tests in this file.",
        allow_module_level=True,
    )

# If we are here, files_actually_present is True.
# Define paths for use in tests. These are now guaranteed to be the dott_demo_files paths.
lecf_path = expected_lecf_path
rnam_path = expected_rnam_path


def test_converter() -> None:
    # No individual skip needed here anymore due to module-level skip.
    # lecf_path and rnam_path are guaranteed to be set to the dott_demo_files paths.
    lecf_data = converter.read_xored_data(lecf_path)
    rnam_data = converter.read_xored_data(rnam_path)
    assert lecf_data[:4] == b"LECF"
    assert rnam_data[:4] == b"RNAM"

    bsc6 = converter.read_resources(lecf_data, rnam_data)
    assert len(bsc6) > 1000
    assert bsc6[:4] == b"Bsc6"
