import os
import pytest
from . import converter

lecf_path = os.path.join(
    os.path.dirname(os.path.dirname(__file__)),
    "DOTTDEMO.001"
)

rnam_path = lecf_path.replace(".001", ".000")


def test_converter() -> None:
    if not os.path.exists(lecf_path) or not os.path.exists(rnam_path):
        pytest.skip("converter test data not present")
    lecf_data = converter.read_xored_data(lecf_path)
    rnam_data = converter.read_xored_data(rnam_path)
    assert lecf_data[:4] == b"LECF"
    assert rnam_data[:4] == b"RNAM"

    bsc6 = converter.read_resources(lecf_data, rnam_data)
    assert len(bsc6) > 1000
    assert bsc6[:4] == b"Bsc6"
