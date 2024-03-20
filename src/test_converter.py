from pprint import pprint
import os
from . import converter

# NOTE: the .lecf is the un-xored file
lecf_path = os.path.join(
    os.path.dirname(os.path.dirname(__file__)), "DOTTDEMO.001.lecf"
    # os.path.dirname(os.path.dirname(__file__)), "TENTACLE.001.lecf"
)

rnam_path = lecf_path.replace(".001.lecf", ".000.rnam")

def test_converter() -> None:
    bsc6 = converter.read_resources(lecf_path, rnam_path)
    assert len(bsc6) > 1000
    # with open("dottdemo.bsc6", "wb") as f:
    #     f.write(bsc6)
