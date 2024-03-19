from pprint import pprint
import os
from . import converter

# NOTE: the .lecf is the un-xored file
lecf_path = os.path.join(
    # os.path.dirname(os.path.dirname(__file__)), "DOTTDEMO.001.lecf"
    os.path.dirname(os.path.dirname(__file__)), "TENTACLE.001.lecf"
)


def test_converter() -> None:
    pass

    # r = converter.read_resources(lecf_path)
    # pprint(r)
    # assert r is None

    # scripts, state = r
    # assert scripts is not None
    # assert state.dscr is not None
