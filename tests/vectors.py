import json
import pathlib

VECTORS = pathlib.Path(__file__).resolve().parent.parent / "spec" / "vectors"


def load(name):
    return json.loads((VECTORS / name).read_text())
