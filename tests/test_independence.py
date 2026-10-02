# The verifier must never import the prover's cryptography (see INDEPENDENCE.md).
import pathlib
import re


def test_verifier_does_not_import_prover():
    banned = re.compile(r"^\s*(from|import)\s+(crypto|tally)\b", re.M)
    for path in (pathlib.Path(__file__).resolve().parent.parent / "verifier").rglob("*.py"):
        assert not banned.search(path.read_text()), f"{path} imports prover code"
