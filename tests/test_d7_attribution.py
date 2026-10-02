"""D7 on the revision 2 boards exactly as exported.

Every one of them publishes each serial's secret nonce in the pre-poll
section, so each is rejected under P1, C11 first at the digest. The
attribution table proper is tested on these boards with the pre-poll
section corrected (tests/test_d7_spec10_rebuilt.py) and on regenerated
boards when present (tests/test_e2e_regenerated.py).
"""

import pathlib

import pytest

import verifier.verify as v
from tests.legacy import strip_nonces
from verifier.spoils import NOT_EXERCISED

BOARDS = pathlib.Path(__file__).resolve().parent / "fixtures" / "boards"
NONCE_LEAK = ["clean", "A8-redirection", "A9-stuffing", "B12-malformed", "C10-tally-tamper"]


def _files(name):
    d = BOARDS / name
    return (d / "board.json").read_bytes(), (d / "signatures.json").read_bytes()


@pytest.mark.parametrize("name", NONCE_LEAK)
def test_exported_board_rejected_p1_for_published_nonces(name):
    r = v.verify(*_files(name))
    assert r.failed_property == "P1", r.summary()
    assert "nonce" in r.failure.reason
    assert all(r.properties[p] == "not_checked" for p in ("P2", "P3", "P4", "P5"))


def test_c11_retroactive_edit_rejected_at_the_digest_first():
    r = v.verify(*_files("C11-retroactive-edit"))
    assert r.failed_property == "P1" and "digest" in r.failure.reason


def _without_nonces(monkeypatch, p3):
    real = v.parse_board
    monkeypatch.setattr(v, "parse_board", lambda obj: real(strip_nonces(obj)))
    monkeypatch.setattr(v, "check_cast_as_intended", lambda board, sel: p3)


def test_clean_board_passes_p4_and_p5_once_p3_does(monkeypatch):
    _without_nonces(monkeypatch, "passed")
    r = v.verify(*_files("clean"))
    assert r.accepted, r.summary()


def test_c1_accepts_with_p3_not_exercised(monkeypatch):
    _without_nonces(monkeypatch, NOT_EXERCISED)
    r = v.verify(*_files("clean"))
    assert r.accepted
    assert r.properties["P3"] == "not_exercised"
    assert "P3: not exercised" in r.summary()


def test_garbage_input_is_a_p1_rejection_not_a_crash():
    r = v.verify(b"{not json", b"{}")
    assert r.failed_property == "P1"
