"""Digest, signatures, register cross-check. Each failure is triggered by
breaking exactly one thing."""

import dataclasses
import json
import pathlib

import pytest

from verifier.integrity import check_ballot_count, check_board_integrity
from tests.boards_v2 import parse_v2
from verifier.parse import load_json, parse_board, parse_signatures
from verifier.result import CheckFailure

BOARDS = pathlib.Path(__file__).resolve().parent / "fixtures" / "boards-v2"


def _load(name):
    d = BOARDS / name
    raw = (d / "board.json").read_bytes()
    obj = load_json(raw)
    sig = parse_signatures(load_json((d / "signatures.json").read_bytes()))
    return raw, obj, parse_v2(obj), sig


@pytest.fixture(scope="module")
def clean():
    return _load("clean")


def test_clean_board_integrity(clean):
    check_board_integrity(*clean)
    check_ballot_count(clean[2])


def test_non_canonical_whitespace_rejected(clean):
    raw, obj, board, sig = clean
    with pytest.raises(CheckFailure, match="canonical"):
        check_board_integrity(json.dumps(obj).encode(), obj, board, sig)


def test_one_byte_edit_changes_digest(clean):
    raw, obj, board, sig = clean
    edited = load_json(raw)
    edited["poll_register"]["ballots_issued"] += 1
    raw2 = json.dumps(edited, sort_keys=True, separators=(",", ":")).encode()
    with pytest.raises(CheckFailure, match="digest"):
        check_board_integrity(raw2, edited, board, sig)


def test_retroactive_edit_is_p1():
    with pytest.raises(CheckFailure) as exc:
        check_board_integrity(*_load("board-edit"))
    assert exc.value.prop == "P1"


def test_k_minus_one_agent_signatures_fail(clean):
    raw, obj, board, sig = clean
    k = board.authority_keys.k
    sig2 = dataclasses.replace(sig, agent_signatures=sig.agent_signatures[:k - 1])
    with pytest.raises(CheckFailure, match="distinct valid agent"):
        check_board_integrity(raw, obj, board, sig2)


def test_exactly_k_agent_signatures_pass(clean):
    raw, obj, board, sig = clean
    sig2 = dataclasses.replace(sig, agent_signatures=sig.agent_signatures[:board.authority_keys.k])
    check_board_integrity(raw, obj, board, sig2)


def test_duplicate_agent_counts_once(clean):
    raw, obj, board, sig = clean
    first = sig.agent_signatures[0]
    sig2 = dataclasses.replace(sig, agent_signatures=(first,) * 4)
    with pytest.raises(CheckFailure, match="distinct valid agent"):
        check_board_integrity(raw, obj, board, sig2)


def test_signature_from_unlisted_key_is_a_rejection(clean):
    raw, obj, board, sig = clean
    extra = (99, sig.agent_signatures[0][1])
    sig2 = dataclasses.replace(sig, agent_signatures=(*sig.agent_signatures, extra))
    with pytest.raises(CheckFailure, match="not on the published list"):
        check_board_integrity(raw, obj, board, sig2)


def test_officer_signature_required(clean):
    raw, obj, board, sig = clean
    sig2 = dataclasses.replace(sig, officer_signature=sig.agent_signatures[0][1])
    with pytest.raises(CheckFailure, match="officer"):
        check_board_integrity(raw, obj, board, sig2)


def test_signature_over_other_digest_fails(clean):
    raw, obj, board, sig = clean
    other = _load("redirection")[3]
    with pytest.raises(CheckFailure, match="officer"):
        check_board_integrity(raw, obj, board, dataclasses.replace(other, digest=sig.digest))


def _reg(board, **kw):
    return dataclasses.replace(board, poll_register=dataclasses.replace(board.poll_register, **kw))


@pytest.mark.parametrize("kw,match", [
    ({"ballots_issued": 4, "ballots_counted": 4}, "ballots_issued"),
    ({"ballots_spoiled": 1, "ballots_counted": 2}, "ballots_spoiled"),
    ({"ballots_counted": 2}, "issued - spoiled"),
    ({"booth_id": "BOOTH-002"}, "booth_id"),
])
def test_register_inconsistencies(clean, kw, match):
    with pytest.raises(CheckFailure, match=match) as exc:
        check_ballot_count(_reg(clean[2], **kw))
    assert exc.value.prop == "P4"


def test_serial_gap_and_repeat(clean):
    board = clean[2]
    b = board.ballots
    gap = dataclasses.replace(board, ballots=(b[0], b[1], dataclasses.replace(b[2], ballot_serial=4)))
    rep = dataclasses.replace(board, ballots=(b[0], b[1], dataclasses.replace(b[2], ballot_serial=2)))
    with pytest.raises(CheckFailure, match="gap"):
        check_ballot_count(gap)
    with pytest.raises(CheckFailure, match="repeated"):
        check_ballot_count(rep)


def test_issued_serial_without_prepoll_commitment(clean):
    board = clean[2]
    pre = dataclasses.replace(board.prepoll,
                              randomness_commitments=board.prepoll.randomness_commitments[1:])
    with pytest.raises(CheckFailure, match="no pre-poll commitment"):
        check_ballot_count(dataclasses.replace(board, prepoll=pre))


def test_stuffing_is_p4():
    with pytest.raises(CheckFailure) as exc:
        check_ballot_count(_load("stuffing")[2])
    assert exc.value.prop == "P4"
