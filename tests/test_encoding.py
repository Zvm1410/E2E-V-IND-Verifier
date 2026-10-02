"""Encodings, SPEC section 3, and the base-hash preimage of 5.2."""

import pytest

from tests.vectors import load
from verifier.encoding import EncodingError, b2i, i2b, label, s32, s64, u64
from verifier.group import P
from verifier.hashes import base_hash, base_hash_preimage


def test_round_trip_pairs_byte_for_byte():
    v = load("encoding.json")
    assert v["count"] == len(v["pairs"]) == 1000
    for pair in v["pairs"]:
        x = int(pair["x"])
        assert i2b(x).hex() == pair["i2b"], pair["x"][:20]
        assert b2i(bytes.fromhex(pair["i2b"])) == x


def test_named_values():
    named = load("encoding.json")["named"]
    assert i2b(1).hex() == named["I2B_of_1"]
    assert i2b(P - 1).hex() == named["I2B_of_p_minus_1"]


def test_one_is_384_bytes_not_one():
    assert i2b(1) == b"\x00" * 383 + b"\x01"


def test_fixed_width_rejects_overflow_and_negatives():
    with pytest.raises(EncodingError):
        i2b(1 << 3072)
    with pytest.raises(EncodingError):
        i2b(-1)
    with pytest.raises(EncodingError):
        u64(2**64)


def test_padded_strings():
    assert s32("BOOTH-001") == b"BOOTH-001".ljust(32, b"\x00")
    assert s64("NOTA") == b"NOTA".ljust(64, b"\x00")
    assert label("EVOTE-BASE-v1") == b"EVOTE-BASE-v1" + b"\x00" * 19
    with pytest.raises(EncodingError):
        s32("x" * 33)
    with pytest.raises(EncodingError):
        s32("BOOTH-é")


def _base_hash_args(v):
    cfg = v["config"]
    return dict(
        election_id=cfg["election_id"],
        candidate_ids=[c["candidate_id"] for c in cfg["candidates"]],
        n=cfg["trustees"]["n"],
        t=cfg["trustees"]["t"],
        pk=int(v["public_key"], 16),
        commitments=[int(c["commitment"], 16) for c in v["trustee_commitments"]],
        k=cfg["authorities"]["k"],
        officer_key=bytes.fromhex(v["officer_public_key"]),
        agent_keys=[bytes.fromhex(a["public_key"]) for a in v["agent_public_keys"]],
    )


def test_base_hash_preimage_matches_field_by_field():
    v = load("base_hash.json")
    mine = base_hash_preimage(**_base_hash_args(v))
    theirs = bytes.fromhex(v["preimage"])
    assert len(mine) == v["preimage_length"] == 4136
    for f in v["field_offsets"]:
        assert mine[f["start"]:f["end"]] == theirs[f["start"]:f["end"]], f["field"]
    assert mine == theirs


def test_base_hash_value():
    v = load("base_hash.json")
    assert base_hash(**_base_hash_args(v)).hex() == v["base_hash"]


def test_base_hash_changes_with_candidate_id():
    args = _base_hash_args(load("base_hash.json"))
    before = base_hash(**args)
    args["candidate_ids"] = ["CAND-X"] + args["candidate_ids"][1:]
    assert base_hash(**args) != before
