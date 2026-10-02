"""D2: subgroup membership, range checks and the strict parser.

The ballot built here is shaped like SPEC 14 but its proofs are not valid;
D2 only checks encoding and shape, D3 checks the proofs. Real ballot and
board vectors replace these fixtures when ballot.json and board.json land.
"""

import copy
import json

import pytest

from tests.vectors import load
from verifier.encoding import in_exponent_range, in_group
from verifier.group import G, P, Q
from verifier.parse import (
    ParseError,
    element,
    exponent,
    load_json,
    parse_ballot,
    parse_decryption_transcript,
    parse_election_config,
)

M = 6


def h(x):
    return format(x, "0768x")


# ---------------------------------------------------- membership, SPEC 2.1


def test_membership_sanity_list_from_b3b():
    assert in_group(G)
    assert in_group(1)  # identity is a member: lower bound is 0 < x
    assert not in_group(0)
    assert not in_group(P - 1)  # order 2, rejected by the exponent test
    assert not in_group(P)
    assert not in_group(P + 1)  # non-canonical 1; only the upper bound stops it


def test_non_canonical_x_plus_p_rejected_for_valid_x():
    for x in (1, G, pow(G, 2, P), pow(G, 12345, P)):
        assert in_group(x)
        assert not in_group(x + P)


def test_exponent_range():
    assert in_exponent_range(0)
    assert in_exponent_range(Q - 1)
    assert not in_exponent_range(Q)
    assert not in_exponent_range(-1)


def test_parser_rejects_p_minus_1_accepts_1():
    assert element(h(1), "x") == 1
    with pytest.raises(ParseError):
        element(h(P - 1), "x")


def test_parser_rejects_x_plus_p_that_fits_768_chars():
    assert len(h(P + G)) == 768
    with pytest.raises(ParseError, match="subgroup"):
        element(h(P + G), "x")


def test_parser_rejects_x_plus_p_that_overflows_width():
    x = pow(G, 987654321, P)
    with pytest.raises(ParseError):
        element(format(x + P, "x"), "x")


@pytest.mark.parametrize("bad", [
    "0" * 767 + "2",           # 768 is fine, so this is the control below
])
def test_hex_control(bad):
    assert element(bad, "x") == 2


@pytest.mark.parametrize("bad", [
    "0" * 766 + "2",            # 767 chars
    "0" * 768 + "2",            # 769 chars
    "0" * 767 + "A",            # uppercase
    "0" * 766 + "0x",           # not hex
    2,                          # JSON number
    None,
])
def test_hex384_width_and_case(bad):
    with pytest.raises(ParseError):
        element(bad, "x")


def test_exponent_q_rejected():
    assert exponent(h(Q - 1), "c") == Q - 1
    with pytest.raises(ParseError, match=r"\[0, q\)"):
        exponent(h(Q), "c")


# -------------------------------------------------------------- raw JSON


@pytest.mark.parametrize("text", [
    '{"a": 1, "a": 2}',
    '{"a": 1.0}',
    '{"a": 1e3}',
    '{"a": NaN}',
    '{"a": Infinity}',
    '{"a": ',
])
def test_load_json_rejects(text):
    with pytest.raises(ParseError):
        load_json(text)


def test_load_json_rejects_bad_utf8():
    with pytest.raises(ParseError):
        load_json(b'{"a": "\xff"}')


# ---------------------------------------------------------------- ballots


def _ballot():
    src = load("decryption.json")["ballots"][0]
    cts = src["ciphertexts"]
    return {
        "record_type": "ballot",
        "booth_id": "BOOTH-001",
        "ballot_serial": src["ballot_serial"],
        "ciphertexts": cts,
        "validity_proofs": [
            {"candidate_index": i, "c0": h(1), "c1": h(2), "f0": h(3), "f1": h(4),
             "a0": c["alpha"], "b0": c["beta"], "a1": h(1), "b1": h(G)}
            for i, c in enumerate(cts)
        ],
        "sum_proof": {"c": h(5), "f": h(6), "a": h(G), "b": h(1)},
    }


def test_ballot_parses():
    b = parse_ballot(_ballot(), M)
    assert len(b.ciphertexts) == len(b.validity_proofs) == M
    assert b.validity_proofs[0].a1 == 1


def test_ballot_survives_json_round_trip():
    text = json.dumps(_ballot(), sort_keys=True, separators=(",", ":"))
    parse_ballot(load_json(text), M)


def _mutated(fn):
    b = copy.deepcopy(_ballot())
    fn(b)
    return b


@pytest.mark.parametrize("name,mutate", [
    ("short", lambda b: b["ciphertexts"].pop()),
    ("long", lambda b: b["validity_proofs"].append(b["validity_proofs"][0])),
    ("reordered", lambda b: b["ciphertexts"].reverse()),
    ("gap", lambda b: b["ciphertexts"][3].update(candidate_index=4)),
    ("extra key", lambda b: b.update(timestamp=0)),
    ("missing key", lambda b: b.pop("sum_proof")),
    ("wrong type", lambda b: b.update(record_type="spoil")),
    ("serial zero", lambda b: b.update(ballot_serial=0)),
    ("serial bool", lambda b: b.update(ballot_serial=True)),
    ("serial string", lambda b: b.update(ballot_serial="1")),
    ("booth too long", lambda b: b.update(booth_id="B" * 33)),
    ("alpha order 2", lambda b: b["ciphertexts"][2].update(alpha=h(P - 1))),
    ("beta non-canonical", lambda b: b["ciphertexts"][0].update(beta=h(P + 1))),
    ("a0 zero", lambda b: b["validity_proofs"][1].update(a0=h(0))),
    ("c0 is q", lambda b: b["validity_proofs"][1].update(c0=h(Q))),
    ("f1 uppercase", lambda b: b["validity_proofs"][5].update(f1=h(0xabc).upper())),
    ("sum c short", lambda b: b["sum_proof"].update(c=h(5)[1:])),
    ("sum b order 2", lambda b: b["sum_proof"].update(b=h(P - 1))),
    ("sum extra", lambda b: b["sum_proof"].update(x=h(1))),
])
def test_ballot_rejections(name, mutate):
    with pytest.raises(ParseError):
        parse_ballot(_mutated(mutate), M)


# ------------------------------------------------------ election config


def test_config_from_base_hash_vector_parses():
    cfg = parse_election_config(load("base_hash.json")["config"], published=False)
    assert cfg.m == 6 and cfg.n == 5 and cfg.t == 3 and cfg.k == 2
    assert (cfg.test_rate_num, cfg.test_rate_den) == (1, 20)


def test_config_rejects_decimal_rate():
    cfg = copy.deepcopy(load("base_hash.json")["config"])
    cfg["test_rate"] = 0.05
    with pytest.raises(ParseError):
        parse_election_config(cfg, published=False)


def test_published_config_must_omit_seed():
    """SPEC 14: the seed drives the encryption randomness in a simulated run."""
    with pytest.raises(ParseError, match="seed"):
        parse_election_config(load("base_hash.json")["config"])


# -------------------------------------------------- decryption transcript


def _transcript():
    v = load("decryption.json")
    return {
        "record_type": "decryption_transcript",
        "subset": v["subset"],
        "lagrange_coefficients": v["lagrange_coefficients"],
        "partials": [{k: p[k] for k in ("trustee_index", "candidate_index", "partial", "proof")}
                     for p in v["partials"]],
    }


def test_transcript_from_decryption_vector_parses():
    tr = parse_decryption_transcript(_transcript(), M, 5, 3)
    assert tr.subset == (1, 3, 5)
    assert len(tr.partials) == 18


def test_transcript_rejects_out_of_order_partials():
    tr = _transcript()
    tr["partials"][0], tr["partials"][1] = tr["partials"][1], tr["partials"][0]
    with pytest.raises(ParseError):
        parse_decryption_transcript(tr, M, 5, 3)


def test_transcript_rejects_coefficient_for_wrong_trustee():
    tr = _transcript()
    tr["lagrange_coefficients"]["2"] = tr["lagrange_coefficients"].pop("3")
    with pytest.raises(ParseError):
        parse_decryption_transcript(tr, M, 5, 3)
