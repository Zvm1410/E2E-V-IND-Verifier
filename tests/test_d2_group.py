"""D2: group parameters, SPEC section 2, against spec/vectors/group.json."""

from tests.vectors import load
from verifier.encoding import hex384_to_int
from verifier.group import G, P, PINNED, Q, verify_group_parameters


def test_literal_matches_vector():
    v = load("group.json")
    assert hex384_to_int(v["p"]) == P
    assert hex384_to_int(v["q"]) == Q
    assert hex384_to_int(v["g"]) == G


def test_pinned_values_match_vector():
    assert PINNED == load("group.json")["pinned"]


def test_all_load_time_assertions_pass():
    verify_group_parameters()
