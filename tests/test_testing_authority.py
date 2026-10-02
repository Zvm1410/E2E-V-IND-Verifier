"""The testing authority's T and schedule (built on crypto.encoding)
must equal what the verifier recomputes from the revealed seed with its own
independent code. Skipped until crypto/ is present."""

import pytest

pytest.importorskip("crypto.encoding")

from testing_authority import TestingAuthority, seed_from_int  # noqa: E402
from verifier.hashes import is_scheduled, schedule_commitment  # noqa: E402

Q = bytes(range(32))


@pytest.mark.parametrize("seed,num,den", [(1, 1, 20), (2, 1, 50), (3, 1, 10), (4, 0, 20)])
def test_authority_matches_verifier(seed, num, den):
    a = TestingAuthority(Q, "BOOTH-001", num, den, 200, seed=seed_from_int(seed))
    revealed = bytes.fromhex(a.reveal())
    assert a.commitment == schedule_commitment(Q, "BOOTH-001", revealed, num, den).hex()
    assert a.schedule == {s for s in range(1, 201) if is_scheduled(revealed, s, num, den)}


def test_c1_schedule_is_empty():
    assert TestingAuthority(Q, "BOOTH-001", 0, 20, 200, seed=seed_from_int(9)).schedule == set()


def test_production_seed_is_fresh():
    a = TestingAuthority(Q, "BOOTH-001", 1, 20, 200)
    b = TestingAuthority(Q, "BOOTH-001", 1, 20, 200)
    assert a.reveal() != b.reveal()
