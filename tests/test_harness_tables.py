"""The results tables render with no results at all."""

from harness.tables import DASH, render


def test_shell_renders_from_nothing(tmp_path):
    text = render(tmp_path)
    for n in range(1, 8):
        assert f"## Table {n}." in text
    assert DASH in text
    assert "0.097" in text  # Table 4 comes from the C0 baseline directly, needs no runs


def test_segment_table_claims_hold():
    """Table 4's text: at matched units C2 (p = 1/50) equals a simple random
    sample of slips, and beats cluster sampling when manipulation is
    concentrated in few booths."""
    import sys
    from pathlib import Path
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "baseline"))
    from baseline_c0 import allocate_manipulation, c0_cluster, c0_srs, same_rate_sample_size
    from harness.tables import (SEGMENT_AUDITED, SEGMENT_BOOTHS, SEGMENT_SCENARIOS,
                                SEGMENT_SIZE)
    n = SEGMENT_BOOTHS * SEGMENT_SIZE
    s = same_rate_sample_size([SEGMENT_SIZE] * SEGMENT_BOOTHS, SEGMENT_AUDITED)
    assert s == SEGMENT_AUDITED * SEGMENT_SIZE == n // 50  # matched units
    for votes, touched in SEGMENT_SCENARIOS:
        c2 = 1 - (1 - 1 / 50) ** votes
        assert abs(c2 - float(c0_srs(n, votes, s))) < 0.002
        cluster = float(c0_cluster(allocate_manipulation(votes, SEGMENT_BOOTHS, touched,
                                                         SEGMENT_SIZE), SEGMENT_AUDITED))
        if touched <= 25 and votes >= 10:
            assert c2 > cluster
