"""The results tables render with no results at all."""

from harness.tables import DASH, render


def test_shell_renders_from_nothing(tmp_path):
    text = render(tmp_path)
    for n in range(1, 8):
        assert f"## Table {n}." in text
    assert DASH in text
    assert "0.097" in text  # Table 4 comes from the C0 baseline directly, needs no runs
