"""Result tables, rendered from whatever results exist.

Every table is drawn even when its inputs are missing, with "—" in empty
cells.

    python -m harness.tables            # writes results/tables.md

Inputs, all under results/:
    sweep.csv            harness.sweep
    full_runs.json       harness.full_runs --clean/--redirect
    attribution.json     harness.full_runs --attribution
    bench_*.json         harness.bench, newest file used
"""

from __future__ import annotations

import csv
import json
import sys
from fractions import Fraction
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
for extra in (ROOT / "baseline",):
    if str(extra) not in sys.path:
        sys.path.insert(0, str(extra))

DASH = "—"
HEADLINE_P = "1/20"
ATTACKS = [("Vote redirection", "redirection", "P3"), ("Ballot stuffing", "stuffing", "P4"),
           ("Malformed ballot injection", "malformed", "P2"),
           ("Tally manipulation", "tally-manipulation", "P5"),
           ("Retroactive board edit", "board-edit", "P1")]


def _load_sweep(results):
    path = results / "sweep.csv"
    if not path.exists():
        return []
    with open(path) as f:
        return list(csv.DictReader(f))


def _cell(rows, **match):
    for r in rows:
        if all(str(r[k]) == str(v) for k, v in match.items()):
            return f"{float(r['rate']):.3f} [{float(r['ci_low']):.3f}, {float(r['ci_high']):.3f}]"
    return DASH


def _table(header, body):
    lines = ["| " + " | ".join(header) + " |", "|" + "---|" * len(header)]
    lines += ["| " + " | ".join(str(c) for c in row) + " |" for row in body]
    return "\n".join(lines)


def headline(rows, k_values):
    body = []
    for k in k_values:
        analytic = f"{1 - (1 - float(Fraction(HEADLINE_P))) ** k:.3f}"
        body.append([k,
                     _cell(rows, config="C0", adversary="A0", p=HEADLINE_P, k=k),
                     _cell(rows, config="C1", adversary="A0", p=HEADLINE_P, k=k),
                     _cell(rows, config="C2", adversary="A0", p=HEADLINE_P, k=k),
                     analytic])
    return _table(["k redirected", "C0 paper audit (SRS)", "C1 no test ballots",
                   "C2 test ballots", "1-(1-p)^k"], body)


def fingerprinting(rows, k_values):
    adversaries = [("A0 blind", "A0", "-", "0.0"), ("AOracle", "AOracle", "-", "0.0"),
                   ("A1 temporal, disciplined tester", "A1", "disciplined", "0.0"),
                   ("A1 temporal, naive tester", "A1", "naive", "0.0"),
                   ("A2 interaction, disciplined tester", "A2", "disciplined", "0.0"),
                   ("A2 interaction, naive tester", "A2", "naive", "0.0")]
    adversaries += [(f"A3 leakage {leak}", "A3", "-", leak)
                    for leak in ("0.0", "0.25", "0.5", "0.75", "1.0")]
    body = [[label] + [_cell(rows, config="C2", adversary=a, tester=t, leak=leak,
                             p=HEADLINE_P, k=k) for k in k_values]
            for label, a, t, leak in adversaries]
    return _table(["Adversary (C2)"] + [f"k={k}" for k in k_values], body)


def by_rate(rows, k_values, p_values):
    body = [[p] + [_cell(rows, config="C2", adversary="A0", p=p, k=k) for k in k_values]
            for p in p_values]
    return _table(["test rate p"] + [f"k={k}" for k in k_values], body)


def cluster_vs_srs():
    """C0 at assembly-segment scale: 250 booths of 800, five audited."""
    try:
        from baseline_c0 import (allocate_manipulation, c0_cluster, c0_srs,
                                 same_rate_sample_size)
    except ImportError:
        return DASH
    booths, size, audited = 250, 800, 5
    s = same_rate_sample_size([size] * booths, audited)
    body = []
    for votes, touched in ((1000, 5), (1000, 25), (1000, 125), (250, 250)):
        counts = allocate_manipulation(votes, booths, touched, booth_capacity=size)
        body.append([votes, touched, f"{float(c0_cluster(counts, audited)):.3f}",
                     f"{float(c0_srs(booths * size, votes, s)):.4f}"])
    return _table(["votes moved", "booths touched", "C0 cluster (ECI practice)",
                   "C0 SRS (upper bound)"], body)


def attribution(results):
    path = results / "attribution.json"
    data = json.loads(path.read_text()) if path.exists() else {}
    body = [[name, expected, data.get(key, DASH)] for name, key, expected in ATTACKS]
    body.append(["(clean election)", "Accept", data.get("clean", DASH)])
    body.append(["(configuration C1)", "Accept, P3 not exercised",
                 data.get("c1-no-test-ballots", DASH)])
    return _table(["Scenario", "Expected", "Verifier"], body)


def full_runs(results):
    path = results / "full_runs.json"
    if not path.exists():
        return _table(["Measure", "Value"], [["clean elections verified", DASH],
                                              ["false rejections", DASH],
                                              ["redirection runs, verifier agrees with model", DASH]])
    d = json.loads(path.read_text())
    return _table(["Measure", "Value"], [
        ["clean elections verified", d.get("clean_runs", DASH)],
        ["false rejections", d.get("false_rejections", DASH)],
        ["redirection runs, verifier agrees with model",
         f"{d.get('agree', DASH)} / {d.get('redirect_runs', DASH)}"],
        ["of which detected (P3)", d.get("detected", DASH)],
        ["ballots per election, serials redirected per run",
         f"{d.get('ballots', DASH)}, {d.get('k', DASH)}"],
    ])


def bench(results):
    files = sorted(results.glob("bench_*.json"))
    if not files:
        return _table(["m", "encrypt p50", "prove p50", "total p50", "total p99"],
                      [[DASH] * 5])
    d = json.loads(files[-1].read_text())
    body = []
    for m, st in d["by_m"].items():
        body.append([m, f"{st['encrypt_ms']['p50']:.0f}", f"{st['prove_ms']['p50']:.0f}",
                     f"{st['total_ms']['p50']:.0f}", f"{st['total_ms']['p99']:.0f}"])
    note = f"\n\n{d['machine']}, Python {d['python']}, peak RSS {d['peak_rss_mb']} MB, " \
           f"{d['ballots_per_m']} ballots per m. Milliseconds."
    return _table(["m", "encrypt p50", "prove p50", "total p50", "total p99"], body) + note


def render(results):
    rows = _load_sweep(results)
    meta_path = results / "sweep.json"
    meta = json.loads(meta_path.read_text()) if meta_path.exists() else {}
    k_values = meta.get("k_values", [1, 2, 5, 10, 20, 50])
    p_values = meta.get("p_values", ["1/50", "1/20", "1/10"])
    runs = meta.get("runs_per_cell", DASH)
    sanity = meta.get("sanity", {})
    parts = [
        "# Results",
        "",
        f"Detection rates are proportions over {runs} simulated elections of "
        f"{meta.get('ballots', 200)} ballots, with Wilson 95% intervals in brackets.",
        "",
        f"## Table 1. Vote redirection detected, by configuration (p = {HEADLINE_P})",
        "", headline(rows, k_values), "",
        f"## Table 2. Fingerprinting adversaries under C2 (p = {HEADLINE_P})",
        "", fingerprinting(rows, k_values), "",
        "## Table 3. C2 with a blind adversary, by test rate",
        "", by_rate(rows, k_values, p_values), "",
        "## Table 4. Paper-audit baseline at segment scale",
        "", cluster_vs_srs(), "",
        "## Table 5. Attack attribution on full-crypto boards",
        "", attribution(results), "",
        "## Table 6. Full-crypto runs: false rejection and the fast-model check",
        "", full_runs(results), "",
        "## Table 7. Per-ballot cost on the target hardware",
        "", bench(results), "",
        "## Sanity checks",
        "",
        f"- A0 under C2 reproduces 1-(1-p)^k across {sanity.get('blind_cells', DASH)} cells "
        f"(Bonferroni family-wise 95%): {sanity.get('blind_matches_analytic', DASH)}",
        f"- Cells outside their own 95% interval (about 1 in 20 expected by chance): "
        f"{', '.join(sanity.get('blind_outside_95_interval', [])) or 'none'}",
        f"- Highest AOracle detection rate: {sanity.get('oracle_max_rate', DASH)}",
        "",
    ]
    return "\n".join(parts)


def main():
    results = ROOT / "results"
    results.mkdir(exist_ok=True)
    (results / "tables.md").write_text(render(results))
    print(f"wrote {results / 'tables.md'}")


if __name__ == "__main__":
    main()
