"""D9: repeated-election runner over the evaluation grid.

Runs harness.sim.simulate across configurations, adversaries, tester
regimes, A3 leakage fractions, test rates p and manipulation counts k,
aggregates detection rates and attaches Wilson 95% intervals.

    python -m harness.sweep                       # standard grid, 2000 runs per cell
    python -m harness.sweep --runs 200 --quick    # smoke run

Writes results/sweep.csv and results/sweep.json (grid, model constants,
and the two D9 sanity checks).
"""

from __future__ import annotations

import argparse
import csv
import json
import os
import time
from fractions import Fraction
from multiprocessing import Pool
from pathlib import Path
from statistics import NormalDist

from harness import sim
from harness.stats import wilson

ROOT = Path(__file__).resolve().parent.parent

P_VALUES = (Fraction(1, 50), Fraction(1, 20), Fraction(1, 10))
K_VALUES = (1, 2, 5, 10, 20, 50)
LEAKS = (0.0, 0.25, 0.5, 0.75, 1.0)
BALLOTS = 200


def cells(p_values, k_values, leaks):
    """(config, adversary, tester, leak) combinations, each crossed with p and k.
    A tester regime only matters to A1 and A2; leakage only to A3."""
    combos = [("C0", "A0", "-", 0.0), ("C1", "A0", "-", 0.0),
              ("C2", "A0", "-", 0.0), ("C2", "AOracle", "-", 0.0)]
    combos += [("C2", a, t, 0.0) for a in ("A1", "A2") for t in sim.TESTERS]
    combos += [("C2", "A3", "-", leak) for leak in leaks]
    return [(c, a, t, leak, p, k) for (c, a, t, leak) in combos
            for p in p_values for k in k_values]


def run_cell(args):
    config, adversary, tester, leak, p, k, runs, ballots = args
    detected = manipulated = 0
    for i in range(runs):
        seed = sim.run_seed(config, adversary, tester, leak, p, k, ballots, i)
        o = sim.simulate(config, adversary, k, p, seed, ballots=ballots,
                         tester=tester if tester != "-" else "disciplined", leak=leak)
        detected += o.detected
        manipulated += o.manipulated
    lo, hi = wilson(detected, runs)
    row = {
        "config": config, "adversary": adversary, "tester": tester, "leak": leak,
        "p": str(p), "k": k, "ballots": ballots, "runs": runs, "detected": detected,
        "rate": detected / runs, "ci_low": lo, "ci_high": hi,
        "mean_manipulated": manipulated / runs, "analytic": "",
    }
    if config == "C2" and adversary == "A0":
        row["analytic"] = 1 - (1 - float(p)) ** k
    elif config == "C0":
        from baseline_c0 import c0_srs  # basket B, vendor/b10
        row["analytic"] = float(c0_srs(ballots, k, ballots * p.numerator // p.denominator))
    elif config == "C1":
        row["analytic"] = 0.0
    return row


def sanity(rows):
    """The two D9 checks, evaluated on the finished sweep.

    Check 1 compares every blind-adversary cell with 1-(1-p)^k. With many
    cells, some 95% intervals miss by chance (about 1 in 20), so the pass
    criterion uses Bonferroni-widened intervals for the whole family; the
    cells outside the plain 95% intervals are still listed."""
    blind = [r for r in rows if r["config"] == "C2" and r["adversary"] == "A0"]
    oracle = [r for r in rows if r["config"] == "C2" and r["adversary"] == "AOracle"]
    outside95 = [f"p={r['p']} k={r['k']}" for r in blind
                 if not r["ci_low"] <= r["analytic"] <= r["ci_high"]]
    z = NormalDist().inv_cdf(1 - 0.05 / (2 * max(1, len(blind))))
    outside_family = [f"p={r['p']} k={r['k']}" for r in blind
                      if not (lambda lo, hi: lo <= r["analytic"] <= hi)(
                          *wilson(r["detected"], r["runs"], z=z))]
    return {
        "blind_matches_analytic": not outside_family,
        "blind_cells": len(blind),
        "blind_outside_family_interval": outside_family,
        "blind_outside_95_interval": outside95,
        "oracle_max_rate": max((r["rate"] for r in oracle), default=None),
    }


def main(argv=None):
    ap = argparse.ArgumentParser(description="D9 repeated-election sweep.")
    ap.add_argument("--runs", type=int, default=2000)
    ap.add_argument("--ballots", type=int, default=BALLOTS)
    ap.add_argument("--quick", action="store_true", help="p = 1/20 and k in {1, 5, 20} only")
    ap.add_argument("--procs", type=int, default=os.cpu_count())
    ap.add_argument("--out", default=str(ROOT / "results"))
    args = ap.parse_args(argv)

    p_values = (Fraction(1, 20),) if args.quick else P_VALUES
    k_values = (1, 5, 20) if args.quick else K_VALUES
    work = [(*c, args.runs, args.ballots) for c in cells(p_values, k_values, LEAKS)]
    started = time.time()
    with Pool(args.procs) as pool:
        rows = pool.map(run_cell, work, chunksize=1)
    elapsed = time.time() - started

    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    with open(out / "sweep.csv", "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)
    checks = sanity(rows)
    meta = {
        "runs_per_cell": args.runs, "ballots": args.ballots, "cells": len(rows),
        "p_values": [str(p) for p in p_values], "k_values": list(k_values),
        "leaks": list(LEAKS), "seconds": round(elapsed, 1),
        "model": {name: getattr(sim, name) for name in dir(sim)
                  if name.isupper() and isinstance(getattr(sim, name), float)},
        "sanity": checks,
    }
    (out / "sweep.json").write_text(json.dumps(meta, indent=2) + "\n")
    print(f"{len(rows)} cells x {args.runs} runs in {elapsed:.0f} s -> {out / 'sweep.csv'}")
    print(f"D9 check 1, A0 reproduces 1-(1-p)^k across {checks['blind_cells']} cells "
          f"(family-wise 95%): {checks['blind_matches_analytic']}; outside the per-cell "
          f"95% interval: {checks['blind_outside_95_interval'] or 'none'}")
    print(f"D9 check 2, AOracle max detection rate: {checks['oracle_max_rate']}")


if __name__ == "__main__":
    main()
