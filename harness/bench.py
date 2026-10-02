"""Hardware benchmark, headless, for the Raspberry Pi.

Times, per ballot and for each candidate count m:

    encrypt_ms   crypto.elgamal.encrypt_selection: m ciphertexts, no proofs
    prove_ms     encrypt_and_prove minus encrypt_ms: the m validity
                 proofs and the sum proof
    total_ms     crypto.encrypt_and_prove, end to end
    verify_ms    this repository's verify_ballot on the same record (--verify;
                 that is the verifier's runtime, not the machine's, and roughly doubles
                 the run)

and reports distributions (min, p50, p90, p99, max, mean), not averages,
because a long tail is a finding. Peak resident memory is
read from the OS once at the end, not simulated.

Run from the project root. Only three prover entry points are called, by
the signatures run_election.py uses.

    python -m harness.bench --ballots 500 --m 2,4,6,8 [--verify]

A full run takes hours on a Pi; progress and an estimate print every 25 ballots.

Writes results/bench_<architecture>_<timestamp>.csv (one row per ballot) and a
.json summary next to it.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import platform
import random
import resource
import statistics
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

HERE = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(HERE))

from verifier.group import G, P, Q  # noqa: E402
from verifier.parse import parse_ballot  # noqa: E402
from verifier.proofs import verify_ballot  # noqa: E402


def load_prover(repo):
    sys.path.insert(0, str(Path(repo).resolve()))
    import crypto  # noqa: F401  (the group repo's path shim)
    from crypto.elgamal import encrypt_selection
    from crypto.encrypt_and_prove import encrypt_and_prove
    from crypto.record import build_ballot_record
    return encrypt_selection, encrypt_and_prove, build_ballot_record


def percentile(sorted_values, pct):
    """Nearest-rank percentile on an already sorted list."""
    if not sorted_values:
        return float("nan")
    rank = max(1, -(-len(sorted_values) * pct // 100))
    return sorted_values[int(rank) - 1]


def describe(values):
    v = sorted(values)
    return {
        "n": len(v),
        "min": v[0],
        "p50": percentile(v, 50),
        "p90": percentile(v, 90),
        "p99": percentile(v, 99),
        "max": v[-1],
        "mean": statistics.fmean(v),
        "stdev": statistics.stdev(v) if len(v) > 1 else 0.0,
    }


def run(repo, ballots, m_values, seed, warmup, verify):
    encrypt_selection, encrypt_and_prove, build_ballot_record = load_prover(repo)
    rng = random.Random(seed)
    sk = 1 + rng.randrange(Q - 1)
    pk = pow(G, sk, P)
    # Any fixed 32 bytes: the proofs bind it, and the verifier is handed the same value.
    q_hash = hashlib.sha256(b"EVOTE-BENCH-v1").digest()
    booth = "BENCH-PI"

    rows = []
    for m in m_values:
        started = time.perf_counter()
        for serial in range(1, warmup + ballots + 1):
            choice = rng.randrange(m)
            r_vector = [1 + rng.randrange(Q - 1) for _ in range(m)]
            proof_rng = random.Random(rng.getrandbits(64))

            t0 = time.perf_counter()
            encrypt_selection(pk, m, choice, randomness=r_vector)
            t1 = time.perf_counter()
            cts, vps, sp = encrypt_and_prove(
                candidate_index=choice, r_vector=r_vector, Q=q_hash, booth_id=booth,
                ballot_serial=serial, pk=pk, m=m, rng=proof_rng)
            t2 = time.perf_counter()
            t3 = t4 = t2
            if verify or serial == 1:
                # Always check the first ballot per m, so a broken prover
                # cannot produce a timing table.
                record = build_ballot_record(booth_id=booth, ballot_serial=serial, m=m,
                                             ciphertexts=cts, validity_proofs=vps,
                                             sum_proof=sp)
                ballot = parse_ballot(json.loads(json.dumps(record)), m)
                t3 = time.perf_counter()
                verify_ballot(q_hash, pk, ballot)  # raises if the proof does not verify
                t4 = time.perf_counter()

            if serial <= warmup:
                continue
            encrypt_ms = (t1 - t0) * 1000
            total_ms = (t2 - t1) * 1000
            done = serial - warmup
            if done % 25 == 0:
                per = (time.perf_counter() - started) / serial
                left = per * (warmup + ballots - serial)
                print(f"  m={m}: {done}/{ballots}, {per:.1f} s/ballot, "
                      f"about {left / 60:.0f} min left for this m", flush=True)
            row = {
                "m": m,
                "serial": serial - warmup,
                "encrypt_ms": round(encrypt_ms, 3),
                "prove_ms": round(total_ms - encrypt_ms, 3),
                "total_ms": round(total_ms, 3),
            }
            if verify:
                row["parse_ms"] = round((t3 - t2) * 1000, 3)
                row["verify_ms"] = round((t4 - t3) * 1000, 3)
            rows.append(row)
        print(f"m={m}: {ballots} ballots done", flush=True)
    return rows


def summarise(rows, m_values, args):
    by_m = {}
    for m in m_values:
        mine = [r for r in rows if r["m"] == m]
        stages = ["encrypt_ms", "prove_ms", "total_ms"] + (["verify_ms"] if args.verify else [])
        by_m[str(m)] = {k: describe([r[k] for r in mine]) for k in stages}
    # ru_maxrss is kilobytes on Linux, bytes on macOS.
    rss = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    rss_mb = rss / 1024 if sys.platform != "darwin" else rss / (1024 * 1024)
    return {
        "machine": platform.machine(),
        "platform": platform.platform(),
        "python": platform.python_version(),
        "utc": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "ballots_per_m": args.ballots,
        "warmup": args.warmup,
        "seed": args.seed,
        "peak_rss_mb": round(rss_mb, 1),
        "by_m": by_m,
    }


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--repo", default=str(HERE), help="project root (holds crypto/)")
    ap.add_argument("--ballots", type=int, default=500, help="timed ballots per m (>= 500)")
    ap.add_argument("--m", default="2,4,6,8", help="comma-separated candidate counts")
    ap.add_argument("--warmup", type=int, default=5, help="untimed ballots per m")
    ap.add_argument("--seed", type=int, default=20260804)
    ap.add_argument("--verify", action="store_true",
                    help="also time this repository's verifier per ballot")
    ap.add_argument("--out", default=str(HERE / "results"))
    args = ap.parse_args(argv)
    if args.ballots < 500:
        print("note: at least 500 ballots are recommended for stable tails", file=sys.stderr)
    m_values = [int(x) for x in args.m.split(",")]

    rows = run(args.repo, args.ballots, m_values, args.seed, args.warmup, args.verify)
    summary = summarise(rows, m_values, args)

    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    # The machine architecture, not the hostname, so result files identify no one.
    stem = f"bench_{platform.machine()}_{datetime.now(timezone.utc):%Y%m%dT%H%M%SZ}"
    with open(out / f"{stem}.csv", "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)
    (out / f"{stem}.json").write_text(json.dumps(summary, indent=2) + "\n")

    print(f"\npeak RSS {summary['peak_rss_mb']} MB on {summary['machine']}")
    print(f"{'m':>3} {'stage':<11} {'p50':>9} {'p90':>9} {'p99':>9} {'max':>9}  (ms)")
    for m, stages in summary["by_m"].items():
        for stage, d in stages.items():
            print(f"{m:>3} {stage[:-3]:<11} {d['p50']:>9.1f} {d['p90']:>9.1f} "
                  f"{d['p99']:>9.1f} {d['max']:>9.1f}")
    print(f"\nwrote {out / stem}.csv and .json")


if __name__ == "__main__":
    main()
