"""Full-crypto elections through the real prover and this verifier.

Runs the real prover in this repository (crypto/, tally/, run_election.py).
Three jobs:

  clean     --clean N: N clean elections, each from a different setup seed.
         The verifier must accept every one; a single rejection stops
         everything.
  check  --redirect N: N elections in which a blind adversary redirects k
         uniformly chosen serials. For each, the fast model's prediction
         (some redirected serial is a scheduled test ballot) is compared
         with the verifier's verdict on the real board. They must agree
         every time; that agreement is what licenses harness.sim for the
         sweep.
  attribution --attribution DIR: verify the seven bundles
         (bundle-<tag>/) under DIR and record each verdict.

    python -m harness.full_runs --clean 30 --redirect 30 --ballots 40
    python -m harness.full_runs --attribution .

Results go to results/full_runs.json and results/attribution.json, which
harness.tables picks up.
"""

from __future__ import annotations

import argparse
import json
import os
import random
import subprocess
import sys
import tempfile
import time
from multiprocessing import Pool
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from verifier.parse import load_json, parse_board  # noqa: E402
from verifier.spoils import recompute_schedule  # noqa: E402
from verifier.verify import verify  # noqa: E402

BUNDLES = ["clean", "redirection", "stuffing", "malformed", "tally-manipulation",
           "board-edit", "c1-no-test-ballots"]


def _verify_dir(d):
    tester_path = d / "tester_selections.json"
    tester = ({int(k): int(v) for k, v in json.loads(tester_path.read_text()).items()}
              if tester_path.exists() else None)
    return verify((d / "board.json").read_bytes(), (d / "signatures.json").read_bytes(),
                  tester_selections=tester)


def _run_election(repo, config, ballots, out_dir, extra=()):
    cmd = [sys.executable, "run_election.py", "--config", str(config),
           "--ballots", str(ballots), "--out-dir", str(out_dir), *extra]
    done = subprocess.run(cmd, cwd=repo, capture_output=True, text=True)
    if done.returncode != 0:
        raise RuntimeError(f"run_election.py failed ({done.returncode}):\n{done.stdout[-2000:]}"
                           f"\n{done.stderr[-2000:]}")


def _config_with_seed(repo, seed, tmp):
    cfg = json.loads((Path(repo) / "config" / "election.json").read_text())
    cfg["seed"] = seed
    path = Path(tmp) / f"election_{seed}.json"
    path.write_text(json.dumps(cfg))
    return path


def _one_run(job):
    """One election and its verification, in a worker process."""
    repo, kind, seed, ballots, targets, tmp = job
    out = Path(tmp) / f"{kind}-{seed}"
    extra = ("--authority-seed", str(seed))
    if targets:
        extra += ("--redirect-serials", ",".join(map(str, targets)))
    started = time.time()
    _run_election(repo, _config_with_seed(repo, seed, tmp), ballots, out, extra)
    result = _verify_dir(out)
    record = {"kind": kind, "seed": seed, "accepted": result.accepted,
              "failed_property": result.failed_property,
              "reason": result.failure.reason if result.failure else None,
              "P3": result.properties["P3"], "seconds": round(time.time() - started)}
    if kind == "redirect":
        board = parse_board(load_json((out / "board.json").read_bytes()))
        schedule = recompute_schedule(board)
        log = json.loads((out / "private_attack_log.json").read_text())
        changed = {e["ballot_serial"] for e in log if e["type"] == "vote_redirection"
                   and e["true_selection"] != e["substituted_selection"]}
        predicted = bool(changed & schedule)
        observed = result.failed_property == "P3"
        record.update(redirected=sorted(changed), scheduled=sorted(schedule),
                      predicted_detection=predicted,
                      agrees=(predicted == observed) and (observed or result.accepted))
    return record


def full_runs(repo, clean, redirect, ballots, k, base_seed, procs, save=None):
    rng = random.Random(base_seed)
    results = {"ballots": ballots, "k": k, "clean_runs": 0, "false_rejections": 0,
               "redirect_runs": 0, "agree": 0, "detected": 0, "runs": []}
    with tempfile.TemporaryDirectory() as tmp:
        jobs = [(repo, "clean", base_seed + i, ballots, None, tmp) for i in range(clean)]
        jobs += [(repo, "redirect", base_seed + 100_000 + i, ballots,
                  sorted(rng.sample(range(1, ballots + 1), k)), tmp) for i in range(redirect)]
        with Pool(procs) as pool:
            for n, record in enumerate(pool.imap_unordered(_one_run, jobs), 1):
                if record["kind"] == "clean":
                    results["clean_runs"] += 1
                    if not record["accepted"]:
                        results["false_rejections"] += 1
                        print(f"FALSE REJECTION on clean seed {record['seed']}: {record['reason']}")
                else:
                    results["redirect_runs"] += 1
                    results["agree"] += record["agrees"]
                    results["detected"] += record["failed_property"] == "P3"
                    if not record["agrees"]:
                        print(f"DISAGREEMENT on seed {record['seed']}: model "
                              f"{record['predicted_detection']}, verifier "
                              f"{record['failed_property'] or 'Accept'}")
                results["runs"].append(record)
                if save:
                    # Saved after every election, so a stopped run keeps what it finished.
                    save(results)
                verdict = "Accept" if record["accepted"] else record["failed_property"]
                print(f"[{n}/{len(jobs)}] {record['kind']} seed {record['seed']}: {verdict} "
                      f"({record['seconds']} s)", flush=True)
    results["runs"].sort(key=lambda r: (r["kind"], r["seed"]))
    return results


def attribution(root):
    out = {}
    for tag in BUNDLES:
        candidates = [Path(root) / f"bundle-{tag}", Path(root) / tag]
        d = next((c for c in candidates if (c / "board.json").exists()), None)
        if d is None:
            print(f"{tag}: not found, skipped")
            continue
        r = _verify_dir(d)
        if r.accepted:
            out[tag] = "Accept" + (", P3 not exercised" if r.properties["P3"] == "not_exercised"
                                   else "")
        else:
            out[tag] = r.failed_property
        print(f"{tag}: {out[tag]}" + (f"  ({r.failure.reason})" if r.failure else ""))
    return out


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--repo", default=str(ROOT), help="project root (holds crypto/ and tally/)")
    ap.add_argument("--clean", type=int, default=0)
    ap.add_argument("--redirect", type=int, default=0)
    ap.add_argument("--ballots", type=int, default=40)
    ap.add_argument("--k", type=int, default=8,
                    help="serials redirected per run (8 at p = 1/20 detects about a third)")
    ap.add_argument("--procs", type=int, default=os.cpu_count(), help="parallel elections")
    ap.add_argument("--seed", type=int, default=20261002)
    ap.add_argument("--attribution", metavar="DIR",
                    help="directory holding the bundle-<tag>/ directories")
    args = ap.parse_args(argv)
    results_dir = ROOT / "results"
    results_dir.mkdir(exist_ok=True)

    if args.attribution:
        data = attribution(args.attribution)
        (results_dir / "attribution.json").write_text(json.dumps(data, indent=2) + "\n")
    if args.clean or args.redirect:
        out_path = results_dir / "full_runs.json"
        data = full_runs(args.repo, args.clean, args.redirect, args.ballots, args.k, args.seed,
                         args.procs,
                         save=lambda r: out_path.write_text(json.dumps(r, indent=2) + "\n"))
        out_path.write_text(json.dumps(data, indent=2) + "\n")
        print(f"\nclean: {data['clean_runs']} runs, {data['false_rejections']} false rejections")
        print(f"redirect: verifier agrees with the model on {data['agree']} of "
              f"{data['redirect_runs']} ({data['detected']} detected)")
        if data["false_rejections"]:
            sys.exit(1)


if __name__ == "__main__":
    main()
