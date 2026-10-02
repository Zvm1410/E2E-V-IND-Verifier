"""Full-crypto elections through the real prover and this verifier.

Runs the real prover in this repository (crypto/, tally/, run_election.py).
Three jobs:

  D10    --clean N: N clean elections, each from a different setup seed.
         The verifier must accept every one; a single rejection stops
         everything (handbook D10).
  check  --redirect N: N elections in which a blind adversary redirects k
         uniformly chosen serials. For each, the fast model's prediction
         (some redirected serial is a scheduled test ballot) is compared
         with the verifier's verdict on the real board. They must agree
         every time; that agreement is what licenses harness.sim for the
         D9 sweep.
  D7     --attribution DIR: verify the seven regenerated bundles unpacked
         under DIR and record which property each was rejected under.

    python -m harness.full_runs --clean 30 --redirect 30 --ballots 40
    python -m harness.full_runs --attribution .

Results go to results/full_runs.json and results/attribution.json, which
harness.tables picks up.
"""

from __future__ import annotations

import argparse
import json
import random
import subprocess
import sys
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from verifier.parse import load_json, parse_board  # noqa: E402
from verifier.spoils import recompute_schedule  # noqa: E402
from verifier.verify import verify  # noqa: E402

BUNDLES = {"clean": "clean", "A8": "A8-redirection", "A9": "A9-stuffing",
           "B12": "B12-malformed", "C10": "C10-tally-tamper",
           "C11": "C11-retroactive-edit", "C1": "C1-no-test-ballots"}


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


def full_runs(repo, clean, redirect, ballots, k, base_seed):
    results = {"ballots": ballots, "k": k, "clean_runs": 0, "false_rejections": 0,
               "redirect_runs": 0, "agree": 0, "runs": []}
    rng = random.Random(base_seed)
    with tempfile.TemporaryDirectory() as tmp:
        jobs = [("clean", i) for i in range(clean)] + [("redirect", i) for i in range(redirect)]
        for n, (kind, i) in enumerate(jobs, 1):
            seed = base_seed + (0 if kind == "clean" else 100_000) + i
            out = Path(tmp) / f"{kind}-{i}"
            extra = ()
            if kind == "redirect":
                targets = sorted(rng.sample(range(1, ballots + 1), k))
                extra = ("--redirect-serials", ",".join(map(str, targets)))
            started = time.time()
            _run_election(repo, _config_with_seed(repo, seed, tmp), ballots, out, extra)
            result = _verify_dir(out)
            record = {"kind": kind, "seed": seed, "accepted": result.accepted,
                      "failed_property": result.failed_property,
                      "reason": result.failure.reason if result.failure else None,
                      "P3": result.properties["P3"]}
            if kind == "clean":
                results["clean_runs"] += 1
                if not result.accepted:
                    results["false_rejections"] += 1
                    print(f"FALSE REJECTION on clean seed {seed}: {result.summary()}")
            else:
                board = parse_board(load_json((out / "board.json").read_bytes()))
                schedule = recompute_schedule(board)
                log = json.loads((out / "private_attack_log.json").read_text())
                changed = {e["ballot_serial"] for e in log if e["type"] == "vote_redirection"
                           and e["true_selection"] != e["substituted_selection"]}
                predicted = bool(changed & schedule)
                observed = result.failed_property == "P3"
                consistent = (predicted == observed) and (observed or result.accepted)
                results["redirect_runs"] += 1
                results["agree"] += consistent
                record.update(redirected=sorted(changed), scheduled=sorted(schedule),
                              predicted_detection=predicted, agrees=consistent)
                if not consistent:
                    print(f"DISAGREEMENT on seed {seed}: model {predicted}, "
                          f"verifier {result.summary()}")
            results["runs"].append(record)
            print(f"[{n}/{len(jobs)}] {kind} seed {seed}: "
                  f"{'Accept' if result.accepted else result.failed_property} "
                  f"({time.time() - started:.0f} s)", flush=True)
    return results


def attribution(root):
    out = {}
    for key, tag in BUNDLES.items():
        candidates = [Path(root) / f"for-basket-d-{tag}", Path(root) / tag]
        d = next((c for c in candidates if (c / "board.json").exists()), None)
        if d is None:
            print(f"{tag}: not found, skipped")
            continue
        r = _verify_dir(d)
        if r.accepted:
            out[key] = "Accept" + (", P3 not exercised" if r.properties["P3"] == "not_exercised"
                                   else "")
        else:
            out[key] = r.failed_property
        print(f"{tag}: {out[key]}" + (f"  ({r.failure.reason})" if r.failure else ""))
    return out


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--repo", default=str(ROOT), help="project root (holds crypto/ and tally/)")
    ap.add_argument("--clean", type=int, default=0)
    ap.add_argument("--redirect", type=int, default=0)
    ap.add_argument("--ballots", type=int, default=40)
    ap.add_argument("--k", type=int, default=3, help="serials redirected per run")
    ap.add_argument("--seed", type=int, default=20261002)
    ap.add_argument("--attribution", metavar="DIR",
                    help="directory holding the unpacked for-basket-d-<tag> bundles")
    args = ap.parse_args(argv)
    results_dir = ROOT / "results"
    results_dir.mkdir(exist_ok=True)

    if args.attribution:
        data = attribution(args.attribution)
        (results_dir / "attribution.json").write_text(json.dumps(data, indent=2) + "\n")
    if args.clean or args.redirect:
        data = full_runs(args.repo, args.clean, args.redirect, args.ballots, args.k, args.seed)
        (results_dir / "full_runs.json").write_text(json.dumps(data, indent=2) + "\n")
        print(f"\nclean: {data['clean_runs']} runs, {data['false_rejections']} false rejections")
        print(f"redirect: verifier agrees with the model on {data['agree']} of "
              f"{data['redirect_runs']}")
        if data["false_rejections"]:
            sys.exit(1)


if __name__ == "__main__":
    main()
