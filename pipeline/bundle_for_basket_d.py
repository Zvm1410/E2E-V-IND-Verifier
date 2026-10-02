"""Package only the artifacts Basket D needs, and nothing else.

Basket D is the independent verifier. Per the project scope it must
NOT see our prover code, and per the handbook it reads only the
exported bulletin board plus the signatures over its digest. This
script bundles those files into ``for-basket-d/`` alongside a short
README that names what each file is and how D re-derives the base
hash Q.

What goes into the bundle
-------------------------
* ``board.json``          - the full SPEC section 14 bulletin board
                            written by run_election.py, with 12
                            top-level keys populated (election_config,
                            base_hash, trustee_setup, authority_keys,
                            prepoll, ballots, spoils, poll_register,
                            schedule_opening, tally_aggregate,
                            decryption_transcript, tally_declaration).
* ``signatures.json``     - officer + agent Ed25519 signatures over
                            ``L("EVOTE-SIG-v1") || digest``.
* ``election.json``       - the election configuration the board was
                            produced against. D needs this to
                            independently recompute Q via its own
                            implementation of ``compute_base_hash``.
* ``README.md``           - short handover note listing the files and
                            pointing at the SPEC.

What does NOT go in
-------------------
* Any source code from crypto/, tally/, board/, app/, tests/.
* Any private material: sk, trustee shares, schedule seed before
  poll close, per-ballot nonces of un-spoiled ballots, private
  attack log. ``board.export.scan_for_secrets`` re-runs here as a
  final safety net; the bundle is refused if it finds anything.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import shutil
import sys
import tarfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))
import crypto  # noqa: F401  (path-shim side effect)

from board.export import scan_for_secrets  # noqa: E402


HANDOVER_README = """# Bulletin board handover for Basket D

This bundle contains only what the independent verifier (Basket D)
consumes. No prover source code is included; per the project scope,
the verifier must be built without visibility into crypto/, tally/,
board/ or app/.

## Files

- **board.json** - the SPEC section 14 bulletin board. Twelve
  top-level keys, each with the shape agreed on Day 2 (see SPEC).
- **signatures.json** - officer + agent Ed25519 signatures over the
  32-byte-padded label `EVOTE-SIG-v1` concatenated with the SHA-256
  board digest.
- **election.json** - the election configuration. Used by the verifier
  only to recompute the base hash Q from its own implementation of
  the SPEC section 5.2 preimage, and to independently know
  `(n, t, agents, k, candidates)`.

## Verifier properties to check (in order)

Per the handbook (SPEC section 8.3 / verifier properties list):

1. **P1** - group parameters, base hash, encoding round-trips, subgroup
   membership of every element on the board.
2. **P2** - every ballot record is well-formed and every validity proof
   verifies against the base hash Q recomputed from `election.json`
   (not from `board.base_hash`).
3. **P3** - the test schedule opens correctly: `SHA-256(schedule_seed) ==
   test_schedule_commitment`, and every scheduled test serial appears
   as a spoil record.
4. **P4** - the pre-poll section holds one commitment per serial in
   `[1, ballots_expected]` and the schedule commitment; a board
   missing any serial fails here.
5. **P5** - the poll register is consistent with the board:
   `ballots_issued == count(ballots)`,
   `ballots_spoiled == count(spoils)`, and
   `ballots_counted == ballots_issued - ballots_spoiled`.

## Digest & signature check

```
digest = SHA-256( L("EVOTE-BOARD-v1")  ||  canonical_json(board_without_signature_fields) )
```

`canonical_json` = sorted keys, no whitespace, ASCII escaping, group
elements and exponents as 768-character lowercase hex strings.

`signatures.json` must show `k` valid agent signatures plus the officer
signature; `k-1` fails.
"""


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Bundle the artifacts Basket D consumes."
    )
    parser.add_argument("--board",   default="out/board.json")
    parser.add_argument("--sigs",    default="out/signatures.json")
    parser.add_argument("--config",  default="config/election.json")
    parser.add_argument("--out-dir", default="for-basket-d")
    parser.add_argument("--tar",     default="for-basket-d.tar.gz",
                        help="Also write a tar.gz of the bundle for handover.")
    args = parser.parse_args()

    board_p = Path(args.board).resolve()
    sigs_p  = Path(args.sigs).resolve()
    cfg_p   = Path(args.config).resolve()
    out_dir = Path(args.out_dir).resolve()

    for p, label in [(board_p, "board"), (sigs_p, "signatures"),
                     (cfg_p, "election config")]:
        if not p.exists():
            print(f"[bundle] ERROR: {label} not found: {p}")
            print("[bundle] Run 'python run_election.py' first to produce it.")
            return 1

    # ---- SAFETY NET: scan_for_secrets before we copy anything. ---
    # This is the same check ``run_election.py`` runs on export, but we
    # re-run here defensively: if anyone hand-edits ``out/board.json``
    # between the run and the bundle, we still catch it before the
    # bundle leaves the machine.
    board_data = json.loads(board_p.read_text(encoding="utf-8"))
    findings = scan_for_secrets(board_data)
    if findings:
        print("[bundle] REFUSED: secrets scan found forbidden fields on the")
        print("[bundle]           board. Handover would leak private data.")
        for f in findings:
            print(f"[bundle]           - {f}")
        return 2

    # ---- Build the bundle ----------------------------------------
    if out_dir.exists():
        shutil.rmtree(out_dir)
    out_dir.mkdir(parents=True)

    shutil.copy2(board_p, out_dir / "board.json")
    shutil.copy2(sigs_p,  out_dir / "signatures.json")
    shutil.copy2(cfg_p,   out_dir / "election.json")
    (out_dir / "README.md").write_text(HANDOVER_README, encoding="utf-8")

    # A manifest of file sizes and SHA-256 digests, so D can verify
    # nothing was truncated in transit.
    manifest = {"files": []}
    for name in sorted(p.name for p in out_dir.iterdir()
                       if p.name != "MANIFEST.json"):
        p = out_dir / name
        h = hashlib.sha256(p.read_bytes()).hexdigest()
        manifest["files"].append({
            "name": name,
            "sha256": h,
            "size_bytes": p.stat().st_size,
        })
    (out_dir / "MANIFEST.json").write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )

    # ---- Also write a tar.gz for easy transport ------------------
    tar_p = ROOT / args.tar
    if tar_p.exists():
        tar_p.unlink()
    with tarfile.open(tar_p, "w:gz") as tar:
        tar.add(out_dir, arcname=out_dir.name)

    print(f"[bundle] Wrote {out_dir}")
    for f in manifest["files"]:
        print(f"    {f['sha256'][:16]}...  {f['size_bytes']:>10} bytes  {f['name']}")
    print(f"[bundle] Wrote {tar_p} ({tar_p.stat().st_size} bytes)")
    print("[bundle] Ready to hand to Basket D.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
