"""Package one election's exported artefacts for verification.

Writes a directory and a .tar.gz holding exactly what crosses the air gap
and what the verifier consumes:

* ``board.json``              the SPEC section 14 bulletin board
* ``signatures.json``         officer and agent signatures over its digest
* ``election.json``           the configuration it was produced from
* ``tester_selections.json``  the tester's record (SPEC 11.1), not part of the board
* ``MANIFEST.json``           size and SHA-256 of each file

The board is scanned for forbidden fields first and the bundle is refused
on a hit. No source code and no private material goes in.
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


BUNDLE_README = """# Bulletin board bundle for the independent verifier

## Files

- **board.json** - the SPEC section 14 bulletin board (revision 3).
- **signatures.json** - officer and agent Ed25519 signatures over
  `L("EVOTE-SIG-v1") || digest`, SPEC section 15.3.
- **election.json** - the configuration the board was produced from.
- **tester_selections.json** - the tester's own record of what they
  pressed on each challenged ballot (SPEC section 11.1). Not part of the
  board and not covered by its signatures; it is the tester's evidence.

## Verify

```
python -m verifier board.json signatures.json --tester tester_selections.json
```

The verifier checks P1 to P5 in the order of SPEC section 16 and names
the first property that fails.
"""


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Package one election for verification."
    )
    parser.add_argument("--board",   default="out/board.json")
    parser.add_argument("--sigs",    default="out/signatures.json")
    parser.add_argument("--config",  default="config/election.json")
    parser.add_argument("--tester",  default="out/tester_selections.json")
    parser.add_argument("--out-dir", default="bundle")
    parser.add_argument("--tar",     default="bundle.tar.gz",
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
    tester_p = Path(args.tester).resolve()
    if tester_p.exists():
        shutil.copy2(tester_p, out_dir / "tester_selections.json")
    (out_dir / "README.md").write_text(BUNDLE_README, encoding="utf-8")

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
    print("[bundle] Ready.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
