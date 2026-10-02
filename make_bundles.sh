#!/usr/bin/env bash
# Regenerate every bundle the verifier is evaluated on.
# Run from the project root.
set -euo pipefail

BALLOTS="${BALLOTS:-60}"
# Fixed so the bundles are reproducible; at 60 ballots and p = 1/20 it draws
# serials 19, 48, 53 and 57 (computed with SPEC 10.2's draw).
AUTHORITY_SEED="${AUTHORITY_SEED:-1}"

run() {
    local tag="$1" config="$2"; shift 2
    echo "=== $tag"
    rm -rf "out-$tag"
    python run_election.py --config "$config" --ballots "$BALLOTS" --out-dir "out-$tag" \
        --authority-seed "$AUTHORITY_SEED" "$@"
    python export_bundle.py \
        --board "out-$tag/board.json" --sigs "out-$tag/signatures.json" \
        --tester "out-$tag/tester_selections.json" --config "$config" \
        --out-dir "bundle-$tag" --tar "bundle-$tag.tar.gz"
}

STD=config/election.json
run clean                 "$STD"
run redirection           "$STD" --redirect-to 5
run stuffing              "$STD" --stuff 3 --force-sign
run malformed             "$STD" --malform
run tally-manipulation    "$STD" --tamper-tally
run board-edit            "$STD" --retroactive-edit
run c1-no-test-ballots    config/election_c1.json

echo "Done: seven bundle-*/ directories and bundle-*.tar.gz files."
