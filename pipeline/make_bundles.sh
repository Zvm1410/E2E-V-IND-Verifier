#!/usr/bin/env bash
# Regenerate every bundle the verifier is evaluated on.
# Run from the root of the group repository (the one with crypto/ and tally/),
# after copying this pipeline/ directory's files over it.
set -euo pipefail

BALLOTS="${BALLOTS:-60}"

run() {
    local tag="$1" config="$2"; shift 2
    echo "=== $tag"
    rm -rf "out-$tag"
    python run_election.py --config "$config" --ballots "$BALLOTS" --out-dir "out-$tag" "$@"
    python bundle_for_basket_d.py \
        --board "out-$tag/board.json" --sigs "out-$tag/signatures.json" \
        --tester "out-$tag/tester_selections.json" --config "$config" \
        --out-dir "for-basket-d-$tag" --tar "for-basket-d-$tag.tar.gz"
}

STD=config/election.json
run clean                 "$STD"
run A8-redirection        "$STD" --redirect-to 5
run A9-stuffing           "$STD" --stuff 3 --force-sign
run B12-malformed         "$STD" --malform
run C10-tally-tamper      "$STD" --tamper-tally
run C11-retroactive-edit  "$STD" --retroactive-edit
run C1-no-test-ballots    config/election_c1.json

echo "Done. Send the seven for-basket-d-*.tar.gz files."
