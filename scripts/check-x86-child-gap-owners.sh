#!/usr/bin/env bash
# Every owner issue in the x86 exec'd-child crossing gap table must be OPEN.
# A closed owner means the gap was fixed (retire the row and lower the
# ceiling) or was cited wrongly (cite the real open issue). Needs `gh`.
set -euo pipefail

table="${1:-crates/carrick-cli/tests/fixtures/x86_child_crossing_gaps.tsv}"
status=0
for owner in $(grep -v '^#' "$table" | cut -f3 | tr -d '#' | sort -un); do
    state=$(gh issue view "$owner" --json state --jq .state)
    if [ "$state" != "OPEN" ]; then
        echo "gap owner #$owner is $state, not OPEN" >&2
        status=1
    fi
done
exit "$status"
