#!/usr/bin/env bash
# Local cases for require-linked-issue.sh (no network; uses the test seams).
set -uo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
fail=0
# run NAME EXPECTED_RC EVENT BODY LABELS_JSON FILES
run() {
  local name=$1 expect=$2 event=$3 body=$4 labels=$5 files=$6
  echo '{"pull_request":{"number":7}}' >"$tmp/event.json"
  jq -n --arg b "$body" --argjson l "$labels" '{body:$b,labels:($l|map({name:.}))}' >"$tmp/pr.json"
  printf '%s\n' "$files" >"$tmp/files.txt"
  GITHUB_EVENT_NAME=$event GITHUB_EVENT_PATH=$tmp/event.json PR_JSON_FILE=$tmp/pr.json \
    CHANGED_FILES_FILE=$tmp/files.txt "$here/require-linked-issue.sh" >/dev/null 2>&1
  local rc=$?
  if [ "$rc" -eq "$expect" ]; then echo "ok   $name"; else echo "FAIL $name (rc=$rc want $expect)"; fail=1; fi
}
code=$'crates/a/src/lib.rs\nREADME.md'
run linked-closes 0 pull_request "Closes #12" '[]' "$code"
run linked-fixes-lower 0 pull_request $'why\nfixes #3' '[]' "$code"
run linked-resolves 0 pull_request "Resolves #3" '[]' "$code"
run linked-part-of 0 pull_request "Part of #3" '[]' "$code"
run linked-cross-repo 0 pull_request "Closes carrick-sh/carrick-nt#9" '[]' "$code"
run unlinked 1 pull_request "no ref here" '[]' "$code"
run template-untouched 1 pull_request $'Closes #\n<!-- Closes #1 -->' '[]' "$code"
run comment-only-ref 1 pull_request $'<!-- Closes #1 -->' '[]' "$code"
run docs-only 0 pull_request "nothing" '[]' $'docs/a.md\nREADME.md\ndocs/x/y.png'
run docs-plus-code 1 pull_request "nothing" '[]' $'docs/a.md\njustfile'
run label-exempt 0 pull_request "nothing" '["no-issue"]' "$code"
run other-label 1 pull_request "nothing" '["bug"]' "$code"
run merge-group 0 merge_group "" '[]' "$code"
exit $fail
