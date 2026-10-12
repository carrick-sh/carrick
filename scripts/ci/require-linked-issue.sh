#!/usr/bin/env bash
# GitHub-first rule gate: a non-docs PR must link an issue.
#
# Passes when any of these hold:
#   - the event is not a pull_request (merge_group etc. pass trivially);
#   - the PR carries the label `no-issue`;
#   - the PR body has a closing reference (Closes/Fixes/Resolves and the
#     close/fix/resolve + d/s variants, case-insensitive) or `Part of`,
#     followed by `#N` or `owner/repo#N`;
#   - every changed file is docs (`*.md` or under `docs/`).
#
# The live PR is fetched (not the event payload) so that "re-run failed jobs"
# after editing the body or adding a label sees the new state.
#
# Test seams (used by scripts/ci/test-require-linked-issue.sh):
#   PR_JSON_FILE        PR object JSON instead of `gh api`
#   CHANGED_FILES_FILE  newline-separated changed paths instead of `gh api`
set -euo pipefail

event_name="${GITHUB_EVENT_NAME:?GITHUB_EVENT_NAME unset}"
if [ "$event_name" != "pull_request" ]; then
  echo "linked-issue: $event_name is not a pull_request; passing."
  exit 0
fi

event="${GITHUB_EVENT_PATH:?GITHUB_EVENT_PATH unset}"
number="$(jq -r '.pull_request.number' "$event")"

if [ -n "${PR_JSON_FILE:-}" ]; then
  pr="$(cat "$PR_JSON_FILE")"
else
  pr="$(gh api "repos/${GITHUB_REPOSITORY:?}/pulls/${number}")"
fi

if jq -e '[.labels[]?.name] | index("no-issue")' <<<"$pr" >/dev/null; then
  echo "linked-issue: label no-issue present; passing."
  exit 0
fi

# Strip HTML comments so the template's instructions cannot satisfy the check.
if jq -r '(.body // "") | gsub("<!--.*?-->"; ""; "s")' <<<"$pr" |
  grep -Eiq '\b(clos(e|es|ed)|fix(es|ed)?|resolv(e|es|ed)|part of):?[[:space:]]+([A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+)?#[0-9]+\b'; then
  echo "linked-issue: PR #$number links an issue; passing."
  exit 0
fi

if [ -n "${CHANGED_FILES_FILE:-}" ]; then
  files="$(cat "$CHANGED_FILES_FILE")"
else
  files="$(gh api --paginate "repos/${GITHUB_REPOSITORY:?}/pulls/${number}/files" --jq '.[].filename')"
fi
if [ -n "$files" ] && ! grep -Evq '(\.md$|^docs/)' <<<"$files"; then
  echo "linked-issue: docs-only PR; passing."
  exit 0
fi

echo "::error title=No linked issue::PR #$number changes non-docs files but its body has no 'Closes #N', 'Fixes #N', 'Resolves #N' or 'Part of #N' (cross-repo owner/repo#N also works). Open or find the issue first, edit the PR body, then re-run this job. Use the 'no-issue' label only for genuinely issue-less changes."
exit 1
