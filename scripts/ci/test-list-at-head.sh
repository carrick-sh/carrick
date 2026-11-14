#!/usr/bin/env bash
# test-list-at-head.sh <test-list args...>: list the PR head's compiled tests after a job that tested the merge ref.
# PR CI checks out refs/pull/N/merge, but the manifest names the PR head ($HEAD), so the head itself is fetched
# (the repository is public; no credentials) and checked out detached once the job's tests are done, then
# `carrick-xtask test-list --head "$HEAD"` lists it (it refuses any other checkout). #2328 item 4.
set -euo pipefail
: "${HEAD:?HEAD must be the PR head commit}"
: "${GITHUB_REPOSITORY:?}"
[[ "$HEAD" =~ ^[0-9a-f]{40}$ ]] || { echo "test-list-at-head: HEAD must be a 40-hex commit SHA" >&2; exit 1; }
git fetch --no-tags --depth=1 "https://github.com/$GITHUB_REPOSITORY" "$HEAD"
git checkout --detach -q FETCH_HEAD
exec just xtask test-list --head "$HEAD" "$@"
