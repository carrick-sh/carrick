#!/usr/bin/env bash
# Start this job's own sccache server once, outside any `just lease` (#1264).
#
# Usage: compiler-cache-start-local.sh
#
# Runs in every job where compiler-cache-env.sh chose backend=local (a
# self-hosted runner), before any compile and before any leased step. A
# leased step runs in its own session, and the lease supervisor kills and
# reaps that session when the step's command ends. A server first started by
# a rustc wrapper inside a leased step died with it and left its socket
# behind, so the next leased step's wrapper failed with "Server startup
# failed: File exists". Started here, the server is no step's descendant and
# lives until `just ci-cache-finish` stops it at job end.
#
# A socket on this job's path that no server answers is stale and is
# removed; one that answers is this job's server and is left running.
set -euo pipefail

: "${SCCACHE_SERVER_UDS:?compiler-cache-env.sh did not select the local backend}"
sccache_bin=${CARRICK_SCCACHE_BIN:-sccache}
if ! command -v "$sccache_bin" > /dev/null; then
    echo "compiler-cache-start-local: '$sccache_bin' is not installed; install it before this step" >&2
    exit 1
fi
if "$sccache_bin" --show-stats > /dev/null 2>&1; then
    echo "compiler cache: local server already running on $SCCACHE_SERVER_UDS"
    exit 0
fi
if [[ -e "$SCCACHE_SERVER_UDS" ]]; then
    echo "compiler cache: removing a stale socket no server answers: $SCCACHE_SERVER_UDS"
    rm -f -- "$SCCACHE_SERVER_UDS"
fi
SCCACHE_IDLE_TIMEOUT=0 "$sccache_bin" --start-server
echo "compiler cache: local server started on $SCCACHE_SERVER_UDS"
