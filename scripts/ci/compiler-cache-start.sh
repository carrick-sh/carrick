#!/usr/bin/env bash
# Start the R2-backed compiler cache server for one hosted CI job (#961).
#
# Usage: compiler-cache-start.sh
#
# Runs right after sccache is installed, in every job where
# compiler-cache-env.sh chose backend=r2, and before any compile. It reads the
# SCCACHE_* settings that script exported, so the server it starts is the one
# every later rustc wrapper call connects to. The server never idles out: it
# must still be up for the first compile after long install steps, and a
# hosted runner is discarded with the job.
#
# sccache refuses to start when the bucket cannot be read. Refused credentials
# fail the job at once, so a wrong or revoked token never silently turns CI
# into uncached builds. Any other startup failure (an R2 5xx such as S3
# "InternalError", or a startup timeout) says nothing about the code: after one
# retry, read-only jobs compile uncached with a warning. The cache-warm writer
# exists to fill the cache, so it still fails. A missing sccache binary is a
# workflow bug, not an outage, and fails too.
set -euo pipefail

: "${GITHUB_ENV:?}" "${SCCACHE_BUCKET:?compiler-cache-env.sh did not select R2}"
: "${SCCACHE_S3_RW_MODE:?compiler-cache-env.sh did not select R2}"
sccache_bin=${CARRICK_SCCACHE_BIN:-sccache}
if ! command -v "$sccache_bin" > /dev/null; then
    echo "compiler-cache-start: '$sccache_bin' is not installed; install it before this step" >&2
    exit 1
fi

for attempt in 1 2; do
    if error=$(SCCACHE_IDLE_TIMEOUT=0 "$sccache_bin" --start-server 2>&1); then
        echo "compiler cache: R2 server started (attempt $attempt)"
        exit 0
    fi
    echo "compiler-cache-start: sccache startup attempt $attempt failed: $error" >&2
    case "$error" in
        *AccessDenied* | *InvalidAccessKeyId* | *SignatureDoesNotMatch* | *NoSuchBucket* | *PermissionDenied*)
            echo "compiler-cache-start: R2 refused the credentials; not falling back" >&2
            exit 1
            ;;
    esac
    "$sccache_bin" --stop-server > /dev/null 2>&1 || true
    if [[ "$attempt" == 1 ]]; then sleep "${CARRICK_SCCACHE_RETRY_SECONDS:-10}"; fi
done
if [[ "$SCCACHE_S3_RW_MODE" == READ_WRITE ]]; then
    echo "compiler-cache-start: the cache writer cannot run uncached" >&2
    exit 1
fi
echo "::warning title=Compiler cache unavailable::R2 failed twice at sccache startup; this job compiles uncached (#961)"
echo "CARRICK_SCCACHE=0" >> "$GITHUB_ENV"
