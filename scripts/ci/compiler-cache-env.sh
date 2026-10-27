#!/usr/bin/env bash
# Select the shared compiler cache backend for one hosted CI job (#858).
#
# Usage: compiler-cache-env.sh FAMILY read-only|read-write
#
# GitHub-hosted jobs with R2 credentials use the Cloudflare R2 bucket named by
# CARRICK_SCCACHE_R2_BUCKET through sccache's S3 backend. Objects are fetched
# lazily per compilation, so a job no longer downloads a multi-GiB archive, and
# the bucket has no size cap, so the warm union no longer evicts itself.
# FAMILY scopes keys (sccache hashes the absolute paths of each runner image).
#
# Self-hosted runners keep a persistent cache on their own disk (#938). A
# runner always builds in the same checkout path, so its entries match from
# job to job; hosted entries never would, and the runner holds no R2
# credentials. The GitHub cache never hit there: its version includes the
# runner's temp path. Each job gets its own server socket, because runners
# sharing one user would otherwise share sccache's default TCP server.
#
# Without credentials (fork and Dependabot pull requests), a GitHub-hosted job
# keeps the bounded GitHub Actions cache: the workflow's actions/cache steps
# run when this prints backend=gha.
#
# sccache refuses to start when the bucket cannot be read, so a wrong or
# revoked token fails the build instead of silently compiling uncached.
set -euo pipefail

family=${1:?usage: compiler-cache-env.sh FAMILY read-only|read-write}
mode=${2:?usage: compiler-cache-env.sh FAMILY read-only|read-write}
: "${GITHUB_ENV:?}" "${GITHUB_OUTPUT:?}" "${RUNNER_TEMP:?}"

case "$family" in
    linux-x64 | linux-arm64 | darwin-hosted) ;;
    *)
        echo "compiler-cache-env: unknown family '$family'" >&2
        exit 2
        ;;
esac
case "$mode" in
    read-only) rw_mode=READ_ONLY ;;
    read-write) rw_mode=READ_WRITE ;;
    *)
        echo "compiler-cache-env: unknown mode '$mode'" >&2
        exit 2
        ;;
esac

if [[ "${RUNNER_ENVIRONMENT:-}" != github-hosted ]]; then
    : "${RUNNER_NAME:?self-hosted runner has no RUNNER_NAME}" "${HOME:?}"
    dir="${CARRICK_SCCACHE_LOCAL_ROOT:-$HOME/.cache/carrick-sccache}/$RUNNER_NAME"
    mkdir -p "$dir"
    {
        echo "SCCACHE_DIR=$dir"
        echo "SCCACHE_CACHE_SIZE=15G"
        echo "SCCACHE_SERVER_UDS=$RUNNER_TEMP/sccache.sock"
    } >> "$GITHUB_ENV"
    echo "backend=local" >> "$GITHUB_OUTPUT"
    echo "compiler cache: family=$family backend=local ($dir, runner is ${RUNNER_ENVIRONMENT:-unknown})"
    exit 0
fi

# The GitHub cache path stays identical so fallback keys keep matching.
echo "SCCACHE_DIR=$RUNNER_TEMP/carrick-sccache" >> "$GITHUB_ENV"

backend=gha
reason="no R2 credentials"
if [[ -n "${AWS_ACCESS_KEY_ID:-}" && -n "${AWS_SECRET_ACCESS_KEY:-}" ]]; then
    : "${CARRICK_SCCACHE_R2_BUCKET:?R2 credentials are set but no bucket is named}"
    : "${CARRICK_SCCACHE_R2_ENDPOINT:?R2 credentials are set but no endpoint is named}"
    {
        echo "SCCACHE_BUCKET=$CARRICK_SCCACHE_R2_BUCKET"
        echo "SCCACHE_ENDPOINT=$CARRICK_SCCACHE_R2_ENDPOINT"
        echo "SCCACHE_REGION=auto"
        echo "SCCACHE_S3_USE_SSL=true"
        echo "SCCACHE_S3_KEY_PREFIX=sccache/$family/"
        echo "SCCACHE_S3_RW_MODE=$rw_mode"
    } >> "$GITHUB_ENV"
    backend=r2
    reason="bucket $CARRICK_SCCACHE_R2_BUCKET, prefix sccache/$family/"
fi

echo "backend=$backend" >> "$GITHUB_OUTPUT"
echo "compiler cache: family=$family backend=$backend mode=$rw_mode ($reason)"
