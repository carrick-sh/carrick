#!/usr/bin/env bash
# Validate with the existing library before Git-based admission; retain the
# Rust guard through build, signing, execution and scoped EXIT cleanup.
# CARRICK_TEST_TARGET=<integration-target> narrows Cargo linking while retaining
# the package's negative control. Omit it to build all test targets.
# CARRICK_SIGNED_FUNCTIONAL=1 declares a non-timing run and opts into the
# bounded functional lease. Gate recipes clear both overrides.
# Use this direct script for focused runs.
set -euo pipefail
cd "$(dirname "$0")/.."
. scripts/lib/build-env.sh
. scripts/lib/test-signed-args.sh
pkg="${1:?usage: scripts/test-signed.sh <package> [libtest args...]}"
shift
export CARRICK_RUN_ID="${CARRICK_RUN_ID-embed-signed-$$}"
test_signed_validate_run_id "$CARRICK_RUN_ID"
test_signed_parse_libtest_args "$@"
test_signed_validate_features "${CARRICK_TEST_SIGNED_FEATURES:-}"
test_signed_validate_target "${CARRICK_TEST_TARGET:-}"
exec cargo --config "$CARRICK_CARGO_CACHE_CONFIG" run --locked -p carrick-xtask -- worktree-run -- /bin/bash scripts/lib/test-signed-body.sh "$pkg" "$@"
