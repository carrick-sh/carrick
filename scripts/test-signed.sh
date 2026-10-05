#!/usr/bin/env bash
# Validate with the existing library before Git-based admission; retain the
# Rust guard through build, signing, execution and scoped EXIT cleanup.
set -euo pipefail
cd "$(dirname "$0")/.."
. scripts/lib/build-env.sh
. scripts/lib/test-signed-args.sh
pkg="${1:?usage: scripts/test-signed.sh <package> [libtest args...]}"
shift
test_signed_validate_run_id "${CARRICK_RUN_ID-embed-signed-$$}"
test_signed_parse_libtest_args "$@"
test_signed_validate_features "${CARRICK_TEST_SIGNED_FEATURES:-}"
exec cargo --config "$CARRICK_CARGO_CACHE_CONFIG" run --locked -p carrick-xtask -- worktree-run -- /bin/bash scripts/lib/test-signed-body.sh "$pkg" "$@"
