#!/bin/sh
# Hold Rust checkout admission through build, signing, execution and cleanup.
set -e
cd "$(dirname "$0")/.."
. scripts/lib/build-env.sh
exec cargo --config "$CARRICK_CARGO_CACHE_CONFIG" run --locked -p carrick-xtask -- worktree-run -- /bin/sh scripts/lib/build-signed-body.sh "$@"
