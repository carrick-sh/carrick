#!/usr/bin/env bash
# Arm driver for the AMP1 Darwin kernel amplification ledger.
#
#   scripts/perf/amplification-capture.sh <arm-tag> [ENV=VAL ...]
#
# One arm per invocation: stamp a run id, capture, reap. Everything that used to
# live in a driver like this is now TYPED and lives in the binary --
# `carrick trace --preflight-quiet-host` settles-and-refuses on a dirty host and
# writes its receipt into the stream header, the AMP1 reader admits or refuses
# the capture, and `carrick debug amplification-ledger` / `amplification-compare`
# own every number. What is irreducibly shell is the arm loop, the
# `CARRICK_RUN_ID` stamp, and `scripts/sudo/kill.sh`.
#
# The image MUST be digest-pinned (`name@sha256:...`) -- the launch refuses a
# tag, because two captures of a moving tag are not a before/after of anything.
# Resolve one from a registry's `Docker-Content-Digest` response header.
#
# Traced runs are perturbed 2-4x: counts and same-instrument ratios are the
# claim, wall is never.
set -uo pipefail
cd "$(dirname "$0")/../.."
BIN=target/release/carrick
OUT=${CARRICK_AMP_OUT:-target/perf/amp1}
IMAGE=${CARRICK_AMP_IMAGE:?set CARRICK_AMP_IMAGE to a digest-pinned image}
BOUND=${CARRICK_AMP_BOUND_SECONDS:-3600}
# The kernel lane is what this tree is measured against; `native` and `vmm` are
# reference lanes. Stamped into the arm banner so a ledger can never be read as
# a before/after of a backend it did not measure.
BACKEND=${CARRICK_AMP_BACKEND:-hvpatch}
GUEST=${CARRICK_AMP_GUEST:-'set -eu; cd /tmp; rm -rf gc-w; printf "package main\nfunc main(){println(\"ok\")}\n" > h.go; GOCACHE=/tmp/gc-w /usr/local/go/bin/go build -o h ./h.go; ./h; echo BUILD_OK'}

TAG=${1:?usage: amplification-capture.sh <arm-tag> [ENV=VAL ...]}
shift
mkdir -p "$OUT"
LOG="$OUT/capture.log"
say() { echo "$@" | tee -a "$LOG"; }

say "=========================================================="
say "arm:    $TAG  $*"
say "binary: $(shasum -a 256 $BIN | cut -d' ' -f1)"
say "source: $(git rev-parse HEAD) tree-clean=$([ -z "$(git status --porcelain)" ] && echo yes || echo no)"
say "host:   $(sw_vers -productVersion) $(sysctl -n machdep.cpu.brand_string)"
say "image:  $IMAGE"
say "backend:$BACKEND"
say "=========================================================="

export CARRICK_RUN_ID="amp1${TAG}$$"
RAW="$OUT/$TAG.raw"
[ -e "$RAW" ] && { say "$TAG REFUSED: $RAW exists (a capture never clobbers evidence)"; exit 3; }

t0=$(date +%s)
env "$@" "$BIN" trace --profile native-amplification --preflight-quiet-host \
    --profile-bound-seconds "$BOUND" -o "$RAW" \
    -- run --exec-backend "$BACKEND" "$IMAGE" /bin/sh -c "$GUEST" \
    > "$OUT/$TAG.out" 2> "$OUT/$TAG.err"
rc=$?
say "$TAG RESULT: exit=$rc wall_s=$(( $(date +%s) - t0 )) out=[$(tr '\n' ' ' < "$OUT/$TAG.out")]"
bash scripts/sudo/kill.sh "$CARRICK_RUN_ID" 2>&1 | tail -1 | tee -a "$LOG"

# A nonzero exit means the capture was REFUSED (dirty host, drops, truncation,
# an unarmed join). The raw file it left behind carries its own drop verdict, so
# it cannot be laundered into a ledger later -- but do not build one from it.
[ "$rc" -eq 0 ] || exit "$rc"
"$BIN" debug amplification-ledger "$RAW" --output "$OUT/$TAG.ledger.json" \
    && say "$TAG LEDGER: $OUT/$TAG.ledger.json"
