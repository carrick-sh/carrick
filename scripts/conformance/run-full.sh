#!/bin/sh
# Durable, idempotent driver for the carrick differential conformance suite.
#
# Re-running this is always safe and self-healing — it brings every precondition
# to the state the harness needs, rebuilds what's stale, then runs:
#
#   1. Registries: the two local registries the suites pull from are STARTED if
#      stopped, CREATED if missing, and their images PUSHED if the registry
#      doesn't already serve them. `docker push` is content-addressed, so an
#      already-served image re-pushes to the SAME digest (no spurious
#      image-guard re-pull on the next run).
#        * localhost:5050  -> cpython-test, ltp   (container name: registry)
#        * localhost:5005  -> go, node            (container name: vt-ferry-registry)
#   2. Build: the SIGNED carrick binary (cargo build strips the HVF entitlement
#      -> HV_DENIED, so always via build-signed.sh) AND the carrick-conformance
#      harness. cargo is incremental, so this is ~free when nothing changed and
#      guarantees the run uses a binary that matches the working tree.
#   3. Run: target/release/carrick-conformance --tier "$TIER" "$@". The harness
#      itself is already idempotent downstream — its image-freshness guard keeps
#      carrick's image bytes == docker's, and its committed oracle cache means a
#      routine run executes only carrick and diffs against cached docker results.
#
# Usage:
#   scripts/conformance/run-full.sh                 # full tier, default output
#   scripts/conformance/run-full.sh --bless         # record: rewrite baseline + matrix
#   TIER=smoke scripts/conformance/run-full.sh      # fast gate
#   scripts/conformance/run-full.sh --suite ltp-kill12 --refresh-oracle
#
# Pass-through args go straight to carrick-conformance (see its --help).
set -e
cd "$(dirname "$0")/../.."

log() { printf '[run-full] %s\n' "$*" >&2; }

# --- 1. registries ----------------------------------------------------------
ensure_registry() { # name port
    name="$1"; port="$2"
    if [ -n "$(docker ps -q -f "name=^${name}$" 2>/dev/null)" ]; then
        return 0  # already running
    fi
    if [ -n "$(docker ps -aq -f "name=^${name}$" 2>/dev/null)" ]; then
        log "starting stopped registry '$name' (:$port)"
        docker start "$name" >/dev/null
    else
        log "creating registry '$name' (:$port)"
        docker run -d --restart=always -p "${port}:5000" --name "$name" registry:2 >/dev/null
    fi
}

# Push image into its registry only if that registry doesn't already serve the
# tag. The image must exist in the local docker store (built/pulled previously).
ensure_image() { # registry/repo:tag
    ref="$1"
    reg="${ref%%/*}"   # localhost:5050
    rest="${ref#*/}"   # repo:tag
    repo="${rest%:*}"  # repo
    tag="${rest##*:}"  # tag
    if curl -fsS -m 5 "http://${reg}/v2/${repo}/tags/list" 2>/dev/null | grep -q "\"${tag}\""; then
        return 0  # registry already serves it
    fi
    if docker image inspect "$ref" >/dev/null 2>&1; then
        log "pushing $ref (registry did not serve it)"
        docker push "$ref" >/dev/null
    else
        log "WARN: $ref not in local docker store and not served by $reg — pull/build it first"
    fi
}

if command -v docker >/dev/null 2>&1; then
    ensure_registry registry 5050
    ensure_registry vt-ferry-registry 5005
    # give a freshly-started registry a moment to accept connections
    sleep 1
    ensure_image localhost:5050/ltp:arm64
    ensure_image localhost:5050/cpython-test:3.12.13
    ensure_image localhost:5005/carrick-go-conformance:1.24
    ensure_image localhost:5005/carrick-nodejs-conformance:24.16.0-26.2.0
else
    log "WARN: docker not found — skipping registry setup (carrick will use its local image cache; uncached docker-oracle suites will fail)"
fi

# --- 2. build (signed carrick + harness) ------------------------------------
log "building signed carrick + conformance harness"
./scripts/build-signed.sh                 # builds the whole workspace, signs carrick
if [ ! -x target/release/carrick-conformance ]; then
    cargo build --release -p carrick-conformance
fi

# --- 3. run -----------------------------------------------------------------
TIER="${TIER:-full}"
log "running carrick-conformance --tier $TIER $*"
exec target/release/carrick-conformance --tier "$TIER" "$@"
