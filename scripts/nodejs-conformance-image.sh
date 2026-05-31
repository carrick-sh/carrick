#!/usr/bin/env bash
# Host convenience wrapper for the Node.js/V8/libuv conformance image.
set -euo pipefail

repo="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
entry="$repo/docker/nodejs-conformance/nodejs-conformance"
image="${IMG:-localhost:5005/carrick-nodejs-conformance:24.16.0-26.2.0}"
platform="${PLATFORM:-linux/arm64}"
build=0
push=0
dry_run=0
pass=()

usage() {
  cat <<'USAGE'
usage: scripts/nodejs-conformance-image.sh [wrapper options] [nodejs-conformance options]

Wrapper options:
  --build          build the conformance image before running
  --push           push the image after a successful build
  --image IMAGE    image reference to build/run
  --platform P     docker build/run platform (default: linux/arm64)
  --dry-run        print the image and delegated entrypoint command
  --help

All other options are passed to docker/nodejs-conformance/nodejs-conformance.
USAGE
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --build) build=1; shift ;;
    --push) push=1; shift ;;
    --image) [[ $# -ge 2 ]] || { echo "--image requires a value" >&2; exit 2; }; image="$2"; shift 2 ;;
    --platform) [[ $# -ge 2 ]] || { echo "--platform requires a value" >&2; exit 2; }; platform="$2"; shift 2 ;;
    --dry-run) dry_run=1; pass+=("$1"); shift ;;
    --help|-h) usage; exit 0 ;;
    *) pass+=("$1"); shift ;;
  esac
done

if [[ "$dry_run" -eq 1 ]]; then
  printf 'image=%s\n' "$image"
  printf 'platform=%s\n' "$platform"
  printf 'nodejs-conformance'
  for arg in "${pass[@]}"; do
    [[ "$arg" == "--dry-run" ]] && continue
    printf ' %s' "$arg"
  done
  printf '\n'
  exit 0
fi

if [[ "$build" -eq 1 ]]; then
  docker build --platform "$platform" -t "$image" "$repo/docker/nodejs-conformance"
fi

if [[ "$push" -eq 1 ]]; then
  docker push "$image"
fi

NODEJS_CONFORMANCE_IMAGE="$image" "$entry" "${pass[@]}"
