#!/usr/bin/env bash
set -euo pipefail

root=${1:?usage: fetch-arm64-python.sh FIXTURE_ROOT}
mkdir -p -- "$root"

# linux/arm64 manifest of the python:3.12-slim image used by the boot probe.
manifest_sha256=c61cffc3bacb94ed026ff8b45d5114b7693dd0420baca0a1ace0e3d0ce9035fd
image="docker.io/library/python@sha256:$manifest_sha256"

# Keep the exact registry manifest so the Rust witness can verify its identity.
token=$(curl --fail --silent --show-error \
    'https://auth.docker.io/token?service=registry.docker.io&scope=repository:library/python:pull' |
    jq --exit-status --raw-output .token)
manifest=$(mktemp)
trap 'rm -f -- "$manifest"' EXIT
curl --fail --silent --show-error \
    --header "Authorization: Bearer $token" \
    --header 'Accept: application/vnd.oci.image.manifest.v1+json' \
    "https://registry-1.docker.io/v2/library/python/manifests/sha256:$manifest_sha256" \
    --output "$manifest"
printf '%s  %s\n' "$manifest_sha256" "$manifest" | sha256sum --check --strict

docker pull --platform linux/arm64 "$image"
container=$(docker create --pull never --platform linux/arm64 "$image")
trap 'rm -f -- "$manifest"; docker rm "$container" >/dev/null' EXIT
docker export "$container" | tar --extract --no-same-owner --directory "$root"
install -m 644 "$manifest" "$root/.carrick-image-manifest.json"
