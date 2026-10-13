#!/usr/bin/env bash
# Hosted trusted publisher only. Credentials belong to this step's env.
set +x
set -euo pipefail

[[ ${GITHUB_SHA:?} =~ ^[0-9a-f]{40}$ ]]
[[ ${BUNDLE_NAME:?} =~ ^[0-9a-f]{64}\.tar\.gz$ ]]
[[ ${BUNDLE_SHA256:?} =~ ^[0-9a-f]{64}$ ]]
bundle="target/fixtures/published/$GITHUB_SHA/$BUNDLE_NAME"
printf '%s  %s\n' "$BUNDLE_SHA256" "$bundle" | sha256sum -c -

parts=$(mktemp -d)
trap 'rm -rf "$parts"' EXIT
# GNU split on the hosted ARM Linux publisher; each PUT is <= 256 MiB.
split -b 268435456 -d -a 2 "$bundle" "$parts/$BUNDLE_SHA256.part"
for part in "$parts"/*.part*; do
    npx --yes wrangler@4.76.0 r2 object put \
        "carrick-gate-images/bundles/$GITHUB_SHA/${part##*/}" \
        --remote --file "$part"
done
