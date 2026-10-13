#!/usr/bin/env bash
# The relay is transport only; expected identity comes from the hosted job.
# Exit nonzero on ANY relay failure so the workflow runs download-artifact.
set +x
set -euo pipefail

[[ ${BUNDLE_NAME:?} =~ ^[0-9a-f]{64}\.tar\.gz$ ]]
[[ ${BUNDLE_SHA256:?} =~ ^[0-9a-f]{64}$ ]]
incoming=target/fixtures/incoming

verify() {
    printf '%s  %s\n' "$BUNDLE_SHA256" "$1" | shasum -a 256 -c -
}

case ${1:-} in
    verify)
        shopt -s nullglob
        bundles=("$incoming"/*.tar.gz)
        test "${#bundles[@]}" -eq 1
        test "${bundles[0]}" = "$incoming/$BUNDLE_NAME"
        verify "${bundles[0]}"
        ;;
    relay)
        [[ ${GITHUB_SHA:?} =~ ^[0-9a-f]{40}$ ]]
        [[ ${BUNDLE_PARTS:?} =~ ^([1-9][0-9]?|100)$ ]]
        # Start fresh even in a persistent workspace; partial downloads never
        # occupy incoming. The EXIT trap cleans up on verification/HTTP failure.
        rm -rf "$incoming"
        mkdir -p "$incoming"
        staging=$(mktemp -d "$incoming/.relay-XXXXXX")
        trap 'rm -rf "$staging"' EXIT
        # This lives outside the wiped job home, under the read-only toolchain.
        token_file=${CARRICK_RELAY_TOKEN_FILE:-/Volumes/carrick-build/carrick-ci/toolchain/relay-token}
        test -f "$token_file" && test ! -L "$token_file"
        # BSD stat on cloudmac; GNU stat supports the portable dry-run test.
        if [[ $(uname -s) = Darwin ]]; then
            permissions=$(stat -f '%u:%Lp' "$token_file")
        else
            permissions=$(stat -c '%u:%a' "$token_file")
        fi
        test "$permissions" = 0:444
        token=$(< "$token_file")
        # Refuse newlines/quotes/control bytes before constructing curl config.
        [[ $token =~ ^[A-Za-z0-9._~+/-]+=*$ ]]

        # Bound the whole relay attempt, including multiple parts, to 45 s.
        deadline=$((SECONDS + 45))
        for ((part=0; part<BUNDLE_PARTS; part++)); do
            remaining=$((deadline - SECONDS))
            test "$remaining" -gt 0
            printf -v suffix '%02d' "$part"
            # No redirect, curlrc, verbose output, token argv or token file in
            # the workspace. Supply the Authorization header only via stdin.
            printf 'header = "Authorization: Bearer %s"\n' "$token" |
                curl --disable --config - --fail --silent --show-error \
                    --proto '=https' --connect-timeout 5 --max-time "$remaining" \
                    --output "$staging/part$suffix" \
                    "https://carrick-gate-relay.tjfontaine.workers.dev/bundles/$GITHUB_SHA/$BUNDLE_SHA256.part$suffix"
            cat "$staging/part$suffix" >> "$staging/$BUNDLE_NAME"
            rm "$staging/part$suffix"
        done
        unset token
        verify "$staging/$BUNDLE_NAME"
        mv "$staging/$BUNDLE_NAME" "$incoming/$BUNDLE_NAME"
        ;;
    *)
        echo 'usage: download-fixture-bundle.sh relay|verify' >&2
        exit 2
        ;;
esac
