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

        # Bound the whole relay attempt, including multiple parts and retries.
        relay_deadline=${RELAY_DEADLINE_SECONDS:-300}
        [[ $relay_deadline =~ ^[1-9][0-9]*$ ]]
        if (( relay_deadline > 600 )); then
            relay_deadline=600
        fi
        deadline=$((SECONDS + relay_deadline))

        fetch_part() {
            local part_suffix=$1
            local part_remaining=$2
            # No redirect, curlrc, verbose output, token argv or token file in
            # the workspace. Supply the Authorization header only via stdin.
            printf 'header = "Authorization: Bearer %s"\n' "$token" |
                curl --disable --config - --fail --silent --show-error \
                    --proto '=https' --connect-timeout 5 --max-time "$part_remaining" \
                    --output "$staging/part$part_suffix" \
                    "https://carrick-gate-relay.tjfontaine.workers.dev/bundles/$GITHUB_SHA/$BUNDLE_SHA256.part$part_suffix"
        }

        for ((part=0; part<BUNDLE_PARTS; part++)); do
            printf -v suffix '%02d' "$part"
            remaining=$((deadline - SECONDS))
            test "$remaining" -gt 0
            fetch_status=0
            fetch_part "$suffix" "$remaining" || fetch_status=$?
            if [[ $fetch_status -ne 0 ]]; then
                case $fetch_status in
                    6|7|18|28|35|52|56)
                        rm -f "$staging/part$suffix"
                        remaining=$((deadline - SECONDS))
                        test "$remaining" -gt 0
                        retry_status=0
                        fetch_part "$suffix" "$remaining" || retry_status=$?
                        if [[ $retry_status -ne 0 ]]; then
                            exit "$retry_status"
                        fi
                        ;;
                    *)
                        exit "$fetch_status"
                        ;;
                esac
            fi
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
