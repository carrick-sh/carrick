#!/usr/bin/env bash
set -euo pipefail

semgrep_bin="${SEMGREP_BIN:-semgrep}"
if ! command -v "$semgrep_bin" >/dev/null 2>&1; then
    echo "error: semgrep is not installed, so the typed-domain gate cannot run." >&2
    exit 1
fi

if [[ -z "${SSL_CERT_FILE:-}" || ! -r "${SSL_CERT_FILE}" ]]; then
    for candidate in \
        /etc/ssl/cert.pem \
        /etc/ssl/certs/ca-certificates.crt \
        /opt/homebrew/etc/ca-certificates/cert.pem
    do
        if [[ -r "$candidate" ]]; then
            export SSL_CERT_FILE="$candidate"
            break
        fi
    done
fi
if [[ -z "${SSL_CERT_FILE:-}" || ! -r "${SSL_CERT_FILE}" ]]; then
    echo "error: no readable CA bundle for semgrep; set SSL_CERT_FILE." >&2
    exit 1
fi

lint_tmp="$(mktemp -d "${TMPDIR:-/tmp}/carrick-semgrep.XXXXXX")"
trap 'rm -rf "$lint_tmp"' EXIT
export SEMGREP_LOG_FILE="${SEMGREP_LOG_FILE:-$lint_tmp/semgrep.log}"
if ! : > "$SEMGREP_LOG_FILE"; then
    echo "error: cannot write semgrep log file: $SEMGREP_LOG_FILE" >&2
    exit 1
fi
export SEMGREP_SEND_METRICS=off
export SEMGREP_ENABLE_VERSION_CHECK=0
export OTEL_SDK_DISABLED=true

"$semgrep_bin" --config .semgrep/ crates/ --severity ERROR --error --quiet
