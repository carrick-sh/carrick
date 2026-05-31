#!/usr/bin/env bash
# Shell-level contract tests for the Node.js conformance image entrypoint.
#
# These tests intentionally use --dry-run / --metadata only; they verify the
# argument surface without requiring Docker, Carrick, or a built Node tree.
set -euo pipefail

repo="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
entry="$repo/docker/nodejs-conformance/nodejs-conformance"
wrapper="$repo/scripts/nodejs-conformance-image.sh"

fail() {
  echo "FAIL: $*" >&2
  exit 1
}

contains() {
  local haystack="$1"
  local needle="$2"
  [[ "$haystack" == *"$needle"* ]] || fail "expected output to contain: $needle"
}

not_contains() {
  local haystack="$1"
  local needle="$2"
  [[ "$haystack" != *"$needle"* ]] || fail "expected output not to contain: $needle"
}

out="$("$entry" --dry-run --runner both --suite app-smoke --line 26 --timeout 9 --jsonl /tmp/node.jsonl)"
contains "$out" "runner=both"
contains "$out" "suite=app-smoke"
contains "$out" "line=26"
contains "$out" "timeout=9"
contains "$out" "jsonl=/tmp/node.jsonl"
contains "$out" "node_ref=v26.2.0"
contains "$out" "libuv_ref=v1.52.1"

meta="$("$entry" --metadata)"
contains "$meta" '"node24_ref":"v24.16.0"'
contains "$meta" '"node26_ref":"v26.2.0"'
contains "$meta" '"libuv_ref":"v1.52.1"'

if "$entry" --dry-run --runner invalid --suite app-smoke >/tmp/nodejs-conf-invalid.out 2>&1; then
  fail "invalid runner unexpectedly succeeded"
fi
contains "$(cat /tmp/nodejs-conf-invalid.out)" "invalid --runner"

wrap="$("$wrapper" --dry-run --runner docker --suite libuv --line 24 --timeout 7)"
contains "$wrap" "image=localhost:5005/carrick-nodejs-conformance:24.16.0-26.2.0"
contains "$wrap" "nodejs-conformance --runner docker --suite libuv --line 24 --timeout 7"

fakebin="$(mktemp -d /tmp/nodejs-conf-fakebin.XXXXXX)"
fake_args="$(mktemp /tmp/nodejs-conf-docker-args.XXXXXX)"
cat > "$fakebin/docker" <<'SH'
#!/usr/bin/env bash
{
  for arg in "$@"; do
    printf '<%s>\n' "$arg"
  done
} > "$FAKE_DOCKER_ARGS"
SH
chmod +x "$fakebin/docker"

rel_jsonl="docs/nodejs-baseline/test-host-path.jsonl"
PATH="$fakebin:$PATH" FAKE_DOCKER_ARGS="$fake_args" "$entry" \
  --runner docker --suite app-smoke --line 24 --timeout 5 --jsonl "$rel_jsonl"
fake_out="$(cat "$fake_args")"
abs_jsonl="$repo/$rel_jsonl"
contains "$fake_out" "<$(dirname "$abs_jsonl"):$(dirname "$abs_jsonl")>"
not_contains "$fake_out" "</usr/local/bin/nodejs-conformance>"
contains "$fake_out" "<--jsonl>"
contains "$fake_out" "<$abs_jsonl>"

fake_carrick_args="$(mktemp /tmp/nodejs-conf-carrick-args.XXXXXX)"
cat > "$fakebin/carrick" <<'SH'
#!/usr/bin/env bash
{
  for arg in "$@"; do
    printf '<%s>\n' "$arg"
  done
} > "$FAKE_CARRICK_ARGS"
SH
chmod +x "$fakebin/carrick"

PATH="$fakebin:$PATH" FAKE_DOCKER_ARGS="$fake_args" FAKE_CARRICK_ARGS="$fake_carrick_args" CARRICK_BIN="$fakebin/carrick" "$entry" \
  --runner both --suite v8-smoke --line 26 --timeout 5 --jsonl "$rel_jsonl" --smoke
carrick_out="$(cat "$fake_carrick_args")"
contains "$carrick_out" "<run>"
contains "$carrick_out" "<--raw>"
contains "$carrick_out" "<NODEJS_CONFORMANCE_EFFECTIVE_RUNNER=carrick>"
not_contains "$carrick_out" "</usr/local/bin/nodejs-conformance>"
contains "$carrick_out" "<--jsonl>"
contains "$carrick_out" "<$abs_jsonl>"

echo "nodejs conformance dry-run contract: ok"
