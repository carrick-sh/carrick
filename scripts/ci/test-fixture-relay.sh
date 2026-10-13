#!/usr/bin/env bash
# Credential-free dry run: fake curl/stat/npx, real splitting and SHA checks.
set -euo pipefail
scripts=$(cd "$(dirname "$0")" && pwd)
scratch=$(mktemp -d)
trap 'rm -rf "$scratch"' EXIT
export RELAY_TEST_ROOT=$scratch
mkdir -p "$scratch/bin"
export PATH="$scratch/bin:$PATH"

# Only file ownership is simulated; production insists on root:0444.
cat > "$scratch/bin/stat" <<'SH'
#!/usr/bin/env bash
printf '%s\n' "${RELAY_TEST_PERMISSIONS:-0:444}"
SH
cat > "$scratch/bin/curl" <<'SH'
#!/usr/bin/env bash
set -euo pipefail
config=$(cat)
test "$config" = 'header = "Authorization: Bearer test-relay-token"'
[[ $* != *test-relay-token* ]]
[[ $* != *--location* ]]
destination=
url=
max_time=
while (($#)); do
    case $1 in
        --output) destination=$2; shift ;;
        --max-time) max_time=$2; shift ;;
        https://*) url=$1 ;;
    esac
    shift
done
test -n "$destination"
test -n "$url"
test "$url" = "https://carrick-gate-relay.tjfontaine.workers.dev/bundles/$GITHUB_SHA/$BUNDLE_SHA256.part${url##*.part}"
if [[ -n "$max_time" ]] && (( max_time > 600 )); then
    echo "curl: max-time $max_time exceeds 600s ceiling" >&2
    exit 99
fi
if [[ ${RELAY_TEST_MODE:-success} = failure ]]; then exit 22; fi
if [[ ${RELAY_TEST_MODE:-success} = corrupt ]]; then
    printf 'corrupted bytes' > "$destination"
elif [[ ${RELAY_TEST_MODE:-success} = slow ]]; then
    if [[ -n "$max_time" ]] && (( max_time <= 45 )); then
        echo "curl: (28) Operation timed out" >&2
        exit 28
    fi
    cp "$RELAY_TEST_ROOT/${url##*.}" "$destination"
elif [[ ${RELAY_TEST_MODE:-success} = transient-failure ]]; then
    if [[ ! -f "$RELAY_TEST_ROOT/transient-failed" ]]; then
        touch "$RELAY_TEST_ROOT/transient-failed"
        echo "curl: (28) Operation timed out" >&2
        exit 28
    fi
    cp "$RELAY_TEST_ROOT/${url##*.}" "$destination"
elif [[ ${RELAY_TEST_MODE:-success} = consecutive-failure ]]; then
    echo "curl: (56) Failure with receiving network data" >&2
    exit 56
else
    cp "$RELAY_TEST_ROOT/${url##*.}" "$destination"
fi
SH
cat > "$scratch/bin/npx" <<'SH'
#!/usr/bin/env bash
set -euo pipefail
test "$1" = --yes
test "$2" = wrangler@4.76.0
test "$3 $4 $5" = 'r2 object put'
test "$7" = --remote
test "$8" = --file
test "$6" = "carrick-gate-images/bundles/$GITHUB_SHA/$BUNDLE_SHA256.part00"
test "$(wc -c < "$9")" -le 268435456
cmp "$9" "$RELAY_TEST_ROOT/original"
printf '%s\n' "$6" > "$RELAY_TEST_ROOT/uploaded-key"
SH
chmod +x "$scratch/bin/"*

cd "$scratch"
export GITHUB_SHA=1111111111111111111111111111111111111111
export BUNDLE_NAME=2222222222222222222222222222222222222222222222222222222222222222.tar.gz
printf 'first half\n' > part00
printf 'second half\n' > part01
cat part00 part01 > original
digest=$(shasum -a 256 original)
export BUNDLE_SHA256=${digest%% *}
export BUNDLE_PARTS=2
export CARRICK_RELAY_TOKEN_FILE="$scratch/relay-token"
printf 'test-relay-token\n' > "$CARRICK_RELAY_TOKEN_FILE"
mkdir -p "target/fixtures/published/$GITHUB_SHA"
cp original "target/fixtures/published/$GITHUB_SHA/$BUNDLE_NAME"
bash "$scripts/upload-fixture-parts.sh" > upload.log 2>&1
test -s uploaded-key
echo 'PASS pinned upload, content-addressed key, part size and bytes'

# Mirror the workflow: a failed relay selects download-artifact, and either
# route must pass the mandatory digest check. Copy simulates the GH action.
download() {
    if bash "$scripts/download-fixture-bundle.sh" relay > relay.log 2>&1; then
        echo relay > selected-path
    else
        echo github > selected-path
        cp original "target/fixtures/incoming/$BUNDLE_NAME"
    fi
    bash "$scripts/download-fixture-bundle.sh" verify > verify.log 2>&1
    cmp original "target/fixtures/incoming/$BUNDLE_NAME"
    test -z "$(find target/fixtures/incoming -name '.relay-*' -print)"
    if grep -F -q test-relay-token relay.log verify.log; then
        echo 'FAIL token appeared in logs' >&2
        exit 1
    fi
}

download
test "$(cat selected-path)" = relay
echo 'PASS relay success: ordered concatenation, SHA-256, no fallback'
export RELAY_TEST_MODE=slow
download
test "$(cat selected-path)" = relay
echo 'PASS slow relay success under new budget: no fallback'
export RELAY_DEADLINE_SECONDS=40
download
test "$(cat selected-path)" = github
grep -F -q "timed out" relay.log
echo 'PASS slow relay with tight budget times out: GitHub fallback verified'
unset RELAY_DEADLINE_SECONDS
export RELAY_DEADLINE_SECONDS=1000
download
test "$(cat selected-path)" = relay
unset RELAY_DEADLINE_SECONDS
echo 'PASS relay budget ceiling enforced at 600s: no fallback'
rm -f "$RELAY_TEST_ROOT/transient-failed"
export RELAY_TEST_MODE=transient-failure
download
test "$(cat selected-path)" = relay
test -f "$RELAY_TEST_ROOT/transient-failed"
grep -F -q "timed out" relay.log
echo 'PASS transient transport failure: retried and succeeded without fallback'
export RELAY_TEST_MODE=consecutive-failure
download
test "$(cat selected-path)" = github
grep -F -q "Failure with receiving network data" relay.log
echo 'PASS consecutive transport failures: GitHub fallback verified'
export RELAY_TEST_MODE=failure
download
test "$(cat selected-path)" = github
echo 'PASS HTTP failure: GitHub fallback verified'
export RELAY_TEST_MODE=corrupt
download
test "$(cat selected-path)" = github
grep -F -q FAILED relay.log
echo 'PASS relay digest mismatch: GitHub fallback verified'
export RELAY_TEST_MODE=success
export RELAY_TEST_PERMISSIONS=501:644
download
test "$(cat selected-path)" = github
unset RELAY_TEST_PERMISSIONS
echo 'PASS unsafe token permissions: GitHub fallback verified'
printf 'invalid"\nheader = "injected' > "$CARRICK_RELAY_TOKEN_FILE"
download
test "$(cat selected-path)" = github
echo 'PASS malformed token: GitHub fallback verified'
mv "$CARRICK_RELAY_TOKEN_FILE" token-target
ln -s token-target "$CARRICK_RELAY_TOKEN_FILE"
download
test "$(cat selected-path)" = github
echo 'PASS symlink token: GitHub fallback verified'
rm "$CARRICK_RELAY_TOKEN_FILE"
download
test "$(cat selected-path)" = github
echo 'PASS absent token: GitHub fallback verified'

# A corrupt GitHub download must fail closed too.
printf 'corrupt GitHub bytes' > "target/fixtures/incoming/$BUNDLE_NAME"
if bash "$scripts/download-fixture-bundle.sh" verify > verify.log 2>&1; then
    echo 'FAIL corrupt GitHub artifact accepted' >&2
    exit 1
fi
grep -F -q FAILED verify.log
echo 'PASS GitHub digest mismatch: rejected'
