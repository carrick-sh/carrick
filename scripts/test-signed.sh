#!/usr/bin/env bash
# Sign and run a crate's cargo test executables so they can boot HVF guests.
#
# A guest under macOS/HVF only runs from an executable carrying the
# com.apple.security.hypervisor entitlement — and the executable that calls
# hv_vm_create is the TEST BINARY (target/debug/deps/<crate>-<hash>), which
# nothing else signs. A bare `cargo test` therefore dies HV_DENIED
# (0xfae94007) on its first guest. This is the test-executable counterpart of
# scripts/build-signed.sh: build the package's test executables without
# running them, push each through the SAME post-link path the shipped CLI
# uses (scripts/lib/post-link-sign.sh: vtool build-version stamp + ad-hoc
# codesign with scripts/entitlements.plist), prove the entitlement landed,
# then run each serially (HVF allows ONE VM per process; the guest tests also
# redirect the process's own fd 1 for the Inherit case).
#
# FAIL-CLOSED by design: an unsigned executable is a FAILURE here, never a
# skip (AGENTS.md: a test no gate executes is not a test). The embed crate
# maps HV_DENIED to `EmbedError::Entitlement`, its guest tests assert that
# variant never appears, and this script additionally runs the NEGATIVE
# control: an ad-hoc-signed copy WITHOUT the entitlement (exactly a bare
# `cargo test` executable) must produce `EmbedError::Entitlement`. A signing
# regression cannot pass silently in either direction.
#
# Usage: scripts/test-signed.sh <package> [libtest args...]
#   scripts/test-signed.sh carrick-embed
#   scripts/test-signed.sh carrick-embed captured_ --nocapture
# The extra args go STRAIGHT to each libtest executable (no cargo in between),
# so do NOT write a `--` separator: libtest would treat everything after it as
# positional filters and silently ignore `--nocapture`.
#
# Written for the macOS system bash (3.2): no mapfile, no `${arr[@]}` on an
# empty array under `set -u`, `+=` array appends only.
#
# Cleanup is run-id scoped: every guest these executables launch carries
# CARRICK_RUN_ID (default embed-signed-<pid>), stamped into the carrier's
# proctitle as `carrick:<run-id>:`; scripts/sudo/kill.sh <run-id> reaps only
# those on exit (plus the `<run-id>-cli` child the CLI-parity test spawns —
# kill.sh anchors on the literal `carrick:<id>:` token, so the `-cli` id needs
# its own call). Never `pkill -f carrick`. Logs are never truncated (tail/grep
# on a gate destroys evidence): every executable's full output goes to the
# terminal.
set -euo pipefail
cd "$(dirname "$0")/.."
. scripts/lib/post-link-sign.sh

pkg="${1:?usage: scripts/test-signed.sh <package> [libtest args...]}"
shift

if [ "$(uname -s)" != "Darwin" ]; then
    echo "test-signed: macOS/HVF only — the entitlement requirement does not exist on this host" >&2
    exit 1
fi
for tool in cargo jq codesign /usr/bin/vtool; do
    if ! command -v "$tool" >/dev/null 2>&1; then
        echo "test-signed: missing required tool: $tool" >&2
        exit 1
    fi
done

entitlements="scripts/entitlements.plist"
negative_test="unsigned_executable_maps_hv_denied_to_entitlement"

run_id="${CARRICK_RUN_ID:-embed-signed-$$}"
export CARRICK_RUN_ID="$run_id"
# Hermetic translation store, as `just test` does: fixture guests must never
# warm (or be warmed by) the user's persistent store.
CARRICK_DSR_STORE_DIR="$(mktemp -d -t carrick-test-store)"
export CARRICK_DSR_STORE_DIR

scratch=()
cleanup() {
    status=$?
    # Scoped reap of anything this run (or its CLI-parity child) left wedged.
    # Guests are same-user processes, so a direct call reaps them; `sudo -n`
    # first (NOPASSWD on the rig: scripts/sudo/ is under carrick/*/*/*) also
    # catches root-owned `carrick trace` front-ends carrying the same id.
    for id in "$run_id" "$run_id-cli"; do
        sudo -n scripts/sudo/kill.sh "$id" >/dev/null 2>&1 \
            || scripts/sudo/kill.sh "$id" >/dev/null 2>&1 \
            || true
    done
    rm -rf "$CARRICK_DSR_STORE_DIR"
    if [ "${#scratch[@]}" -gt 0 ]; then
        rm -f "${scratch[@]}"
    fi
    exit "$status"
}
trap cleanup EXIT

# 1. Build (never run) the package's test executables and collect their
#    paths. Only the package's OWN test-profile artifacts carry
#    `profile.test == true` plus an `executable`; dependencies compile with
#    `test: false`. The JSON goes to a file first so a build failure stops the
#    script (a process substitution's exit status would not).
json_log="$(mktemp -t carrick-test-signed-build)"
scratch+=("$json_log")
cargo test -p "$pkg" --no-run --message-format=json >"$json_log"
exes=()
while IFS= read -r exe; do
    [ -n "$exe" ] && exes+=("$exe")
done < <(jq -r 'select(.reason == "compiler-artifact" and .profile.test == true and .executable != null) | .executable' "$json_log")
if [ "${#exes[@]}" -eq 0 ]; then
    echo "test-signed: cargo produced no test executables for $pkg" >&2
    exit 1
fi

# 2. Sign each executable in place through the shared post-link path, and
#    PROVE the entitlement is on the file before trusting it.
for exe in "${exes[@]}"; do
    scratch+=("$exe.raw.$$" "$exe.tmp.$$")
    carrick_post_link_sign "$exe" "$exe" "$entitlements"
    if ! codesign -d --entitlements - "$exe" 2>&1 | grep -q 'com.apple.security.hypervisor'; then
        echo "test-signed: $exe does not carry com.apple.security.hypervisor after signing" >&2
        exit 1
    fi
    echo "test-signed: signed $exe"
done

# 3. Run each signed executable serially (one VM per process).
failed=0
for exe in "${exes[@]}"; do
    echo "test-signed: running $exe $*"
    if ! env RUST_TEST_THREADS=1 "$exe" "$@"; then
        echo "test-signed: FAIL $exe" >&2
        failed=1
    fi
done

# 4. Negative control. The executable carrying the negative test is copied
#    and re-signed ad-hoc WITHOUT the entitlement — byte-for-byte the state
#    of a bare `cargo test` binary — and must classify HV_DENIED as
#    EmbedError::Entitlement. The test is #[ignore] so step 3 skips it.
carrier=""
for exe in "${exes[@]}"; do
    if "$exe" --list 2>/dev/null | grep -qx "$negative_test: test"; then
        carrier="$exe"
        break
    fi
done
if [ -z "$carrier" ]; then
    echo "test-signed: no test executable of $pkg carries $negative_test; the negative control cannot run" >&2
    exit 1
fi
noent="$carrier.noent.$$"
scratch+=("$noent")
cp -f "$carrier" "$noent"
codesign --force --sign - "$noent"
if codesign -d --entitlements - "$noent" 2>&1 | grep -q 'com.apple.security.hypervisor'; then
    echo "test-signed: $noent still carries the hypervisor entitlement; the negative control would prove nothing" >&2
    exit 1
fi
neg_log="$(mktemp -t carrick-test-signed-negative)"
scratch+=("$neg_log")
echo "test-signed: negative control on $noent"
neg_rc=0
env RUST_TEST_THREADS=1 "$noent" --ignored --exact "$negative_test" >"$neg_log" 2>&1 || neg_rc=$?
cat "$neg_log"
if [ "$neg_rc" -ne 0 ] || ! grep -aq '^test result: ok. 1 passed' "$neg_log"; then
    echo "test-signed: FAIL negative control ($negative_test did not pass on the unentitled copy, rc=$neg_rc)" >&2
    failed=1
fi

if [ "$failed" -ne 0 ]; then
    echo "test-signed: FAILED ($pkg)" >&2
    exit 1
fi
echo "test-signed: OK ($pkg: ${#exes[@]} signed executable(s) passed, negative control passed)"
