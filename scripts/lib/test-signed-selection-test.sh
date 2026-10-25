#!/usr/bin/env bash
# Linux/macOS harness: exercise the production unsigned census and selection
# with fake libtest executables; signing only records which files were chosen.
set -euo pipefail
cd "$(dirname "$0")/../.."
root=$(mktemp -d)
trap 'rm -rf "$root"' EXIT
sed -n '/^# 2\. Enumerate/,/^    rebuilt_args=()/p' scripts/lib/test-signed-body.sh | sed '$d' | sed '$d' >"$root/selection"
for binary in alpha beta entitlement_negative; do
    cat >"$root/$binary" <<'FAKE'
#!/usr/bin/env bash
if [ "${2:-}" = --ignored ]; then
    case "$0" in *entitlement_negative) echo 'unsigned_executable_maps_hv_denied_to_entitlement: test';; esac
else
    case "$0" in
        *alpha) echo 'module::wanted: test';;
        *beta) if [ "${SAME_TEST:-0}" = 1 ]; then echo 'other::wanted: test'; else echo 'unrelated: test'; fi;;
        *) echo 'unsigned_executable_maps_hv_denied_to_entitlement: test';;
    esac
fi
FAKE
    chmod +x "$root/$binary"
done
carrick_post_link_sign() { printf '%s\n' "$1" >>"$root/signed"; }
test_signed_has_entitlement() { return 0; }
run_case() (
    requested_filter=$1 has_exact=$2 ignored_only=0 include_ignored=0
    negative_test=unsigned_executable_maps_hv_denied_to_entitlement
    entitlements=unused scratch=()
    exes=("$root/alpha" "$root/beta" "$root/entitlement_negative")
    rm -f "$root/signed"
    . "$root/selection"
    [ "${#sign_exes[@]}" = "$3" ]
    [ "${#run_exes[@]}" = "$4" ]
    [ "${run_exes[0]}" = "$root/alpha" ]
    grep -Fxq "$root/alpha" "$root/signed"
    grep -Fxq "$root/entitlement_negative" "$root/signed"
    [ "$(wc -l <"$root/signed" | tr -d ' ')" = "$3" ]
)
run_case wanted 1 2 1
run_case wanted 0 2 1
run_case '' 0 3 2
export SAME_TEST=1
run_case wanted 0 3 2
if run_case wanted 1 3 2; then exit 1; fi
unset SAME_TEST
if run_case absent 1 2 1; then exit 1; fi
printf 'signed selection harness: passed\n'
