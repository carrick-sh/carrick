#!/usr/bin/env bash
# Linux/macOS harness: exercise the production unsigned census and selection
# with fake libtest executables; signing only records which files were chosen.
set -euo pipefail
cd "$(dirname "$0")/../.."
root=$(mktemp -d)
trap 'rm -rf "$root"' EXIT
. scripts/lib/test-signed-selection.sh
. scripts/lib/test-signed-args.sh
export TMPDIR="$root"
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
run_case() (
    requested_filter=$1 has_exact=$2 ignored_only=0 include_ignored=0
    negative_test=unsigned_executable_maps_hv_denied_to_entitlement
    scratch=()
    exes=("$root/alpha" "$root/beta" "$root/entitlement_negative")
    rm -f "$root/signed"
    test_signed_select_executables
    printf '%s\n' "${sign_exes[@]}" >"$root/signed"
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

for target in '' guest_smoke test-target test_123; do
    test_signed_validate_target "$target"
done
for target in '../escape' '--all' 'two targets' 'comma,target' 'glob*' '.hidden'; do
    if test_signed_validate_target "$target"; then exit 1; fi
done
printf 'signed selection harness: passed\n'
