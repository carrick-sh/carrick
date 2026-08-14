#!/bin/sh
# Validate a saved hvpatch-alias-sharing.d capture. The D program itself exits
# nonzero for live failures; this companion makes the same contract reviewable
# and testable against retained output, including captures interrupted before
# their END record reached the consumer.
set -eu

capture=${1:?usage: validate-hvpatch-alias-sharing.sh <capture>}
[ -r "$capture" ] || { echo "HVPATCHALIAS validation: unreadable capture" >&2; exit 2; }

if grep -q '^HVPATCHALIAS|error|' "$capture"; then
    echo "HVPATCHALIAS validation: provider error" >&2
    exit 3
fi

summary=$(grep '^HVPATCHALIAS|end|' "$capture" || true)
[ "$(printf '%s\n' "$summary" | grep -c .)" -eq 1 ] || {
    echo "HVPATCHALIAS validation: missing or duplicate completion" >&2
    exit 2
}

field() {
    printf '%s\n' "$summary" | tr '|' '\n' | sed -n "s/^$1=//p"
}

maps=$(field maps)
faults=$(field faults)
walks=$(field walks)
fault_walks=$(field fault_walks)
fault_ttbrs=$(field fault_ttbrs)
bounded=$(field bounded)
errors=$(field errors)

for value in "$maps" "$faults" "$walks" "$fault_walks" "$fault_ttbrs" "$bounded" "$errors"; do
    case "$value" in
        ''|*[!0-9]*) echo "HVPATCHALIAS validation: malformed completion" >&2; exit 2 ;;
    esac
done

[ "$bounded" -eq 0 ] || { echo "HVPATCHALIAS validation: timeout" >&2; exit 4; }
[ "$errors" -eq 0 ] || { echo "HVPATCHALIAS validation: provider errors=$errors" >&2; exit 3; }
[ "$maps" -gt 0 ] && [ "$faults" -gt 0 ] && [ "$walks" -gt 0 ] \
    && [ "$fault_walks" -gt 0 ] && [ "$fault_ttbrs" -gt 0 ] || {
        echo "HVPATCHALIAS validation: incomplete companion capture" >&2
        exit 2
    }

echo "HVPATCHALIAS validation: ok"
