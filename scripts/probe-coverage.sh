#!/bin/sh
# Print the goal's headline metric: # of owned invariant probes (✅/🧪) vs
# # of LTP-only backlog items (⬜) in docs/conformance-coverage.md. Run from
# anywhere in the repo.
#
# This *replaces* "LTP MATCH count" as the thing the goal tracks. A new probe
# row in the coverage map bumps the numerator; a new ⬜ in the backlog bumps
# the denominator until a probe owns it.

set -e
cd "$(dirname "$0")/.."
doc=docs/conformance-coverage.md
if [ ! -f "$doc" ]; then
  echo "missing $doc" >&2
  exit 66
fi

probe_rows=$(grep -E '^\| .* \| (✅|🧪)' "$doc" | wc -l | tr -d ' ')
backlog_rows=$(grep -E '^- ⬜' "$doc" | wc -l | tr -d ' ')
probe_bins=$(find conformance-probes/src/bin -maxdepth 1 -name '*.rs' | wc -l | tr -d ' ')

echo "carrick conformance coverage (headline metric)"
echo "  owned invariant rows  : $probe_rows  (probe ✅ or lib-test 🧪)"
echo "  LTP-only backlog rows : $backlog_rows  (⬜)"
echo "  probe binaries in tree: $probe_bins  (one .rs per probe in src/bin/)"

# Quick gap check: probe binaries that don't appear in any coverage-map row.
echo ""
echo "probes WITHOUT a coverage-map row (unowned outputs):"
missing=0
for f in conformance-probes/src/bin/*.rs; do
  name=$(basename "$f" .rs)
  # crude: look for the bare name as a backtick-quoted token in the map
  if ! grep -qE "\\\`$name\\\`" "$doc"; then
    echo "  - $name"
    missing=$((missing + 1))
  fi
done
if [ "$missing" -eq 0 ]; then
  echo "  (none)"
fi
