#!/usr/bin/env bash
# Mechanical release-closure assertion for the VM-free test coordinator.
set -euo pipefail
if ! command -v grep >/dev/null 2>&1; then
    echo 'vmfree schedule closure check requires grep' >&2
    exit 1
fi
cd "$(dirname "$0")/.."
cargo_tree="$(cargo tree -p carrick-cli --edges normal --prefix none --format '{p} [{f}]')"
if grep -Eq '^carrick-kernel-example v' <<<"$cargo_tree"; then
    echo 'vmfree schedule leaked into the product dependency closure' >&2
    exit 1
else
    grep_status=$?
    if [ "$grep_status" -ne 1 ]; then
        echo "vmfree schedule closure grep failed with status $grep_status" >&2
        exit "$grep_status"
    fi
fi
# Instrumentation may be selected by the non-product harness only.
if grep -Eq '^carrick-kernel v.*\[.*schedule-hooks' <<<"$cargo_tree"; then
    echo 'kernel schedule-hooks leaked into the product feature closure' >&2
    exit 1
else
    grep_status=$?
    if [ "$grep_status" -ne 1 ]; then
        exit "$grep_status"
    fi
fi
# The shared source hook is guarded at macro definition, so optimized builds
# contain neither the call nor its point expression.
if ! python3 - <<'PY'
from pathlib import Path
import re
import sys

source = Path("crates/carrick-kernel/src/kernel/schedule.rs").read_text()
enabled = r'#\[cfg\(all\(debug_assertions, feature = "schedule-hooks"\)\)\]'
disabled = r'#\[cfg\(not\(all\(debug_assertions, feature = "schedule-hooks"\)\)\)\]'
empty_hook = r'\(\$hooks:expr, \$event:expr\) => \{\};'
sys.exit(0 if re.search(enabled, source)
         and re.search(disabled, source)
         and re.search(empty_hook, source) else 1)
PY
then
    echo 'vmfree schedule hook lost its release compile-out guard' >&2
    exit 1
fi
echo 'vmfree schedule excluded from product closure and release hook expansion'
