#!/usr/bin/env bash
# Codemod: rewrite non-portable `libc::<X>` uses in carrick-runtime to the
# `carrick_portable::<X>` shim (see crates/carrick-portable). Idempotent.
#
# Scope: the divergent-symbol set that does NOT compile on Linux. Width issues
# (host_tty termios), the peercred/xucred/ptrace cluster, and macOS-only modules
# are intentionally NOT handled here (they need contextual fixes). Run from repo
# root: ./scripts/port-codemod.sh [DIR]   (DIR defaults to crates/carrick-runtime/src)
set -euo pipefail

dir="${1:-crates/carrick-runtime/src}"
files=$(grep -rlE 'libc::(EV_ADD|EV_DELETE|EV_ENABLE|EV_ONESHOT|EV_CLEAR|EV_ERROR|EV_EOF|EVFILT_READ|EVFILT_WRITE|NOTE_DELETE|NOTE_WRITE|NOTE_EXTEND|NOTE_ATTRIB|NOTE_RENAME|CLOCK_UPTIME_RAW|TCP_NOPUSH|TCP_KEEPALIVE|AF_LINK|__error)' "$dir" || true)

[ -z "$files" ] && { echo "nothing to rewrite under $dir"; exit 0; }

for f in $files; do
  perl -0777 -i -pe '
    # errno write: `*libc::__error() = <expr>;` -> set_errno(<expr>);
    s/\*libc::__error\(\)\s*=\s*([^;]+?);/carrick_portable::set_errno($1);/g;
    # errno read in a standalone unsafe block -> safe errno() (drops the unsafe)
    s/unsafe\s*\{\s*\*libc::__error\(\)\s*\}/carrick_portable::errno()/g;
    # any remaining bare read -> errno() (keeps surrounding unsafe; harmless)
    s/\*libc::__error\(\)/carrick_portable::errno()/g;
    # plain divergent constants: libc::X -> carrick_portable::X (word-bounded)
    s/\blibc::(EV_ADD|EV_DELETE|EV_ENABLE|EV_ONESHOT|EV_CLEAR|EV_ERROR|EV_EOF|EVFILT_READ|EVFILT_WRITE|NOTE_DELETE|NOTE_WRITE|NOTE_EXTEND|NOTE_ATTRIB|NOTE_RENAME|CLOCK_UPTIME_RAW|TCP_NOPUSH|TCP_KEEPALIVE|AF_LINK)\b/carrick_portable::$1/g;
  ' "$f"
  echo "rewrote $f"
done

echo "done. Review with: git diff -- $dir"
