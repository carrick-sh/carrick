#!/bin/sh
# bhyve-grind.sh — tight edit→build→test loop for the bhyve LTP parity grind.
#
# Why this exists: closing the bhyve<->KVM LTP gap is a long grind of small,
# per-suite fixes (the high-leverage clusters — ring-0 fork, signal-death,
# cross-process futex, connect(0.0.0.0) — are done; the rest is +1..2 each, see
# `project_bhyve_parity_campaign` memory for the prioritized backlog). This wraps
# the repetitive parts: rsync the local crates to the FreeBSD bhyve box, build the
# bhyve binary, run specific LTP suites against the COMMITTED oracle (carrick-only,
# no Docker), and report verdicts or raw failure modes. The babysit (kill wedged
# guests + reap leaked /dev/vmm nodes) is folded into every run.
#
# The bhyve lane runs x86_64 guests on a FreeBSD/amd64 host; sockets/clocks/etc.
# hit the FreeBSD host, so most remaining failures are FreeBSD-vs-Linux ABI diffs.
#
# Config (env): BHYVE_BOX (default root@<lab-ip> — see the FreeBSD test box),
#   BHYVE_DIR (default /path/to/carrick-conf), BHYVE_REG (insecure registry serving
#   localhost:5050/ltp:arm64), BHYVE_IMG (default localhost:5050/ltp:arm64).
#
# Usage:
#   scripts/conformance/bhyve-grind.sh build              # rsync crates + build bhyve binary
#   scripts/conformance/bhyve-grind.sh run  S1 S2 ...      # verdicts vs committed oracle (MATCH/REGRESSION)
#   scripts/conformance/bhyve-grind.sh char S1 S2 ...      # first TFAIL/TBROK per suite (root-cause)
#   scripts/conformance/bhyve-grind.sh reap               # kill wedged guests + reap leaked VM nodes
#   scripts/conformance/bhyve-grind.sh full [jsonl]       # full LTP no-regression run -> /tmp/ltpfull.jsonl
#   scripts/conformance/bhyve-grind.sh stillfail <jsonl> <bhyve-specific.txt>  # still-failing bhyve-specific list
#
# Typical loop: edit a crate -> `build` -> `run <the affected suites>` (confirm
# they flip + nothing nearby regresses) -> commit -> periodically `full` for the
# comprehensive no-regression gate. Suites are LTP binary names WITHOUT the
# `ltp-` prefix (e.g. `stat03 stat03_64`).

set -eu
BOX="${BHYVE_BOX:-root@<lab-ip>}"
DIR="${BHYVE_DIR:-/path/to/carrick-conf}"
REG="${BHYVE_REG:-localhost:5050}"
IMG="${BHYVE_IMG:-localhost:5050/ltp:arm64}"
SSH="ssh -o ConnectTimeout=15 -o ServerAliveInterval=20 -o ServerAliveCountMax=400 -o BatchMode=yes"
ENVV="CARRICK_INSECURE_REGISTRIES=$REG"
BUILD="cargo build --release -j4 -p carrick-cli --no-default-features --features platform-freebsd,syscall-shim"
# Reap leaked/wedged guests; works whether run remotely (in a heredoc) or as a phrase.
REAP='ps -axo pid,etimes,command 2>/dev/null | awk "/carrick:/ && \$2>180 {print \$1}" | xargs -r kill -9 2>/dev/null; for vm in $(ls /dev/vmm/ 2>/dev/null | grep carrick); do pid=$(echo "$vm" | sed "s/carrick-\([0-9]*\)-.*/\1/"); kill -0 "$pid" 2>/dev/null || bhyvectl --destroy --vm="$vm" >/dev/null 2>&1; done'

cmd="${1:-help}"; shift 2>/dev/null || true

case "$cmd" in
  sync)
    rsync -az crates/ "$BOX:$DIR/crates/"
    ;;
  build)
    rsync -az crates/ "$BOX:$DIR/crates/"
    # shellcheck disable=SC2029
    $SSH "$BOX" "cd $DIR && $BUILD 2>&1 | grep -E '^error|error\[|Finished' | tail -3"
    ;;
  run)
    S=""; for s in "$@"; do S="$S --suite ltp-$s"; done
    # shellcheck disable=SC2029
    $SSH "$BOX" "cd $DIR && $REAP; pkill -9 -f 'carrick:conf-' 2>/dev/null; \
      $ENVV ./target/release/carrick-conformance --lane bhyve-local --ecosystem ltp $S \
        --workers 3 --flake-retries 0 2>&1 | grep -E 'MATCH|REGRESSION|DIFF|CRASH|TIMEOUT|summary' | tail -30"
    ;;
  char)
    for t in "$@"; do
      # shellcheck disable=SC2029
      $SSH "$BOX" "cd $DIR && $REAP; \
        $ENVV timeout 40 ./target/release/carrick run --name grind --platform linux/amd64 --raw \
          --fs host $IMG /bin/sh -c /opt/ltp/testcases/bin/$t 2>&1 \
        | grep -iE 'TFAIL|TBROK|TRIPLEFAULT|trap engine|panic' | head -2 | sed \"s|^|$t :: |\""
    done
    ;;
  reap)
    $SSH "$BOX" "$REAP; echo \"vms: \$(ls /dev/vmm 2>/dev/null | grep -c carrick)\""
    ;;
  full)
    out="${1:-/tmp/ltpfull.jsonl}"
    # shellcheck disable=SC2029
    $SSH "$BOX" "cd $DIR && $REAP; pkill -9 -f 'carrick:conf-' 2>/dev/null; \
      $ENVV ./target/release/carrick-conformance --lane bhyve-local --ecosystem ltp \
        --workers 3 --flake-retries 0 --jsonl $out 2>&1 | tail -5"
    echo "jsonl on box: $out (scp it back to tally true-MATCH = match/(total-oracle_fail))"
    ;;
  stillfail)
    # stillfail <full-run.jsonl> <bhyve-specific.txt>  -> bhyve-specific suites still NOT matching
    full="${1:?need full-run jsonl}"; spec="${2:?need bhyve-specific.txt}"
    python3 - "$full" "$spec" <<'PY'
import json, sys
full, spec = sys.argv[1], sys.argv[2]
verdict = {json.loads(l)['name']: json.loads(l).get('verdict') for l in open(full)}
want = [s.strip() for s in open(spec) if s.strip()]
fail = [s for s in want if verdict.get(s) != 'match']
print(f"{len(fail)}/{len(want)} bhyve-specific still failing:")
print(' '.join(n.replace('ltp-','') for n in fail))
PY
    ;;
  *)
    sed -n '2,40p' "$0"
    ;;
esac
