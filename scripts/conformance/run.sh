#!/bin/bash
# Differential syscall conformance harness.
#
# Each case is a shell snippet exercising syscall-observable behaviour. We
# run the IDENTICAL snippet under carrick (--fs host) and under Docker
# (real arm64 Linux) and diff the output. A difference is a candidate gap
# in carrick's syscall layer — surfaced by name, immediately, instead of
# discovered via downstream archaeology (e.g. "dpkg returned 100").
#
# Usage: scripts/conformance/run.sh [name-filter]
set -u

IMAGE="docker.io/library/ubuntu:24.04"
CARRICK="${CARRICK:-./target/release/carrick}"
FILTER="${1:-}"

# name|snippet  — keep snippets deterministic (no timestamps, pids, hashes).
CASES=(
  "getcwd|cd /tmp && mkdir -p a/b && cd a/b && pwd"
  "mkdir_chdir|mkdir -p /x/y/z && cd /x/y/z && pwd"
  "access_root|test -w /var/lib/dpkg && echo W || echo noW; test -r /etc/passwd && echo R || echo noR; test -x /bin/sh && echo X || echo noX"
  "readdir_created|cd /tmp && touch zz_newfile && ls zz_newfile && ls | grep -c zz_newfile"
  "pipe_cat|echo hello | cat"
  "rename|cd /tmp && echo content > a.txt && mv a.txt b.txt && cat b.txt && ls a.txt 2>&1 | sed 's/.*: //'"
  "symlink|cd /tmp && ln -sf /etc/hostname lnk && readlink lnk"
  "hardlink|cd /tmp && echo hl > f1 && ln f1 f2 && cat f2"
  "stat|stat -c '%s %F %a' /etc/passwd"
  "copy_file_range|cp /etc/hostname /tmp/h2 && cat /tmp/h2 >/dev/null && echo cp_ok"
  "fd_redirect|exec 3>/tmp/fd3.txt; echo via3 >&3; exec 3>&-; cat /tmp/fd3.txt"
  "chmod|cd /tmp && touch m && chmod 640 m && stat -c '%a' m"
  "truncate|cd /tmp && printf 'abcdef' > t && truncate -s 3 t && cat t && echo"
  "append|cd /tmp && echo one > ap && echo two >> ap && cat ap"
  "mkdir_rmdir|cd /tmp && mkdir rd && rmdir rd && ls rd 2>&1 | sed 's/.*: //'"
  "uname|uname -s"
  "id_root|id -u; id -g"
  "readback_large|cd /tmp && yes abcdefgh | head -1000 > big && wc -l big && wc -c big"
)

norm() {
  # Drop carrick's scratch warning and any blank trailing noise.
  sed -e '/case-insensitive; defaulting/d' -e '/Pass .--fs host./d'
}

run_carrick() { timeout 90 "$CARRICK" run "$IMAGE" --raw --fs host /bin/sh -c "$1" 2>&1 | norm; }
run_docker()  { timeout 90 docker run --rm --platform linux/arm64 "$IMAGE" /bin/sh -c "$1" 2>&1 | norm; }

pass=0; fail=0; failed_names=()
for entry in "${CASES[@]}"; do
  name="${entry%%|*}"; snip="${entry#*|}"
  [ -n "$FILTER" ] && [[ "$name" != *"$FILTER"* ]] && continue
  c_out="$(run_carrick "$snip")"
  d_out="$(run_docker "$snip")"
  if [ "$c_out" = "$d_out" ]; then
    printf 'PASS  %s\n' "$name"; pass=$((pass+1))
  else
    printf 'FAIL  %s\n' "$name"; fail=$((fail+1)); failed_names+=("$name")
    printf '  --- carrick ---\n%s\n  --- linux ---\n%s\n' "$(echo "$c_out" | sed 's/^/    /')" "$(echo "$d_out" | sed 's/^/    /')"
  fi
done
echo "----"
echo "pass=$pass fail=$fail"
[ "$fail" -gt 0 ] && { echo "failed: ${failed_names[*]}"; exit 1; } || exit 0
