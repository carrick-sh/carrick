#!/usr/bin/env bash
# Build the #2668 reducers: one STATIC glibc Linux binary (x86_64 or aarch64,
# whichever gcc this is) whose modes each fork a child and then use memory
# the parent had before the fork, or memory the kernel hands it afterwards.
# Every mode runs inside a forked-and-exec'd child of the launcher unless a
# second argument is given, so the process under test is not the root.
#
#   rwx   store to a pre-fork PROT_READ|WRITE|EXEC private page (child alive,
#         then reaped)
#   kw    kernel copy-out (read(2)) into pre-fork resident pages; kwx: RWX
#   kwp   read(2) into a mapped, never-touched page (#2701)
#   alt   SIGSEGV handler on a pre-fork sigaltstack; altt: stack touched
#         first; altp: stack mapped and never touched (#2701)
#   chld  SIGCHLD handler with SA_ONSTACK on a never-touched stack (#2701)
#   brk   24 MiB of brk growth in 128 KiB steps plus fresh anonymous mmaps,
#         one byte per page, with the child alive and again after its reap;
#         brkx: the child execs /bin/true
#
# Native Linux prints "<mode>: PASS" and "launcher: mode=<mode> status=0".
#
#   ./build.sh && carrick run -v "$PWD":/red debian:bookworm-slim /red/fork-parent-memory rwx
set -euo pipefail
fixture_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cc="${CC:-gcc}"
"$cc" -static -O1 -o "$fixture_dir/fork-parent-memory" "$fixture_dir/fork-parent-memory.c"
file "$fixture_dir/fork-parent-memory"
