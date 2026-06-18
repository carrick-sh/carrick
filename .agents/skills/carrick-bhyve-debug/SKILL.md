---
name: carrick-bhyve-debug
description: Use when debugging the carrick bhyve/FreeBSD x86_64 backend — reading guest-physical memory, walking guest page tables, and tracing guest syscalls on FreeBSD with lldb + DTrace.
---

# Debugging carrick's bhyve (FreeBSD x86_64) backend

The FreeBSD/bhyve backend runs an x86_64 Linux guest under bhyve via libvmmapi.
Debugging it means reading GUEST state — guest-physical memory, the guest page
tables, the guest's Linux syscalls — from the host carrick process. Two
first-class tools on FreeBSD: **lldb** (the carrick-bhyve plugin) for guest
memory + page tables, and **DTrace** for guest syscalls + host correlation.
Prefer these over `eprintln!` (see [[feedback_use_debuggers]]).

Test box: `root@<lab-ip>` (FreeBSD 15.1 amd64), carrick at `/path/to/carrick`.
Build: `cargo build --release -p carrick-cli --no-default-features --features platform-freebsd`.
Always set `CARRICK_RUN_ID=<id>` and reap with `pkill -9 -f "carrick:<id>"` — never a bare carrick pkill.

## Step 0: install a Python-enabled lldb (ONE TIME)

FreeBSD's base `/usr/bin/lldb` is built with the **LUA** script interpreter only
— no Python — so the Rust pretty-printers AND the carrick plugin (both Python)
cannot load there (`lldb --print-script-interpreter-info` → `{"language":"lua"}`).
Install the ports build side-by-side (same LLVM version, won't collide):
```
pkg install -y llvm19          # -> /usr/local/bin/lldb19 (Python 3.11) + lldb-server19
```
Use **`lldb19`** for anything scripted. For Rust struct/Vec/String inspection,
load the providers (they're Python, version-tolerant):
```
lldb19 -o 'command script import /usr/local/lib/rustlib/etc/lldb_lookup.py' \
       -o 'command source   /usr/local/lib/rustlib/etc/lldb_commands' ...
```
`p windows` on a `&Vec` prints only the pointer — **deref** (`p *windows`) to
expand. Without the providers (or on base lldb) you can still read a Vec:
`p ((T*)v->buf.inner.ptr.pointer.pointer)[i].field`, `p v->len`, sizes via
`image lookup -t T`.

## The carrick-bhyve lldb plugin (`scripts/carrick_bhyve_lldb.py`)

Reads guest memory by GPA via the libvmmapi `vm_map_gpa` FFI (an inferior call),
so it needs **no** Rust-struct introspection and works on optimized release
carrick. It auto-captures the `struct vmctx *` from the first `vm_map_gpa` call
(a breakpoint that auto-continues).

```
lldb19 -b \
  -o 'command script import /path/to/carrick/scripts/carrick_bhyve_lldb.py' \
  -o 'settings set target.env-vars CARRICK_INSECURE_REGISTRIES=<lab-ip>:5005 CARRICK_RUN_ID=dbg' \
  -o 'breakpoint set --name vm_run' \   # stop once the guest starts: ALL of memory is materialized
  -o run \
  -o 'bhyve-walk 0xfffffefffa' \         # walk a guest VA through the page tables -> GPA
  -o 'bhyve-gpa  0x2045ffa 64' \         # hexdump guest-physical memory
  -o quit \
  -- ./target/release/carrick run --platform linux/amd64 <img> /bin/echo HELLO
```
- `bhyve-gpa  <gpa> [len]` — hexdump len bytes (default 64) of guest-physical memory.
- `bhyve-walk <va> [pml4_gpa]` — 4-level x86-64 page-table walk (root default
  `0x200000` = `X86_PML4_GPA`); prints each level's entry + flags + the final GPA.
- `bhyve-ctx` — show the captured vmctx.

Notes: inferior FFI calls work on FreeBSD lldb — but **cast the args** (`vm_map_gpa`
wants `struct vmctx *`, not `void *`). Capture a typed value from the breakpoint
frame (`expr struct vmctx *$ctx = ctx`) to avoid the cast. `follow-fork` works
(`settings set target.process.follow-fork-mode child`) — but for THIS backend
the bring-up/materialization runs in the **main** process, so you usually don't
need it; the guest's later forks do.

## DTrace: guest syscalls + host correlation

The carrick USDT probes WORK on FreeBSD but the invocation matters
(see [[reference_freebsd_dtrace_usdt]] — the "usdt no-op" was a verification error):
- pass **`-Z`** (zero-match-at-compile, bind late — the probes only exist after
  the process registers them), and
- the process must be ALIVE; the guest is short-lived, so use `dtrace -Z -c`.

Guest syscall frequency (find the loop / what the guest did):
```
dtrace -Z -q -c '<carrick run ... /bin/echo HI>' \
  -n 'carrick*:::syscall-entry { @[arg0] = count(); }'   # arg0 = NORMALIZED (aarch64-numbered) nr
```
Guest syscall ARGS — `arg2` is the host address of the `[u64;6]` arg array; use a
TYPED pointer (DTrace rejects `void* + int`):
```
carrick*:::syscall-entry /arg0 == 64/ {            /* write (aarch64 nr 64) */
  this->p = (uint64_t *)copyin(arg2, 48);
  printf("write fd=%d buf=0x%x len=%d\n", this->p[0], this->p[1], this->p[2]);
}
```
Host correlation — `syscall::write:entry /arg0==1/` shows what carrick actually
emits to stdout (filter out dtrace's OWN printf-to-stdout, which also hits fd 1).

## Worked example: the argv-`0xFF` corruption (commit ad7f0e0f)

`echo HELLO` on bhyve printed one garbage byte. The method that cracked it:
1. `bhyve-gpa` the materialized stack top → `/bin/echo\0HELLO\0` IS present (string correct).
2. `bhyve-walk 0xfffffefffa` (argv[1] VA) → the correct GPA, and `bhyve-gpa` that GPA → "HELLO" (page tables correct).
3. `bhyve-gpa` the pointer block → `argc=2`, `argv[1]` pointer correct.
   **The entire stack was correct** → the fault was read/execution-side, not memory setup.
4. DTrace the guest `write()` → `len=1` (echo saw no argument).
5. Root cause: the init blob's ring-0 RSP = `LINUX_STACK_TOP`, so its `iretq`-frame
   `push`es clobbered the argv strings at the top of the user stack. Fix: ring-0
   RSP = the init-blob slot tail (`X86_INIT_BLOB_GPA + 256`), matching the sibling
   entry and the design.

**Lesson:** when the guest's DATA is provably correct but it still misbehaves,
suspect the guest ENTRY state (RSP/RIP/segments) and any **ring-0 scratch that
overlaps user memory**. Compare against the KVM bring-up (`KVM_SET_REGS` sets RSP
directly, no ring-0 blob) — divergence there is the tell.

## Gotchas
- Program args go **after `--`** on the lldb command line; NEVER `settings set
  target.run-args …` (it mis-parses `--platform` as an lldb option).
- `breakpoint set … --condition "expr"` (double quotes); `-C "cmd" -G1` for a
  print-and-continue breakpoint.
- The `"no plugin for the language 'rust'"` warning prints lazily on the first
  Rust-frame stop — its absence early does NOT mean providers loaded.
- Remote driving from macOS: `lldb-server19 platform --server --listen "0.0.0.0:PORT"`
  on the box; `platform select remote-freebsd` + `platform connect connect://<lab-ip>:PORT`
  on the mac (keep a local copy of the amd64 binary for DWARF).
