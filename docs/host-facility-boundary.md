# What carrick asks Darwin for, and what it must answer itself

Carrick has its own kernel. Linux tasks, process identity, address spaces, waits
and signals live in the kernel graph, and guest `fork`/`clone` do not create host
processes. That changes where the boundary belongs:

> **Reach for the host only where the host is genuinely the authority — real I/O
> and real hardware. Anything whose truth lives entirely inside the guest is
> carrick's own responsibility and must be answered from the kernel graph.**

This is not a style preference. Every defect listed at the bottom of this file was
carrick asking Darwin a question only the guest could answer, and each one was
GUEST-VISIBLE — three of them leaked host state into the guest.

## The host IS the authority for

- **Files and file contents.** Real bytes on a real filesystem.
- **Sockets and the wire.** Real packets to real peers.
- **Memory.** Real mappings, real pages.
- **The time source and the CPU.** A monotonic counter and cycles are hardware.

## The host is NOT the authority for

Anything the guest defines about itself:

- **Identity** — pid, tid, ppid, pgid, sid, uid/gid/groups, capabilities.
  Under HVPatch every guest process is a thread of ONE carrier, so a host pid is
  the CARRIER's and is identical for all of them. `std::process::id()` cannot
  answer a guest question; `identity_pid()` can.
- **Process relationships** — parents, children, process groups, sessions,
  reaping, "does this pid exist". A `kill(pid, 0)` probe asks Darwin about a
  namespace it knows nothing about.
- **Resource limits** — an rlimit is a property of a Linux process, not of the
  carrier that happens to host it.
- **The network NAMESPACE view** — which interfaces exist, which addresses they
  carry, routes, hostname. The wire is the host's; the VIEW is the guest's.
- **Name resolution policy** — which resolver, which hosts file. (The DNS query
  itself is wire traffic and therefore host I/O; deciding what to ask is not.)
- **Signal delivery between guest processes** — the sender, the target and the
  disposition are all guest state.

## Why this keeps producing guest-visible bugs

Delegating a guest concern to Darwin does not merely give an approximate answer.
It gives the HOST'S answer, which is a different universe:

| defect | what the guest saw |
|---|---|
| `SCM_CREDENTIALS` from `peer_ucred(host_fd)` | `pid=97396 uid=501 gid=20` — the macOS pid and the Mac user's uid/gid, where Linux gives `pid=1 uid=0 gid=0` |
| interface list from host `getifaddrs` | the Mac's `en0` IPv6, so libuv RAN two tests Linux skips |
| `/proc/net/if_inet6` fabricating `fe80::…:1` | an address on no interface anywhere |
| guest DNS through host `getaddrinfo` | mDNSResponder initialising ObjC on a host thread, aborting every forked child (`node-libuv --network bridge`, exit 134) |
| `prlimit(other_pid)` writing `self.proc` | the CALLER's limit changed, the target's untouched |

The pattern is identical each time, and so is the fix: answer from the kernel
graph, keyed by the exact task.

## Compiler-resolved local census (2026-08-20)

Pinned Clippy diagnostics establish the configured callsite census for the
product profiles that actually execute. The current macOS check executes
`macos-cli-default`, `macos-runtime-default`, and `macos-hvf-default`. An
independent checked compiler-capture receipt binds those diagnostics to the
catalog and exact profile memberships; the reviewed inventory contains 682
local rows:

| classification | rows | meaning |
|---|---:|---|
| `forbidden_semantic` | 173 | known semantic host-authority debt; classification does not fix or waive it |
| `declared_backing` | 318 | reviewed access to a named backing object or real host I/O |
| `declared_substrate` | 191 | reviewed operation on an authenticated carrier resource |

The validator proves that checked evidence has the required shape and that the
executed-profile callsite set has not drifted. Human source review supplies the
semantic classification; neither compiler diagnostics, the receipt, nor JSON
schema validation proves that a rationale is true.

The Linux, FreeBSD, and NetBSD CLI/runtime profiles are still pending. A green
local check is deliberately reported as partial and is not cross-platform
completeness. The rejected lexical-scanner commits were breaker evidence, not
closure; the compiler-resolved successor plan replaces them.

The narrow escape companion uses Semgrep plus a checked standalone Rust helper
that tokenizes with `proc_macro2`. Together they catch unmistakable catalog
escapes such as raw `libc::syscall`, `dlopen`/`dlsym`, assembly and its import
aliases, and local declarations or `link_name` aliases of watched host APIs,
including syntax in recursively nested macro token groups. Comments are absent
from that token stream; strings, raw/byte/C strings, characters, labels, and
lifetimes remain atomic tokens instead of being interpreted by a hand lexer.
Exclusions are exact reviewed relative paths; a nested path with the same
suffix is not exempt. The Python wrapper only validates the helper's JSON,
applies those exact path allowlists, and propagates build/scan failure. Neither
layer resolves Rust names, cfg, modules, or reachability, and neither turns an
enumerated catalog into a capability boundary. Phase 1 must still introduce
the typed host-capability facade and deny raw host APIs outside that facade.

## The test that catches this class

A single guest process makes host and guest answers coincide, which is why the
smoke lane cannot see any of it. **A case exercising TWO live guest processes is
worth more than any number of single-process cases** — the same conclusion
`docs/identity-and-scope-domains.md` reaches from the other direction.


---

# Which SYSCALLS must never reach Darwin

The boundary above is a principle; this is the list it implies. Of the 337
syscalls on the aarch64 table, four groups are ones where **the host has no
correct answer to give**, because the entire question is about guest state:

| group | rows | why the host cannot answer |
|---|---:|---|
| `process` | 83 | pid/ppid/pgid/sid, fork/clone/wait/exit, rlimits, capabilities, ptrace, seccomp, namespaces — all kernel-graph state; a host pid is the CARRIER's and is identical for every guest process |
| `ipc` | 22 | SysV and POSIX message queues/semaphores/shm are carrick's own tables and namespaces |
| `signal` | 14 | dispositions, masks, pending sets and delivery BETWEEN guest processes |
| `sched` | 14 | affinity, priority and policy as the guest sees them (`sched_yield` is the one real exception — that is CPU) |
| **total** | **133 (39%)** | |

The rest legitimately reach the host, because the host owns the thing being asked
about: `fs` (103) real files, `mm` (31) real mappings, `net` (23) real wire, `io`
(10) real I/O, and `time` (28) which is mixed — the clock SOURCE is hardware,
while timers and their expiry are guest bookkeeping.

## Historical guest-dispatch spot count (2026-08-19)

This lexical count predates the compiler-resolved census above. It remains
useful as investigation history, but it is neither current callsite authority
nor closure evidence. Host `libc` calls then seen inside guest-authority
dispatch modules were:

| module | host calls |
|---|---:|
| `sysv.rs` | 64 |
| `proc.rs` | 32 |
| `mqueue.rs` | 22 |
| `signal.rs` | 7 |
| `creds.rs` | 1 |

Most of the `sysv`/`mqueue` count is LEGITIMATE and must stay: those subsystems
keep their segments in real files, so `open`/`close`/`pread`/`pwrite`/`ftruncate`/
`fstat` there are backing-store I/O, which is exactly what the host is for.
SysV semaphores, by contrast, are pure in-kernel synchronization with no backing
store and are moved to pure in-memory state.

What does not belong, by name:

| call | uses | what it answers wrongly |
|---|---:|---|
| `libc::getpgrp` | 6 | FIXED under HVPatch (carrier's group vs guest group) |
| `libc::kill` | 5 | FIXED under HVPatch (delivers via kernel graph queues) |
| `libc::wait4` | 5 | FIXED under HVPatch (waits via kernel graph child state) |
| `libc::waitid` | 5 | FIXED under HVPatch (same) |
| `libc::getppid` | 4 | FIXED under HVPatch (parent read from kernel graph) |
| `libc::getpid` | 4 | FIXED under HVPatch (virtual_pid / TaskId) |

## Make it mechanical, not aspirational

The table now carries `Authority { Guest, Host, Hybrid }` alongside
`SupportLevel` and `SyscallHandler` in `carrick_abi::syscall::Syscall`:

1. Every syscall row spells `Authority::{Guest, Host, Hybrid}` explicitly; no
   catch-all classifier supplies missing authority.
2. `just lint-domains` runs the deterministic Semgrep gate and the real
   compiler census `--check`. On macOS that is the exact three-profile local
   census above, with all six non-local profiles reported pending.
3. The checked catalog and independent compiler receipt bind the executed
   callsite set. Structured review validation detects drift and malformed
   evidence; human review, not the validator, establishes semantic truth.
4. The 173 `forbidden_semantic` rows are frozen debt, not accepted authority or
   completed fixes. Classifying a row never makes its behavior correct.
5. Semgrep and the checked `proc_macro2` token helper prevent new unmistakable
   bypass syntax outside exact reviewed modules, including nested macro groups
   and renamed imports. Only the Phase 1 typed capability facade can make raw
   host-authority access structurally unavailable elsewhere.

Phase 0 therefore makes the current local boundary explicit and drift-gated.
It does not prove cross-platform census completeness, semantic containment, or
the absence of raw host operations outside a future typed facade.
