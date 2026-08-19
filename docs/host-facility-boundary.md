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

## Standing audit (2026-08-19)

Counts are non-test uses in guest-facing paths (`dispatch/`, `vfs/`,
`namespace/`). Presence is not automatically a bug — some name real host
resources — but each is a place to ask "whose truth is this?".

| call | uses | verdict |
|---|---:|---|
| `std::process::id()` | 92 | mostly guest questions; `signal.rs` still carries comments saying "getpid() exposes the host pid", which described the RETIRED one-process-per-guest model |
| `getifaddrs` | 20 | guest netns view built from the host's interface list |
| `libc::kill(pid, 0)` | 8 | guest pid existence probed against the HOST's pid space |
| `libc::getpgrp` / `getsid` | 12 | guest process groups/sessions read from the carrier's |
| `peer_ucred` | 4 | FIXED — now `identity_pid` + `cred_snapshot` |
| `libc::getrlimit(RLIMIT_NPROC)` in `vfs/proc.rs` | 1 | `/proc/…/limits` synthesised from the HOST's limits |
| `gethostname` | 1 | UTS namespace is guest state |
| `libc::getrlimit/setrlimit(RLIMIT_NOFILE)` in `time.rs` | 2 | LEGITIMATE — carrick really does open host fds and must size its own budget |
| `sysconf` | 3 | check per call: CPU count is hardware, most else is not |

Ranked first, because it closes a known row and shares its root cause with the
`docs/identity-and-scope-domains.md` audit: **give rlimits a kernel-graph home
keyed by `TaskId`**, the way credentials already have. That fixes
`TestPrlimitFileLimit` (`prlimit` on another process), `/proc/…/limits`, and
removes two host calls at once.

## The test that catches this class

A single guest process makes host and guest answers coincide, which is why the
smoke lane cannot see any of it. **A case exercising TWO live guest processes is
worth more than any number of single-process cases** — the same conclusion
`docs/identity-and-scope-domains.md` reaches from the other direction.
