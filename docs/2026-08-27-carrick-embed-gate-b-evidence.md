# Phase B — two containers in one carrier: Gate B evidence

Date: 2026-08-27. Branch `feat/carrick-embed`.

## Verdict

`just gate-containers` (`conformance_container_gate`) **PASSES both modes** —
sequential and concurrent — on a signed HVF artifact:

```
test conformance_container_gate ... ok
test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 51 filtered out
```

Both containers report every asserted line: `getpid=1`, their own
`hostname`, `own_marker_written=true`, `foreign_marker_visible=false`,
`child_comm_visible=true`, `foreign_proc_visible=false`, `peer_ready=true`,
`mmap_arena_ok=true`.

Source HEAD at the passing run: `97d2fa4091884fe28cdce05081d85c40f387ef1f`.

## What this phase is NOT yet claiming

**No phase receipt.** The program's bar is one exact signed artifact carrying a
green `just ci`, matching guest probes, an ABBA receipt for the disabled path,
and this report. Two of those are open:

* `just ci` fails on `epoll_wakes_accepted_socket_after_peer_write` — a latched
  socket leaving the epoll kqueue fd readable. It is intermittent (passes 3/3
  on re-run) but it is a SPURIOUS WAKEUP, which contradicts the standing rule
  that guest epoll readiness is carrick-owned and host kqueue is only a wake
  source. It is being fixed, not retried until green.
* The `conformance_probes` gate reports 27 `arm64:musl` gaps. Most predate this
  branch and are unrelated to embedding; `procselfpid` MOVED FROM GAP TO MATCH
  over this work. No ABBA receipt has been taken.

## The four defects Gate B found

Every one was invisible to unit tests and to the single-container smoke lane,
and every one is the same family: a statement that was TRUE when one host
process served one guest, still compiles, and is wrong once a carrier hosts
several containers.

### 1. The eager mmap arena was retired per container

`retire_initial_mmap_arena` ends in `inventory_hv_vm_unmap` over the whole 32
GiB arena — VM-WIDE state — but ran during each container's root bring-up. The
second call tore out sparse arena pages a sibling had already faulted in.
Retirement is now once per carrier VM, released with the VM.

### 2. `AliasOwnershipScope::Root` collapsed two containers into one scope

The enum documented itself as "the original/root address space in this host
process", and `alias_matches_process_scope` matched it with
`mm_root_slot.is_none()`. `None` is the default in `HvfTaskState::neutral()`,
and a later container's root is built through the `new_with_plan` carrier REUSE
lane, which leaves it `None`. Both containers therefore matched every
`Root`-scoped alias and each treated the other's private aliases as its own —
a deterministic, byte-identical SIGSEGV writing `LINUX_MMAP_BASE + 8`
(`esr=0x92000045`, DFSC 5 translation fault, `SEGV_MAPERR`).

Fixed with `ContainerRootToken`, minted per container root. Deliberately NOT
fixed by giving each root its own `mm_root_slot`: that also isolates the scopes
and was tried and reverted, because it disturbs identity-page publication. The
enum's own comment already said the root slot "is an ownership token only".

### 3. Fork inheritance used the semantic host address

`ThreadMappingDesc::from_region` used `region.host_addr` rather than deriving
the physical host base, and `inherited_fork_inventory_extents` then added the
offset a second time. Offset regions dropped out of the child descriptor and
teardown failed with `HVPatch COW VA 0x6000004000 IPA 0x9b00204000 has no
matching 16 KiB physical backing`. The arithmetic matches the addresses
exactly: `0x6000004000` sits 16 KiB above compound base `0x9b00200000`.

### 4. `host_to_ns_or_self_for` returned zero despite its name

The last failing line was `getpid=0` from a container's init. Instrumenting the
probe to sample three ways settled it:

```
getpid=0   getpid_again=0   proc_status_pid=1
```

Persistent, not racy — and synthetic `/proc/self/status` was CORRECT, so the
kernel graph held the right pid and only the syscall path was wrong. The
function's `None` arm returns `host_pid`, but its lookup miss returned `0`.
That value reaches the guest twice over: the trapped `getpid` handler returns
`identity_pid()` directly, and the EL1 identity page publishes it to a fast
path that takes no VM exit and re-checks nothing.

The zero is not simply a bug, which is why a blanket change would have been
wrong: `self_ns_ppid` calls the same function, and there `0` is CORRECT —
`pid_namespaces(7)` specifies `getppid() == 0` for a process whose parent lives
outside the namespace, and returning a host pid would also leak host identity.
The two questions are now two functions: `host_to_ns_or_self_for` keeps the
zero for ppid, and `ns_self_pid_for` answers "what is MY pid here?" and never
returns zero.

## Hypotheses that were wrong, and how they died

Recorded because the cost of re-deriving them is real:

* **Recycled identity-page backing.** Refuted: the failure appeared on ALPHA,
  the FIRST container, which has no predecessor.
* **Missing release ordering between the pid and gate stores.** A release fence
  changed nothing. (The fence was kept — the gate is a publication flag and the
  ordering is correct on its own merits — but it was not this bug.)
* **The `unwrap_or(0)` in the SECOND branch of `identity_pid`.** Removed; the
  zero persisted, because the primary branch was the source.
* **An executor holding `ContainerRootToken(0)`** for the COW failure. Plausible
  and wrong; the offset arithmetic in #3 was the real cause.

Three of the four were killed by measurement rather than argument. The pattern
worth keeping: instrumentation that PERTURBS (per-write logging, a debug-profile
build) closed the window every time — 10/10 and 6/6 passes — so the evidence
that mattered came from making the PROBE report more, not from making the
runtime log more.
