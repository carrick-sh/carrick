# EL1 in-guest kernel (`carrick-el1`) — design

Status: approved 2026-09-22. Supersedes the native-islands/DSR direction in
`handoff-inotify09-2026-09-22.md` as the path to near-1x syscall cost.

## 1. Why: measured, not assumed

Quiet host, signed binary `0f657b02` at `dbf360ebb`:

| Path | Cost per call |
|---|---:|
| Bare HVF exit + resume (`hvc #2`, zero host work) | 0.65 µs avg, 0.54 µs min |
| Same via data abort | 0.72 µs |
| Carrick syscall served at EL1 (getpid) | 0.042 µs |
| Carrick EL1 clock gate | 0.091 µs |
| Carrick host-dispatched syscall (invalid-fd lseek, no I/O) | 1.39 µs |
| Native Linux trapping syscall (prior oracle) | 0.125 µs |

A trap costs 33x an in-guest EL1 service; the floor alone is 5x Linux's whole
syscall. inotify09 does five in-zone syscalls per iteration, so exits alone
exceed Linux's entire 2.0 µs iteration. The exit must go for in-zone work.

## 2. Goal and screen

Serve in-zone syscalls inside the VM at EL1. First vertical: the unchanged
original inotify09 (both race participants) with zero exits in its hot loop.
Screen for continued investment: inotify09 under 12 s against a
contemporaneous reference (the 2x milestone). Semantics: same Docker
differential and contracts as today; no widened budgets, no retries.

## 3. Shape

New crate `crates/carrick-el1`: `no_std`, target `aarch64-unknown-none`,
position-independent image linked for a fixed guest region
(`LINUX_EL1_KERNEL_BASE`, 64 MiB, kernel-only stage-1 AP=00, never EL0
mapped). The host loads the image at boot the way it installs the EL1
vectors today and points VBAR_EL1 at its vector table. Every EL0 SVC lands in
it. It serves what it owns and forwards everything else through the existing
`hvc #2` mailbox path unchanged, so it regresses nothing when it owns nothing.
The host `carrick-kernel` remains the authority for everything not delegated.
Backend-neutral: KVM/bhyve get the same savings.

A shared, `no_std`, host-and-guest crate `crates/carrick-el1-abi` defines the
in-memory layout of every delegated object, the recall protocol words, and
the region layout, so host and guest cannot disagree about offsets.

## 4. Ownership, not leases

The unit of delegation is a whole kernel object, never a field. Today's seek,
write and clock gates on the identity page are field leases; they are exactly
the ownership-bug class and are retired by this design.

- An object's state is `Host` or `Guest(handle)`. The host `OpenDescription`
  (and inotify instance, pipe, futex key, VMA) gains a typed `Delegated`
  variant holding the guest handle; its fields are not reachable.
- Any host path that must touch a delegated object calls one typed
  `recall(handle) -> HostState`, which stops guest access (per-object
  generation word; guest checks it under its object lock), copies state back
  and republishes it as `Host`. After recall the guest entry is dead.
- Delegation is decided at creation from a static eligibility rule (private
  rootfs file, no host observer, no `--fs host` mount).
- Recall points, each with a contract: fork (object shared across the fork —
  the guest table is per-carrier, so fork keeps delegation and bumps a share
  count), exec (close-on-exec), dup/close, `/proc/self/fd` readlink, fanotify
  or host observer arrival, carrier teardown.
- `just lint-domains` gains a rule: no host code outside `el1_delegation`
  matches on `Delegated` fields.

## 5. What moves in, in order

1. Regular files on the private OCI rootfs: openat/read/write/pread64/
   pwrite64/readv/writev/lseek/fstat/close. Bytes live in a guest page cache
   carved from the shared aperture; host populates on first delegated open;
   guest owns offset and size; write-back to the host layer on recall.
   Open/close still exit at first (path resolution stays host-side); the
   per-byte and per-offset work stays in-guest.
2. inotify instances and watches on delegated files: inotify_init1,
   add_watch, rm_watch, read, event queue, IN_IGNORED ordering. Fix the
   descriptor-reuse and coalescing difference recorded in
   `inotify-first-principles` against the oracle here. Write/lseek on a
   delegated file emits events in-guest. Completes the inotify09 vertical.
3. Pipes, in-zone loopback sockets, epoll over in-zone objects; futex fast
   paths (uncontended wait/wake in-guest; blocking forwards to the host,
   which parks the vCPU; wake uses the existing host interrupt path).
4. Anonymous mmap/munmap/madvise/brk over a guest-owned frame pool with
   in-guest stage-1 edits and TLBI; foreign-MM transport retires as it goes.

Host-side forever: host files under `--fs host`, non-loopback sockets, tty
and pty, exec image loading.

## 6. Runtime inside the guest

Per-vCPU kernel stacks; bump-plus-free-list allocator over the region; spin
locks taken with IRQs masked; no sleeping in EL1 — anything that would block
forwards to the host. Time from CNTVCT. No EL1 scheduler: the host executor
pool stays the scheduler and EL1 only runs on the trapping vCPU.

## 7. Evidence and debugging

- Guest half of the event ring in the shared aperture, read by
  `carrick debug` and `carrick-lldb`.
- Per-syscall-kind EL1-served vs forwarded counters on the identity page;
  a `carrick trace` profile reports them.
- `carrick debug hvf-exit-floor` productizes the spike harness.
- Per step: a red contract with an exit-count budget (zero exits in the hot
  loop) beside the semantic differential; signed embed binding; Docker
  differential; default ON with `CARRICK_EL1=0` bisection hatch.

## 8. Transport slimming (parallel, independent)

Contract `kernel.transport.exit-overhead`: host-dispatched invalid-fd lseek
under 1.0 µs. Attribute the ~0.46 µs around the exit with the existing
`hvf-syscall-transport` USDT probe, then remove per-exit host syscalls, batch
register reads through the mailbox, drop redundant per-exit work.

## 9. Execution

Director (this session) owns the ownership protocol, contracts, reviews and
signed verification. Large code edits are Antigravity worker briefs through
the agy director, one red contract per brief, reviewed as diffs. Opus/Sonnet
subagents for bounded research and review.

## 10. Risks and stop rules

- Two kernels sharing state: whole-object rule + recall + lint.
- EL1 code is a new privilege domain: region never EL0-mapped; guest pointers
  validated against stage-1 before use, as the host does today.
- Host observers of delegated files force recall; out of scope for step 1.
- Stop rule: if steps 1+2 do not make inotify09's hot loop exit-free, stop
  expansion, keep receipts, remove ineffective product code.
