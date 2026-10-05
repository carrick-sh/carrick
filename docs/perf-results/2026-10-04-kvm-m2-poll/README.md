# KVM M2 static musl startup regression

The first bad commit is `0d3882d8501fe70ec744af3769708930efcb7dd9`,
`fix(x86): handle x86_64 poll(2) with its own ABI, not folded into ppoll`.
Its parent `2cbd1e4a7b2b318359ef89344a76352a1982a311` passes twice;
the culprit and main `b1167c6e19811c5b3a601d979cedca844656454f` fail twice.
The automated [bisect log](bisect.log) covers the entire parent-to-main
interval. Every runnable point was sampled twice, with no mixed outcomes.
Two revisions (`ab0f14dd6`, `695142a7b`) could not compile the KVM crate
and were skipped, not called good or bad. No Docker or copied binaries.

The [bisect script](bisect-run.sh) builds the musl fixture in its own directory
so Cargo reads its fixed-address ELF configuration. Building with only
`--manifest-path` from the root ignores that configuration and produces PIE.
The script checks ET_EXEC, rebuilds the runner/test with two build jobs,
and treats missing/skipped fixtures and unexpected failures as inconclusive.

The red is:

```text
M2 stdout mismatch: got "" want "hello, x86_64 world\n"
```

[GDB](main-gdb.log) stopped in the real shared service loop on clean main:

1. Native `set_tid_address(218)` returns through canonical 96.
2. Native `poll(7)` has `nfds=3`, `timeout_ms=0`; normalization produces
   `CARRICK_PRIVATE_X86_POLL` (`18446744073709551575`).
3. The standalone loop has no matching arm and returns `-ENOSYS` (-38).
4. The guest masks signals, then calls `tkill(SIGABRT)`, exiting 134.
   There is no write syscall before the abort.

The normalization change was correct: [Linux poll(2)](https://man7.org/linux/man-pages/man2/poll.2.html)
uses an integer timeout; ppoll takes a timespec pointer. The full dispatcher
was updated in that commit, but the standalone bring-up loop was omitted.
The extra wire values are plain ABI constants: the common kernel bitflags
known-bit mask remains unchanged. The correction adds the missing private-poll
arm without changing normalization
or the full kernel dispatcher. It copies in Linux pollfds, calls host poll once,
translates named event bits/errno, and writes back only revents. It does not
retry, sleep, or fabricate readiness. Empty sets do not access the array pointer.

The VM-free `x86.run-elf.poll` contract normalizes a real native frame and
requires readiness, invalid/negative-fd semantics, stale-revents clearing and
EFAULT. At 1/8/32 ready descriptors it requires exactly 8*n guest bytes read
and 2*n written. All three tests failed with -38 [before the fix](poll-contract-red.log).
M2 retains its existing exact stdout and exit-status assertions.

## Scope and host authority

This is the standalone VMM bring-up runner, not `carrick run`'s syscall path.
The caller census of `run_elf_service_loop` has three non-test callers:
`carrick-vmm-kvm/src/run_elf_x86.rs`, `carrick-vmm-bhyve/src/run_elf.rs`, and
`carrick-vmm-nvmm/src/run_elf.rs`. Their wrappers are reached only by the
standalone VMM binaries and tests. There is no CLI/engine/runtime caller.
`crates/README.md` names standalone target-host runners separately, and
`carrick-runtime/src/bin/carrick-kvm.rs` documents the distinction explicitly.
The shared x86 crate is a product dependency, but this service loop is not
reachable from the product execution path.

The private `StandaloneHostFds` capability is constructed only at the standalone
service-loop call site; the bridge is private and explicitly forbids use by
the product virtual-fd/rlimit path.

The existing standalone read/write handlers operate directly on inherited
host descriptors. Poll uses that same domain; its resource-limit query bounds
host descriptor-array allocation against host FD capacity. It does not read
or replace the kernel's virtual guest RLIMIT_NOFILE. In-zone descriptors and
rlimits still belong to the common kernel. This harness remains partial:
its existing ppoll/signal approximations are not fixed here, and hosts without
POLLRDHUP cannot synthesize that Linux-only readiness bit. No security,
full syscall conformance, or runtime-ratio claim is made.

## Verification

- Clean fix parent `b1167c6e1`, rebuilt in the scratch worktree: M2 fails
  twice ([first](main-red-1.log), [second](main-red-2.log)).
- Fixed worktree: M2 passes twice ([first](fix-green-1.log),
  [second](fix-green-2.log)); exact stdout, empty stderr, exit zero.
- `cargo test --locked -p carrick-vmm-kvm`: all 45 tests pass after building
  `carrick-x86-cpl0` for `x86_64-unknown-none`. The initial full-crate attempt
  stopped on the missing CPL0 image; it was built locally, never copied.
- `cargo test --locked -p carrick-x86 --lib`: all 45 tests pass.
- `just clippy`, focused x86 all-target Clippy, `just check-layering`,
  formatting, and `just lint-domains` pass (Linux compiler profiles;
  other host profiles remain pending).
- The native Linux fixture output also matches the committed oracle exactly.
  [Artifact hashes](artifacts.sha256) identify the first passing candidate
  runner and ELF, before the extra event values were narrowed to plain ABI
  constants. They are historical evidence, not final-head acceptance. Final
  artifact identity and gate receipts are recorded in the PR.
- Acceptance, domain lint, and remote gate receipts are reported in the PR.
  Known inherited rustdoc/fetch/cfg fixes belong to PR #3; they are not
  folded into this regression fix.

Signed HVF and Docker gates are director-owned and were not run on this host.

## Portable host readiness

Cloudmac host acceptance on `01f0c26a3` exposed two additional adapter defects
in the unchanged [poll assertions](poll-macos-red.log): eight ready duplicate
entries returned one, and an invalid descriptor with `events = 0` returned
zero instead of `POLLNVAL`. The gate completed with only those two test
failures; the Linux-portable gate on that commit passed.

Native Darwin `poll` gives readiness only to the last repeated descriptor
and does not validate a descriptor when its event mask registers no filter.
The bridge now validates every distinct nonnegative inherited host descriptor
with `F_GETFD`, combines host interests per descriptor for one host poll,
then publishes and counts each original Linux pollfd independently. Invalid
entries are already ready, so the remaining host poll uses a zero timeout.
Negative descriptors remain ignored. There are no retries or sampling loops.

[Native observations](native-poll-macos.log) also show that Darwin needs an
explicit `POLLHUP` interest to detect a closed peer when no input events were
requested. Adding that interest does not report ordinary readable data to an
entry with an empty mask. The adapter always requests hangup notification and
filters ordinary readiness against each original entry's own interest mask.

The original assertions remain intact. Additional cases cover distinct
descriptor populations at 1/8/32, duplicate entries with different interests,
and an unrequested hangup. Both repeated and distinct populations retain the
exact 8*n guest bytes read and 2*n bytes written. Final-head results and the
superseding Linux/cloudmac receipts are reported in the PR.

## Negative timeouts and pipe endpoint semantics

Review of `4bb670667` found two remaining BSD translation gaps. The
[native-boundary timeout test](poll-timeout-red.log) failed before the fix:
`left: -2, right: -1`. Linux interprets every negative timeout as infinite,
whereas FreeBSD requires -1. The bridge now normalizes negative values to -1,
retaining the zero-timeout override when an invalid descriptor is ready.
Tests use a ready descriptor with both -2 and INT_MIN, so neither can hang.

The [macOS regression run](poll-bsd-semantics-red.log) also failed the new
closed-reader pipe test: `left: 16, right: 8`. Native BSD pipe write endpoints
report HUP after all readers close; Linux requires ERR, even for `events = 0`.
After the native wait, each distinct descriptor reporting HUP is classified
with `fstat` (FIFO type) and `F_GETFL` (write-only access mode). Only pipe write
endpoints have HUP replaced by ERR. Duplicate guest entries receive and count
the corrected result independently; read endpoints and sockets retain HUP.
Normal readiness needs no additional metadata queries. The tests retain exact
guest-copy budgets and cover two zero-interest entries for the broken writer.

The native-call boundary accepts a one-shot callable, with the production
callable issuing exactly one libc poll. This permits deterministic timeout
and EINTR assertions without process-wide signal-handler mutation. The EINTR
test injects a native error and verifies Linux errno translation, no retry and
no copyout; it does not claim asynchronous signal-delivery coverage. A bounded
producer makes an initially unready socket readable during a positive wait.
The nfds test reads the current limit without changing it: count at the limit
reaches memory validation, while limit+1 returns EINVAL before native polling.
No sleeps, widened production timeout, retry or weakened assertion was added.

Both red logs use the previous behavior plus the new tests and a behavior-
preserving extraction of the native call. The pipe failure is a live macOS
observation; FreeBSD's timeout boundary is asserted portably, not represented
as a live FreeBSD execution. Final focused results are recorded in PR #34.
Full acceptance remains with the director's batch-5 gate.
