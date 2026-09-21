# sendmsg02 host-wait / ASID retirement cycle

The full-run `ltp-sendmsg02` timeout is reproducible as a CPU-slot ownership
cycle during terminal address-space retirement. This change releases a borrowed
CPU after the replacement executor has saved/detached its task and passed the
backend boundary audits, before retirement waits for peer invalidation acks.
The exact task binding, execution lease and claim remain owned until normal
settlement. ASID/root release still requires all owner-thread acknowledgements.

## Original failures and independent Linux authority

`target/conformance/results.hvf.full.jsonl` records `conf-2171-s1116`
(sendmsg02, serial confirmation) at 40.199 s after a loaded 35.279 s budget
kill, and `conf-2171-c1254` (shmctl05) at 40.228 s. Both declarations remain
40 s. Timeout ratio fields are cutoff ratios, not completed performance samples.

The current canonical Docker image was qualified as native aarch64, with 10
online CPUs, then both tests ran sequentially with `/bin/sh -c` and unchanged
40 s deadlines. No Carrick guest ran during this phase. The copied JSON and
raw streams are the receipts; both named containers were removed successfully.

- Image: `localhost:5050/ltp@sha256:bc75ded40c5827f2ec9e1891edc23b988beae3f428f5be2c8fd7e3ee52fee80b`.
- sendmsg02 binary SHA-256: `e625d6d274ed551588e1fe1eb9a4636812ce6a9ac530d157162c572b37c9b1e5`.
- shmctl05 binary SHA-256: `9c9d448d00e5d063ac1dfe4788055750549cea88d1bce0de53438951ce3a316f`.
- sendmsg02: PASS, exit 0, 15.195 s.
- shmctl05: PASS, exit 0, 16.652 s, "Exceeded execution loops" before its assertion.

The [LTP 20260529 sendmsg02 source](https://github.com/linux-test-project/ltp/blob/20260529/testcases/kernel/syscalls/sendmsg/sendmsg02.c)
forks four client/server pairs per online CPU and requests shutdown after
15 seconds through a SysV semaphore. Its repeated tmpdir lines are buffered
stdio inherited across fork and flushed at child exit, not independent launches.
The [shmctl05 source](https://github.com/linux-test-project/ltp/blob/20260529/testcases/kernel/syscalls/shmctl/shmctl05.c)
declares `min_runtime=40`, but
[fuzzy synchronization](https://github.com/linux-test-project/ltp/blob/20260529/include/tst_fuzzy_sync.h)
can stop at 3,000,000 loops first. Therefore that declaration does not prove
that a 40-second harness cutoff is invalid. Neither timeout is waived or widened.
There is not yet evidence that shmctl05 shares sendmsg02's cycle.

## Exact failing signed capture

Preserved executable:
`target/investigations/parity-20260920/carrick-03d6545ce6e46988ef8e67bf1615b44b36d2f88740bfbeaf71811ed4809d1ad5`.
Its existing artifact receipt records source HEAD
`9784dc289edcddc640ceab7386efe047917f6212` plus the pre-existing dirty fs/vfs
changes, SHA-256 matching the filename, CDHash
`aef61a1683d22642ed13f702109d78ed11c2ca61`, LC_UUID
`4FA13D27-5C19-3234-97B8-A744349EA53F`, entitlement and DOF section present.
This investigation did not relink or re-sign that executable.

`carrick debug lldb-run --deadline-seconds 40` launched the same pinned image
and shell command with run ID `sendmsg02-attribution-20260920`. The pre-attach
kernel snapshot and all-thread backtraces establish:

- Slot root executor 9, CPU 0: replacement owner executor 16 / exiting tid 4;
  returning waiter executor 9 / tid 32, exact generation 1233.
- Slot root executor 10, CPU 1: replacement owner executor 13 / exiting tid 9;
  returning waiter executor 10 / tid 3, exact generation 1023.
- Executors 9 and 10 are inside `HostWaitToken::resume`, returning from
  `write_owned_stdio_sink`; they need their borrowed CPUs back.
- Executors 13 and 16, plus executor 2, are inside
  `consume_invalidation_acks_servicing` from terminal `invalidate_after_exec`.
  They retain CPU ownership while waiting for the returning executors to
  service owner-thread ASID commands.
- The parent waits for exact child 3; scheduler queue is empty. This is not a
  sendmsg network-readiness wait or evidence that the semaphore stop was lost.

`capture-summary.json` preserves the relevant snapshot fields and SHA-256/path
receipts for the full snapshot, backtraces, guest log and 55 MiB modified-memory
core under `/private/tmp/carrick-timeout-attribution-20260920/sendmsg-capture/`.
LLDB capture succeeded; scoped cleanup reported zero remaining processes.

## Deterministic contract and acceptance boundary

The existing `kernel.scheduler.host-wait-handoff` contract now names this
retirement obligation and the sendmsg02 ecosystem witness. The runtime fake
backend drives one original host waiter and one replacement on one guest CPU.
A gated owner-thread ASID invalidation holds the replacement after save; the
original must resume and settle before that dependency is released. The test
always releases the gate and joins workers before asserting, including red.

Red: `saved_replacement_returns_host_wait_slot_before_terminal_retirement`
failed after 2.02 s with "saved replacement held borrowed P across terminal
retirement: Timeout". The original detached-cleanup version also failed red and passed green; the
stronger invalidation-boundary variant is the committed regression. A separate test rejects live and foreign execution claims at the new
boundary. No counters, deadline, concurrency, retry or polling policy changed.

Final focused checks: all 93 runtime executor tests passed in 0.17 s,
including the stronger invalidation-boundary variant and authentication tests.
All 21 kernel-example `scheduler_handoff` tests and the contract registry
check also passed. Modified Rust files pass rustfmt; `git diff --check` is clean.

Signed post-fix reproduction, broad signed gates, and shmctl05 runtime
attribution remain outstanding at this checkpoint. Host tests do not close
those obligations.
