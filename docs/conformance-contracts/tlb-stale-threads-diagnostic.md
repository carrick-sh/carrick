# Threaded TLB witness early death (#1857)

This is diagnostic work under `kernel.el1.signal-delivery-owner` and
`kernel.el1.fault-entry`, not a fix or a new conformance verdict. Linux
mprotect(2) requires every worker's revoked write to raise SIGSEGV; sigaction(2)
requires that a valid handler can inspect and change its interrupted context.
No semantic policy, invalidation algorithm, timeout or work budget changes.

## What the fixture actually does

`fixtures/embed-el1-sched/src/tlb.rs` owns the command protocol, not the
kernel. Main pins to CPU 0; workers pin to CPUs 1 through n. Each round:

1. `warm`: all workers touch the RW page, record their command, increment ACKS.
2. Main makes the page RO. `write-probe` is one ARM STR. SIGSEGV must enter
   `on_probe_segv`, increment the worker's FAULTS, and advance ucontext PC by 4.
   Only after returning does the worker acknowledge the command.
3. Main restores RW and warms again, then unmaps the page. `read-probe` is
   one LDR; the handler skips it, preserving its sentinel register value.
4. Main remaps at the same address and verifies every word is zero.

The injected mode omits worker 1's ACK for command 0x202 **after** its STR and
handler finish. It must terminate at the existing ten-second deadline with
`acks=3 target=4`, `seen=0x202 acknowledged=0x101`; it must never do another
page edit. Thus death before that command returns prevents both tests from
reaching their intended assertion. This is a hypothesis about their common
failure, not signed proof of its cause.

The fixture's ACKS are not hardware shootdown acknowledgements. Page edits
use the shared MM owner and descriptor publication; architectural invalidation
is performed by the ARM venue. The in-ring mprotect entry is
`dispatch.rs`'s `permission` adapter -> `memory::try_serve_mprotect` with
`HardwareAnonymousPermissionEditor`; native descriptor transactions use
`CurrentMmMaintenance`, whose `HardwareCpu::invalidate_asid` executes
`DSB ISHST; TLBI ASIDE1IS; DSB ISH; ISB` (architectural broadcast, not a
fixture ACKS increment). Host-served edits retain the HVF maintenance path.
Expected permission faults run through
`dispatch_fault_with_prepared` and the declined/native signal owner; a
host-classified fault can re-enter via `arm_deliver_declined_fault_signal_with`.
Its terminal default disposition returns to the existing host core/exit path.

## Evidence and remaining hypotheses

The unmodified x86_64 Linux `just test-el1-native` passed 778 tests with three
ignored. The harness supplies host-backed user memory, and does not execute
these ARM instructions or the hardware-only signal copy venue. It therefore
cannot reproduce or exclude the signed failure. KVM uses a different signal
frame codec and hardware copy venue; a passing KVM case would not prove ARM
signal-frame supply or TLB ordering.

`git log -S` / `git log -L` on the fixture found the command barrier originated
in `test(runtime): witness required tlb invalidations without host round trips`
and was made terminal by `fix(conformance): stop TLB witnesses at the first
missed ack`. Neither subsequent #1740 (native constructors), #1828 (wait-key
capacity), #1851 (x86 entropy), nor #1858 (madvise planner) edits this protocol.
The classified-signal changes in `arm_signal`, `dispatch`, and `signal_delivery`
are a more relevant investigation path than attributing the failure to those
recent PRs without a signed bisect.

One suspect: the ARM `access_user_target` disallows backing supply for a direct
signal copy, and `copy_signal_frame` collapses OwnerWait to Fault. An untouched
stack page or an owner dependency may therefore prevent handler installation.
The x86 `native_process::Service::copy_signal_bytes` similarly converts
OwnerWait to Busy before the shared boolean frame-copy result; that venue
also needs a retained-signal-copy investigation if contention is observed.
No such failure has been observed on HVF in this round. Do not fix it by
pretouching stacks, serializing the probes, or changing deadlines.

## Director capture on carrick-m4

Rebuild fixtures using the normal signed fixture bundle workflow: fixture
inputs changed (exported data symbols), so an old bundle is inadmissible.
Keep one signed test executable and record its HEAD, SHA-256, CDHash, LC_UUID,
entitlement and DOF. Run the signed smoke first, then both exact tests. The
existing `scripts/dtrace/hvpatch-idle-kick-segv-origin.d` now consumes
`el1-native-diagnostic` through the same authenticated HVC #6 operation 8.
Its existing session bound and scoped cleanup rules still apply. No live
provider qualification of this renamed probe is claimed by the Linux worker.

The new failure-only reason strings distinguish:

- `signal-copy-refused`: original typed owner/copy refusal, record identity,
  destination address and byte count, before the existing errno conversion;
- `signal-frame-build`: PC, ESR, FAR, selected SP, signal and codec refusal;
- `signal-frame-copy`: PC, ESR, FAR, interrupted SP, frame extent and signal;
- `signal-terminal`: original entry ESR/FAR, PC, final signal/code and mask.

Join by host PID and authenticated CPU/MM/root. A host-classified re-entry's
`entry-esr` may be a synthetic checkpoint, not an architectural abort: use the
existing `vcpu-fault` / `hvpatch-guest-fault` ESR/PC/FAR records for that case.
Zero events do not establish success: the failure may precede this venue or
refuse diagnostic authentication. This diagnostic adds one bounded crossing
per reported refusal; use uninstrumented artifacts for timing claims.

The fixture exports its **existing atomics** under stable ELF symbols; it does
not mirror, poll, or add work to their publication:

| ELF symbol | Storage |
|---|---|
| CARRICK_TLB_CMD | one u32 command, sequence in high bits and op in low byte |
| CARRICK_TLB_ACKS | one u32 cumulative acknowledgement count |
| CARRICK_TLB_PROBE_PAGE | one u64 guest VA |
| CARRICK_TLB_WORKER_TIDS | seven u32 Linux TIDs |
| CARRICK_TLB_WORKER_COMMANDS | seven u32 last-seen commands |
| CARRICK_TLB_WORKER_ACKS | seven u32 acknowledged commands |
| CARRICK_TLB_FAULTS | seven u64 fault counters |

Preserve the exact unstripped guest ELF and guest core (or a carrier
modified-memory core with the exact MM's translation/backing). Resolve these
symbols with `llvm-nm` from that ELF and read their bytes in the **guest**
address space. They are guest VAs, not host pointers: never pass them directly
to host LLDB `memory read` or DTrace `copyin`. A guest ELF core's PT_LOADs can
be read by guest VA; a carrier core first needs the live MM's stage-1 IPA and
retained host backing. Missing core bytes are missing evidence, never zero.
The values at the terminal safe point identify the last live command and
which workers returned from their probe/handler and acknowledged it. They do
not reconstruct an earlier simultaneous snapshot while workers were running.

The new VM-free assertion drives the existing production classified-fault
entry with an unusable signal stack. It is red before the diagnostic and
green after, requiring the frame failure detail without changing the final
SIGSEGV policy. It proves diagnostic reachability, not either #1857 fix.
Fresh paired signed base/head populations remain director-owned.

## Host and fixture dependence (director follow-up)

Both current `main.rs` and `tlb.rs` support `omit-first-write-ack`. The version
before that mode was introduced still recognized `tlb-stale-threads`, parsed
only rounds/workers, and ignored the extra argument. Missing the omit mode
alone would run the ordinary probe; it does not directly turn an unknown
argument into SIGSEGV. A stale ELF can still have an independent runtime bug.

`fixtures::inputs::FIXTURES` includes `fixtures/embed-el1-sched`.
`resolve_graph` adds that whole local package directory; `source_hashes`
enumerates its tracked files, including `src/tlb.rs` and `src/main.rs`, with
`git ls-files` and hashes each one. The builder script and fixture Cargo.lock
are inputs too. `Manifest::input_identity` covers this map, compiler-reported
inputs and build policy. `test-signed-body.sh` runs `fixtures verify` before
signing/execution; verification rehashes every installed executable. Thus a
properly verified bundle cannot legitimately hide an older tlb.rs under the
current source identity. This audit is not a verification of either Mac's
actual installed bundle or mounted bytes.

The loader's `common::repo_root` is compiled from CARGO_MANIFEST_DIR. A copied
or mis-reused test artifact could therefore load a different checkout's ELF
than the runner verified. No such mismatch is proven here. The new lazy
`embed-fixture-loaded` USDT record names the **actual** path, SHA-256 and length
of the exact Vec mounted by `el1_sched_vfs`, plus exposed guest CPU count.
It is emitted before guest execution and does not add guest output/syscalls.
Compare its ELF hash to the el1-sched destination's row in the verified
`target/fixtures/installed.json` manifest on each host; also retain the
`fixture_validation` row from the signed runner. Absent probes remain missing
evidence. Enabling this record adds one fixture-sized hash before execution.

The two tests do not install a fixed SchedulingPolicy: the default count comes
from `host_facts::logical_cpu_count`, clamped to MAX_GUEST_CPUS. On macOS that
honors CARRICK_EXPOSED_CPUS or prefers hw.perflevel0.logicalcpu before falling
back to host logical counts. Two workers need CPU IDs 0, 1 and 2. A worker pin
failure increments ERRORS (the main CPU-0 pin fails setup with exit 1), so a
small topology can invalidate a result but is not by itself a demonstrated
explanation for empty output and SIGSEGV. Preserve the FIXTURE guest_cpus,
CARRICK_EXPOSED_CPUS, CARRICK_BOUND_EXECUTORS and CARRICK_SPARE_EXECUTORS values.
Record `sw_vers`, `uname -a`, and `sysctl hw.model hw.logicalcpu
hw.perflevel0.logicalcpu` with each Mac's artifact identity; these host facts
cannot be recovered from this Linux worker. Do not make #1884's gate-side
comparison changes in this PR.
