# Tier-D physical-x18 / XNU fork boundary (2026-08-08)

## Question

Can Tier D leave Linux AArch64 `x18` instructions byte-for-byte intact and use
physical `x18`, including in Node/V8 JIT code, without paying a veneer on every
use?

## XNU mechanism

Qualified against Apple OSS XNU commit
`f6217f891ac0bb64f3d375211650a4c1ff8ca1ea` (`xnu-12377.1.9`):

- `osfmk/arm64/machine_task.c::machine_task_process_signature` sets
  `task->preserve_x18` for the private `com.apple.private.custom-x18-abi` /
  `com.apple.private.uexc` entitlements. It also has a compatibility rule for
  macOS binaries whose `LC_BUILD_VERSION` SDK is older than macOS 13.
- `osfmk/arm64/pcb.c::machine_thread_process_signature` copies that task
  policy into `ARM_MACHINE_THREAD_PRESERVE_X18` for a newly signed thread.
- `osfmk/arm64/locore.s::exception_return` explicitly zeros `x18` when that
  machine-thread flag is absent and restores saved `x18` when it is present.
- `process_signature` is an exec/spawn path (`bsd/kern/kern_exec.c`). A normal
  Darwin `fork` duplicates register state but does not rerun signature
  processing for the child task/thread.

The private entitlement is not a shipping option: an ad-hoc-signed probe with
it was killed by AMFI. An SDK-12 `LC_BUILD_VERSION` stamp is usable and is now
paired with a runtime syscall proof; metadata alone is never trusted.

## Live probes

A minimal arm64 leaf set a sentinel in `x18`, made Darwin `getpid` via
`svc #0x80`, and compared `x18` after return.

| Process shape | SDK 27 stamp | SDK 12 stamp |
|---|---:|---:|
| freshly exec'd process | zeroed | sentinel preserved |
| `fork` child | n/a | zeroed |
| `vfork` child | n/a | zeroed |

Thus the compatibility policy is real after exec but is not fork-inherited on
this host. `vfork` does not provide an escape hatch.

## V8 byte-integrity result

The former dynamic far route wrote Carrick UDF/branch words into V8 code.
Postmortem disassembly showed V8 legitimately reading those generated
instruction bytes as data in `MaglevCodeGenerator::CollectRetainedMaps`; one
read consumed Carrick's `0x0000b452` UDF as part of an eight-byte value. Any
in-place dynamic text marker is therefore incorrect regardless of decoder
coverage.

The physical-x18 prototype stopped modifying ordinary V8 publications. A
20-run app screen then reached 18/20 with passing iterations around 0.31-0.33 s
(`target/conformance/logs/tierd-physical-x18-v2/app-20.jsonl`), versus roughly
0.50 s for the earlier virtualized route. This is opportunity evidence, not a
retained performance result: both failures were fork children whose `x18` had
been zeroed.

A follow-up Mach recovery experiment emulated naturally faulting
`ldr/str [x18, #imm]` against the last syscall-parked value. DTrace disproved
the premise: at fork the parked value could be `0xc0`, while guest code later
computed a new pointer in `x18` before its first memory use. Linux owns `x18`
as an ordinary GPR, so a boundary snapshot cannot reconstruct intervening
writes. The recovery experiment was removed rather than retained as a
probabilistic fix.

## Durable decision

1. Guest-visible dynamic bytes remain immutable. Dynamic `svc` / `tpidr_el0`
   execute through the byte-preserving DSR shadow; Linux CTR/DCZID reads use
   the Mach exception emulator.
2. Physical x18 is not a shipping mechanism. After the syscall-only probe had
   passed, canonical Node repeatedly set x18 and later observed it as zero
   across a pure guest call window containing no guest syscall, sysreg access,
   or Carrick JIT boundary. Mach replies, signal delivery, fork, and other XNU
   return paths are independent clobber surfaces, so a syscall probe cannot
   establish the required invariant.
3. Static Tier-D images therefore use the existing virtual-x18 veneers on every
   process. Dynamic ranges enter shadow policy before guest execution and keep
   their Linux-visible bytes unchanged while the AArch64 DSR translator owns
   execution, x18, sysregs, TLS, and syscalls.
4. Fork children retain the same byte-preserving route instead of depending on
   inheritance of XNU's private physical-x18 policy. The compatibility probe
   remains diagnostic evidence only.

## Stopping-point qualification

The narrow shadow mechanism is covered by
`direct_runner::tests::anonymous_rwx_code_is_published_through_dynamic_wx`:
one V8-shaped dynamic block starts as a non-executable source, faults into DSR,
returns to static Tier-D text, and is read back byte-for-byte. During final
release qualification this test exposed a configuration split: test builds
could publish a shadow range, while the non-test branch still refused every
publication when physical x18 was disabled. The first freshly signed screen
therefore failed deterministically at the first Node publication (0/20 app and
0/20 child, all rc125). Moving the already-journaled shadow publication ahead
of the physical-x18/direct-patching branch made release and test builds use the
same product route.

The rebuilt and signed binary first completed both canonical screens. After the
event-driven waiter correction, a second signed build was screened again so the
receipt covered the exact stopping tree:

| Workload | Result | Receipt |
|---|---:|---|
| Node app-smoke, concurrent screen 1 | 20/20 PASS | `target/perf/tierd-stop3-virtual-x18-app-20.jsonl` |
| Node `spawnSync` child, concurrent screen 1 | 19/20 PASS | `target/perf/tierd-stop3-virtual-x18-child-20.jsonl` |
| Node `spawnSync` child, sequential follow-up | 50/50 PASS | `target/perf/tierd-stop4-virtual-x18-child-seq-50.jsonl` |
| Node app-smoke, concurrent screen 2 | 20/20 PASS | `target/perf/tierd-stop5-virtual-x18-app-par-20.jsonl` |
| Node `spawnSync` child, concurrent screen 2 | 20/20 PASS | `target/perf/tierd-stop5-virtual-x18-child-par-20.jsonl` |

The first child of the first concurrent refresh died by guest `SIGSEGV`; it was
not a timeout. It did not repeat in the next 69 child runs, including a second
concurrent campaign, but the stopping point does not claim that this
low-frequency cold/cross-process failure is explained or eliminated. These
screens are reliability evidence only, not a performance comparison. The
virtual-x18/shadow route is materially slower than the discarded physical-x18
prototype, and no new Docker-bound ABBA was run at this stopping point. The
broader <=2x product goal and the remaining child-process reliability tail both
remain open.
