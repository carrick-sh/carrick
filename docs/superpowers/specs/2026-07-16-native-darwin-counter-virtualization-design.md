# Native Darwin Counter Virtualization Design

Date: 2026-07-16
Status: approved for implementation

## Problem

The Darwin-native backend currently classifies guest
`mrs <Xt>, CNTVCT_EL0` as a verbatim DSR copy. On Apple Silicon, the raw EL0
counter advances through host suspend, while Carrick implements Linux
`CLOCK_MONOTONIC` with Darwin `CLOCK_UPTIME_RAW`, which excludes suspend.
After this host accumulated about 8.7 hours of sleep, the full local gate
proved the mismatch deterministically: raw `CNTVCT` was about 44,437 seconds
while `CLOCK_UPTIME_RAW` was about 13,200 seconds.

This breaks the native vDSO's clock fast path because it reads `CNTVCT_EL0`
directly, while syscall clock handling and vvar calibration use
`CLOCK_UPTIME_RAW`. The existing hazard test correctly refuses to bless that
split timeline.

Darwin's own `mach_absolute_time` fast path establishes the relevant host
contract. It reads the hardware counter, adds a live commpage offset, and
retries if that offset changes during the read. The offset accounts for host
suspend and therefore produces the same suspend-excluding timeline as
`CLOCK_UPTIME_RAW` without a system call.

## Goals

- Make every native guest `CNTVCT_EL0` read observe the Linux monotonic
  timeline Carrick already exposes through clock syscalls.
- Preserve the vDSO fast path without adding a Carrick gateway transition per
  clock read.
- Handle every architectural destination register without exposing Carrick's
  reserved physical x18/x28 state.
- Fail over to a correctness-first host read when Darwin introduces a counter
  mode the inline path does not understand.
- Prove the fix on a host whose raw counter has already diverged through
  suspend, rather than relying on a freshly booted machine.

## Non-goals

- Changing HVF counter virtualization. HVF already supplies a guest counter
  aligned with `CLOCK_UPTIME_RAW`.
- Changing `CNTFRQ_EL0`; its frequency remains directly readable and matches
  the counter tick unit.
- Changing Linux clock-id policy, realtime-offset semantics, or the vvar ELF
  contract.
- General access to Darwin commpage data from guest code.

## Design

### Typed decode boundary

Add an explicit DSR instruction action for a virtual counter read instead of
letting `CNTVCT_EL0` fall through the generic copy path. The action carries the
architectural destination register. `CNTFRQ_EL0` remains a normal virtualized
copy.

Keeping the distinction typed prevents a later decoder expansion from silently
restoring the raw-counter behavior. Profiling and diagnostic names must also
identify counter virtualization rather than counting it as an ordinary copied
instruction.

### Inline current-host path

At native-runtime initialization, classify Darwin's commpage counter mode into
a small typed plan. The current host reports mode 3, for which Apple's
`mach_absolute_time` reads implementation-defined counter
`S3_4_C15_C10_6`; older mode 1 hosts use `CNTVCT_EL0`. Both explicitly known
modes receive an inline DSR plan:

1. materialize the fixed commpage timebase address in a Carrick scratch
   register;
2. load the signed/wrapping counter offset;
3. read the mode-selected host counter into the guest destination;
4. reload and compare the offset, retrying if Darwin changed it concurrently;
5. add the stable offset to the raw counter.

The offset is read for every guest counter read, so a process that remains
alive across a later host suspend automatically observes Darwin's updated
timeline. No per-process calibration becomes stale.

The emitter may use only Carrick-owned physical scratch registers and must
preserve guest x15/x16/x17 through their existing context slots. Destinations
x18 and x28 must commit through the existing virtual-register machinery;
`XZR` discards the result. Aliased scratch/destination cases receive explicit
lowering rather than relying on undocumented register luck.

The commpage address is an internal host implementation detail. Generated code
may read only the fixed timebase fields required by this sequence; no commpage
pointer or other host memory becomes guest-visible.

### Future-mode fallback

The host-side mode classifier recognizes only counter encodings Carrick has
explicitly tested: mode 1 `CNTVCT_EL0` and mode 3 `S3_4_C15_C10_6`. Mode 0,
mode 2 (`CNTVCTSS_EL0`), and unknown values must not emit a guessed instruction
or use raw `CNTVCT`. They lower the read to a typed sensitive exit whose handler
calls `mach_absolute_time` and writes the result to the architectural
destination. Mode 2 can move inline only after its encoding and behavior have
their own red-first proof on a host that selects it.

This fallback is slower but correct, and it confines any performance impact to
future Darwin/CPU combinations until their mode receives its own red-first
inline implementation. Diagnostics expose fallback use so it cannot remain a
silent performance regression.

### Clock and vvar coherence

The adjusted counter is in the same tick unit as `CNTFRQ_EL0`. Therefore the
existing aarch64 vDSO math converts it directly to suspend-excluding nanoseconds.
The vvar continues to publish:

- `VVAR_OFF_FREQ = CNTFRQ_EL0`;
- `VVAR_OFF_REALTIME_OFF_NS = wall_ns - CLOCK_UPTIME_RAW_ns`.

The vDSO monotonic result becomes adjusted-counter nanoseconds, and its realtime
result adds the existing realtime offset. The syscall and vDSO paths therefore
retain one timeline without changing the shared vvar ABI.

## Error handling

- An unreadable or unknown commpage mode selects the gateway fallback; it does
  not abort native startup.
- The inline sequence retries only while Darwin changes the offset. It has no
  user-controlled address or unbounded host allocation.
- On supported aarch64 macOS, the fallback uses the total
  `mach_absolute_time()` API. Off-target builds retain the existing typed
  unsupported native boundary rather than returning a fabricated raw counter.
- Artifact replay records the typed lowering and any process-specific gateway
  binding using the existing normalization rules; it must not embed a stale
  counter value or offset.

## Verification

Implementation follows red-green TDD:

1. Change the existing decoder test so `CNTVCT_EL0` must classify as a virtual
   counter read; observe it fail while the decoder still returns `Copy`.
2. Add an execution-oracle test that translates a counter read and brackets it
   with `CLOCK_UPTIME_RAW`. On this already-suspended host it must fail against
   the current raw-counter lowering by the measured multi-hour gap.
3. Cover ordinary destinations, reserved x18/x28 destinations, scratch aliases,
   and `XZR`.
4. Inject known and unknown host counter modes to prove the inline selection and
   fallback policy without depending on one machine's commpage contents.
5. Re-run focused DSR decode/emission/oracle tests and strict runtime Clippy.
6. Build and codesign the release binary, then run a native vDSO-versus-syscall
   clock reducer with a unique `CARRICK_RUN_ID` and scoped cleanup.
7. Run `RUST_TEST_THREADS=1 just ci`; the original counter hazard gate must be
   green on this host without rebooting it.

The fast-path proof records emitted instruction count and verifies that the
common mode does not produce a gateway exit. This fix is not complete if it
restores correctness by returning clock reads to the trap-heavy path.

## Clean-room boundary

The implementation derives Linux behavior from Carrick's existing clock
contract and differential probes. The Darwin mechanism is derived from the
locally installed Apple `libsystem_kernel` implementation and public host APIs.
No Linux kernel source is used.
