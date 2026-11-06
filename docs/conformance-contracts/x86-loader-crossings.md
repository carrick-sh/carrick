# x86 dynamic loader crossings (#1714)

Contract: `kernel.el1.arm-ring-first-crossing`.

The x86 crossing subset refused canonical `openat`, `faccessat` and `writev`
before they could reach the shared host-file dispatcher. ARM admitted those
same host-file operations. The shared x86 personality decoder also left native
`access` (21) undecoded: the HAL's existing legacy lowering happened only after
a crossing that ring entry refused.

Both admission and HAL now use one syscall-ABI operand lowering for legacy
`access(path, mode)` to `faccessat(AT_FDCWD, path, mode, 0)`. Native ordinal 21
remains intact for transport and diagnostics. The ISA distinction is required
because asm-generic has no legacy `access` syscall. No new dispatch handler is
introduced. Host operations retain their existing ARM semantics and costs.

The production `x86_production_forward` binding exercises each loader call
with and without pending work, with no file venue and invalid user pointers.
It requires a Forward result, untouched return word, no refusal or guest-service
count, and no completed-work boundary. The decoder binding separately checks
canonical identity, operand order, zero flags and preserved native identity.
Crossing classification remains a single constant-time dense lookup.

The real KVM acceptance is a dynamically linked `/bin/echo ok` and glibc
`/usr/local/bin/python3 -c pass`, using the same image and rebuilt release
artifact before and after the fix. A passing routing test alone does not prove
those workload results or change the conformance scoreboard.

Live verification exposed another loader prerequisite: native `fstat` and
`newfstatat` lacked private-ABI entries at ring admission. The existing host
handlers already write the x86 144-byte stat layout. The shared table now
resolves those native numbers to their existing private identities, and the
single crossing declaration admits those aliases only on x86. It does not
admit the ARM-layout canonical stat calls on x86 or private IDs on ARM.

The resulting KVM run still does not satisfy workload acceptance. Echo reaches
library mapping and fails there: its complete refusal census contains two
native `mmap` (9) refusals. The requested loader calls have zero refusals.
Python still exits 127. This is evidence of a remaining file-backed mapping
crossing gap, not a passing ecosystem row; no scoreboard baseline is updated.

## Private-file mapping design boundary

A fresh KVM run after rebasing the three crossing commits reproduces both
workload failures. Echo exits 127 without stdout and diagnoses `libc.so.6:
failed to map segment from shared object`. Its complete refusal census has
exactly two native mmap (9) refusals. Python exits 127 without stdout and
reports that it cannot find `libpython3.12.so.1.0`; its complete census has
one mmap refusal and one readlinkat (267) refusal. Python's diagnostic alone
does not establish that the library is absent from its image.

A KVM hardware execution breakpoint at MSR_LSTAR captured the six original
syscall operands, before CPL0 changes the registers. The debugger single-stepped
the entry instruction, then rearmed the breakpoint; no guest or handler code
was patched. A separate uninstrumented run supplies each refusal census.

| Workload | address | length | prot | flags | fd | offset | Result |
|---|---:|---:|---:|---:|---:|---:|---|
| Ubuntu echo, first map | 0 | 0x13cb | 1 (R) | 0x2 (PRIVATE) | 3 | 0 | refused |
| Ubuntu echo, library map | 0 | 0x212d90 | 1 (R) | 0x802 (PRIVATE, DENYWRITE) | 4 | 0 | refused |
| Ubuntu echo, later anonymous map | 0 | 0x2000 | 3 (RW) | 0x22 (PRIVATE, ANONYMOUS) | -1 | 0 | served |
| Python slim, first map | 0 | 0x128f | 1 (R) | 0x2 (PRIVATE) | 3 | 0 | refused |

None of the observed refused calls uses MAP_FIXED. Subsequent fixed library
segments, mprotect and executable startup have not been reached or proven.
The first file map is consistent with the loader cache, but the breakpoint
did not decode its pathname; the table makes no pathname assertion.

The refusal chain is structural:

- `crates/carrick-x86-cpl0/src/anonymous.rs:67` calls the shared
  `serve_delegated_anonymous` with `file: None` (line 74). The shared
  `decide_reservation_syscall` in `crates/carrick-el1/src/memory.rs` forwards
  private file mappings without a retained byte source; it already accepts
  DENYWRITE and FIXED with an appropriate source.
- `crates/carrick-personality-linux/src/dispatch.rs:1120` applies the shared
  strict crossing policy to the forwarded x86 call. mmap is deliberately
  absent from `crossing.rs`; this installs errno 38 and records the refusal.
- ARM handles that decline through `arm_native_service_exit` in
  `crates/carrick-el1-linux/src/dispatch.rs:1171`. `native_host_file_stage`
  requests `HostFileOp::MapPrivate`, served by the shared
  `SyscallDispatcher` native file handler in
  `crates/carrick-kernel/src/dispatch/native_files.rs:567`. The source is
  retained under its exact handle and generation. The native process retry
  consumes it and calls shared `serve_delegated_mapping` at
  `crates/carrick-el1-linux/src/dispatch.rs:3099`; the reservation owner
  publishes the private file node in ring. Fault supply reads from that
  retained source, rather than reopening the numeric descriptor.

The missing x86 mechanism is the native file-source service and its physical
supply/lifetime binding, not Linux mmap flag decoding or a new mmap handler:

1. CPL0 does not stage the ARM native host-file service; its
   `CompletionRoute::NativeService` arm in
   `crates/carrick-x86-cpl0/src/linux_personality.rs:1038` refuses that route.
   The existing staging function is coupled to `TrapFrame`; adapting it must
   preserve canonical call operands and exact native identities.
2. The x86 fault binding sets `PreparedFaultPath.file_slots: None` in that
   file at line 631. Therefore the shared private-file fault publication in
   `crates/carrick-el1/src/fault.rs:1662` cannot run on this binding.
3. The physical owner-grant handler in
   `crates/carrick-x86-cpl0-host/src/cpl0_anonymous.rs:1808` explicitly rejects
   any `window.host_backing`. It has no retained source custody or byte-read
   completion for those grants. Merely enabling file slots would hit this
   invariant instead of supplying the library.

Per the director's explicit stop condition, this slice stops at that boundary.
No mmap crossing is added and no second mmap implementation is introduced.
The extension needs to lift native source custody/service completion into
shared host code, bind CPL0 to the existing shared staging and reservation
owners, and implement only the x86 descriptor projection in the ISA layer.
Source retirement, close-after-map, fixed replacement, EOF/SIGBUS, partial
last-page zeroing, fork/COW, Busy-once recovery and exact owner generation all
need production witnesses before workload acceptance. Existing shared
private-file tests are reusable lower-layer evidence, not proof that KVM has
this binding. After that boundary is served, Python also needs its observed
readlinkat refusal investigated through the existing shared VFS path.
