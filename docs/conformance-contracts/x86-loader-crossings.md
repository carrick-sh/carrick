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
