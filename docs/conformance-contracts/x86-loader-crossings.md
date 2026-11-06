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
