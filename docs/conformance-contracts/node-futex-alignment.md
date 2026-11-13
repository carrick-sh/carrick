# Node futex admission (#1671 / #1850)

The `kernel.futex.contention` contract covers the op-393 error boundary.
Op 393 is FUTEX_WAIT_BITSET_PRIVATE | FUTEX_CLOCK_REALTIME on futex(2)
(AArch64 syscall 98, x86_64 syscall 202), not futex_waitv(2).
Linux authority: https://man7.org/linux/man-pages/man2/futex.2.html,
ERRORS: a futex address lacking four-byte alignment returns errno 22.

The ARM native fork/exec witness drives production dispatch with a live parent
and child. Misalignment must finish in ring with -22, never decline to a
native child's counted -38. Masks 0, 1 and 0xffffffff cover both empty and
nonempty bitsets. The x86 native-process entry exercises all three nonzero
alignment offsets and the same masks. Neither path may read the operand or
install a wait: the structural budget is exactly zero operand loads.

The signed `el1_node` tests reproduce the scoreboard commands, including
`node -e 'console.log(process.version)'` for the row called `node-version`.
They report both output streams on failure. This alignment witness does not
establish that Node supplied a misaligned word. Node's exact failing futex
operation and errno still require signed attribution; the ecosystem tests
remain required, and no Node pass is inferred from lower-layer alignment tests.


Unexpected immediate ring futex errors are sampled into the existing bounded
syscall-frame diagnostic buffer, preserving original operands, execution
binding and numeric return. Expected wait results (0, errno 4, 11 and 110)
consume no records. The 32-slot buffer retains a prefix; saturation or an empty
sample is not proof of absence. Sampling changes neither completion nor wait
ownership. The ABI known-answer test checks filtering, retention, snapshot and
numeric formatting; the production ARM invalid-operand witness checks that the
real family records op 393 / errno 22. Signed Node assertions include samples.
