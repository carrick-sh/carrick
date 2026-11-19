# AArch64 soft CPU resident blocks

The VM-free witness runs the production dispatcher and executable memory adapter
on Linux ARM64. The two blocks implement a decrement-and-branch loop and an HVC
provider exit. The Arm ARM defines the instruction semantics. At 1, 100 and
10,000 iterations, each of the two resident blocks should decode and emit once.
The test checks the exit PC and the retired instructions as well as the work
counts. QEMU user mode can run the same binary on x86_64.
