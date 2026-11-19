# AArch64 soft CPU resident blocks

The VM-free witness runs the production dispatcher and executable memory adapter
on Linux ARM64. The two blocks implement a decrement-and-branch loop and an HVC
provider exit. The Arm ARM defines the instruction semantics. At 1, 100 and
10,000 iterations, each of the two resident blocks should decode and emit once.
The test checks the exit PC and the retired instructions as well as the work
counts. QEMU user mode can run the same binary on x86_64.

The dispatcher rechecks execute permission and the guest-physical code frame
on every entry. The memory owner provides the frame's generation. The probe
owner bumps it for guest stores and host loads. The self-modifying witness
executes a block, overwrites it from a different code page, then requires the
replacement HVC at the original PC with no stale dispatch.

The cache is scoped to one run on one memory owner. Changing the root, ASID
or exception level selects a separate key. Replacing a frame or a generation
replaces the cached block for that key. Untracked memory cannot supply a cache
hit. Production carrier wiring and native release timing remain separate gates.

Each resident translation owns its immutable RX mapping. At all three scales
the host adapter publishes twice, calls mprotect twice and synchronizes the
I-cache twice. The dispatcher loads architectural state directly into the
runner's frame and writes back from that same frame.
