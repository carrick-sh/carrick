# AArch64 soft CPU resident blocks

The VM-free witness runs the production dispatcher and executable memory adapter
on Linux ARM64. The two blocks implement a decrement-and-branch loop and an HVC
provider exit. The Arm ARM defines the instruction semantics. At 1, 100 and
10,000 iterations, each of the two resident blocks should decode and emit once.
The test checks the exit PC and the retired instructions as well as the work
counts. QEMU user mode can run the same binary on x86_64.

On each dispatcher lookup, the dispatcher rechecks execute permission and the
guest-physical code frame. The memory owner provides the frame's generation. The probe
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

Set `CARRICK_SOFT_AARCH64_CACHE=0` to disable residency in the Linux ARM64
runner. Code still passes through the same preparation and execution steps.

An `IC IVAU` data translation names the physical frame. The launcher-owned
memory advances that frame's code generation through the extent inventory, so
resident aliases miss their generation check and unrelated frames stay
resident. The two-frame fixture goes from ten to nine emissions and checks
both generations. Whole-cache instructions retain their full flush.

The launcher also exercises physical retirement and exec loader writes.
Removing a page completes the extent retirement before releasing its backing.
A later mapping of the same physical address receives a new code generation
when it is first translated. Rewriting executable bytes through the loader
advances that generation again. The synthetic lifecycle fixture observes the
unmapped fetch failure and verifies that subsequent HVCs match the replacement
images. The dispatcher cache is scoped to a single run, and the witness works
at the launcher boundary without an ARM soft VMM lifecycle registration.

## Native branch chains

The direct and register branch exits share a tagged table of resident host
entries. The native path keeps guest registers live across a hit and branches
past the next block's host prologue. A link is installed only after a fetch
and generation check in the current TTBR/ASID/EL regime. The table borrows
one local stage-1 seat and pins the immutable mappings during a launch.
TLBI and regime changes clear the table. Guest writes to tracked code and
IC IVAU unlink every alias of the changed physical frame. Writable inline RAM
loans exclude tracked code, and launcher unmaps and exec writes happen outside
the run, after all links have been dropped.

Every native edge, including each back-edge, checks for a host kick or an
unmasked IRQ request. A caller can assert the IRQ request when its timer is
due. The dispatcher delivers it at the next block boundary. In the absence of
earlier exits, the dispatcher regains control after 256 blocks or the remaining
step budget, whichever is smaller. The dispatch budget for the direct loop is
four cold launches plus one per 256 iterations. Both modes retain exact
retirement counts and the same provider exit. Use
`CARRICK_SOFT_AARCH64_CHAIN=0` for the single-block launch path.

The native fixture covers direct and indirect chaining, BLR reading LR before
overwriting it, retirement at the exact step limit, a back-edge request that
arrives after the dispatcher has checked the pending flag, and a cross-page
guest store that revokes a warm link. The production carrier fixtures compare
chain on/off with identical initial state through the first HVC for EL1 boot
and static musl hello. No signed embed or Docker binding is registered.

### R4f evidence

The launch-bound assertion first failed at 100 iterations on the inline-memory
base, with 101 dispatches against a limit of five. Disabling frame unlinking
made the guest-write witness spend its budget running stale code. Disabling
the native pending check delayed the kick from the first back-edge to block
256. Both witnesses pass with the checks in place.

Ten interleaved off/on pairs used one release AArch64 runner under QEMU user
mode on the same x86-64 worker. The table shows median throughput and exact
counts for the two modes.

| Fixture | Dispatches off → on | Executed blocks | Retired instructions | Blocks/s off → on | Instructions/s off → on |
| --- | ---: | ---: | ---: | ---: | ---: |
| Memory loop, 10,000 iterations | 10,003 → 43 | 10,003 | 40,001 | 628,001 → 8,385,668 | 2,511,313 → 33,533,448 |
| Production EL1 to first guest HVC | 1,947 → 910 | 1,947 | 5,597 | 28,265 → 27,054 | 81,253 → 77,773 |
| Static musl hello to first carrier call | 7,926 → 3,986 | 7,926 | 20,308 | 47,626 → 42,427 | 122,026 → 108,707 |

The memory loop still has three stage-1 walks, two memory exits and four
publications in each mode. The EL1 and musl fixtures retain their register
state and first carrier exits, including the forwarded write and ppoll
mailboxes. QEMU shows a large hot-loop gain alongside lower throughput on
both production fixtures. Native ARM64 release throughput is unmeasured.
