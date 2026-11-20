# AArch64 soft CPU stage-1 walks

`arm.softcpu.stage1-tlb` uses the production dispatcher and native host
launcher under bootstrap stage-1 tables. The fixture executes a loop at 1,
100, and 10,000 iterations, copying a word between two distinct data pages.
The unchanged regime and permission class of each page allow three total
walks: one for fetch, one for the load, and one for the store. The fixture
checks the copied word, retired instruction count, and HVC exit. On the
pre-TLB build the three scales retired correctly and walked 7, 502, and
50,002 times.

The dispatcher TLBI test writes an invalid descriptor through a guest store,
executes the architectural barrier and TLBI sequence, and checks that the
next load takes the L3 translation abort with its original FAR and ELR.
The EL1 abort vector must reach its own provider exit.

A second dispatcher witness loads the same VA under two TTBR0/ASID values,
then sets PAN and checks that the ordinary load aborts. A hit is tagged by
both raw TTBRs, TCR, SCTLR, VA page, access plane, EL and the applicable
PAN/UAO and access class. A regime change or TLBI clears the local cache.
The dispatcher drops it when stage 1 is disabled and at every provider
handoff. The disable witness switches roots in flat mode, restores the
original registers and observes new code and data walks after re-enabling
stage 1. AT and DC ZVA still use the walker for their required leaf attributes.

The fast result is a guest physical address. The memory provider still
checks backing for every access. Cache use requires the provider to own the
local stage-1 seat while dispatch runs. The Linux arm64 launcher enables
the TLB by default and accepts the exact opt-out `CARRICK_SOFT_AARCH64_TLB=0`.

## R4c evidence

At 1, 100, and 10,000 iterations the memory loop walks 3 pages on each
run. It decodes, emits and publishes 4 blocks at every scale. The 10,000
iteration run takes 20,000 memory exits.

The rates below are medians from five same-host interleaved pairs of
counter-enabled AArch64 release binaries in QEMU user mode on Debian x86_64,
pinned to CPU 0. Both variants use the same EL1 image and GNU cross linker.
The musl probe includes syscall tracing. Other verification jobs ran on the
host during measurement.

| Probe | Stage-1 walks before → after | Blocks/s before → after | Instructions/s before → after |
|---|---:|---:|---:|
| Memory loop, 10,000 iterations | 50,002 → 3 | 236,618 → 860,691 | 315,488 → 1,147,578 |
| EL1 trampoline to first HVC | 5,547 → 72 | 26,556 → 27,482 | 51,297 → 53,086 |
| Static musl hello to first carrier call | 19,078 → 127 | 27,152 → 44,700 | 53,569 → 88,189 |

With the TLB opt-out, the EL1 trampoline took 5,547 walks and reached the
same HVC. The rates measure the soft dispatcher in QEMU. Native ARM timing,
the production carrier lifecycle, and the Python wall budget remain open.
