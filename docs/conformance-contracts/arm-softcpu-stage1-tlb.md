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
The dispatcher drops it at every provider handoff. AT and DC ZVA still use
the walker for their required leaf attributes.

The fast result is a guest physical address. The memory provider still
checks backing for every access. Cache use requires the provider to own the
local stage-1 seat while dispatch runs. The Linux arm64 launcher enables
the TLB by default and accepts the exact opt-out `CARRICK_SOFT_AARCH64_TLB=0`.
