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
