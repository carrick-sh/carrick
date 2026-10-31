# X86 MM-private COW copy window (`kernel.mm.private-cow-window`)

Linux private mappings preserve independent bytes across fork. A physical
replacement at 8 GiB must be usable without a permanent supervisor data alias.
Each MM owns one supervisor branch and two idle copy leaves. Fork clones that
branch while retaining shared supervisor branches. Under the exact-MM editor,
copy maps a read-only source and writable destination, both inaccessible to
users, then restores both idle words and drains translations before release.
A failed restoration is indeterminate and forbids backing reuse.

The VM-free bindings are
`x86_fork_clones_private_upper_branch_and_keeps_supervisor_sharing`,
`x86_cow_maps_private_scratch_pair_for_high_physical_replacement`,
and `private_copy_pair_has_bounded_work_and_restores_before_completion`.
Provisioning takes three exclusive zero table grants, 1537 descriptor reads
and three comparisons. Copy takes five descriptor reads, four comparisons
and two fixed-span drains. Fork adds exactly 1536 census reads for the private
branch. Admission authenticates all three actual table frames against the
launch grants separately from user mapping transaction identities.

The production KVM binding is
`mounted_static_x86_two_live_mms_have_private_anonymous_leaves`: shared-owner
fork, CPU1 child, CPL0 wait/exit, sixteen new PRIVATE pages in each MM, distinct
roots and physical pages, and an active peer. Kernel-owned user-copy crossings
carry their selected user address explicitly; hardware CR2 is not their demand.
The existing five-second bound is unchanged. No ARM runtime or ratio claim is
conferred by this x86 binding.
