# EL1 metadata allocation prerequisite

At source 1b50d2a5e the unused BumpAllocator begins at EL1_HEAP_BASE, exactly EL1_OBJECT_TABLE_BASE. The independent host-only reservation witness fails (Cargo 101): its first 64-byte allocation overlaps the assigned object table. No returned pointer was dereferenced. This is not evidence of current guest corruption: the allocator has no production users, and the EL1 image currently has no global allocator.

The extracted MMU core uses alloc collections, while EL1 still depends only on the allocation-free scheduler and inotify cores. Before linking that MMU implementation into guest fault service, choose an explicit metadata ownership and allocation model: reserved-region exclusion, reclamation, allocation-failure routing, and host/guest pointer-domain compatibility must be established. Simply installing this dormant bump allocator as GlobalAlloc is invalid, and its lack of free cannot satisfy repeated allocation/return acceptance. A bounded bootstrap region cannot become the final fixed guest frame pool.

This receipt identifies a prerequisite, not a completed allocator contract or the required guest first-touch proof. Register the precise semantic/work contract before implementing the chosen model. The standalone Cargo project is retained at target/el1-completion/allocator-prerequisite and depends on the checked-out Carrick crates.
