# Initial ELF private-page ownership

`mm.initial.elf-private` owns private frame publication for the initial x86
ELF image, including data and text. The initial anonymous stack already
used this ownership. Authority: mmap(2) MAP_PRIVATE and fork(2). The VM-free
`fresh_owner_maps_static_text_data_and_stack_with_publications` test failed
with PRIVATE=0 on the data leaf before correction. The initial builder now
uses the private descriptor operation for every owned initial page; the KVM
receipt reconstruction mirrors that exact operation without relaxing any
transaction, live-descriptor or inventory authentication.

This changes no population or work budget: one frame initialization,
descriptor edit and publication per initial page. A forked signal wait found
the defect when a COW write correctly refused an unowned source descriptor.
