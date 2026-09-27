# Metadata backing and failed-unmap retention

Pre-change source: 188114c43. Contract: kernel.el1.metadata-allocation.
The existing reset operation was extracted without changing its behavior to
allow an injected backend unmap. A fake refused unmap reproduces loss of the
backing owner (reset-red.log, exit 101), despite its stage-2 mapping remaining
live. The old reset also cleared its aperture bits for overlapping reuse.

The correction retains records and occupied spans until unmap succeeds.
The test verifies retained pointer and payload, no overlapping reuse, successful
retry, no second unmap, and preservation of an unpublished reservation.
Ordinary alloc_zeroed/Layout backing is replaced with Carrick OwnedHostMapping
MAP_SHARED allocation, making ownership non-copyable and host-page aligned.
The guest and host share one backing VM object. This reuses the existing host
mapping implementation rather than introducing another mapping primitive.

Both metadata grant tests pass; scoped HVF library Clippy with -D warnings and
formatting pass. This is VM-free ownership evidence. The previous signed
allocator result remains tied to c33e1d152, not this change. Carrier custody/VM
generation binding, concurrent guest use, IRQ protocol and remaining work
budgets are still open; signed verification is batched after those direct
requirements are integrated. First-touch and the full migration remain open.
