# Exec replacement live resolver regression

The public probe gate on `33b590cd8762cb89cdba343fa95dff6d87508c81`
aborts at the first probe of each shard (`accessx`, `acceptsock`, `abortdeath`)
with `dispatch::brk: protect_range failed during brk heap expansion`.
No broad probe, smoke, full, or EL1 migration acceptance follows from the
previous focused signed fork and occupancy greens.

The existing `accessx` signed embed probe reproduces the failure without the
whole gate. LLDB reports an 8 KiB RW heap expansion and the underlying error
`stage-1 page-table manager unresolved arena 0x9a00200000`.
The precise pre-fix executable is retained under
`target/el1-completion/live-integrated/brk-before-fix/`; its hash is recorded in
`source-evidence.json`. The modified-memory abort core remains under the same
scratch parent as `brk-probe.core`.

## Corrected diagnosis

Optimized `frame variable logical` displayed a zero-length key. This was
misleading: disassembly plus live registers prove logical and physical ends
are both `0x9a00400000`, base `0x9a00200000`, physical length `0x200000`, and
request length 8. Do not add a zero-length-marker exception or relax bounds.
`brk-registers.log` records these actual operands. `brk-owner2.log` records the
resolver's retained MM root as `0x9a00000000`, the predecessor root.

`execve_rebuild_inner` creates a new `MmAccessState` but does not install its
live resolver. Subsequent authority binding can retain the predecessor's
resolver, which cannot authenticate the successor root. The correction binds
the successor resolver immediately after replacing the MM state, matching
other MM creation paths. Bounds, owner generation checks, and pinning remain
unchanged; no scan or retry is introduced. This is the exec binding of the
`kernel.fork.stage1-image` live-authority invariant.

The focused signed red-to-green run passes both musl and GNU `accessx` on the
corrected source (base plus `correction.patch`), with source-hash-validated
oracle equality, negative entitlement control, and zero scoped leftovers.
Fresh native arm64 Docker runs on Carrick's matching April Ubuntu image also
match both committed oracles and leave no containers. Exact commands, binary
hashes and image layer identity are in `native.json`. The signed artifact receipt
and frozen binary identity are retained beside this document.

Broader signed probes, full CI, smoke/full promotion and actual EL1 first-touch
service remain open. No end-to-end timing improvement is claimed.
