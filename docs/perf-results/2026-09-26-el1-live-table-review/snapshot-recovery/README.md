# Snapshot restore preserves recovery state

Base: `988c0aedc`, director corrections over live-table candidate `22323a343`.
Contract: `kernel.fork.stage1-image`.

The existing missing-extension test asserted only the returned error. Adding
an assertion on the actual root backing fails before the correction: restore
had already copied the root before discovering that the extension was absent.
Restore now resolves every destination before any write. It resolves each arena
once, retaining a temporary pointer vector linear in arena count; the unsafe
caller still supplies quiescence and mapping lifetime through the whole copy.
This is bounded restore scratch, not a per-descriptor read allocation.

Authority and editor restore APIs borrow the caller's optional owned image.
Failure leaves that image available; success consumes it and preserves the
existing old-manager recycling result. The authority control now fails a
restore, retains its image, retries with available backing, and succeeds.

Four foreign-COW error paths previously discarded restore errors through
`.ok().flatten()`. They now share an explicit result handler. Successful
compensation keeps ordinary refusal/retry behavior. Failed compensation stores
the pre-image in MM scratch and raises a named carrier fault before cleanup can
retire the replacement owner while modified descriptors still reference it.
This new invariant-failure disposition is reviewed in the abort ledger; it is
not a claim that an unavailable mapping can be recovered by retrying a guest.
The new carrier-fault branch has source/ledger review, not a signed death test.

Verification, with `RUSTC_WRAPPER=`:
- Original core control: one failure on partial root overwrite (red log).
- `cargo test -p carrick-mmu-core -p carrick-aarch64 --lib`: 82 + 74 passed.
- Updated authority retry control and authority suite: 20 passed.
- `RUST_TEST_THREADS=1 cargo test -p carrick-vmm-hvf --lib`: 563 passed,
  3 existing ignored; includes reversible foreign-COW boundary and retry tests.
- Targeted three-crate all-target Clippy: passed.
- Contract registry: passed (57 contracts).
- All abort-ledger shards and formatting: passed.

Memory integration remains withheld pending extension retirement/resolver
lifetime review and clean-tree integration gates. Actual EL1 fault service,
signed promotion, and workload ratios remain uncompleted goal requirements.
