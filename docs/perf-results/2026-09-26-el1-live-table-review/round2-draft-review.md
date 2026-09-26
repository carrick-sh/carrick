# Live-table round-2 draft review

The independent snapshot witness was rerun against a frozen copy of the in-flight MMU source. The existing witness now fails with a panic in PageTableManager::clone, instead of the round-1 silent shared-live fallback. Cargo exited 101. This is draft evidence, not a claim about an eventual committed candidate; revalidate its source hash before final review.

The source remains in target/el1-completion/live-review-round2/src/aarch64.rs. The witness is the existing snapshot-fallback-repro.rs in this directory; the resident allocation remains alive and only resolver availability is revoked. No guest, Docker, or invalid-pointer execution was involved.

Source review also found that restore_quiesced_snapshot_to_host skips unresolved arenas, while the safe Stage1Authority::restore_image caller subsequently converts the image to live storage and replaces the manager. Rollback drops journal entries while similarly skipping unresolved backing. These require explicit failure handling and preservation of recoverable transaction state. They have not yet been independently exercised by this receipt.

The cached-retirement test uses manually retired structural owners and a new independent mapping, while its root case only drops the state. It does not establish actual pooled-root retirement/reissue safety across a descriptor access. That requirement remains open.
