# Root retirement retains descriptor-access exclusion

Base: director rollback correction `878d3a69e` over candidate `22323a343`.
Contract: `kernel.fork.stage1-image`.

The previous cached-retirement fixture allocated two independent anonymous
mappings despite describing pooled root reuse. It now uses a one-slot
`PreMappedRootSlotPool` and asserts that the reissued slot has the exact same
host pointer. The retained owner remains alive across actual pool release.

An injected backend retirement callback attempts nonblocking access through
that root's `Stage1Authority`. Before the correction this access succeeded:
the high-water query had already dropped the manager lock. The red test fails
specifically on the lost exclusion assertion. No guest or HVF VM executes;
the backend callback is an explicit test seam and the pool storage is real.

Root retirement now retains both the page-table authority identity read guard
and the existing inner descriptor-access lock through backend retirement,
structural owner removal, and pooled slot release. The callback also runs for
an absent manager, allowing abandoned publication to retire its backing.
No per-descriptor allocation or pin is introduced. This extends exact-MM
retirement exclusion; it does not serialize unrelated address spaces.

Verification (`RUSTC_WRAPPER=`, with `RUST_TEST_THREADS=1` for HVF tests):
- Focused `live_resolver_` controls: 2 passed after the red failure.
- `cargo test -p carrick-vmm-hvf --lib`: 563 passed, 3 existing ignored.
- `cargo clippy -p carrick-aarch64 -p carrick-vmm-hvf --all-targets -- -D warnings`: passed.
- Workspace format check passed.

This corrects the root retirement access window. Extension retirement,
resolver lifetime coverage for all callers, snapshot failure recovery,
integrated inventories/CI, signed execution and workload acceptance remain
open; the live-table candidate is still unintegrated.
