# Gate status

Source commit: `f1bff2ec47d91ec358f6b55801f21498062edec7`.

- `cargo fmt --all -- --check`: pass.
- `cargo test -p carrick-mmu-core --lib`: pass, 107 tests.
- `cargo test -p carrick-el1 --lib`: pass, 66 tests.
- `cargo check -p carrick-aarch64 --all-targets`: pass.
- Focused HVF tagged-live-leaf parity test: pass.
- Warning-denied Clippy for `carrick-mmu-core`, `carrick-el1`,
  `carrick-aarch64`, `carrick-vmm-hvf`, and `carrick-embed` tests: pass.
- Conformance contract registry: pass, 64 contracts, 15 claims, 144 surfaces.
- Signed `el1_anonymous_permission_transitions_stay_in_guest`: pass at all
  declared page and round scales; unentitled negative control passes; cleanup
  is zero.
- Same-source native arm64 Docker: pass at 256, 1,024, and 4,096 pages.
- `just lint-domains`: reaches the same three previously documented findings in
  `crates/carrick-el1/src/alloc.rs` for existing inline assembly. This
  checkpoint adds no inline assembly and does not claim the aggregate gate
  green.

Full checkpoint-2 `just ci` and `just el1-gate` acceptance remain pending until
the remaining mmap-family, fork-COW, and host page-table pause work lands.
