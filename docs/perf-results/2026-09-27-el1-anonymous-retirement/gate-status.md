# Gate status

The following checks passed on the implementation that became
`8b1af0a1963a339e9f8182ab429362543509a021`:

- `just fmt-check`
- `cargo clippy --workspace --all-targets -- -D warnings`
- `just deny`
- `just check-matrix`
- `just check-layering`
- `just check-kernel-portable`
- `just check --workspace`
- `just doc`
- `cargo run -p carrick-conformance-contract --bin check-contracts -- --root .`
- `cargo test -p carrick-mmu-core --lib` (102 passed)
- exact changed-path regressions for owned live-table reuse, fixed anonymous
  replacement rearming, and grant accounting
- `just test-integration`, including runtime, kernel, trace, engine, image, CLI,
  and all `carrick-conformance-next` shards
- committed signed HVF scale witness, negative entitlement control, DTrace
  lifecycle screen, and native arm64 Docker same-source controls

The full aggregate gates stop on two inherited failures outside this increment:

- `just lint-domains` reports three existing inline-assembly findings in
  `crates/carrick-el1/src/alloc.rs`. This increment does not modify that file,
  and the findings are present at its base commit.
- `just test` reaches
  `gic::tests::run_to_exit_withdraws_an_in_loop_kick_on_every_surfaced_exit`,
  whose source-text ratchet requires
  `Self::run_to_exit_inner(vcpu, mailbox, &mut kick_armed)`. The required text is
  absent at the base commit and this increment does not modify `gic.rs`.

These failures limit the repository-wide aggregate-gate claim. They do not
invalidate the focused semantic, structural, signed execution, or Docker
acceptance bound to this checkpoint.
