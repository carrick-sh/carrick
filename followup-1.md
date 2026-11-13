# Follow-up (P2): HVF `diagnostic_identity` still reads the install-gated `grant`

`crates/carrick-vmm-hvf/src/metadata_grant.rs` `diagnostic_identity` authenticates
a stopped lane for refusal diagnostics through `AddressSpaces::grant`, which
returns `None` while a sibling vCPU's page-table pause raises the gate. #1742's
fix moved `GrantExecution::from_stopped_lane` to `AddressSpaces::installed_grant`.
A refusal recorded during a pause therefore loses its observed identity.
Diagnostics only, so this is not a P0. Switch it to `installed_grant` and extend
the macOS `root_execution` test with a raised gate. This is macOS-only code: it
needs a Mac `cargo test -p carrick-vmm-hvf --lib` run.
