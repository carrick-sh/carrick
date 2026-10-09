# ARM ring-first terminal and aperture correction

Terminal/geometry checkpoint: `f8068568ecb88d276ee346805fe07b0fb70a965d`.
Typed-policy checkpoint: `3bc8203a285c796a3f713406f45906f095af2fa3`.
Contract: `kernel.el1.arm-ring-first-crossing`.

## Diagnosis and red evidence

The inherited `target/ringswitch-hang-bt.txt` names the strict witness and
shows idle vCPUs. This branch's live ARM dispatcher passes no process venue;
shared thread exit declines home and last-thread exits. The strict crossing
set rejected both terminal calls. The VM-free test
`strict_arm_terminal_calls_without_process_owner_cross_to_carrier` returned
`Served` instead of `Forward` before the fix (exit status was refused).
The director ruled that both terminal notifications cross, matching x86,
when an in-ring owner does not serve them. This requires no new fallback path.

There was also concrete shared-memory corruption:
`EL1_APERTURE_CONTROL_OFFSET == EL1_SERVICE_COPY_TABLE_OFFSET == 0x1B_0000`.
Strict configuration set bit 3 in the first service-copy L3 descriptor.
`aperture_control_is_disjoint_from_service_copy_descriptors` failed with
"strict control aliases the service-copy L3 descriptors" before correction.
The corrected control starts at `0x1B_2000`, after the entire service-copy
record. Compile-time alignment and MM portal end checks enforce the geometry;
the image ABI hash now includes control geometry and flag semantics
(`0x06e229185340f7fb`). The aligned HVF fixture initializes the slot-zero
idle descriptors, toggles strict/off/default and reclaims the slot each time.

The mandatory `crossing_set` method first produced compiler E0046 at x86
`NativeLane`; both x86 contexts now name `HostCrossingSet::X86` explicitly.
Commit: `dcc703f03`.

## Inherited witness review

The raw-fixture direction was useful for avoiding unported libc startup.
The inherited rseq version was replaced explicitly: rseq returns ENOSYS
through either path and its terminal helper spins if exit returns. The new
registered raw fixture checks getuid refusal/forwarding, successful getpid,
host clock, bounded five-second ppoll readiness and exit_group completion.
It traps on an unexpectedly returned terminal syscall. The embed witness sets `ArmRingFirst::{Strict, OptOut}` directly and does
not change process environment.

## VM-free verification

- `cargo test -p carrick-personality-linux`: 34 unit tests plus 48 integration
  tests passed.
- `cargo test -p carrick-el1 --lib`: 318 passed.
- `cargo test -p carrick-el1-abi`: 125 passed.
- `cargo test -p carrick-vmm-hvf --lib hatch::tests`: 3 passed.
- `just test-kernel-semantics`: passed.
- `cargo check -p carrick-embed --test arm_ring_first_hatch`: passed.
- `cargo check --release --manifest-path fixtures/linux-aarch64-hello/Cargo.toml
  --target aarch64-unknown-linux-musl --bin carrick-linux-aarch64-ring-first`:
  passed. Debug-profile checking this no_std fixture first failed because its
  panic strategy is abort only in the release profile.
- `just fmt-check`: passed.
- `just clippy`: passed.
- The initial actual-PR-base domain gate rejected the inherited backend
  environment-read cohort (see `authority-delta-failure.txt`). Per director
  ruling, the engine now resolves the hatch from the frontend snapshot and
  the typed option reaches the backend through existing run/image builders.
  The new backend read and its introduced ceiling were removed.
- `arm_ring_first_policy_survives_builder_freeze` first failed with `None`
  instead of `Some(Strict)`, then passed for both settings after the frozen
  container preserved the option. Engine snapshot/explicit override and
  boot-region preservation tests also passed.
- The workspace clippy gate subsequently caught two explicit CLI request
  constructors missing the new field; both now request snapshot resolution.
  Final clippy/format/domain gates are pending below.

Raw local logs live under `target/ringswitch-*.log`. Red-first logs:
`ringswitch-required-isa-red.log`, `ringswitch-terminal-red.log`, and
`ringswitch-aperture-red.log`.

## Signed verification

The published `f8068568ecb88d276ee346805fe07b0fb70a965d` bundle verifies all
1,134 executables against the typed-policy checkpoint by input identity
`b600ef0ca57ce49c6d03dcd6f042996db1c13294574caff919611b0f05cbfff6`.
Archive SHA-256:
`0dbfda4f0fc75e58603a5f4171a61da131124cc65bfc7e8d4b372c3c5380fb1d`.
No mismatched fixture artifact was executed. Signed verification is pending
completion of the focused source gates. Full acceptance, Docker and ecosystem
promotion are outside this scoped worker gate, per director host profile.
No performance ratio is claimed.
