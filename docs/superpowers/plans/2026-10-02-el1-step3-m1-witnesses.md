# M1 contract preparation (no functional cutover)

Baseline: `e59eec4e4e63f187f81d1f954a0f2c53b797edb8`.
Production behavior is unchanged. Phase B settlement and step-2 memory remain
prerequisites. No Docker, signed guest, runtime ratio or migration acceptance
is claimed. All new witnesses are VM-free; no new executable probe is added.

## Known-red gates: flips at M1 cutover

The director approved exact `expect_err` gates, a common greppable prefix and
same-commit inversion when the old owner is deleted. These run normally;
there are no ignores, should-panic tests, retries or reduced budgets. Passing
a known-red gate means the defect is still present, not conformance success.

| Binding (prefix `red_until_step3_m1_`) | Positive requirement | Exact current failure |
| --- | --- | --- |
| `carrick-kernel::kernel::objects::ipc::tests::one_table_writer` | shared F_SETFD visible to the host observer | `host slot flags diverge from shared authority` |
| `carrick-kernel::kernel::objects::ipc::tests::no_host_slot_selection` | shared close of bare fd 0 makes 0 the next allocation | `host selector ignores shared fd zero hole` (host chooses 3) |
| `carrick-fd-core::tests::sparse_fork_visits_only_populated_descriptors` | one populated descriptor costs one source-slot visit | `backed-capacity fork scan`, exactly 65/4096/65536 visits |

Both kernel witnesses keep a forked peer live. The sparse witness copies one
high fd at each backed capacity and verifies the child's backing and shared
refcount. The existing fork-filetable affine populated-descriptor budget is
unchanged. The core's current O(backed capacity) implementation is explicitly
red against that requirement; this ledger does not choose a new algorithm.

## Semantic and structural bindings

`kernel.el1.ipc-fd-authority` is now registered. Its fd-core bindings include:

- `fork_shares_description_but_not_descriptor_flags`: two live tables,
  shared offsets/status, independent CLOEXEC.
- `m1_clone_files_exec_unshares_before_cloexec_sweep`: a shared table identity
  reflects CLOEXEC changes; a copied exec table sweeps without touching peers.
- `unshare_close_range_keeps_siblings_intact`: close and CLOEXEC variants.
- `m1_rights_and_mapping_pins_outlive_dup2_and_numeric_reuse`: rights and
  mapping pin reducers, receiving installation, exactly-once last-pin release.
- `el1_ipc_lock_free_pins_race_close_reuse_and_growth` and
  `el1_ipc_concurrent_pins_and_closes_release_exactly_once`: threaded races,
  generations and finalization; no polling or timeout changes.
- `logarithmic_work_at_four_scales_without_an_allocator`: 65/130/4096/65536,
  allocation search <= 2*levels-1 bitmap words. The no-alloc core cannot
  allocate in steady state; fixture backing is supplied before operations.
- `el1_ipc_direct_lookup_reads_one_slot_at_every_scale`: two reads of one
  descriptor slot per pin at 65/4096/65536.

Kernel bindings:

- `m1_failed_pair_copyout_leaves_no_descriptors_or_reserved_holes`: invalid
  pipe2 copyout returns numeric EFAULT (14), restores descriptor population,
  and leaves 3/4 reusable after failure and after close.
- `m1_close_releases_posix_locks_before_last_alias_or_mapping` dispatches
  close while a duplicate and actual mapped-file reference remain live. A
  competing process owner can acquire the lock immediately after close;
  final-OFD release cannot substitute for this Linux close-time rule.
  `hvpatch_classic_record_locks_conflict_by_task_generation_and_release_on_close`
  supplies the existing lock-policy reducer.
- `mapped_file_reference_survives_last_fd_and_releases_last_fragment` and
  `mapped_file_reference_release_does_not_close_a_live_fd` exercise actual
  mapped-file retention and final fragment release in the current host model.
- Bare stdio is exercised in the host-slot selection witness. Existing
  `serial_host_el1_ipc_file_table_fork_exec_and_refusal` and
  `serial_host_el1_ipc_file_table_publishes_mutations_and_functional_retirement`
  remain serial production-adapter witnesses, not new EL0 acceptance.

`just test-kernel` now includes fd-core and EL1 ABI unit tests so its receipt
cannot omit the pin/bitmap/sparse-fork contracts. Production Rust changes are
confined to existing cfg(test) modules.

## Open integration proof

Core table identities are live owners, not scheduled Linux processes. A core
pin named mapping/rights is not proof that mmap/SCM_RIGHTS use that pin.
EL0 mapped-file release and POSIX lock cleanup, full
CLONE_FILES/exec process wiring, two isolated carriers with overlapping VAs,
and signed EL0 witnesses remain required at cutover. Register their executable
fixtures in carrick-conformance-next; do not claim the reducers close those
layers. No retained-CLI exception is introduced.

## Verification receipt

With `CARGO_BUILD_JOBS=3`, foreground:

- `just test-kernel`: exit 0; fd-core 32, EL1 ABI 109, kernel 2348 passed;
  the kernel's pre-existing one ignored test and serial partition are unchanged.
  All kernel-semantics suites completed. All three known-red gates executed.
- `cargo test -p carrick-conformance-contract --test registry`: 11 passed.
- `just clippy`: exit 0, workspace/all targets under `-D warnings`.
- `just fmt` and `git diff --check`: exit 0.

Initial compile verification caught a wrong expected return type in the new
install-pin test; corrected before the green fd-core run. The first full kernel
run rejected new descriptors missing the required `structural_budgets` field;
corrected and the full recipe rerun green. Neither was baseline red evidence.
Source/fixture identities: `docs/perf-results/2026-10-02-step3-m1-contracts/source-sha256.txt`.
The budgets are enforced directly by typed unit fixtures; the new descriptors
do not invent WorkMetric observations for bitmap levels or table identities.

Inventory generation adds the newly registered syscall contract associations;
Linux syscall declarations and support classifications are unchanged. The
first lint run detected that expected inventory drift before refresh.
K1 operation inventory and taxonomy rebinding includes only shifted test rows
and five added test-category sites (one table guard, two mapping, two lifecycle).
The new host-flag inspection is explicitly `test_or_definition` / `inspect_misc`
in `red_until_step3_m1_one_table_writer`. Production rows and production counts
are byte-for-byte unchanged. No production owner is removed or reclassified.
