# Retired authority checker rule audit

This audit compares the checkers on final main (`8f6e6bc08aea`) with PR 51.
The checker rules are unchanged from the earlier `8ebd6fe41693` audit.
The replacements consume working production source or live compiler diagnostics;
accepted identities are operation / owner / lane counters, never source positions.
COUNT means a monotone ceiling and DELETE-AT-ZERO. TYPE/BOUNDARY and zero rules
continue to fail independently of the count ratchet.

| Previous checker and enforced operation/rule | Replacement or deliberate retirement |
|---|---|
| `check-k1-file-authority-inventory`: `read_open_files`, `write_open_files`, `lock_next_fd`, `lock_stdio_cloexec`, `lock_closed_stdio`, `read_fd_open_paths`, `write_fd_open_paths`, `lock_splice_pushback`, `read_epoll_fds`, `write_epoll_fds`, `epoll_wake_registry`, `nofile_soft`, `set_nofile_soft` | COUNT: closed K1 vocabulary, `SourceCensus.k1`, and `authority_debt::source_counts`; exact operation/owner/lane cohorts in the nine K1 families. |
| Same checker: description `read_for_io`, `write_for_io`, `inspect`, `try_inspect` | COUNT: description IO/guard vocabulary, canonical type calls and receiver-binding census. Aliases/references of typed bindings retain authority; ambiguous fields, aliases and helper chains are hard dialect errors. Field/variable spelling never supplies proof. Unrelated typed receivers are not charged when an unconditional inherent method or a closed local trait implementation proves dispatch. The trait proof admits receiver-only, unit-returning contracts; generic, inherited, associated-type and conditional contracts remain unresolved. |
| Same checker: `open_description`, `concrete_backing`, `OpenDescriptionRef` | COUNT: K1 vocabulary and symbolic owners. Function-value/unsupported generic operation shapes fail in `authority_dialect`; audited canonical shapes remain closed. |
| Same checker: `for_fork_copy`, `for_exec`, `native_reexec_fd`, `restore_native_reexec_fd`, `copy_file_table_for_host_fork` | COUNT: `file_lifecycle` vocabulary and `k1_lifecycle` cohorts. FileTable/Kernel receivers are distinguished from unrelated same-name APIs. Current production counts: 3, 1, 0, 0, 1 respectively; a new unconfigured caller fails as an unknown cohort, and an extra call in an existing owner exceeds its exact ceiling. |
| Same checker: `host_fork_file_authority_rejection` token | DELETE-NOW: this retired rejection API is already absent from current main. It is not an authority accessor. Actual host-fork FileTable copies are counted by the lifecycle APIs above. |
| Same checker: words `epoll/Epoll/EPOLL`, `splice/Splice/tee/vmsplice/sendfile/PipeStream/pushback`, `mmap/Mmap/mapping/Mapping/io_uring/IoUring/ioring` | Deliberately retire the text-only thematic index: it counted comments, names, declarations and unrelated vector operations, rather than authority crossings. Actual table/description crossings retain K1 epoll, stream-transfer and mapping-ring cohorts; actual host crossings retain live compiler cohorts. Merely mentioning a theme is not debt. |
| Same checker: exclude `self.vmas.splice`, `mod mmap`, `include_str!("mmap.rs")` | DELETE-NOW with the thematic index: these are not table/description authority operations. Literal source includes still participate in the production module closure where executable. |
| Same checker: whole `kernel/objects.rs` / `dispatch/fd_table.rs` classified as definitions, `file_authority/` excluded, lexical test-file/module heuristics | Replace broad exemptions with TYPE/BOUNDARY: exact `DEFINITION_OWNERS`, approved FileTable guard signatures, structural source ownership, and provable built-in test exclusions. Production accessors inside these files are counted; arbitrary methods or files cannot acquire an exemption by location. |
| Same checker: exact entries, text, line, counts, file-count summaries and checked-in inventory equality | Deliberately retire positional equality and descriptive summaries; COUNT checks source directly. Moves do not change debt. Missing source owners, undeclared authority modules, unresolved inclusion/attributes/macros remain hard errors. |
| `check-k1-file-authority-taxonomy`: every table/description inventory row classified exactly once, nonempty enclosing function, schema 1, closed migration families, consistent family totals | `AuthorityDebtCeilings::validate`, `assign`, and `SourceCensus` owners: closed nine K1 families, one operation/owner/lane cohort, no duplicate/reassigned family and no unknown owner. Family totals derive from counters; no positional taxonomy rows remain. |
| `check-k1-burndown`: each of the nine families stays below its ceiling; unknown families fail | COUNT at the finer operation/owner/lane level: `check_counts` and `ratchet` reject increases, new cohorts, family reassignment and removal of a nonzero counter. Zero cohorts may be deleted. |
| `check-dispatch-lock-authority`: raw `proc`, `pty_table`, `sysv_process`, SysV namespace `state`, FileTable `open_files/next_fd/stdio_cloexec/closed_stdio/fd_open_paths/epoll_fds` lock acquisitions, including try/read/write variants | COUNT: the retained token-aware discovery supplies `raw_lock` cohorts by semantic owner and lane. Original category/total ceilings are replaced by exact finer cohorts, not discarded; raw operation names are closed by the shared vocabulary. |
| Same checker: sole trusted `IpcView::lock_sysv_process` minting and `SysvNamespacePermit::lock_paired` pairing classifications | TYPE/BOUNDARY: retained `validate_boundary_rules`, required production helpers, exact `pub(in crate::dispatch::sysv)` visibility and prohibition on cross-module authority references. Exact approved FileTable guard boundaries also reject new guard-returning escape APIs. |
| Same checker: inventory IDs, ordinals, source expressions, lines, trusted row annotations and summary consistency | Retire row identity and annotation validation with the row ledger. Source boundary rules remain live; closed symbolic schema and ceilings replace ledger structure. |
| `check-runtime-aborts`: raw abort findings, no new raw sinks, no fatal-to-raw reversal | Unconditional ZERO: retained abort discovery rejects every production raw termination sink. This is stronger than grandfathering existing raw rows. Restricted-dialect import/re-export and macro rules prevent name-based evasion. |
| Same checker: literal nonempty `carrick_fatal!` domains; carrier-fault versus typed-error debt; typed-error ceiling | KEEP literal fatal-domain validation; COUNT `fatal:DOMAIN` by owner/lane in closed `fatal_carrier_fault` and `fatal_typed_error_debt` families. Their ceilings are monotone. |
| Same checker: four shard names/routes, schema, per-function ordinals/fingerprints, source equality, row `rationale/failure_domain/typed_error` strings, raw-to-fatal identity reconciliation | DELETE-NOW: these validate the positional/sharded classification ledger, not Rust behavior. Closed family/domain/owner counters retain the classifications; source positions, sink-flip matching, rationale text and typed-error prose are deliberately no longer executable policy. Relevant boundary/debt explanations live in the retirement design docs and review. |
| `check-runtime-global-state`: `static`, `thread_local!`, `std::env::var/var_os`, cfg-sensitive discovery; six classification names | COUNT: retained global discovery under the source-bound production verdict, symbolic `global:KIND` cohorts in closed global families. Built-in test-only exclusion is proven centrally; unknown/reassigned classifications fail. |
| Same checker: concurrent container-scoped global debt must be absent | Unconditional ZERO for `global_container_debt` in `AuthorityDebtCeilings::validate`; no nonzero ceiling may authorize it. |
| Same checker: forbid ambient `RUN_ID`, `CONTAINER_ID`, `CURRENT_*REGISTRY/FUTEX`; `CARRICK_RUN_ID` reads only at LaunchContext; no-argument `current_*registry/futex` accessors | KEEP structural `_validate_production_globals` checks in the retained checker, independent of ceiling acceptance. Existing four eliminated run-ID reads retain zero cohorts until their base is zero. |
| Same checker: ledger schema, duplicate identities, matching source hashes, stale/additional rows, rationale and container-debt destination strings | Replace ledger schema/duplicates/additions with strict counter validation and live discovery. Retire source hash identity, stale-row equality and mandatory prose fields; hashes remain transient integrity checks for a census verdict, never landing identity. |
| `check-task-participant-witnesses`: raw Task threads arithmetic/projection/cardinality (including aliases), scalar executor-census storage and numeric live APIs, numeric participant-witness APIs without `_for_probe`, crash-safe-point mutation scope and exact-mm quiesce restrictions | KEEP token structural rules in the retained checker under the central production verdict; `SourceCensus::task_call` and `verify_task_rules` additionally enforce semantic owner scopes and required owner discovery. No count ceiling permits these forbidden forms. |
| `check-host-authority-transitions`: exact 46-operation catalog and independent manifest binding, required syscall/dlopen/dlsym and host-PID operations, profile/build-matrix validity, pinned compiler/toolchain, Cargo diagnostic resolution including macro expansions | KEEP catalog, matrix and live compiler discovery. Ephemeral diagnostics feed `host_substrate`, `host_backing`, `host_forbidden_semantic` or separate `build_time` operation/owner/profile-lane counters. Unsupported target/toolchain/profile selection remains a hard error. |
| Same checker: every live diagnostic has a reviewed classification, no unreviewed or legacy-unreachable row, exact coverage of executed profiles, unknown/pending profiles not accepted as executed | COUNT: live `host_counts` must assign every observed operation/owner/profile to a closed family and ceiling. Diagnostics are discovered on each target; Linux and BSD do not stand in for macOS. Pending profiles remain explicitly reported. |
| Same checker: per-site review IDs, span/expansion identities, nonempty resource/rationale evidence, anti-generic / repeated-resource prose checks | Deliberately retire per-site identity and prose validators with the positional inventory. The classified symbolic owner cohorts retain crossing/debt distinctions; explanations are documented per owner in the retirement design. Unknown cohorts still fail, so new debt cannot inherit a positional row's evidence. |
| Same checker: macOS source/toolchain/row hash capture, exact capture/inventory equality, recapture provenance and static acceptance of the stored capture | DELETE-NOW: live compiler discovery on the actual host replaces stored capture acceptance. No checked-in macOS receipt becomes stale when lines move; integrity of transient source verdicts and compiler results is still checked. |
| `rebind-k1-taxonomy`, `reconcile-host-authority-positions`, `reconcile-line-pinned-inventories`, remote recapture tooling and their rename/reconciliation tests | DELETE-NOW: their only purpose was repairing or regenerating positional rows/captures. No replacement mutation step; source discovery and monotone symbolic checking run directly. An unrelated production line-move witness verifies this property. |

## Follow-up discovery correction

The receiver and lifecycle fixes expose 32 existing production calls omitted by
the prior replacement census: five lifecycle calls and 27 description calls.
No runtime authority operation was added. Head ceiling totals change **5806 →
5838**; the schema-absent main bootstrap changes **5810 → 5842**. Every corrected
cohort uses the actual current source count on both sides; the four existing
zero-cohort reductions remain. The five lifecycle operation totals above include
no test callers or accessor definitions. The two native-reexec operations have
zero callers; introducing one fails the unknown-cohort rule.

| Corrected family | Previous replacement ceiling | Current exact ceiling |
|---|---:|---:|
| `k1_create_install` | 60 | 61 |
| `k1_epoll_wait` | 15 | 24 |
| `k1_inspect_misc` | 123 | 137 |
| `k1_lifecycle` | 8 | 14 |
| `k1_mapping_ring` | 5 | 7 |

Every changed cohort (all others remain unchanged):

| Family | Operation | Owner | Was → now |
|---|---|---|---:|
| `k1_lifecycle` | `copy_file_table_for_host_fork` | `carrick_kernel::dispatch::kernel_context::SyscallDispatcher::reset_one_task_kernel_binding_for_current_process` | 0 → 1 |
| `k1_lifecycle` | `for_exec` | `carrick_kernel::kernel::objects::task::ThreadResources::for_exec` | 0 → 1 |
| `k1_lifecycle` | `for_fork_copy` | `carrick_kernel::kernel::objects::task::ThreadResources::for_clone` | 0 → 1 |
| `k1_lifecycle` | `for_fork_copy` | `carrick_kernel::kernel::operations::Kernel::copy_file_table_for_host_fork` | 0 → 1 |
| `k1_lifecycle` | `for_fork_copy` | `carrick_kernel::kernel::operations::Kernel::unshare_file_table_for_close_range` | 0 → 1 |
| `k1_inspect_misc` | `inspect` | `carrick_kernel::dispatch::fd_table::crate::kernel::FileDescription::distinct_open_path_snapshot` | 0 → 1 |
| `k1_inspect_misc` | `inspect` | `carrick_kernel::dispatch::fd_table::crate::kernel::FileDescription::host_socket_authority` | 0 → 1 |
| `k1_inspect_misc` | `inspect` | `carrick_kernel::dispatch::fd_table::crate::kernel::FileDescription::in_memory_pipe_endpoint` | 0 → 1 |
| `k1_inspect_misc` | `inspect` | `carrick_kernel::dispatch::fd_table::crate::kernel::FileDescription::in_memory_tcp_at_mark` | 0 → 1 |
| `k1_inspect_misc` | `inspect` | `carrick_kernel::dispatch::fd_table::crate::kernel::FileDescription::inspect_kind` | 0 → 1 |
| `k1_inspect_misc` | `inspect` | `carrick_kernel::dispatch::fd_table::crate::kernel::FileDescription::is_empty_pipe_reader_with_writer` | 0 → 1 |
| `k1_inspect_misc` | `inspect` | `carrick_kernel::dispatch::fd_table::crate::kernel::FileDescription::open_path_snapshot` | 0 → 1 |
| `k1_inspect_misc` | `inspect` | `carrick_kernel::dispatch::fd_table::crate::kernel::FileDescription::pidfd_watch` | 0 → 1 |
| `k1_inspect_misc` | `inspect` | `carrick_kernel::dispatch::fd_table::crate::kernel::FileDescription::retained_current_executable` | 0 → 1 |
| `k1_inspect_misc` | `inspect` | `carrick_kernel::dispatch::fd_table::crate::kernel::FileDescription::retained_exec_source` | 0 → 1 |
| `k1_epoll_wait` | `inspect` | `carrick_kernel::dispatch::format_time::timerfd_poll_source_from_lease` | 0 → 1 |
| `k1_inspect_misc` | `inspect` | `carrick_kernel::dispatch::host_io::OwnedHostFileCursor::capture_recalled` | 0 → 1 |
| `k1_epoll_wait` | `inspect` | `carrick_kernel::dispatch::net::epoll_ops::NetView<'a>::description_epoll_effective_interest` | 0 → 1 |
| `k1_epoll_wait` | `inspect` | `carrick_kernel::dispatch::net::epoll_ops::NetView<'a>::description_ipc_read_arrival` | 0 → 1 |
| `k1_epoll_wait` | `inspect` | `carrick_kernel::dispatch::net::epoll_ops::NetView<'a>::description_read_avail_bytes` | 0 → 1 |
| `k1_epoll_wait` | `inspect` | `carrick_kernel::dispatch::net::epoll_ops::NetView<'a>::interest_is_connected_host_socket` | 0 → 1 |
| `k1_inspect_misc` | `inspect` | `carrick_kernel::dispatch::net::lifecycle::NetView<'a>::connect` | 2 → 3 |
| `k1_inspect_misc` | `inspect` | `carrick_kernel::dispatch::net::lifecycle::NetView<'a>::reconnect_disconnected_inzone_stream` | 0 → 1 |
| `k1_lifecycle` | `inspect` | `carrick_kernel::el1_delegation::detach_recalled_member` | 0 → 1 |
| `k1_inspect_misc` | `read_for_io` | `carrick_kernel::dispatch::fs::locks::retained_host_file_for_lock` | 0 → 1 |
| `k1_mapping_ring` | `read_for_io` | `carrick_kernel::dispatch::mem::backing::MemView<'a>::discard_private_file_segment` | 0 → 1 |
| `k1_mapping_ring` | `read_for_io` | `carrick_kernel::dispatch::mem::backing::MemView<'a>::snapshot_private_mmap_description` | 0 → 1 |
| `k1_epoll_wait` | `write_for_io` | `carrick_kernel::dispatch::net::epoll_ops::NetView<'a>::detach_description_from_all_epolls` | 0 → 1 |
| `k1_epoll_wait` | `write_for_io` | `carrick_kernel::dispatch::net::epoll_ops::NetView<'a>::detach_epoll_owners` | 0 → 1 |
| `k1_epoll_wait` | `write_for_io` | `carrick_kernel::dispatch::net::epoll_ops::write_rearm::IoRearm::complete_read` | 0 → 1 |
| `k1_epoll_wait` | `write_for_io` | `carrick_kernel::dispatch::net::epoll_ops::write_rearm::IoRearm::complete_write` | 0 → 1 |
| `k1_create_install` | `write_for_io` | `carrick_kernel::dispatch::net::lifecycle::NetView<'a>::reconnect_disconnected_inzone_stream` | 0 → 1 |

## Conditional compilation audit

The normalization diff against the 8ebd6fe41 merge base was inspected for every
changed production file containing `target_os`: 85 files. The audit also searched
all source for retained `thiserror`, `serde`, `clap` and `zerocopy` imports after
qualifying their derives. This found two macOS-only cleanup sites:

| Site / change class | Conditional compilation reasoning |
|---|---|
| `carrick-vfs/src/apfs.rs` | The module is macOS-only; `ApfsError` derives `::thiserror::Error` explicitly. The old `Error as _` proc-macro import is unused and is removed. A temporary portable crate compiles this exact source on Linux with `-D warnings`: red with the import, green without it. This checks the source without claiming macOS execution. |
| `carrick-runtime/src/dtrace_symbols.rs` | The module is macOS-only. Every serde derive names `::serde`; serialization uses `serde_json`, with no `Serialize`/`Deserialize` method calls or manual trait implementations. Both redundant underscore imports are removed. |
| CLI `args.rs` / `trace_cli.rs` | Keep `clap::Parser`: `try_parse_from` and `Cli::parse_from` use its trait, including the macOS/FreeBSD trace-child branch. The args test import remains inside its test module. |
| `carrick-spec/src/lib.rs` | Keep serde imports: manual `impl Serialize` / `impl Deserialize` and `String::deserialize` need them. The `ValueEnum` test import stays within its feature-enabled test; existing OS-specific platform constructors retain their original cfgs. |
| Kernel `dispatch/{mod,ioring,net/support,sysv}.rs` and test `IntoBytes` imports | Keep byte-layout traits: concrete `as_bytes` / `read_from_prefix` methods use them. No derive-only import remains. These operations compile independently of host OS; existing conditional host socket translations are preserved. |
| `carrick-x86/src/fault.rs` | Keep `FromBytes as _` and `IntoBytes as _`: `Self::read_from_bytes` and descriptor `as_bytes` require trait lookup. Qualifying derives does not remove these real uses. |
| `carrick-portable/src/lib.rs` | Existing approved portable aliases remain in mutually exclusive macOS / FreeBSD / NetBSD / non-BSD cfg branches. Each imported libc constant belongs to its actual target; Linux fallback constants do not enter BSD compilation. The live BSD ceiling checks compile those branches. |
| Runtime `vcpu_loop/{binding,outcome,threads,wait_wake}.rs` | Host/architecture-sensitive executor imports remain scoped to macOS/aarch64 or the exact child test module that uses them. The earlier Linux test-scope corrections do not widen signed/macOS imports or add blanket allows. |
| VFS `fs_backend/host.rs` / CPL0 `fixture.rs` | Test-support visibility and the relocated freestanding fixture retain their explicit feature/test and `target_os = "none"` boundaries. Imports remain in the same compiled branches as their callers. |
| Remaining normalized files | Derive providers and description accessor calls are qualified explicitly; existing host cfg conditions and control flow remain intact. They introduce no leftover derive-only imports. Explicit FileDescription calls use the same authority type on every host. |

The exact path set for this audit is recorded below. Linux and both BSD compiler
lanes verify the host-portable branches; macOS-only discovery remains a director
run on cloudmac at the pushed head.

carrick-cli:

- `crates/carrick-cli/src/args.rs`
- `crates/carrick-cli/src/commands.rs`
- `crates/carrick-cli/src/hvpatch_carrier_cpu_attribution_profile.rs`
- `crates/carrick-cli/src/hvpatch_core_profile.rs`
- `crates/carrick-cli/src/hvpatch_exit_attribution_profile.rs`
- `crates/carrick-cli/src/hvpatch_k1_profile.rs`
- `crates/carrick-cli/src/trace_cli.rs`
- `crates/carrick-cli/src/trace_profile.rs`

carrick-conformance:

- `crates/carrick-conformance/src/engine.rs`
- `crates/carrick-conformance/src/native.rs`

carrick-conformance-contract:

- `crates/carrick-conformance-contract/src/personality_boundary.rs`

carrick-core:

- `crates/carrick-core/src/mm/reservation/root.rs`
- `crates/carrick-core/src/mm/transaction/owner.rs`

carrick-el1:

- `crates/carrick-el1/src/alloc.rs`
- `crates/carrick-el1/src/isa/x86/interrupts.rs`

carrick-el1-abi:

- `crates/carrick-el1-abi/src/lib.rs`

carrick-hal:

- `crates/carrick-hal/src/error.rs`

carrick-host-bsd:

- `crates/carrick-host-bsd/src/multiplexer.rs`

carrick-kernel:

- `crates/carrick-kernel/src/container.rs`
- `crates/carrick-kernel/src/dispatch/fd_table.rs`
- `crates/carrick-kernel/src/dispatch/format_time.rs`
- `crates/carrick-kernel/src/dispatch/fs.rs`
- `crates/carrick-kernel/src/dispatch/fs/rw.rs`
- `crates/carrick-kernel/src/dispatch/fs/sendfile.rs`
- `crates/carrick-kernel/src/dispatch/fs/stat.rs`
- `crates/carrick-kernel/src/dispatch/fs/state.rs`
- `crates/carrick-kernel/src/dispatch/fs/tests.rs`
- `crates/carrick-kernel/src/dispatch/fs/transfer.rs`
- `crates/carrick-kernel/src/dispatch/host_io.rs`
- `crates/carrick-kernel/src/dispatch/ioring.rs`
- `crates/carrick-kernel/src/dispatch/kernel_context.rs`
- `crates/carrick-kernel/src/dispatch/mem.rs`
- `crates/carrick-kernel/src/dispatch/mem/backing.rs`
- `crates/carrick-kernel/src/dispatch/mod.rs`
- `crates/carrick-kernel/src/dispatch/net.rs`
- `crates/carrick-kernel/src/dispatch/net/epoll_ops.rs`
- `crates/carrick-kernel/src/dispatch/net/epoll_ops/write_rearm.rs`
- `crates/carrick-kernel/src/dispatch/net/lifecycle.rs`
- `crates/carrick-kernel/src/dispatch/net/support.rs`
- `crates/carrick-kernel/src/dispatch/proc.rs`
- `crates/carrick-kernel/src/dispatch/sysv.rs`
- `crates/carrick-kernel/src/dispatch/tests.rs`
- `crates/carrick-kernel/src/dispatch/time.rs`
- `crates/carrick-kernel/src/network/socket_namespace.rs`

carrick-observability:

- `crates/carrick-observability/src/probes.rs`

carrick-personality-linux:

- `crates/carrick-personality-linux/src/abi/thread.rs`

carrick-portable:

- `crates/carrick-portable/src/lib.rs`

carrick-runtime:

- `crates/carrick-runtime/src/carrier.rs`
- `crates/carrick-runtime/src/dtrace_symbols.rs`
- `crates/carrick-runtime/src/vcpu_loop/binding.rs`
- `crates/carrick-runtime/src/vcpu_loop/exec.rs`
- `crates/carrick-runtime/src/vcpu_loop/executor/backend.rs`
- `crates/carrick-runtime/src/vcpu_loop/executor/pool.rs`
- `crates/carrick-runtime/src/vcpu_loop/lifecycle.rs`
- `crates/carrick-runtime/src/vcpu_loop/outcome.rs`
- `crates/carrick-runtime/src/vcpu_loop/quiesce.rs`
- `crates/carrick-runtime/src/vcpu_loop/signal.rs`
- `crates/carrick-runtime/src/vcpu_loop/threads.rs`
- `crates/carrick-runtime/src/vcpu_loop/wait_wake.rs`

carrick-spec:

- `crates/carrick-spec/src/lib.rs`

carrick-vfs:

- `crates/carrick-vfs/src/apfs.rs`
- `crates/carrick-vfs/src/fs_backend/host.rs`
- `crates/carrick-vfs/src/rootfs.rs`

carrick-vmm-hvf:

- `crates/carrick-vmm-hvf/src/bin/hvf_kernel_memory_probe.rs`
- `crates/carrick-vmm-hvf/src/hvf_aarch64_engine.rs`
- `crates/carrick-vmm-hvf/src/io_wait.rs`
- `crates/carrick-vmm-hvf/src/metadata_grant.rs`
- `crates/carrick-vmm-hvf/src/trap.rs`
- `crates/carrick-vmm-hvf/src/trap/carrier_custody.rs`
- `crates/carrick-vmm-hvf/src/trap/cow_engine.rs`
- `crates/carrick-vmm-hvf/src/trap/execve_rebuild.rs`
- `crates/carrick-vmm-hvf/src/trap/foreign_mm.rs`
- `crates/carrick-vmm-hvf/src/trap/frame_inventory.rs`
- `crates/carrick-vmm-hvf/src/trap/global_frame.rs`
- `crates/carrick-vmm-hvf/src/trap/guest_alias.rs`
- `crates/carrick-vmm-hvf/src/trap/guest_memory.rs`
- `crates/carrick-vmm-hvf/src/trap/mapping_plan.rs`
- `crates/carrick-vmm-hvf/src/trap/memory_protection.rs`
- `crates/carrick-vmm-hvf/src/trap/persistent_executor.rs`
- `crates/carrick-vmm-hvf/src/trap/process_plan.rs`
- `crates/carrick-vmm-hvf/src/trap/task_mapping_index.rs`
- `crates/carrick-vmm-hvf/src/trap/vcpu_admission.rs`

carrick-x86:

- `crates/carrick-x86/src/interrupts.rs`

carrick-x86-cpl0:

- `crates/carrick-x86-cpl0/src/entry.rs`
- `crates/carrick-x86-cpl0/src/fixture.rs`

## Final main rebase and discovery

The one final rebase uses `8f6e6bc08aea90244b66a43192cf970462d33909`.
Fresh Linux, FreeBSD and NetBSD compiler observations are re-derived by symbolic
owner. Main adds three `global:env_var` BuildTime cohorts in
`carrick_observability::build_program::main`: `CARGO_CFG_TARGET_ARCH`,
`CARGO_CFG_TARGET_OS`, and `HOST`, each exactly one. This build program is
byte-identical to main.

Main's host/target USDT selection compiles the stub in the Linux-to-FreeBSD
cross lane. Thus 22 probe owners lose one `std::process::id` crossing in each
FreeBSD profile: 44 exact ceilings change 1 → 0. These zero cohorts remain for
DELETE-AT-ZERO. Linux/NetBSD compiler counts are unchanged. Native macOS keeps
its real provider; its previous symbolic counts remain pending the director's
fresh discovery on the pushed landing candidate.

| Final correction | Was | Now |
|---|---:|---:|
| `build_time` | 27 | 30 |
| `host_substrate` | 1194 | 1150 |
| `freebsd_cli` compiled crossings | 565 | 543 |
| `freebsd_runtime` compiled crossings | 446 | 424 |
| Head total | 5838 | 5797 |
| Initial-main bootstrap total | 5842 | 5801 |
| Retained cohorts | 4986 | 4989 |

The four existing runtime environment-read reductions remain. Direct review of
current main confirms those four source calls still exist, while no other
runtime source authority operation changed since the prior bootstrap. Source
counts and all executed compiler lanes are re-derived, not padded. The initial
bootstrap records the final main SHA above as informational provenance.

The 22 probe owners (each in both `freebsd_cli` and `freebsd_runtime`):

- `carrick_observability::probes::real::execve_argv`
- `carrick_observability::probes::real::fs_op`
- `carrick_observability::probes::real::futex_route`
- `carrick_observability::probes::real::futex_unexpected_errno`
- `carrick_observability::probes::real::guest_exit`
- `carrick_observability::probes::real::guest_image_base`
- `carrick_observability::probes::real::host_jit_range`
- `carrick_observability::probes::real::host_pipe_io`
- `carrick_observability::probes::real::itimer_fire`
- `carrick_observability::probes::real::native_tierd_exception`
- `carrick_observability::probes::real::native_tierd_unsupported`
- `carrick_observability::probes::real::native_x86_fault`
- `carrick_observability::probes::real::native_x86_fault_history`
- `carrick_observability::probes::real::native_x86_fault_stack`
- `carrick_observability::probes::real::native_x86_pc`
- `carrick_observability::probes::real::native_x86_resolve`
- `carrick_observability::probes::real::native_x86_xstate`
- `carrick_observability::probes::real::native_x86_xstate_edge`
- `carrick_observability::probes::real::path_open`
- `carrick_observability::probes::real::ulock_requeue`
- `carrick_observability::probes::real::ulock_wait`
- `carrick_observability::probes::real::ulock_wake`

## Initial bootstrap acceptance

The owner-approved one-time cutover accepts the audited symbolic bootstrap only
when the base lacks the symbolic schema. `source_commit` is informational census
provenance, not an acceptance identity. A schema-bearing base always refuses the
bootstrap and uses the normal monotone ratchet instead.

CI and the merge queue census the actual merged tree under test. That tree must
satisfy the restricted dialect, exact committed ceilings and unconditional zero
rules. A test-only advance of main therefore needs no provenance rewrite; a new
production authority operation fails the merged-tree ceiling or unknown-cohort
check. No raw-base interpreter or normalization patch is introduced.

Red-first: a schema-absent base with a different SHA was refused before dropping
the SHA comparison. Regression tests also prove that two merged-tree lifecycle
calls exceed a committed ceiling of one, and that a schema-bearing base refuses
the bootstrap.

## PR 85 landing rebase

The landing base is `9cbe10d75a93dfeb37cb0a3d32026a332857ad7f`.
Preserve main's shared SlotId, typed CPL0 forward boundary and contract surfaces;
keep retired positional inventories deleted. Move main's fixture witness into
parsed fixture source. Qualify AllowedHostCrossing's built-in derive providers:
the restricted census first rejected their ambiguous glob-import scope.

Fresh symbolic source export observes exactly two new shared carrier-fault
cohorts, each one: `fatal:el1::prepare_child` and `fatal:el1::run_next`, owned by
`carrick_el1::personality::lifecycle::<El1PendingFamilies<'a,F,C,U,G> as
LifecycleNative<'a>>::prepare_child` and the corresponding `run_next` owner.
These are the invariant sinks added by PR 85, not relaxed existing budgets.
All other source and Linux/FreeBSD/NetBSD compiler cohorts are unchanged.

| Counter | Before PR 85 | Landing |
|---|---:|---:|
| `fatal_carrier_fault` | 867 | 869 |
| Head ceiling sum | 5797 | 5799 |
| Initial-main bootstrap ceiling sum | 5801 | 5803 |
| Retained cohorts | 4989 | 4991 |

The recorded bootstrap source SHA describes this newly audited content;
bootstrap acceptance remains schema-absent-only. The actual merged tree must
satisfy the restricted dialect, exact ceilings and zero rules. Scanner logic,
vocabulary and discovery output format are unchanged from `e2588bd4f`.
