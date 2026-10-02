//! Normalized syscall handler routing table and dispatch execution routes.
//!
//! Chains each subsystem module's routing table into a single resolution
//! mechanism for claimed syscalls, separating ordinary and MM-mutation routes.

use carrick_abi::syscall::nr;
use carrick_guest_mem::CurrentMmMemory;

use super::dispatcher::SyscallDispatcher;
use super::mm_authority::MmExecutorParticipation;
use super::outcome::{DispatchOutcome, LinearMemory};
use super::request::{MutationSyscallCtx, SyscallCtx, SyscallRequest};
use super::{
    DispatchError, ThreadCtx, bpf, creds, fs, keys, mem, mm_mutation, mount_api, mqueue, net, perf,
    proc, resources, signal, syslog, sysv, time,
};
use crate::compat::{CompatReporter, SyscallArgs};

/// A normalized syscall handler resolved to a bare function pointer: the
/// `define_syscall!`-generated `sys_*` methods all share this signature, so a
/// `number → handler` table is just a `match` returning one of these. Each
/// dispatch module owns a `dispatch_<area>(number) -> Option<SyscallHandler<M>>`
/// over the numbers IT implements; `dispatch_normalized` chains them. Adding a
/// syscall is then a one-module edit — no shared routing table to contend on
/// (Task A1). See [[plan-concurrent-fanout-lanes]] Part A.
pub type SyscallHandler<M> =
    fn(&SyscallDispatcher, &mut SyscallCtx<M>) -> Result<DispatchOutcome, DispatchError>;
pub type MutationSyscallHandler<M> =
    fn(&SyscallDispatcher, &mut MutationSyscallCtx<M>) -> Result<DispatchOutcome, DispatchError>;

/// Resolve a syscall number to its handler by chaining every dispatch module's
/// own routing table. This is the single source of truth for "is this number
/// claimed, and by which handler"; both `dispatch_normalized` (which builds the
/// ctx and invokes the handler) and `dispatch_normalized_known` (the membership
/// test) go through it. Each module owns its own arms, so a future agent adds a
/// syscall by editing ONE module's `dispatch_<area>` — never this function (the
/// central `dispatch()` chokepoint is gone). See [[plan-concurrent-fanout-lanes]].
pub(crate) fn resolve_handler<M: CurrentMmMemory>(number: u64) -> Option<SyscallHandler<M>> {
    fs::dispatch_fs(number)
        .or_else(|| net::dispatch_net(number))
        .or_else(|| mem::dispatch_mem(number))
        .or_else(|| proc::dispatch_proc(number))
        .or_else(|| keys::dispatch_keys(number))
        .or_else(|| signal::dispatch_signal(number))
        .or_else(|| time::dispatch_time(number))
        .or_else(|| creds::dispatch_creds(number))
        .or_else(|| sysv::dispatch_sysv(number))
        .or_else(|| mqueue::dispatch_mqueue(number))
        .or_else(|| bpf::dispatch_bpf(number))
        .or_else(|| perf::dispatch_perf(number))
        .or_else(|| mount_api::dispatch_mount_api(number))
        .or_else(|| syslog::dispatch_syslog(number))
}

pub(crate) fn resolve_mutation_handler<M: CurrentMmMemory>(
    number: u64,
) -> Option<MutationSyscallHandler<M>> {
    fs::dispatch_fs_mutation(number)
        .or_else(|| mem::dispatch_mem_mutation(number))
        .or_else(|| sysv::dispatch_sysv_mutation(number))
}

pub const MM_MUTATION_SYSCALLS: &[u64] = &[
    25, 196, 214, 215, 216, 222, 226, 227, 228, 229, 230, 231, 232, 233, 284,
];

/// The mapping syscalls whose host venue may mirror host rows into a
/// delegated root after their backend work, and for which ENOMEM is a Linux
/// answer (map-count exhaustion): `shmat`, `munmap`, `mremap`, `mmap`,
/// `mprotect`, `mlock`, `munlock`, `mlockall`, `madvise`, `mlock2`. `brk`
/// answers exhaustion with the unchanged break; `msync`, `mincore`,
/// `munlockall` and `fcntl` never add root nodes.
fn mm_mutation_may_mirror(number: u64) -> bool {
    matches!(
        number,
        196 | MUNMAP | 216 | 222 | 226 | 228 | 229 | 230 | 233 | 284
    )
}

const MUNMAP: u64 = 215;

pub fn syscall_requires_mm_mutation(number: u64, _args: SyscallArgs) -> bool {
    MM_MUTATION_SYSCALLS.contains(&number)
}

pub trait NormalizedDispatchRoute {
    fn dispatch<M: CurrentMmMemory>(
        &mut self,
        dispatcher: &SyscallDispatcher,
        _kernel: &crate::kernel::KernelContext,
        request: SyscallRequest,
        memory: &mut M,
        reporter: &CompatReporter,
        thread: Option<ThreadCtx>,
    ) -> Option<Result<DispatchOutcome, DispatchError>>;
}

pub struct OrdinaryDispatchRoute<'lease, 'executor> {
    pub host_wait: Option<super::request::HostWaitContext<'lease>>,
    pub lease: Option<&'lease crate::kernel::objects::ThreadExecutionLease>,
    pub mm_executor: Option<&'executor mut MmExecutorParticipation>,
}

impl NormalizedDispatchRoute for OrdinaryDispatchRoute<'_, '_> {
    fn dispatch<M: CurrentMmMemory>(
        &mut self,
        dispatcher: &SyscallDispatcher,
        kernel: &crate::kernel::KernelContext,
        request: SyscallRequest,
        memory: &mut M,
        reporter: &CompatReporter,
        thread: Option<ThreadCtx>,
    ) -> Option<Result<DispatchOutcome, DispatchError>> {
        dispatcher.dispatch_normalized_with_lease(SyscallCtx {
            host_wait: self.host_wait,
            kernel,
            request,
            memory,
            reporter,
            thread,
            execution_lease: self.lease,
            mm_executor: self.mm_executor.take(),
        })
    }
}

pub struct MutationDispatchRoute<'guard, 'authority, 'lease> {
    pub guard: &'guard mut mm_mutation::MmMutationGuard<'authority>,
    pub lease: Option<&'lease crate::kernel::objects::ThreadExecutionLease>,
}

impl<'guard, 'authority, 'lease> NormalizedDispatchRoute
    for MutationDispatchRoute<'guard, 'authority, 'lease>
{
    fn dispatch<M: CurrentMmMemory>(
        &mut self,
        dispatcher: &SyscallDispatcher,
        kernel: &crate::kernel::KernelContext,
        request: SyscallRequest,
        memory: &mut M,
        reporter: &CompatReporter,
        thread: Option<ThreadCtx>,
    ) -> Option<Result<DispatchOutcome, DispatchError>> {
        dispatcher.dispatch_normalized_mutation(MutationSyscallCtx {
            kernel,
            request,
            memory,
            reporter,
            thread,
            mm_mutation: self.guard,
            execution_lease: self.lease,
        })
    }
}

impl SyscallDispatcher {
    /// Dispatch a syscall through the chained per-module routing. Returns `None`
    /// for an unclaimed number (the caller ENOSYSes); otherwise builds the
    /// transient `SyscallCtx` and invokes the resolved handler.
    #[cfg(test)]
    pub(crate) fn dispatch_normalized(
        &self,
        kernel: &crate::kernel::KernelContext,
        request: SyscallRequest,
        memory: &mut impl CurrentMmMemory,
        reporter: &CompatReporter,
        thread: Option<ThreadCtx>,
    ) -> Option<Result<DispatchOutcome, DispatchError>> {
        self.dispatch_normalized_with_lease(SyscallCtx {
            host_wait: None,
            kernel,
            request,
            memory,
            reporter,
            thread,
            execution_lease: None,
            mm_executor: None,
        })
    }

    pub(crate) fn dispatch_normalized_with_lease<M: CurrentMmMemory>(
        &self,
        mut ctx: SyscallCtx<'_, M>,
    ) -> Option<Result<DispatchOutcome, DispatchError>> {
        let handler = resolve_handler(ctx.request.number.raw())?;
        let canonical_nr = ctx.request.number.raw();
        let outcome = resources::with_captured_resources(ctx.kernel, || {
            if matches!(
                ctx.request.number,
                nr::UNLINKAT | nr::LINKAT | nr::RENAMEAT | nr::OPENAT | nr::RENAMEAT2
            ) {
                // Qualify zero path-visit aggregates: the measured request
                // reached the instrumented dispatcher, even on a cache hit.
                // fs_op's lazy USDT closure evaluates its payload only when
                // the probe is enabled.
                carrick_observability::probes::fs_op("path-census:armed", "", 0);
            }
            handler(self, &mut ctx)
        });
        // Single choke point for the fork-coherent resolve cache: a structural
        // namespace mutation (mkdirat/unlinkat/symlinkat/linkat/renameat/
        // renameat2/mknodat) can change how OTHER paths resolve, so bump the
        // shared generation that invalidates every process's cache. Every guest
        // syscall funnels through here exactly once; content writes are not in
        // the set, so a syscall-bound write/lseek loop keeps its cached resolves.
        if fs::is_structural_namespace_mutation(canonical_nr) {
            self.fs.rootfs_vfs.dentry_cache.coherence.bump_generation();
            self.fs
                .rootfs_vfs
                .dentry_cache
                .note_structural_dispatch(matches!(
                    &outcome,
                    Ok(DispatchOutcome::Returned { value }) if *value >= 0
                ));
        }
        Some(outcome)
    }

    pub(crate) fn dispatch_normalized_mutation<'authority, 'lease, M: CurrentMmMemory>(
        &self,
        mut ctx: MutationSyscallCtx<'_, 'authority, 'lease, M>,
    ) -> Option<Result<DispatchOutcome, DispatchError>> {
        let handler = resolve_mutation_handler(ctx.request.number.raw())?;
        // A delegated MM's host mapping syscall first reconciles the returns
        // its EL1 root owes, so no host step plans over retired memory.
        let permit = ctx.mm_mutation.host_alias_permit();
        let reconciled = self
            .mem_view()
            .reconcile_el1_deferred_returns(&permit, ctx.memory);
        drop(permit);
        match reconciled {
            Ok(_) => {}
            Err(mem::el1_reservations::El1ReturnError::Authority(refusal)) => {
                return Some(Err(mem::anonymous::root_refusal(refusal)));
            }
            // The backend could not retire the extents (they stay owed):
            // the same answer a failed `munmap` backend retirement gives.
            Err(mem::el1_reservations::El1ReturnError::Backend { .. }) => {
                return Some(Ok(DispatchOutcome::errno(carrick_abi::LINUX_ENOMEM)));
            }
        }
        if let Some(errno) = self.secure_host_venue_metadata(&ctx.request) {
            return Some(errno.and_then(|errno| {
                if ctx.request.number == carrick_abi::syscall::nr::BRK {
                    // Linux's raw brk ABI reports allocation failure with the
                    // unchanged break; libc translates that to ENOMEM.
                    Ok(DispatchOutcome::returned_u64(
                        self.mem().lock().program_break(),
                    )?)
                } else {
                    Ok(DispatchOutcome::errno(errno))
                }
            }));
        }
        Some(resources::with_captured_resources(ctx.kernel, || {
            handler(self, &mut ctx)
        }))
    }

    /// A delegated MM's mapping syscall secures the root nodes its host
    /// commits may need before any backend work; `Some` is the answer when
    /// it cannot (ENOMEM, as at the map-count limit).
    fn secure_host_venue_metadata(
        &self,
        request: &SyscallRequest,
    ) -> Option<Result<carrick_abi::LinuxErrno, DispatchError>> {
        let number = request.number.raw();
        let brk = request.number == carrick_abi::syscall::nr::BRK;
        if !brk && !mm_mutation_may_mirror(number) {
            return None;
        }
        let view = self.mem_view();
        let need = if brk {
            mem::anonymous::HostMetadataNeed::Break(carrick_guest_mem::GuestVa(request.args.0[0]))
        } else if number == MUNMAP {
            let [address, length, ..] = request.args.0;
            // A malformed range fails the syscall's own validation first.
            mem::anonymous::HostMetadataNeed::Retire(view.munmap_edit_range(address, length)?)
        } else {
            mem::anonymous::HostMetadataNeed::Mapping
        };
        view.secure_host_venue_metadata(need).transpose()
    }

    /// Focused unit-test boundary for mutation handlers. Production callers
    /// receive their guard from an exact-MM stage-1 pause; tests use the
    /// real page-table-pause issuer rather than falling back to the ordinary
    /// route (which intentionally cannot resolve mutation syscalls).
    #[cfg(test)]
    pub(crate) fn dispatch_normalized_mutation_for_test(
        &self,
        kernel: &crate::kernel::KernelContext,
        request: SyscallRequest,
        memory: &mut impl CurrentMmMemory,
        reporter: &CompatReporter,
        thread: Option<ThreadCtx>,
    ) -> Option<Result<DispatchOutcome, DispatchError>> {
        mm_mutation::test_support::with_guard(self.mm_mutation_coordinator(), |guard| {
            self.dispatch_normalized_mutation(MutationSyscallCtx {
                kernel,
                request,
                memory,
                reporter,
                thread,
                mm_mutation: guard,
                execution_lease: None,
            })
        })
    }

    /// Membership test: is `number` claimed by some dispatch module? Mirrors
    /// `dispatch_normalized` exactly (both go through `resolve_handler`), so the
    /// two can never drift. Uses `LinearMemory` as the concrete memory type —
    /// the claimed set is independent of `M`.
    pub(crate) fn dispatch_normalized_known(number: u64) -> bool {
        static KNOWN_SYSCALL_BITMAP: std::sync::LazyLock<[u64; 8]> =
            std::sync::LazyLock::new(|| {
                let mut bitmap = [0u64; 8];
                for nr in 0..512 {
                    if resolve_handler::<LinearMemory>(nr).is_some()
                        || resolve_mutation_handler::<LinearMemory>(nr).is_some()
                    {
                        bitmap[(nr / 64) as usize] |= 1 << (nr % 64);
                    }
                }
                bitmap
            });

        if number < 512 {
            (KNOWN_SYSCALL_BITMAP[(number / 64) as usize] & (1 << (number % 64))) != 0
        } else {
            resolve_handler::<LinearMemory>(number).is_some()
                || resolve_mutation_handler::<LinearMemory>(number).is_some()
        }
    }

    /// Characterization seam for the per-module routing refactor (Task A1).
    ///
    /// Returns whether the (chained) normalized routing claims `number` — i.e.
    /// whether some dispatch module owns a handler for it. This is the single
    /// membership oracle the `routing_tests` characterization test pins against,
    /// so the refactor that moves arms out of the central table and into each
    /// module's `dispatch_<area>` cannot silently drop or re-route a number.
    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) fn resolves(&self, number: u64) -> bool {
        Self::dispatch_normalized_known(number)
    }
}

#[cfg(test)]
mod routing_tests {
    //! Characterization test for the per-module syscall routing refactor
    //! (Task A1). `ROUTED_NUMBERS` is the COMPLETE set of syscall numbers the
    //! dispatcher routed at the start of the refactor — every arm of the
    //! original central `normalized_dispatch!` table, with multi-number arms
    //! expanded and the carrick-private x86 numbers included by their constant
    //! values. The refactor moves these arms out of the central table and into
    //! each dispatch module's own `dispatch_<area>` routing fn; chaining those
    //! fns must keep routing IDENTICAL. `resolves(n)` must hold for every
    //! number here at every step, and a known-unrouted number must NOT resolve.
    use std::sync::Arc;

    use super::*;
    use crate::dispatch::*;
    use crate::linux_abi::{
        CARRICK_PRIVATE_X86_ALARM, CARRICK_PRIVATE_X86_DUP2, CARRICK_PRIVATE_X86_FSTAT,
        CARRICK_PRIVATE_X86_LSTAT, CARRICK_PRIVATE_X86_NEWFSTATAT, CARRICK_PRIVATE_X86_POLL,
        CARRICK_PRIVATE_X86_SELECT, CARRICK_PRIVATE_X86_STAT, CARRICK_PRIVATE_X86_TIME,
    };

    /// Every syscall number routed by the dispatcher, enumerated from the full
    /// original routing table (multi-number arms expanded). If the refactor
    /// drops or re-routes any number, the membership assertion below fails.
    const ROUTED_NUMBERS: &[u64] = &[
        // --- fs ---
        17,
        23,
        24,
        CARRICK_PRIVATE_X86_DUP2,
        CARRICK_PRIVATE_X86_STAT,
        CARRICK_PRIVATE_X86_FSTAT,
        CARRICK_PRIVATE_X86_LSTAT,
        CARRICK_PRIVATE_X86_NEWFSTATAT,
        25,
        26,
        27,
        28,
        29,
        32,
        33,
        46,
        47,
        48,
        34,
        35,
        36,
        37,
        38,
        49,
        50,
        52,
        53,
        452,
        54,
        55,
        56,
        57,
        59,
        61,
        62,
        63,
        64,
        65,
        66,
        67,
        68,
        69,
        70,
        71,
        76,
        78,
        79,
        80,
        81,
        82,
        83,
        88,
        267,
        84,
        451,
        276,
        279,
        285,
        286,
        287,
        291,
        436,
        437,
        439,
        5,
        6,
        7,
        8,
        9,
        10,
        11,
        12,
        13,
        14,
        15,
        16,
        43,
        44,
        45,
        75,
        77,
        // --- net ---
        19,
        20,
        21,
        22,
        CARRICK_PRIVATE_X86_POLL,
        CARRICK_PRIVATE_X86_SELECT,
        72,
        73,
        198,
        199,
        200,
        201,
        202,
        203,
        204,
        205,
        206,
        207,
        208,
        209,
        210,
        211,
        212,
        242,
        243,
        269,
        // --- mem ---
        214,
        215,
        216,
        222,
        223,
        226,
        227,
        228,
        229,
        230,
        231,
        232,
        233,
        425,
        426,
        427,
        283,
        // --- proc ---
        30,
        31,
        58,
        92,
        95,
        96,
        97,
        98,
        99,
        100,
        117,
        118,
        119,
        120,
        121,
        122,
        123,
        124,
        125,
        126,
        127,
        142,
        154,
        155,
        156,
        157,
        160,
        161,
        162,
        167,
        168,
        220,
        221,
        281,
        260,
        277,
        275,
        278,
        424,
        434,
        93,
        94,
        178,
        435,
        293,
        // --- signal ---
        74,
        129,
        130,
        131,
        132,
        133,
        134,
        135,
        136,
        137,
        138,
        139,
        240,
        // --- time ---
        85,
        86,
        87,
        101,
        102,
        103,
        107,
        108,
        109,
        110,
        111,
        112,
        113,
        114,
        115,
        CARRICK_PRIVATE_X86_ALARM,
        CARRICK_PRIVATE_X86_TIME,
        153,
        163,
        165,
        169,
        170,
        171,
        179,
        261,
        266,
        // --- creds ---
        90,
        91,
        140,
        141,
        143,
        144,
        145,
        146,
        147,
        148,
        149,
        150,
        158,
        166,
        151,
        152,
        159,
        172,
        173,
        174,
        175,
        176,
        177,
        // --- sysv ---
        186,
        187,
        188,
        189,
        190,
        191,
        192,
        193,
        194,
        195,
        196,
        197,
    ];

    #[test]
    fn dispatcher_activates_one_authenticated_file_authority_root() {
        let dispatcher = SyscallDispatcher::new();
        let root_table = dispatcher.captured_file_table();
        assert_eq!(dispatcher.file_authority_binding(), None);
        let binding = dispatcher
            .activate_file_authority(Arc::clone(&root_table))
            .expect("activate FileAuthority");
        assert_eq!(binding.epoch.raw(), 1);
        assert_eq!(binding.client.id.raw(), 1);
        assert_eq!(
            binding.generation,
            crate::file_authority::ObjectGeneration::INITIAL
        );
        assert_eq!(
            dispatcher
                .activate_file_authority(Arc::clone(&root_table))
                .expect("idempotent FileAuthority activation"),
            binding
        );
        assert_eq!(dispatcher.file_authority_binding(), Some(binding));

        // Different Arc with same table ID is fatal
        let foreign_table_same_id = Arc::new(crate::kernel::FileTable::new(root_table.id()));
        let res = dispatcher.activate_file_authority(foreign_table_same_id);
        assert!(matches!(
            res,
            Err(crate::file_authority::AuthorityFatal::InvariantViolation(_))
        ));

        // Different Arc with different table ID is fatal
        let ids = crate::kernel::ObjectIdRegistry::new();
        let foreign_table = Arc::new(crate::kernel::FileTable::new(
            ids.file_table_id().expect("table id"),
        ));
        let res = dispatcher.activate_file_authority(foreign_table);
        assert!(matches!(
            res,
            Err(crate::file_authority::AuthorityFatal::InvariantViolation(_))
        ));

        // Dropping all external strong Arcs allows the root table to be dropped
        let weak = Arc::downgrade(&root_table);
        drop(root_table);
        // Note: dispatcher's one_task kernel context also holds a strong reference in its initial state,
        // so if we drop the dispatcher context or check the weak reference when only dispatcher holds it:
        assert_eq!(weak.strong_count(), 1); // Only the dispatcher's captured one-task kernel context
    }

    #[test]
    fn authority_call_operates_on_successor_table_without_launch_root_comparison() {
        let dispatcher = SyscallDispatcher::new();
        let root_table = dispatcher.captured_file_table();
        dispatcher
            .activate_file_authority(Arc::clone(&root_table))
            .expect("activate FileAuthority");

        let ids = crate::kernel::ObjectIdRegistry::new();
        let successor_table = Arc::new(crate::kernel::FileTable::new(
            ids.file_table_id().expect("table id"),
        ));
        let number = crate::kernel::FileSlotNumber::for_open_fd(3).expect("fd");
        let fixture = crate::dispatch::fd_table::InMemoryPipeTestFixture::new(10, 65536);
        successor_table.install(number, fixture.read, false);
        let slot = successor_table
            .capture_slot_authority(number)
            .expect("slot token");

        let command = crate::file_authority::Command::SetCanonicalPipeCapacity {
            slot,
            capacity: crate::file_authority::PipeCapacity::bounded(65536).expect("capacity"),
            accounting: crate::kernel::objects::PipeCapacityAccounting::InMemory,
        };

        let outcome = dispatcher
            .authority_call(successor_table, slot, command)
            .expect("authority call on successor table");
        assert!(matches!(
            outcome,
            crate::file_authority::Outcome::CanonicalPipeCapacitySet { .. }
        ));
    }

    #[test]
    fn authority_call_rejects_table_id_mismatch_as_fatal() {
        let dispatcher = SyscallDispatcher::new();
        let root_table = dispatcher.captured_file_table();
        dispatcher
            .activate_file_authority(Arc::clone(&root_table))
            .expect("activate FileAuthority");

        let ids = crate::kernel::ObjectIdRegistry::new();
        let table_a = Arc::new(crate::kernel::FileTable::new(
            ids.file_table_id().expect("table a id"),
        ));
        let table_b = Arc::new(crate::kernel::FileTable::new(
            ids.file_table_id().expect("table b id"),
        ));
        let number = crate::kernel::FileSlotNumber::for_open_fd(3).expect("fd");
        let fixture = crate::dispatch::fd_table::InMemoryPipeTestFixture::new(10, 65536);
        table_a.install(number, fixture.read, false);
        let slot_a = table_a
            .capture_slot_authority(number)
            .expect("slot a token");

        let command = crate::file_authority::Command::SetCanonicalPipeCapacity {
            slot: slot_a,
            capacity: crate::file_authority::PipeCapacity::bounded(65536).expect("capacity"),
            accounting: crate::kernel::objects::PipeCapacityAccounting::InMemory,
        };

        // Passing table_b with slot_a (which belongs to table_a) is fatal
        let err = dispatcher
            .authority_call(table_b, slot_a, command)
            .expect_err("mismatched table and slot token");
        assert!(matches!(
            err,
            AuthorityCallError::Fatal(crate::file_authority::AuthorityFatal::InvariantViolation(_))
        ));
    }

    #[test]
    fn dispatch_error_file_authority_fatal_lowers_to_run_fatal() {
        let fatal_err = DispatchError::FileAuthorityFatal(
            crate::file_authority::AuthorityFatal::InvariantViolation("injected test fatal"),
        );
        let lowered = lower_handler_result(Err(fatal_err));
        assert!(matches!(
            lowered,
            Err(DispatchError::FileAuthorityFatal(
                crate::file_authority::AuthorityFatal::InvariantViolation(_)
            ))
        ));
    }

    #[test]
    fn every_routed_number_resolves() {
        // `resolves` is independent of dispatcher instance state, but matches the
        // brief's `&self` signature so a future per-instance routing could hook in.
        let d = SyscallDispatcher::new();
        for &n in ROUTED_NUMBERS {
            assert!(
                d.resolves(n),
                "syscall number {n} (0x{n:x}) lost its handler — routing changed!"
            );
        }
        // The full set is large; guard against accidental list truncation. This
        // is the count of INDIVIDUAL numbers (multi-number arms like `5 | 6`
        // expanded), which exceeds the original table's 235 arms.
        assert_eq!(
            ROUTED_NUMBERS.len(),
            243,
            "ROUTED_NUMBERS lost entries — the characterization set must stay complete"
        );
    }

    #[test]
    fn unrouted_number_does_not_resolve() {
        let d = SyscallDispatcher::new();
        // 9999 is not a Linux syscall and is not claimed by any module.
        assert!(!d.resolves(9999), "an unclaimed number must not resolve");
        // u64::MAX (no carrick-private constant uses it) is also unclaimed.
        assert!(!d.resolves(u64::MAX), "u64::MAX must not resolve");
    }
}
