//! # The HVF trap boundary
//!
//! This is the seam where a Linux guest's `svc #0` becomes a host Rust syscall
//! dispatch. carrick runs unmodified Linux ELF code as guest EL0 inside a single
//! Hypervisor.framework VM, with NO Linux kernel underneath it — when the guest
//! issues a syscall, control must cross all the way out to host userspace, get
//! serviced against Darwin primitives, and resume the guest as if a kernel had
//! handled it. This module owns that crossing in both directions.
//!
//! ## Theory of operation: the round trip of one syscall
//!
//! 1. **Guest `svc #0` (EL0).** The guest executes a normal AArch64 supervisor
//!    call. With `SCTLR_EL1.M=1` and our stage-1 identity tables installed, this
//!    is a synchronous exception from the lowest EL.
//! 2. **EL1 vector table (`VBAR_EL1`).** HVF does NOT exit to the host on a bare
//!    EL0 `svc`; it routes the exception to EL1, which is *still inside the VM*.
//!    `map_plan` programs `VBAR_EL1` to a guest-physical vector page (built by
//!    `crate::memory`) whose lower-EL-synchronous entry is a tiny trampoline. The
//!    trampoline runs at EL1 — this is carrick code executing in the guest, never
//!    the guest's own code.
//! 3. **`hvc #2` → EL2 VM-exit.** The vector trampoline issues a hypervisor call.
//!    THAT is what HVF surfaces to the host as an `EXCEPTION` exit from
//!    `hv_vcpu_run`. (Plain EL0 memory aborts HVF cannot satisfy — a stack
//!    overflow running SP off the mapped stack — surface directly as an
//!    `EXCEPTION` exit with `EC=0x20/0x24` instead; see
//!    [`is_aarch64_el0_abort_exception`].) The reason we trampoline through EL1
//!    rather than letting HVF trap the `svc` directly is that the EL1 stage
//!    gives us a place to do stage-1 TLB maintenance (`hvc #1`, see
//!    `HvfInner::run_el1_maintenance`) on a platform whose public HVF has no
//!    stage-2 TLBI.
//! 4. **Host decode.** `HvfInner::run_until_syscall` reads the exit info,
//!    confirms `EC=0x16` (our HVC) *and* that the underlying `ESR_EL1` is an
//!    `svc` (anything else — an ID-register read, a real fault — is handled or
//!    surfaced as [`TrapError::EL0Fault`]), then reads x0..x5/x8 into an
//!    [`Aarch64SyscallFrame`] and returns it to the runtime dispatcher.
//! 5. **Host dispatch + resume.** The dispatcher services the syscall against
//!    Darwin and calls `HvfInner::complete_syscall`, which writes the retval
//!    into x0. The next `hv_vcpu_run` resumes the trampoline's `eret`, dropping
//!    back to EL0 at the instruction after the `svc` (HVF latched that address in
//!    `ELR_EL1` when it took the exception).
//!
//! ## The load-bearing EL0/EL1 invariant
//!
//! The single most important distinction in this module is *whose code is the
//! vCPU running*. EL0 is genuine Linux guest userspace; EL1+ is always carrick's
//! trap trampoline. A PC (or register snapshot) captured at EL1 is a *carrick*
//! address and must NEVER be treated as a guest resume target — injecting a
//! signal frame at an EL1 PC overwrites an in-flight syscall and wedges the
//! thread. [`ExecLevel::from_pstate`] is the systematic classifier; every site
//! that captures a live vCPU PC for guest use must consult it. The kick path in
//! `HvfInner::run_until_syscall` is the sharp example: a cross-thread
//! `hv_vcpus_exit` can land while the vCPU is mid-trampoline at EL1, so it resumes
//! the vCPU to a clean EL0 boundary before reporting the kick (this fixed a real
//! SIGURG storm corrupting a futex waiter at `vectors_base+0x404`).
//!
//! ## The [`SyscallTrap`] contract
//!
//! The runtime loop drives the engine through one trait, [`SyscallTrap`]:
//! `next_syscall` (run until a trap; `Ok(None)` is a no-syscall kick exit),
//! `complete_syscall` (write the retval), `fork` / `execve_into` (address-space
//! lifecycle), and the signal pair `inject_signal` / `restore_from_sigframe`.
//! [`HvfTrapEngine`] is the real implementation; the runtime also has a
//! non-HVF `SplitView` adapter, which is why every method has a portable
//! default and a `#[cfg(not(macos+aarch64))]` stub returning
//! [`TrapError::UnsupportedPlatform`]. Errors are typed: most variants carry the
//! syndrome/ELR/FAR so the runtime can translate a guest fault into the right
//! Linux signal, and [`TrapError::SignalDeliveryFault`] specifically models
//! Linux's `force_sigsegv` (an unwritable signal stack kills the thread-group by
//! SIGSEGV rather than fatalling carrick).
//!
//! ## Address-space lifecycle: fork, clone, execve
//!
//! There is no guest kernel to copy a page table, so process/thread creation is
//! done by *rebuilding HVF state around the host's own fork/threads*:
//!
//! - **`fork(2)`** (`HvfInner::fork`) is a real `libc::fork`. macOS HVF state is
//!   not fork-safe, so the parent tears down its vCPU+VM via the *raw* API
//!   BEFORE forking (a live VM at fork time leaves the child unable to
//!   `hv_vm_create`); both sides then rebuild a fresh VM and re-`hv_vm_map` the
//!   same host buffers. The legacy VMM path gets private-buffer isolation from
//!   host `MAP_PRIVATE` fork COW and clones only the child's independently
//!   editable stage-1 table backing. HVPatch instead shares stable global
//!   frames read-only across distinct per-mm stage-1 graphs and copies only the
//!   first writer's affected compound frame. Genuine guest `MAP_SHARED`
//!   mappings remain shared on either path.
//! - **Thread clone** (`HvfInner::build_thread_spec` / `from_thread_spec`)
//!   keeps ONE process VM and gives each guest thread its own vCPU in it. The
//!   stage-2 mappings are VM-global, so a sibling only re-materialises local
//!   syscall-path metadata (UNOWNED, `memory: None`) and never frees the main
//!   engine's buffers. Because HVF caps concurrent vCPUs, sibling creation
//!   passes through an admission gate (`wait_for_vcpu_slot`); see the
//!   private `vcpu_gate` module for why a guest that out-threads the cap *blocks*
//!   rather than failing `clone` (Linux has no such cap, so failing would
//!   deadlock a join). A *multithreaded* fork additionally quiesces siblings,
//!   destroys their vCPUs so the forker can `hv_vm_destroy`, then republishes the
//!   rebuilt VM for them to recreate vCPUs in (`release_vcpu_for_fork` /
//!   `publish_vm_for_siblings` / `rebuild_vcpu_after_fork`).
//! - **`execve(2)`** (`HvfInner::execve_into`) tears down and rebuilds the VM
//!   like fork, but installs a brand-new [`AddressSpace`] and resets the vCPU to
//!   "initial process startup" (zeroed GPRs, entry trampoline) rather than
//!   "resume mid-syscall". It has no successful return.
//!
//! All three paths bypass `applevisor`'s `Drop`: once a single `fork(2)` has run,
//! applevisor's internal handle bookkeeping no longer matches HVF, and its
//! destructors panic ("no VM or vCPU available"). `HvfInner` is held in a
//! [`std::mem::ManuallyDrop`] and the host pages leak until process exit — which
//! is fine, the process is exiting anyway, and the kernel reclaims the VM.
//!
//! ## Signals: synthesising kernel signal delivery in userspace
//!
//! `HvfInner::inject_signal` builds a Linux-shaped `CarrickSigframe` (siginfo +
//! ucontext + a full GPR/PC/SP/PSTATE/FPSIMD snapshot), pushes it onto SP_EL0
//! (or the SA_ONSTACK alt stack), points x30 at the restorer, sets x0..x2 to the
//! handler arguments, and redirects the resumed PC to the handler. On
//! `rt_sigreturn(2)`, `HvfInner::restore_from_sigframe` pops the frame and
//! restores the pre-signal state. Two non-obvious subtleties:
//!
//! - The authoritative pre-signal PSTATE source DIFFERS by injection path. At a
//!   syscall boundary the hardware latched EL0's PSTATE into `SPSR_EL1`; on a
//!   kick exit no exception was taken, so `SPSR_EL1` is stale and `CPSR` holds
//!   the live EL0 state. Reading the wrong one resumes the interrupted routine
//!   with stale NZCV — conditional branches go the wrong way — which was exactly
//!   Go's async-preemption (SIGURG) corruption.
//! - V0–V31 / FPSR / FPCR must round-trip across both signals *and* fork/clone,
//!   or a handler (or post-fork resume) that touches SIMD corrupts the
//!   interrupted thread's vector file. This collides with an `applevisor-sys`
//!   ABI bug: see `set_simd_fp_reg_v` — Apple's `hv_vcpu_set_simd_fp_reg` takes
//!   a 16-byte vector BY VALUE in a V register, but the stable binding mistypes
//!   it as `u128` (passed in a GP register pair), so the kernel reads garbage and
//!   silently zeroes the target register while returning `HV_SUCCESS`. We route
//!   every V-register *write* through a tiny C shim that gets the vector ABI
//!   right on stable Rust; reads are pointer-based and unaffected.
//!
//! ## Guest memory access from the syscall path
//!
//! The dispatcher reads/writes guest buffers through this engine's
//! [`GuestMemory`] impl. Because guest RAM is `MAP_SHARED` and another host
//! thread's vCPU can mutate it concurrently, host-side copies go byte-wise
//! `read_volatile`/`write_volatile` (`volatile_copy_from_guest`) to remove
//! language-level UB (it does NOT make the data race "correct" — the guest owns
//! its own synchronization). Writes from the syscall path are permission-checked
//! (a write into a read-only / carrick-owned mapping returns EFAULT, not a host
//! SIGBUS); carrick-internal writes (vdso, sigframe, bootstrap) use the unchecked
//! path deliberately. High-VA Rosetta aliases can overlap by VA, so region
//! lookup disambiguates by walking the guest's own stage-1 tables to the IPA the
//! guest actually uses (`HvfInner::translate_va`).
//!
//! ## Sharp edges / known limitations
//!
//! - **No stage-2 TLBI on public arm64 HVF.** Guest-visible `mprotect`/`munmap`
//!   semantics are implemented entirely in stage-1 (page-table edits + an EL1
//!   `tlbi` trampoline); the stage-2 mapping is left in place. This is why
//!   munmap'd arena backing is still physically mapped (only stage-1-invalidated)
//!   and why `HvfInner::zero_guest_backing` can scrub a reclaimed region the
//!   permission-checked writes would refuse.
//! - **Stage-2 perm escalation.** `hvf_perms` escalates writable data regions
//!   to `ReadWriteExec` to work around an HVF stage-2 quirk where RW-without-X
//!   mappings fail to translate EL0 data accesses. Guest-visible W^X is enforced
//!   in stage-1 instead.
//! - **Drop is intentionally a no-op.** See above; touching applevisor
//!   destructors post-fork panics.
//! - **`ptr::write`-based in-place replacement.** Rebuilding the engine
//!   (`replace_destroyed_hvf_inner`) and the post-fork/clone VM swaps use
//!   `mem::forget`/`ptr::write` to avoid running Drop on already-raw-destroyed
//!   handles. These are the single sanctioned no-drop replacement points; do not
//!   assign an `HvfInner`/vCPU/VM field normally after a raw teardown.

// The hub types live in the leaf crate carrick-guest-mem (A2); import them from
// there, not via `crate::dispatch`, so trap.rs has NO dependency on the
// dispatcher — the last edge blocking a future carrick-vmm-hvf crate (A3).
use crate::elf::SegmentPerms;
use crate::memory::AddressSpace;
use crate::syscall_mailbox::{
    HvfSyscallTransport, MailboxBinding, MailboxSlotAllocator, MailboxSlotId,
};
use carrick_aarch64::Aarch64VcpuSnapshot;
use carrick_guest_mem::MemoryError;
use serde::Serialize;
use std::collections::HashMap;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};

mod sysreg;
use sysreg::*;
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
mod vcpu_gate;
// The vvar clock calibration sources (a frequency-only EL0 read plus the
// CLOCK_UPTIME_RAW monotonic base). The raw counter pair remains exported for
// explicit divergence diagnostics, not production calibration. The
// Darwin-native backend's vvar stamper uses the identical frequency/uptime
// sources as `populate_vdso_data_page` below.
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
pub use sysreg::{host_clock_uptime_ns, host_counter, host_counter_frequency};

// Process-wide PROT_NONE bookkeeping is a neutral-core abstraction shared with
// every other backend (KVM included) — see carrick_mem::protections. Both hold
// it as `Arc<MemoryProtections>` and clone it into each sibling vCPU thread.
use carrick_mem::protections::MemoryProtections;

// SyscallTrap/TrapError/ForkOutcome moved down into the carrick-hal leaf crate
// (the runtime↔engine contract is platform-agnostic). Re-export them here so
// existing `crate::trap::…` paths in carrick-vmm-hvf and carrick-runtime are
// unchanged. HvfTrapEngine below implements the trait from its new home.
use carrick_hal::aarch64::ExecLevel;
// The ESR exception-class decode surface (classifier fns + the SVC/HVC class
// consts) hoisted into carrick_hal::aarch64 must stay PUB-re-exported here:
// `carrick_runtime::trap` is this module on macOS, and external consumers (the
// trap_hvf integration test) import the classifiers through that path. A plain
// `use` made them private and broke `cargo test -p carrick-runtime`
// (E0603/E0432 in tests/trap_hvf.rs).
pub use carrick_hal::aarch64::{
    AARCH64_HVC_EXCEPTION_CLASS, AARCH64_SVC_EXCEPTION_CLASS, aarch64_exception_class,
    is_aarch64_hvc_exception, is_aarch64_hvc_fault, is_aarch64_hvc_maintenance,
    is_aarch64_svc_exception, is_aarch64_syscall_exception,
};
pub use carrick_hal::trap::{ForkOutcome, RawSyscall, SyscallTrap, TrapError};

pub const HVF_PAGE_SIZE: u64 = 0x4000;
// Guest stage-1 uses a 4 KiB granule even though HVF maps stage-2 in 16 KiB
// chunks. Syscall memory copies must reselect the backing at this boundary.
const GUEST_STAGE1_PAGE_SIZE: u64 = 0x1000;
// ESR exception-class decode (svc/hvc/maintenance/syscall classifiers, the
// SVC/HVC class consts, and ExecLevel) live in the shared carrick_hal::aarch64
// module — imported above. This SHIFT is kept local only for the counter-trap
// TESTS that synthesize an ESR syndrome (cntfrq/cntvct/dczid), so it is test-only.
#[cfg(test)]
const AARCH64_EXCEPTION_CLASS_SHIFT: u64 = 26;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TrapBackend {
    HypervisorFramework,
}

#[cfg(test)]
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
mod task_only_carrier_directory_tests {
    use super::*;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    pub(super) struct TestCowAuthority;

    impl carrick_hal::FrameCowAuthority for TestCowAuthority {
        fn quiesce(
            &self,
        ) -> Result<Box<dyn carrick_hal::FrameCowQuiesce>, Box<dyn std::error::Error + Send + Sync>>
        {
            Ok(Box::new(()))
        }

        fn reserve(
            &self,
            _frame_candidates: usize,
            _mapping_candidates: usize,
            _event_count: usize,
        ) -> Result<carrick_hal::FrameInventoryReservation, Box<dyn std::error::Error + Send + Sync>>
        {
            Err(Box::new(std::io::Error::other("unused test reserve")))
        }

        fn apply(
            &self,
            _commit: carrick_hal::FrameInventoryCommit<()>,
        ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
            Err(Box::new(std::io::Error::other("unused test apply")))
        }

        fn mapping_is_live(
            &self,
            _mapping: carrick_hal::MappingId,
            _frame: carrick_hal::FrameId,
            _gpa: carrick_guest_mem::Gpa,
            _length: carrick_hal::FrameLength,
        ) -> Result<bool, Box<dyn std::error::Error + Send + Sync>> {
            Ok(false)
        }

        fn frame_mapping_count(
            &self,
            _frame: carrick_hal::FrameId,
        ) -> Result<Option<usize>, Box<dyn std::error::Error + Send + Sync>> {
            Ok(None)
        }
    }

    fn identity(generation: u64) -> HvpatchCarrierTaskIdentity {
        HvpatchCarrierTaskIdentity {
            task_serial: 41,
            thread_serial: 73,
            execution_generation: generation,
            linux_pid: 41,
            linux_tid: 73,
            asid: 9,
        }
    }

    fn test_state(rollbacks: &Arc<AtomicUsize>) -> HvpatchCarrierTaskState {
        HvpatchCarrierTaskState::Test {
            rollbacks: Arc::clone(rollbacks),
            order: None,
        }
    }

    fn owner_key(
        directory: &HvpatchCarrierTaskStateDirectory,
        generation: u64,
        nonce: u64,
    ) -> HvpatchCarrierTaskStateKey {
        HvpatchCarrierTaskStateKey {
            directory_instance: directory.instance,
            task_serial: 41,
            thread_serial: 73,
            execution_generation: generation,
            nonce: std::num::NonZeroU64::new(nonce).unwrap(),
        }
    }

    #[test]
    fn carrier_keys_are_exact_nonreused_and_terminal_retirement_rolls_back() {
        let directory = Arc::new(HvpatchCarrierTaskStateDirectory::default());
        let rollbacks = Arc::new(AtomicUsize::new(0));
        let first = directory
            .publish(
                identity(1),
                test_state(&rollbacks),
                HvpatchPreparedTaskAuthority::default(),
            )
            .unwrap();
        assert!(
            directory
                .publish(
                    identity(1),
                    test_state(&rollbacks),
                    HvpatchPreparedTaskAuthority::default(),
                )
                .is_err()
        );
        assert_eq!(rollbacks.load(Ordering::SeqCst), 1);
        let first_key = first.registration.as_ref().unwrap().key;
        drop(first);
        assert_eq!(rollbacks.load(Ordering::SeqCst), 2);
        let successor = directory
            .publish(
                identity(2),
                test_state(&rollbacks),
                HvpatchPreparedTaskAuthority::default(),
            )
            .unwrap();
        assert_ne!(first_key, successor.registration.as_ref().unwrap().key);
        drop(successor);
        assert_eq!(rollbacks.load(Ordering::SeqCst), 3);
    }

    #[test]
    fn injected_alias_and_directory_failures_rollback_before_visibility() {
        for failpoint in [1, 2] {
            let directory = Arc::new(HvpatchCarrierTaskStateDirectory::default());
            let rollbacks = Arc::new(AtomicUsize::new(0));
            let preimage = alias(0x3333_0000 + usize::from(failpoint), 1);
            let replacement = alias(0x4444_0000 + usize::from(failpoint), 3);
            register_shared_alias(preimage);
            assert!(
                directory
                    .publish_inner(
                        identity(u64::from(failpoint)),
                        test_state(&rollbacks),
                        HvpatchPreparedTaskAuthority {
                            pending_aliases: vec![replacement],
                            ..HvpatchPreparedTaskAuthority::default()
                        },
                        failpoint
                    )
                    .is_err()
            );
            assert_eq!(rollbacks.load(Ordering::SeqCst), 1);
            assert!(directory.inner.lock().states.is_empty());
            assert!(alias_registry().lock().contains(&preimage));
            assert!(!alias_registry().lock().contains(&replacement));
            assert!(
                replay_mappings()
                    .lock()
                    .contains(&replay_mapping_key(preimage))
            );
            alias_registry().lock().retain(|entry| {
                !(entry.ipa == preimage.ipa && entry.ownership_scope == preimage.ownership_scope)
            });
            replay_mappings()
                .lock()
                .retain(|(ipa, _, _, _)| *ipa != preimage.physical_ipa);
        }
    }

    fn alias(host: usize, perms: u64) -> AliasBacking {
        AliasBacking {
            start: 0x7fff_1000_0000,
            ipa: 0x6fff_1000_0000,
            host_addr: host,
            size: 0x1000,
            physical_ipa: 0x5fff_1000_0000,
            physical_host_addr: host,
            physical_size: 0x4000,
            perms,
            guest_writable: perms & 2 != 0,
            sharing: GuestMappingSharing::Private,
            ownership_scope: AliasOwnershipScope::MmRootSlot {
                base: 0x4fff_1000_0000,
                size: 0x4000,
            },
            inventory_backing: InventoryBackingIdentity::Private(0x41),
            shared_key_base: 0,
            shared_key_offset: 0,
            owner_generation: 7,
        }
    }

    #[test]
    fn alias_receipt_restores_exact_registry_and_replay_preimages() {
        let preimage = alias(0x1111_0000, 1);
        let replacement = alias(0x2222_0000, 3);
        register_shared_alias(preimage);

        let directory = HvpatchCarrierTaskStateDirectory::default();
        let receipt =
            AliasPublicationReceipt::commit(owner_key(&directory, 1, 1), &[replacement]).unwrap();
        assert!(alias_registry().lock().contains(&replacement));
        assert!(
            replay_mappings()
                .lock()
                .contains(&replay_mapping_key(replacement))
        );

        receipt.retire_exact();
        assert!(alias_registry().lock().contains(&preimage));
        assert!(!alias_registry().lock().contains(&replacement));
        assert!(
            replay_mappings()
                .lock()
                .contains(&replay_mapping_key(preimage))
        );
        assert!(
            !replay_mappings()
                .lock()
                .contains(&replay_mapping_key(replacement))
        );

        alias_registry().lock().retain(|entry| {
            !(entry.ipa == preimage.ipa && entry.ownership_scope == preimage.ownership_scope)
        });
        replay_mappings()
            .lock()
            .retain(|(ipa, _, _, _)| *ipa != preimage.physical_ipa);
    }

    #[test]
    fn alias_retirement_never_restores_over_a_later_writer() {
        let preimage = alias(0x5555_0000, 1);
        let owned = alias(0x6666_0000, 3);
        let later = alias(0x7777_0000, 5);
        register_shared_alias(preimage);
        let directory = HvpatchCarrierTaskStateDirectory::default();
        let receipt =
            AliasPublicationReceipt::commit(owner_key(&directory, 2, 1), &[owned]).unwrap();
        register_shared_alias(later);
        receipt.retire_exact();
        assert!(alias_registry().lock().contains(&later));
        assert!(!alias_registry().lock().contains(&preimage));
        alias_registry().lock().retain(|entry| {
            !(entry.ipa == later.ipa && entry.ownership_scope == later.ownership_scope)
        });
        replay_mappings()
            .lock()
            .retain(|(ipa, _, _, _)| *ipa != later.physical_ipa);
    }

    #[test]
    fn buried_alias_owner_retires_without_clobbering_successor() {
        let preimage = alias(0x8888_0000, 1);
        let first_value = alias(0x9999_0000, 3);
        let second_value = alias(0xaaaa_0000, 5);
        register_shared_alias(preimage);
        let directory = HvpatchCarrierTaskStateDirectory::default();
        let first =
            AliasPublicationReceipt::commit(owner_key(&directory, 3, 1), &[first_value]).unwrap();
        let second =
            AliasPublicationReceipt::commit(owner_key(&directory, 4, 2), &[second_value]).unwrap();
        first.retire_exact();
        assert!(alias_registry().lock().contains(&second_value));
        second.retire_exact();
        assert!(alias_registry().lock().contains(&preimage));
        assert!(!alias_registry().lock().contains(&first_value));
        alias_registry().lock().retain(|entry| {
            !(entry.ipa == preimage.ipa && entry.ownership_scope == preimage.ownership_scope)
        });
        replay_mappings()
            .lock()
            .retain(|(ipa, _, _, _)| *ipa != preimage.physical_ipa);
    }

    #[test]
    fn external_writer_between_owned_versions_becomes_effective_base() {
        let preimage = alias(0xbbbb_0000, 1);
        let first_value = alias(0xcccc_0000, 3);
        let external = alias(0xdddd_0000, 5);
        let second_value = alias(0xeeee_0000, 7);
        register_shared_alias(preimage);
        let directory = HvpatchCarrierTaskStateDirectory::default();
        let first =
            AliasPublicationReceipt::commit(owner_key(&directory, 5, 1), &[first_value]).unwrap();
        register_shared_alias(external);
        let second =
            AliasPublicationReceipt::commit(owner_key(&directory, 6, 2), &[second_value]).unwrap();
        first.retire_exact();
        assert!(alias_registry().lock().contains(&second_value));
        second.retire_exact();
        assert!(alias_registry().lock().contains(&external));
        alias_registry().lock().retain(|entry| {
            !(entry.ipa == external.ipa && entry.ownership_scope == external.ownership_scope)
        });
        replay_mappings()
            .lock()
            .retain(|(ipa, _, _, _)| *ipa != external.physical_ipa);
    }

    #[test]
    fn repeated_alias_key_exhaustion_is_preflighted_without_partial_publication() {
        let preimage = alias(0xf111_0000, 1);
        let first_value = alias(0xf222_0000, 3);
        let second_value = alias(0xf333_0000, 5);
        register_shared_alias(preimage);
        {
            let mut versions = alias_version_registry().lock();
            let key = (preimage.ipa, preimage.ownership_scope);
            versions
                .alias_epochs
                .iter_mut()
                .find(|(candidate, _)| *candidate == key)
                .unwrap()
                .1 = u64::MAX - 1;
        }
        let directory = HvpatchCarrierTaskStateDirectory::default();
        assert!(
            AliasPublicationReceipt::commit(
                owner_key(&directory, 7, 1),
                &[first_value, second_value]
            )
            .is_err()
        );
        assert!(alias_registry().lock().contains(&preimage));
        assert!(!alias_registry().lock().contains(&first_value));
        {
            let mut versions = alias_version_registry().lock();
            let key = (preimage.ipa, preimage.ownership_scope);
            versions
                .alias_epochs
                .iter_mut()
                .find(|(candidate, _)| *candidate == key)
                .unwrap()
                .1 = 1;
        }
        alias_registry().lock().retain(|entry| {
            !(entry.ipa == preimage.ipa && entry.ownership_scope == preimage.ownership_scope)
        });
        replay_mappings()
            .lock()
            .retain(|(ipa, _, _, _)| *ipa != preimage.physical_ipa);
    }

    #[test]
    fn external_unregister_and_clear_invalidate_owned_versions() {
        let preimage = alias(0xf666_0000, 1);
        let owned = alias(0xf777_0000, 3);
        register_shared_alias(preimage);
        let directory = HvpatchCarrierTaskStateDirectory::default();
        let receipt =
            AliasPublicationReceipt::commit(owner_key(&directory, 8, 1), &[owned]).unwrap();
        let scope = match owned.ownership_scope {
            AliasOwnershipScope::MmRootSlot { base, size } => Some((base, size)),
            _ => None,
        };
        unregister_alias(owned.start, owned.size, scope);
        receipt.retire_exact();
        assert!(!alias_registry().lock().contains(&preimage));
        assert!(!alias_registry().lock().contains(&owned));

        register_shared_alias(preimage);
        let receipt =
            AliasPublicationReceipt::commit(owner_key(&directory, 9, 2), &[owned]).unwrap();
        clear_alias_registry();
        clear_replay_mappings();
        receipt.retire_exact();
        assert!(alias_registry().lock().is_empty());
        assert!(
            replay_mappings()
                .lock()
                .iter()
                .all(|(ipa, _, _, _)| *ipa != owned.physical_ipa)
        );
    }

    fn empty_inventory_commit(raw: u64) -> carrick_hal::FrameInventoryCommit<()> {
        let id = std::num::NonZeroU64::new(raw).unwrap();
        let capacity = carrick_hal::FrameEventCapacity::for_event_count(1).unwrap();
        carrick_hal::FrameInventoryReservation::from_kernel_candidates(
            carrick_hal::FrameInventoryProvenance::from_kernel_entropy([raw as u8; 32]),
            carrick_hal::FrameInventoryBatch::prepare(
                carrick_hal::KernelTransactionId::from_kernel_allocation(id),
                capacity,
            )
            .unwrap(),
            Vec::new(),
            Vec::new(),
        )
        .commit(())
    }

    fn retirement_inventory_commit(
        raw: u64,
        mappings: &[carrick_hal::MappingId],
    ) -> carrick_hal::FrameInventoryCommit<()> {
        let transaction = carrick_hal::KernelTransactionId::from_kernel_allocation(
            std::num::NonZeroU64::new(raw).unwrap(),
        );
        let capacity = carrick_hal::FrameEventCapacity::for_event_count(mappings.len()).unwrap();
        let mut reservation = carrick_hal::FrameInventoryReservation::from_kernel_candidates(
            carrick_hal::FrameInventoryProvenance::from_kernel_entropy([raw as u8; 32]),
            carrick_hal::FrameInventoryBatch::prepare(transaction, capacity).unwrap(),
            Vec::new(),
            Vec::new(),
        );
        for &mapping in mappings {
            reservation
                .push(carrick_hal::FrameInventoryEvent::UnmapMapping {
                    transaction,
                    mapping,
                    generation: carrick_hal::MappingGeneration::from_backend_counter(
                        std::num::NonZeroU64::new(2).unwrap(),
                    ),
                })
                .unwrap();
        }
        reservation.commit(())
    }

    fn test_kernel_apply(
        commit: carrick_hal::FrameInventoryCommit<()>,
        raw: u64,
        mm: std::num::NonZeroU64,
        revision: u64,
        mappings: Vec<(carrick_hal::MappingId, carrick_hal::FrameId)>,
    ) -> carrick_hal::FrameInventoryApplyReceipt {
        carrick_hal::FrameInventoryApplyReceipt::from_kernel_authority(
            carrick_hal::FrameInventoryProvenance::from_kernel_entropy([raw as u8; 32]),
            commit.batch().transaction(),
            mm,
            revision,
            mappings,
        )
    }

    #[test]
    fn inventory_phase_is_process_owned_and_exactly_ordered() {
        let ledger = Arc::new(parking_lot::Mutex::new(HvpatchFrameInventory::default()));
        let mut sibling = HvpatchTaskInventoryAuthority::SiblingShared {
            ledger: Arc::clone(&ledger),
        };
        let mm = std::num::NonZeroU64::new(501).unwrap();
        assert!(
            sibling
                .apply_process_inventory(|_| unreachable!(), mm)
                .is_err()
        );
        assert_eq!(sibling.phase_name(), "sibling_shared");

        let commit = empty_inventory_commit(91);
        let challenge = commit.receipt_challenge();
        let mut process = HvpatchTaskInventoryAuthority::ProcessPrepared {
            ledger: Arc::clone(&ledger),
            staged: Vec::new(),
            commit: Some(commit),
            challenge: Some(challenge),
        };
        let id = |raw| {
            std::num::NonZeroU64::new(raw)
                .map(carrick_hal::MappingId::from_kernel_allocation)
                .unwrap()
        };
        let frame =
            carrick_hal::FrameId::from_kernel_allocation(std::num::NonZeroU64::new(3).unwrap());
        process
            .apply_process_inventory(
                |commit| Ok(test_kernel_apply(commit, 91, mm, 10, vec![(id(2), frame)])),
                mm,
            )
            .unwrap();
        assert_eq!(process.phase_name(), "inventory_published");
        let expected_transaction = carrick_hal::KernelTransactionId::from_kernel_allocation(
            std::num::NonZeroU64::new(91).unwrap(),
        );
        let mut pending = PendingForkFrameReceipt {
            transaction: carrick_hal::KernelTransactionId::from_kernel_allocation(
                std::num::NonZeroU64::new(92).unwrap(),
            ),
            kind: carrick_observability::probes::HvpatchForkFrameKind::PrivateCow,
            parent_mapping: id(1),
            child_mapping: id(2),
            frame,
            ipa: 0x4000,
            length: 0x4000,
        };
        assert!(process.activate(&[pending]).is_err());
        assert_eq!(process.phase_name(), "inventory_published");
        pending.transaction = expected_transaction;
        process.activate(&[pending]).unwrap();
        assert_eq!(process.phase_name(), "active");
        let frame5 =
            carrick_hal::FrameId::from_kernel_allocation(std::num::NonZeroU64::new(5).unwrap());
        let frame7 =
            carrick_hal::FrameId::from_kernel_allocation(std::num::NonZeroU64::new(7).unwrap());
        let mapping_pairs = [(id(2), frame), (id(4), frame5), (id(6), frame7)];
        {
            let mut current = ledger.lock();
            for (index, &(mapping, frame)) in mapping_pairs.iter().enumerate() {
                current.extents.insert(
                    (0x4000 + index as u64 * 0x4000, 0x4000),
                    InventoryExtent {
                        frame,
                        mapping,
                        backing: InventoryBackingIdentity::Private(index as u64 + 1),
                        stage2_base: 0x1000_0000 + index as u64 * 0x4000,
                        stage2_length: 0x4000,
                    },
                );
            }
        }
        assert!(
            process
                .prepare_retirement(retirement_inventory_commit(95, &[id(2)]))
                .is_err()
        );
        // A post-activation munmap/COW retirement changed the exact live set.
        ledger.lock().extents.remove(&(0x8000, 0x4000));
        let expected_after_unmap = vec![mapping_pairs[0], mapping_pairs[2]];
        let unrelated_commit = empty_inventory_commit(92);
        let unrelated = carrick_hal::FrameInventoryRetirementReceipt::from_kernel_authority(
            test_kernel_apply(unrelated_commit, 92, mm, 11, Vec::new()),
            false,
        );
        assert!(!authenticate_pending_retirement(
            &expected_after_unmap,
            &[pending],
            &unrelated
        ));
        let retirement_commit = retirement_inventory_commit(93, &[id(2), id(6)]);
        process.prepare_retirement(retirement_commit).unwrap();
        process
            .apply_retirement(mm, &[pending], |retirement_commit| {
                Ok(
                    carrick_hal::FrameInventoryRetirementReceipt::from_kernel_authority(
                        test_kernel_apply(
                            retirement_commit,
                            93,
                            mm,
                            11,
                            expected_after_unmap.clone(),
                        ),
                        true,
                    ),
                )
            })
            .unwrap();
        assert_eq!(process.phase_name(), "retired");

        let ledger = Arc::new(parking_lot::Mutex::new(HvpatchFrameInventory::default()));
        let rejected_commit = empty_inventory_commit(94);
        let rejected_challenge = rejected_commit.receipt_challenge();
        let mut rejected = HvpatchTaskInventoryAuthority::ProcessPrepared {
            ledger,
            staged: Vec::new(),
            commit: Some(rejected_commit),
            challenge: Some(rejected_challenge),
        };
        assert!(
            rejected
                .apply_process_inventory(
                    |_| {
                        Err(TrapError::Hypervisor(
                            "injected kernel apply reject".to_owned(),
                        ))
                    },
                    mm
                )
                .is_err()
        );
        assert_eq!(rejected.phase_name(), "retired");
        assert!(rejected.activate(&[]).is_err());
    }

    #[test]
    fn shared_process_activation_has_no_process_inventory_transaction() {
        let ledger = Arc::new(parking_lot::Mutex::new(HvpatchFrameInventory::default()));
        let mut shared = HvpatchTaskInventoryAuthority::SharedProcess {
            ledger: Arc::clone(&ledger),
        };
        let mm = std::num::NonZeroU64::new(777).unwrap();
        assert!(
            shared
                .apply_process_inventory(|_| unreachable!(), mm)
                .is_err()
        );
        assert_eq!(shared.phase_name(), "shared_process");
        shared.activate(&[]).unwrap();
        assert_eq!(shared.phase_name(), "shared_process");

        let commit = empty_inventory_commit(778);
        let challenge = commit.receipt_challenge();
        let mut copied = HvpatchTaskInventoryAuthority::ProcessPrepared {
            ledger,
            staged: Vec::new(),
            commit: Some(commit),
            challenge: Some(challenge),
        };
        assert!(copied.activate(&[]).is_err());
        assert_eq!(copied.phase_name(), "prepared");
    }

    #[test]
    fn root_parent_shared_process_interns_by_exact_kernel_mm_without_parent_row() {
        let directory = Arc::new(HvpatchCarrierTaskStateDirectory::default());
        let rollbacks = Arc::new(AtomicUsize::new(0));
        let ledger = Arc::new(parking_lot::Mutex::new(HvpatchFrameInventory::default()));
        let publish = |task_serial, thread_serial, generation| {
            directory
                .publish(
                    HvpatchCarrierTaskIdentity {
                        task_serial,
                        thread_serial,
                        execution_generation: generation,
                        linux_pid: task_serial as i32,
                        linux_tid: thread_serial as i32,
                        asid: 9,
                    },
                    test_state(&rollbacks),
                    HvpatchPreparedTaskAuthority {
                        shared_kernel_mm: Some(0xfeed),
                        inventory: HvpatchTaskInventoryAuthority::SharedProcess {
                            ledger: Arc::clone(&ledger),
                        },
                        ..HvpatchPreparedTaskAuthority::default()
                    },
                )
                .unwrap()
        };
        let root_vfork_child = publish(101, 101, 1);
        let nested_vfork_child = publish(202, 202, 1);
        let first_mm = root_vfork_child
            .registration
            .as_ref()
            .unwrap()
            .task_mm
            .as_ref()
            .unwrap();
        let second_mm = nested_vfork_child
            .registration
            .as_ref()
            .unwrap()
            .task_mm
            .as_ref()
            .unwrap();
        assert!(Arc::ptr_eq(first_mm, second_mm));
        drop(root_vfork_child);
        drop(nested_vfork_child);
        assert_eq!(rollbacks.load(Ordering::SeqCst), 2);
    }

    #[test]
    fn shared_mm_retires_carrier_before_final_task_authority() {
        let directory = Arc::new(HvpatchCarrierTaskStateDirectory::default());
        let rollbacks = Arc::new(AtomicUsize::new(0));
        let order = Arc::new(parking_lot::Mutex::new(Vec::new()));
        let alias_preimage = alias(0xf444_0000, 1);
        let alias_owned = alias(0xf555_0000, 3);
        register_shared_alias(alias_preimage);
        let publish = |generation| {
            directory
                .publish(
                    identity(generation),
                    HvpatchCarrierTaskState::Test {
                        rollbacks: Arc::clone(&rollbacks),
                        order: Some(Arc::clone(&order)),
                    },
                    HvpatchPreparedTaskAuthority {
                        pending_aliases: (generation == 21)
                            .then_some(alias_owned)
                            .into_iter()
                            .collect(),
                        drop_order: Some(Arc::clone(&order)),
                        ..HvpatchPreparedTaskAuthority::default()
                    },
                )
                .unwrap()
        };
        let first = publish(21);
        let second = publish(22);
        let first_mm = first
            .registration
            .as_ref()
            .unwrap()
            .task_mm
            .as_ref()
            .unwrap();
        let second_mm = second
            .registration
            .as_ref()
            .unwrap()
            .task_mm
            .as_ref()
            .unwrap();
        assert!(Arc::ptr_eq(first_mm, second_mm));
        drop(first);
        assert!(order.lock().is_empty());
        assert!(alias_registry().lock().contains(&alias_owned));
        drop(second);
        assert_eq!(&*order.lock(), &["carrier", "task"]);
        assert!(alias_registry().lock().contains(&alias_preimage));
        assert_eq!(rollbacks.load(Ordering::SeqCst), 2);
        alias_registry().lock().retain(|entry| {
            !(entry.ipa == alias_preimage.ipa
                && entry.ownership_scope == alias_preimage.ownership_scope)
        });
        replay_mappings()
            .lock()
            .retain(|(ipa, _, _, _)| *ipa != alias_preimage.physical_ipa);
    }

    #[test]
    fn process_descriptor_drops_real_lease_while_host_backing_is_live() {
        let host = crate::host_mapping::OwnedHostMapping::map_shared_anon(
            0x4000,
            crate::host_mapping::HostMappingKind::PrivateAnon,
        )
        .unwrap();
        let host_addr = host.as_ptr();
        let observed = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let mut lease = GlobalFrameStage2Lease::fixed(0x1234_0000, 0x4000);
        lease.drop_backing_audit = Some((host_addr as usize, Arc::clone(&observed)));
        let descriptor = ProcessMappingDesc {
            start: 0x1000,
            ipa: 0x1234_0000,
            end: 0x5000,
            stage2_lease: Some(lease),
            host: ForkMappingHost::Owned(host),
            size: 0x4000,
            physical_ipa: 0x1234_0000,
            physical_host_addr: host_addr,
            physical_size: 0x4000,
            inventory_backing: InventoryBackingIdentity::Private(1),
            perms: applevisor::memory::MemPerms::ReadWrite,
            is_dynamic_alias: false,
            sharing: GuestMappingSharing::Private,
            guest_writable: true,
            shared_key_base: 0,
            shared_key_offset: 0,
            inherited_frame: None,
        };
        drop(descriptor);
        assert!(observed.load(Ordering::SeqCst));
        assert!(!alias_backing_is_live(host_addr as usize));
    }

    #[test]
    fn exhausted_nonce_aborts_prepared_authority_before_visibility() {
        let directory = Arc::new(HvpatchCarrierTaskStateDirectory::default());
        directory.next.store(u64::MAX, Ordering::SeqCst);
        let rollbacks = Arc::new(AtomicUsize::new(0));
        assert!(
            directory
                .publish(
                    identity(9),
                    test_state(&rollbacks),
                    HvpatchPreparedTaskAuthority::default(),
                )
                .is_err()
        );
        assert_eq!(rollbacks.load(Ordering::SeqCst), 1);
        assert!(directory.inner.lock().states.is_empty());
    }

    #[test]
    fn carrier_token_is_rejected_by_a_different_directory_instance() {
        let first = Arc::new(HvpatchCarrierTaskStateDirectory::default());
        let second = Arc::new(HvpatchCarrierTaskStateDirectory::default());
        let rollbacks = Arc::new(AtomicUsize::new(0));
        let binding = first
            .publish(
                identity(11),
                test_state(&rollbacks),
                HvpatchPreparedTaskAuthority::default(),
            )
            .unwrap();
        let key = binding.registration.as_ref().unwrap().key;
        assert!(second.retire(key).is_err());
        assert!(first.inner.lock().states.contains_key(&key));
        drop(binding);
        assert!(first.inner.lock().states.is_empty());
    }

    #[test]
    fn duplicate_core_key_rejects_different_linux_metadata() {
        let directory = Arc::new(HvpatchCarrierTaskStateDirectory::default());
        let rollbacks = Arc::new(AtomicUsize::new(0));
        let binding = directory
            .publish(
                identity(12),
                test_state(&rollbacks),
                HvpatchPreparedTaskAuthority::default(),
            )
            .unwrap();
        let mut mismatched = identity(12);
        mismatched.linux_tid += 1;
        mismatched.asid += 1;
        assert!(
            directory
                .publish(
                    mismatched,
                    test_state(&rollbacks),
                    HvpatchPreparedTaskAuthority::default(),
                )
                .is_err()
        );
        assert_eq!(directory.inner.lock().states.len(), 1);
        drop(binding);
    }

    /// COW arming and COW deferred publication are ONE authority. A task that
    /// can arm a COW range must also own the slot its deferred publications
    /// land in. Half the pair is exactly how every forked PROCESS reached a
    /// worker with `cow_armed` set and no publication slot: the omission was
    /// swallowed by `..Default::default()` and surfaced only at child
    /// activation, after the child had already been published.
    #[test]
    fn prepared_task_authority_rejects_half_a_cow_authority() {
        let armed = || Arc::new(parking_lot::Mutex::new(CowArmedRanges::default()));
        let publications = || Arc::new(parking_lot::Mutex::new(Vec::new()));

        HvpatchPreparedTaskAuthority::default()
            .validate_cow_authority_pairing()
            .expect("neither half present is a complete, COW-less authority");

        HvpatchPreparedTaskAuthority {
            cow_armed: Some(armed()),
            cow_deferred_publications: Some(publications()),
            ..HvpatchPreparedTaskAuthority::default()
        }
        .validate_cow_authority_pairing()
        .expect("both halves present is a complete COW authority");

        let error = HvpatchPreparedTaskAuthority {
            cow_armed: Some(armed()),
            ..HvpatchPreparedTaskAuthority::default()
        }
        .validate_cow_authority_pairing()
        .expect_err("arming without a publication slot must fail closed");
        assert!(
            error
                .to_string()
                .contains("armed COW without publication state"),
            "unexpected error: {error}"
        );

        let error = HvpatchPreparedTaskAuthority {
            cow_deferred_publications: Some(publications()),
            ..HvpatchPreparedTaskAuthority::default()
        }
        .validate_cow_authority_pairing()
        .expect_err("a publication slot without arming must fail closed");
        assert!(
            error
                .to_string()
                .contains("COW publication state without arming"),
            "unexpected error: {error}"
        );
    }

    #[test]
    fn committed_child_requires_fresh_exact_kernel_cow_binding() {
        let (issuer, verifier) = carrick_hal::HvpatchChildTokenIssuer::new_pair();
        let directory = Arc::new(HvpatchCarrierTaskStateDirectory::new(
            std::num::NonZeroU64::new(0x881).unwrap(),
            verifier,
        ));
        let rollbacks = Arc::new(AtomicUsize::new(0));
        let mut binding = directory
            .publish(
                identity(31),
                test_state(&rollbacks),
                HvpatchPreparedTaskAuthority {
                    inventory: HvpatchTaskInventoryAuthority::SiblingShared {
                        ledger: Arc::new(parking_lot::Mutex::new(HvpatchFrameInventory::default())),
                    },
                    ..HvpatchPreparedTaskAuthority::default()
                },
            )
            .unwrap();
        assert!(binding.activate().is_err());
        let mm = std::num::NonZeroU64::new(0x1234).unwrap();
        let authority: Arc<dyn carrick_hal::FrameCowAuthority> = Arc::new(TestCowAuthority);
        let cow_identity = carrick_hal::FrameCowIdentity {
            linux_pid: 41,
            linux_tid: 73,
            mm: mm.get(),
            asid: 9,
        };
        let token = |generation, cow_identity, authority_identity| {
            issuer.issue(
                41,
                73,
                generation,
                cow_identity,
                std::num::NonZeroU64::new(authority_identity).unwrap(),
                Arc::clone(&authority),
            )
        };
        let (foreign_issuer, _) = carrick_hal::HvpatchChildTokenIssuer::new_pair();
        let foreign = foreign_issuer.issue(
            41,
            73,
            31,
            cow_identity,
            std::num::NonZeroU64::new(9).unwrap(),
            Arc::clone(&authority),
        );
        assert!(binding.bind_child_kernel(foreign).is_err());
        let wrong = token(32, cow_identity, 1);
        assert!(binding.bind_child_kernel(wrong).is_err());
        let parent_tid = token(
            31,
            carrick_hal::FrameCowIdentity {
                linux_tid: 72,
                ..cow_identity
            },
            2,
        );
        assert!(binding.bind_child_kernel(parent_tid).is_err());
        let stale_asid = token(
            31,
            carrick_hal::FrameCowIdentity {
                asid: 8,
                ..cow_identity
            },
            3,
        );
        assert!(binding.bind_child_kernel(stale_asid).is_err());
        let exact = token(31, cow_identity, 4);
        binding.bind_child_kernel(exact).unwrap();
        binding.activate().unwrap();
        assert_eq!(
            *binding
                .registration
                .as_ref()
                .unwrap()
                .task_mm
                .as_ref()
                .unwrap()
                .kernel_mm
                .lock(),
            Some(mm)
        );
        let duplicate = token(31, cow_identity, 5);
        assert!(binding.bind_child_kernel(duplicate).is_err());
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct TrapCapabilities {
    pub backend: TrapBackend,
    pub available_on_this_host: bool,
    pub implemented: bool,
}

pub fn hvf_capabilities() -> TrapCapabilities {
    TrapCapabilities {
        backend: TrapBackend::HypervisorFramework,
        available_on_this_host: cfg!(all(target_os = "macos", target_arch = "aarch64")),
        implemented: cfg!(all(target_os = "macos", target_arch = "aarch64")),
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct GuestMappingPlan {
    /// The user-mode entry point (real `_start` of the loaded ELF, already
    /// rebased through any PIE bias). When `el0_trampoline_entry` is `None`
    /// this is also the vCPU's initial PC. When the trampoline is installed
    /// this becomes ELR_EL1 instead, and the vCPU starts at the trampoline.
    pub entry: u64,
    pub initial_stack_pointer: Option<u64>,
    /// Guest physical address of the EL0 entry trampoline page (a single
    /// `eret` instruction). When set, the trap engine starts the vCPU here
    /// in EL1h and uses `entry` as the post-`eret` PC in EL0t.
    pub el0_trampoline_entry: Option<u64>,
    /// Guest physical address to program into VBAR_EL1 so EL0 SVC traps are
    /// routed through the EL1 vector page (which forwards them via HVC).
    pub el1_vectors_base: Option<u64>,
    /// Guest physical address of the stage-1 identity page-table root.
    /// When set, the trap engine programs TTBR0_EL1 / TCR_EL1 / MAIR_EL1
    /// and enables stage-1 (`SCTLR_EL1.M=1`).
    pub stage1_page_tables_base: Option<u64>,
    /// Page-granular read-only guest-VA spans from non-writable ELF `PT_LOAD`
    /// segments. Stage-1 already enforces these for guest stores; HVF also
    /// seeds the shared syscall protection table from them so copyout-style
    /// syscalls return `EFAULT` for `.text`/`.rodata` destinations.
    pub ro_spans: Vec<carrick_mem::elf::RoSpan>,
    pub mappings: Vec<GuestMapping>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct GuestMapping {
    /// Guest VIRTUAL address the region is mapped at (also the key for
    /// software syscall-path memory access). Equals `ipa_start` for every
    /// region except Rosetta's high-VA alias.
    pub guest_start: u64,
    /// Intermediate physical address actually handed to `hv_vm_map`. Identity
    /// (== `guest_start`) for all regions but the Rosetta window, which is
    /// aliased to a low IPA (see `crate::memory::ipa_for_va`).
    pub ipa_start: u64,
    pub mapped_size: u64,
    pub offset_in_mapping: u64,
    pub payload_size: u64,
    pub perms: SegmentPerms,
    /// Host backing is `MAP_SHARED` (kept shared across fork). Mirrors
    /// `MemoryRegion::shared`.
    pub shared: bool,
    #[serde(skip)]
    image: std::sync::Arc<Vec<u8>>,
    /// Optional immutable, fully-patched file artifact for a private RX
    /// mapping. Every exec creates a fresh MAP_PRIVATE host view; the artifact
    /// itself is cached and never mutated.
    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    #[serde(skip)]
    private_file_backing: Option<ExecPrivateFileBacking>,
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
#[derive(Clone, Debug)]
struct ExecPrivateFileBacking {
    identity: u64,
    file: std::sync::Arc<std::fs::File>,
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
impl PartialEq for ExecPrivateFileBacking {
    fn eq(&self, other: &Self) -> bool {
        self.identity == other.identity
    }
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
impl Eq for ExecPrivateFileBacking {}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
struct ExecPrivateFileKey {
    source_ptr: usize,
    source_len: usize,
    mapped_size: usize,
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
#[derive(Debug)]
struct CachedExecPrivateFile {
    source: std::sync::Arc<Vec<u8>>,
    backing: ExecPrivateFileBacking,
    mapped_size: usize,
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
#[derive(Debug, Default)]
struct ExecPrivateFileCache {
    entries: HashMap<ExecPrivateFileKey, CachedExecPrivateFile>,
    mapped_bytes: usize,
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
const EXEC_PRIVATE_FILE_CACHE_CAPACITY: usize = 64;
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
const EXEC_PRIVATE_FILE_CACHE_BYTES: usize = 256 * 1024 * 1024;

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
fn exec_private_file_cache_enabled() -> bool {
    std::env::var_os("CARRICK_HVPATCH_EXEC_PRIVATE_FILE_CACHE").as_deref()
        != Some(std::ffi::OsStr::new("0"))
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
fn exec_private_file_cache() -> &'static parking_lot::Mutex<ExecPrivateFileCache> {
    static CACHE: std::sync::OnceLock<parking_lot::Mutex<ExecPrivateFileCache>> =
        std::sync::OnceLock::new();
    CACHE.get_or_init(|| parking_lot::Mutex::new(ExecPrivateFileCache::default()))
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
fn create_exec_private_file_artifact(
    source: &[u8],
    mapped_size: usize,
) -> Result<std::fs::File, std::io::Error> {
    use std::os::unix::fs::{FileExt, OpenOptionsExt};

    if source.len() > mapped_size || mapped_size == 0 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "invalid hvpatch private executable artifact extent",
        ));
    }
    static NEXT_FILE: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);
    let sequence = NEXT_FILE.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let path = std::env::temp_dir().join(format!(
        ".carrick-hvpatch-exec-{}-{sequence}",
        std::process::id()
    ));
    let file = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&path)?;
    if let Err(error) = std::fs::remove_file(&path) {
        drop(file);
        let _ = std::fs::remove_file(&path);
        return Err(error);
    }
    file.set_len(mapped_size as u64)?;
    file.write_all_at(source, 0)?;
    Ok(file)
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
fn cached_exec_private_file_backing(
    source: std::sync::Arc<Vec<u8>>,
    mapped_size: usize,
) -> Result<ExecPrivateFileBacking, TrapError> {
    let key = ExecPrivateFileKey {
        source_ptr: std::sync::Arc::as_ptr(&source) as usize,
        source_len: source.len(),
        mapped_size,
    };
    if let Some(cached) = exec_private_file_cache()
        .lock()
        .entries
        .get(&key)
        .filter(|cached| std::sync::Arc::ptr_eq(&cached.source, &source))
    {
        return Ok(cached.backing.clone());
    }

    let file = create_exec_private_file_artifact(&source, mapped_size).map_err(|error| {
        TrapError::Hypervisor(format!(
            "create hvpatch private executable artifact (size={mapped_size}): {error}"
        ))
    })?;
    static NEXT_IDENTITY: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);
    let candidate = ExecPrivateFileBacking {
        identity: NEXT_IDENTITY.fetch_add(1, std::sync::atomic::Ordering::Relaxed),
        file: std::sync::Arc::new(file),
    };
    let mut cache = exec_private_file_cache().lock();
    if let Some(cached) = cache
        .entries
        .get(&key)
        .filter(|cached| std::sync::Arc::ptr_eq(&cached.source, &source))
    {
        return Ok(cached.backing.clone());
    }
    while cache.entries.len() >= EXEC_PRIVATE_FILE_CACHE_CAPACITY
        || cache.mapped_bytes.saturating_add(mapped_size) > EXEC_PRIVATE_FILE_CACHE_BYTES
    {
        let Some(victim) = cache.entries.keys().next().copied() else {
            break;
        };
        if let Some(removed) = cache.entries.remove(&victim) {
            cache.mapped_bytes = cache.mapped_bytes.saturating_sub(removed.mapped_size);
        }
    }
    if mapped_size <= EXEC_PRIVATE_FILE_CACHE_BYTES {
        cache.mapped_bytes = cache.mapped_bytes.saturating_add(mapped_size);
        cache.entries.insert(
            key,
            CachedExecPrivateFile {
                source,
                backing: candidate.clone(),
                mapped_size,
            },
        );
    }
    Ok(candidate)
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
fn attach_exec_private_file_backings(plan: &mut GuestMappingPlan) -> Result<(), TrapError> {
    if !exec_private_file_cache_enabled() {
        return Ok(());
    }
    for mapping in &mut plan.mappings {
        let eligible = mapping.perms.execute
            && !mapping.perms.write
            && !mapping.shared
            && mapping.offset_in_mapping == 0
            && !mapping.image.is_empty()
            && mapping.image.len() <= mapping.mapped_size as usize
            && mapping.mapped_size as usize <= EXEC_PRIVATE_FILE_CACHE_BYTES;
        if !eligible {
            continue;
        }
        mapping.private_file_backing = Some(cached_exec_private_file_backing(
            std::sync::Arc::clone(&mapping.image),
            mapping.mapped_size as usize,
        )?);
    }
    Ok(())
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
fn lazy_exec_page_tables_enabled() -> bool {
    std::env::var_os("CARRICK_HVPATCH_LAZY_EXEC_PAGE_TABLES").as_deref()
        != Some(std::ffi::OsStr::new("0"))
}

impl GuestMappingPlan {
    pub fn from_address_space(address_space: &AddressSpace) -> Result<Self, TrapError> {
        // Default to sharing immutable ELF payloads between the loaded image and
        // mapping plan. The =0 hatch restores the pre-optimization copy so one
        // signed binary can perform a schedule-identical liveness bisection.
        let share_payload = std::env::var_os("CARRICK_HVPATCH_SHARE_EXEC_PAYLOAD").as_deref()
            != Some(std::ffi::OsStr::new("0"));
        let sparse_initial_stack = std::env::var_os("CARRICK_HVPATCH_SPARSE_EXEC_STACK").as_deref()
            != Some(std::ffi::OsStr::new("0"));
        let initial_stack_pointer = address_space.initial_stack_pointer();
        let mut mappings = Vec::with_capacity(address_space.regions().len());
        for region in address_space.regions() {
            let guest_start = align_down(region.start, HVF_PAGE_SIZE);
            // The IPA actually mapped — identity for everything except the
            // Rosetta high-VA window, which is aliased down to a low IPA.
            let ipa_start = align_down(crate::memory::ipa_for_va(region.start), HVF_PAGE_SIZE);
            // Back the FULL Rosetta window (2 MiB) so its page-table block has no
            // unbacked tail; other regions round their end up to a page.
            let guest_end = if crate::memory::is_rosetta_va(region.start) {
                crate::memory::LINUX_ROSETTA_VA_BASE + crate::memory::LINUX_ROSETTA_WINDOW_SIZE
            } else {
                align_up(region.end, HVF_PAGE_SIZE)?
            };
            let mapped_size =
                guest_end
                    .checked_sub(guest_start)
                    .ok_or(TrapError::MappingOverflow {
                        guest_start,
                        mapped_size: 0,
                    })?;
            let mapped_len = usize::try_from(mapped_size)
                .map_err(|_| TrapError::MappingTooLarge(mapped_size))?;
            let mut offset_in_mapping = region.start - guest_start;

            // Keep only the payload bytes, not a full zero-padded copy of the
            // (potentially 512 MiB) mapping. hv_vm_allocate hands back lazily
            // zero-filled, HVF-managed memory, so we write just the payload at
            // its offset and let untouched pages fault in on demand. Building
            // and writing the whole region here is what pinned ~2 GiB resident
            // per guest process for mappings the guest never touches.
            let _ = mapped_len;
            let is_initial_stack = sparse_initial_stack
                && region.start == crate::memory::LINUX_STACK_TOP - crate::memory::LINUX_STACK_SIZE
                && region.end == crate::memory::LINUX_STACK_TOP;
            let image = if is_initial_stack {
                let stack_pointer = initial_stack_pointer.ok_or_else(|| {
                    TrapError::Hypervisor(
                        "initial stack region has no initial stack pointer".to_owned(),
                    )
                })?;
                let payload_offset = align_down(
                    stack_pointer.checked_sub(region.start).ok_or_else(|| {
                        TrapError::Hypervisor(
                            "initial stack pointer lies below stack region".to_owned(),
                        )
                    })?,
                    HVF_PAGE_SIZE,
                );
                let payload_offset_usize = usize::try_from(payload_offset)
                    .map_err(|_| TrapError::MappingTooLarge(payload_offset))?;
                let payload = region.bytes().get(payload_offset_usize..).ok_or_else(|| {
                    TrapError::Hypervisor("initial stack payload offset exceeds backing".to_owned())
                })?;
                offset_in_mapping = offset_in_mapping.checked_add(payload_offset).ok_or(
                    TrapError::MappingOverflow {
                        guest_start,
                        mapped_size,
                    },
                )?;
                std::sync::Arc::new(payload.to_vec())
            } else if share_payload {
                region.shared_bytes()
            } else {
                std::sync::Arc::new(region.bytes().to_vec())
            };

            mappings.push(GuestMapping {
                guest_start,
                ipa_start,
                mapped_size,
                offset_in_mapping,
                payload_size: image.len() as u64,
                perms: region.perms,
                shared: region.shared,
                image,
                #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
                private_file_backing: None,
            });
        }

        Ok(Self {
            entry: address_space.entry(),
            initial_stack_pointer: address_space.initial_stack_pointer(),
            el0_trampoline_entry: address_space.el0_trampoline_entry(),
            el1_vectors_base: address_space.el1_vectors_base(),
            stage1_page_tables_base: address_space.stage1_page_tables_base(),
            ro_spans: address_space.ro_spans().to_vec(),
            mappings,
        })
    }
}

// The public HVF trap engine IS `Aarch64EngineCore<HvfAarch64Vmm>`: the shared
// `carrick-aarch64` scaffold parameterized over the thin HVF backend trait pair
// (`crate::hvf_aarch64_engine`). Every existing `crate::trap::HvfTrapEngine`
// reference (carrick-runtime's run loop, the integration tests) resolves through
// this alias unchanged. The trap loop / register walk / guest-memory gate /
// fork/execve/sibling sequencing / threaded lifecycle now live ONCE in
// carrick-aarch64; the HVF-specific atoms below feed it through the trait pair.
//
// The leak-until-exit Drop discipline (NEVER run applevisor's Vcpu /
// VirtualMachine destructors after a `fork(2)`, or they panic with "no VM or
// vCPU available") now lives per-half: `HvfAarch64Vcpu`'s `Drop` skips
// `ManuallyDrop::drop`, and `HvfVmState` holds the VM in a no-op `ManuallyDrop`.
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
pub type HvfTrapEngine =
    carrick_aarch64::Aarch64EngineCore<crate::hvf_aarch64_engine::HvfAarch64Vmm>;

/// Bring up the HVF trap engine from a loaded image: create the VM + vCPU, map
/// the guest address space, and park the vCPU at the EL0-entry trampoline. The
/// runtime calls this instead of the old `HvfTrapEngine::new()` + `map_plan`.
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
pub fn new_hvf_trap_engine(image: &AddressSpace) -> Result<HvfTrapEngine, TrapError> {
    crate::hvf_aarch64_engine::bring_up(image)
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
const GPR_TABLE: [applevisor::vcpu::Reg; 31] = [
    applevisor::vcpu::Reg::X0,
    applevisor::vcpu::Reg::X1,
    applevisor::vcpu::Reg::X2,
    applevisor::vcpu::Reg::X3,
    applevisor::vcpu::Reg::X4,
    applevisor::vcpu::Reg::X5,
    applevisor::vcpu::Reg::X6,
    applevisor::vcpu::Reg::X7,
    applevisor::vcpu::Reg::X8,
    applevisor::vcpu::Reg::X9,
    applevisor::vcpu::Reg::X10,
    applevisor::vcpu::Reg::X11,
    applevisor::vcpu::Reg::X12,
    applevisor::vcpu::Reg::X13,
    applevisor::vcpu::Reg::X14,
    applevisor::vcpu::Reg::X15,
    applevisor::vcpu::Reg::X16,
    applevisor::vcpu::Reg::X17,
    applevisor::vcpu::Reg::X18,
    applevisor::vcpu::Reg::X19,
    applevisor::vcpu::Reg::X20,
    applevisor::vcpu::Reg::X21,
    applevisor::vcpu::Reg::X22,
    applevisor::vcpu::Reg::X23,
    applevisor::vcpu::Reg::X24,
    applevisor::vcpu::Reg::X25,
    applevisor::vcpu::Reg::X26,
    applevisor::vcpu::Reg::X27,
    applevisor::vcpu::Reg::X28,
    applevisor::vcpu::Reg::X29,
    applevisor::vcpu::Reg::X30,
];

/// Process-wide handoff for multithreaded fork: the forking thread (parent),
/// after rebuilding its VM, publishes a clone here so quiesced sibling threads
/// recreate their vCPUs in the same (new) process VM.
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
type SharedVm = applevisor::vm::VirtualMachineInstance<applevisor::vm::GicDisabled>;

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
fn rebuilt_vm_cell() -> &'static parking_lot::Mutex<Option<SharedVm>> {
    static CELL: std::sync::OnceLock<parking_lot::Mutex<Option<SharedVm>>> =
        std::sync::OnceLock::new();
    CELL.get_or_init(|| parking_lot::Mutex::new(None))
}

/// How guest-visible sharing maps onto the host and HVPatch's one VM.
///
/// `ForkSharedAnonymous` deliberately shares only the host backing and explicit
/// fork-child descriptor. It stays in the owning mm's IPA scope and does not
/// acquire shared-file futex identity. `GlobalShared` is the existing shared
/// aperture / MAP_SHARED-file behavior whose IPA is VM-global.
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum GuestMappingSharing {
    Private,
    ForkSharedAnonymous,
    GlobalShared,
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
impl GuestMappingSharing {
    fn shares_across_fork(self) -> bool {
        self != Self::Private
    }

    fn uses_global_ipa(self) -> bool {
        self == Self::GlobalShared
    }

    fn has_shared_futex_identity(self) -> bool {
        self == Self::GlobalShared
    }
}

/// Process-global registry of dynamic alias mappings, so a vCPU can
/// re-establish one in ITS shared VM after fork dropped it.
///
/// Threads share ONE hv_vm, but `fork()` tears that VM down and rebuilds it from
/// ONLY the forking thread's per-thread `mappings` list (see `HvfInner::fork`).
/// A global-shared alias mapped by a SIBLING thread is therefore lost from the
/// rebuilt VM, and any later access stage-2-faults (the go-build telemetry
/// counter: a counter file `mmap(MAP_SHARED)`'d on one thread, read via LDAR on
/// another after `go` forks `compile`). arm64 HVF has no stage-2 TLB shootdown,
/// so we cannot push the map to siblings eagerly; instead each vCPU LAZILY
/// re-maps on the fault, keyed off this registry.
///
/// Every alias is registered for thread fallback. The sharing classification
/// decides whether its IPA is process-scoped or global and whether fork reuses
/// the backing; those decisions must not be inferred from host `MAP_SHARED`.
/// A high-VA alias's IPA window → host backing, registered PROCESS-GLOBALLY. Two
/// roles: (1) the stage-2 lazy on-fault re-map (a vCPU whose forked VM lost an
/// alias re-establishes it), and (2) the SYSCALL-PATH cross-thread fallback —
/// `mapping_for_range` consults this when a guest buffer lives in a high-VA alias
/// ANOTHER thread mapped (each `HvfInner.mappings` is per-thread; Go's heap arenas
/// are shared across goroutines, so a sibling-mapped arena was invisible to a
/// thread's syscall and EFAULTed). The VA→IPA half is already process-shared
/// (`translate_va` over the Arc-shared page tables); this supplies the IPA→host
/// half. Stores a NON-OWNING raw `host_addr` only (never an OwnedHostMapping), so
/// it never participates in Drop / double-free; the backing's lifetime stays with
/// the owning thread's `mappings` Vec and this entry is removed on `munmap`
/// (`unregister_alias`).
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum AliasOwnershipScope {
    /// Alias belongs to the original/root address space in this host process.
    Root,
    /// Alias belongs to exactly one HVPatch address space.  The scope is
    /// rebound in the forked host child when an inherited shared-anonymous
    /// frame is materialized into that child's new mm. The stage-1 root slot
    /// tuple is an ownership token only; guest frames use global IPAs.
    MmRootSlot { base: u64, size: u64 },
    /// Shared-file aliases use the historical VM-global IPA namespace.
    Global,
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
fn alias_ownership_scope(
    sharing: GuestMappingSharing,
    mm_root_slot: Option<(u64, u64)>,
) -> AliasOwnershipScope {
    if sharing.uses_global_ipa() {
        AliasOwnershipScope::Global
    } else if let Some((base, size)) = mm_root_slot {
        AliasOwnershipScope::MmRootSlot { base, size }
    } else {
        AliasOwnershipScope::Root
    }
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
fn rebind_inherited_alias_to_process(
    mut alias: AliasBacking,
    mm_root_slot: (u64, u64),
) -> AliasBacking {
    alias.ownership_scope = AliasOwnershipScope::MmRootSlot {
        base: mm_root_slot.0,
        size: mm_root_slot.1,
    };
    alias
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct AliasBacking {
    /// Guest VIRTUAL start of the alias (the syscall-path region key).
    start: u64,
    ipa: u64,
    host_addr: usize,
    /// Exact guest-visible VA/IPA extent. This deliberately excludes any
    /// host/HVF granule padding retained by `physical_size` below.
    size: usize,
    /// The whole HVF-granular stage-2 extent retained behind this semantic
    /// fragment. Partial Linux unmaps split only the live fields above; VM
    /// rebuild and frame inventory continue to use this exact physical extent.
    physical_ipa: u64,
    physical_host_addr: usize,
    physical_size: usize,
    perms: u64,
    /// Whether the guest may WRITE the alias (a PROT_READ MAP_SHARED file alias
    /// must EFAULT a syscall write, not SIGBUS the host through the raw pointer).
    guest_writable: bool,
    sharing: GuestMappingSharing,
    ownership_scope: AliasOwnershipScope,
    inventory_backing: InventoryBackingIdentity,
    shared_key_base: u64,
    shared_key_offset: u64,
    /// Which incarnation of the global-frame lease this row was published
    /// against — see [`GlobalFrameHostOwner::generation`]. Without it a row that
    /// outlives its lease silently re-authenticates against the next one.
    owner_generation: u64,
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
fn semantic_extent_size(start: u64, end: u64) -> usize {
    usize::try_from(end.saturating_sub(start)).unwrap_or(usize::MAX)
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
fn is_kernel_only_stage1_range(start: u64, len: usize) -> bool {
    let end = start.saturating_add(len as u64);
    start >= crate::memory::LINUX_KERNEL_REGION_BASE
        && end
            <= crate::memory::LINUX_KERNEL_REGION_BASE
                .saturating_add(carrick_mem::memory::LINUX_KERNEL_REGION_SIZE)
}

// Futex-word keying for `MAP_SHARED` file mappings lives in
// `carrick_host::futex_key` (portable POSIX) so the native (DSR) backend
// derives its waiter keys with the SAME scheme on every host OS. Re-exported
// here because this trap layer is where the keys are consumed on HVF.
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
pub use carrick_host::futex_key::{shared_file_key_base, shared_futex_waiter_key};

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
fn alias_registry() -> &'static parking_lot::Mutex<Vec<AliasBacking>> {
    static CELL: std::sync::OnceLock<parking_lot::Mutex<Vec<AliasBacking>>> =
        std::sync::OnceLock::new();
    CELL.get_or_init(|| parking_lot::Mutex::new(Vec::new()))
}

/// Process-global ownership of host mappings installed at reusable global frame
/// IPAs. Per-vCPU mapping rows are non-owning views; otherwise the vCPU that
/// happened to service `mmap` would pin the host extent until process exit even
/// after another thread completed the final `munmap`.
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
#[derive(Debug)]
struct GlobalFrameHostOwner {
    _mapping: crate::host_mapping::OwnedHostMapping,
    _lease: GlobalFrameStage2Lease,
    perms: u64,
    /// Which incarnation of this `(IPA, length)` lease this is.
    ///
    /// The host-pointer check alone is NOT an identity. Retiring an owner
    /// `munmap`s its host buffer and returns the IPA to the allocator, and both
    /// come straight back: measured on the canonical host, a
    /// `map_shared_anon`/`munmap` cycle returns the SAME host VA 499 of 499
    /// times, with ONE distinct address
    /// (`docs/perf-results/2026-08-19-global-frame-lease-identity/`). So a stale
    /// per-thread row naming the old triple re-authenticates against the NEW
    /// owner and the anonymous-reuse scrub zeroes a live granule — confirmed to
    /// be the `cpython-importlib` SIGSEGV (5/8 crashes, 0/14 once the identity
    /// cannot recur).
    generation: u64,
}

/// Monotonic source for [`GlobalFrameHostOwner::generation`]. Never reused, so a
/// retired lease's incarnation can never be mistaken for a live one. Starts at
/// 1, leaving 0 free as "no generation known".
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
static GLOBAL_FRAME_OWNER_GENERATION: std::sync::atomic::AtomicU64 =
    std::sync::atomic::AtomicU64::new(1);

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
fn next_global_frame_owner_generation() -> u64 {
    GLOBAL_FRAME_OWNER_GENERATION.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
}

/// The live owner generation for `(ipa, length)`, or 0 when unowned.
///
/// Rows stamp this at publication, which always happens while the lease is
/// live, so a row records the incarnation it was actually published against.
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
fn global_frame_host_owner_generation(ipa: u64, length: u64) -> u64 {
    global_frame_host_owners()
        .lock()
        .get(&(ipa, length))
        .map_or(0, |owner| owner.generation)
}

// SAFETY: the mapping is process-address-space state. Its address is stable,
// HVF and guest-memory access already cross host threads, and the only owning
// operation (Drop/munmap) is serialized by the topology lock plus this mutex.
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
unsafe impl Send for GlobalFrameHostOwner {}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
fn global_frame_host_owners()
-> &'static parking_lot::Mutex<std::collections::BTreeMap<(u64, u64), GlobalFrameHostOwner>> {
    static CELL: std::sync::OnceLock<
        parking_lot::Mutex<std::collections::BTreeMap<(u64, u64), GlobalFrameHostOwner>>,
    > = std::sync::OnceLock::new();
    CELL.get_or_init(|| parking_lot::Mutex::new(std::collections::BTreeMap::new()))
}

/// Global-frame stage-2 leases owned by a CARRIER MM rather than by a mapping
/// row or a host-owner registration.
///
/// A forked process's fresh kernel-state frames are reserved by the fork path
/// and must outlive every per-task mapping projection, which are `unowned` and
/// carry no lease. Parking them in the carrier alone made them invisible to
/// `retire_stage2_extent_from_mappings`, whose fallback then released the IPA
/// while the lease was still live — and the lease's own `Drop` released it a
/// second time, tripping the allocator's exact-extent check and aborting the
/// carrier. Keying them here makes the owner findable, so the extent is
/// released exactly once, by whichever of retirement or carrier teardown
/// reaches it first.
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
fn carrier_stage2_leases()
-> &'static parking_lot::Mutex<std::collections::BTreeMap<(u64, u64), GlobalFrameStage2Lease>> {
    static CELL: std::sync::OnceLock<
        parking_lot::Mutex<std::collections::BTreeMap<(u64, u64), GlobalFrameStage2Lease>>,
    > = std::sync::OnceLock::new();
    CELL.get_or_init(|| parking_lot::Mutex::new(std::collections::BTreeMap::new()))
}

/// Publish a carrier-owned lease and return its key. Fails closed on a
/// duplicate: two owners for one extent is the double-release shape itself.
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
fn register_carrier_stage2_lease(lease: GlobalFrameStage2Lease) -> Result<(u64, u64), TrapError> {
    let key = lease.key();
    let mut leases = carrier_stage2_leases().lock();
    if leases.contains_key(&key) {
        return Err(TrapError::Hypervisor(format!(
            "carrier stage-2 lease collision at IPA 0x{:x} size {}",
            key.0, key.1
        )));
    }
    leases.insert(key, lease);
    Ok(key)
}

/// Take the carrier-owned lease for an exact extent, if one is published.
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
fn take_carrier_stage2_lease(ipa: u64, length: u64) -> Option<GlobalFrameStage2Lease> {
    carrier_stage2_leases().lock().remove(&(ipa, length))
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
fn register_global_frame_host_owner(
    lease: GlobalFrameStage2Lease,
    mapping: crate::host_mapping::OwnedHostMapping,
    perms: u64,
) -> Result<(), TrapError> {
    let key = lease.key();
    if key.1 != mapping.len() as u64 || !lease.mapped {
        return Err(TrapError::Hypervisor(format!(
            "global frame host owner lease/backing mismatch: lease={key:?} backing={}",
            mapping.len()
        )));
    }
    if let Some(debug_ipa) = std::env::var("CARRICK_FORK_DEBUG_IPA")
        .ok()
        .and_then(|raw| u64::from_str_radix(raw.trim_start_matches("0x"), 16).ok())
        && key.0 <= debug_ipa
        && debug_ipa < key.0.saturating_add(key.1)
    {
        eprintln!(
            "[FORKDBG] register_global_frame_host_owner ipa={:#x} len={:#x} host={:p}\n{}",
            key.0,
            key.1,
            mapping.as_ptr(),
            std::backtrace::Backtrace::force_capture(),
        );
    }
    let mut owners = global_frame_host_owners().lock();
    if owners.contains_key(&key) {
        return Err(TrapError::Hypervisor(format!(
            "global frame host owner collision at IPA 0x{:x} size {}",
            key.0, key.1
        )));
    }
    owners.insert(
        key,
        GlobalFrameHostOwner {
            _mapping: mapping,
            _lease: lease,
            perms,
            generation: next_global_frame_owner_generation(),
        },
    );
    Ok(())
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
fn retire_global_frame_host_owner(ipa: u64, length: u64) -> bool {
    // Lifecycle debug: CARRICK_FORK_DEBUG_IPA=<hex> logs every owner
    // retirement overlapping that IPA, with the caller. Retiring an owner
    // drops its OwnedHostMapping — macOS can recycle the host VA immediately —
    // so a retire while a live process still references the frame is the
    // scrubbed-shared-granule bug's trigger shape.
    if let Some(debug_ipa) = std::env::var("CARRICK_FORK_DEBUG_IPA")
        .ok()
        .and_then(|raw| u64::from_str_radix(raw.trim_start_matches("0x"), 16).ok())
        && ipa <= debug_ipa
        && debug_ipa < ipa.saturating_add(length)
    {
        eprintln!(
            "[FORKDBG] retire_global_frame_host_owner ipa={ipa:#x} len={length:#x}\n{}",
            std::backtrace::Backtrace::force_capture(),
        );
    }
    let owner = global_frame_host_owners().lock().remove(&(ipa, length));
    let retired = owner.is_some();
    drop(owner);
    retired
}

/// Authenticate a non-owning mapping/alias row against the exact live global
/// owner, not merely against the current host VM map.
///
/// Dynamic rows deliberately outlive individual COW generations in per-vCPU
/// metadata. After the last logical reference retires, macOS may immediately
/// recycle that host VA for an unrelated frame. A `mach_vm_region` liveness
/// query would then accept the stale pointer and let anonymous-reuse zeroing
/// scrub the unrelated allocation. The `(IPA, length, host pointer)` triple is
/// the owning lease identity and therefore the only safe HVPatch predicate.
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
fn global_frame_host_owner_matches(
    ipa: u64,
    length: u64,
    host_addr: usize,
    generation: u64,
) -> bool {
    let (owner_host_addr, owner_generation) = global_frame_host_owners()
        .lock()
        .get(&(ipa, length))
        .map_or((0, 0), |owner| {
            (owner._mapping.as_ptr() as usize, owner.generation)
        });
    // The GENERATION is what turns this into an identity. Without it the triple
    // re-authenticates against a DIFFERENT incarnation of the same recycled
    // `(IPA, length, host VA)`, which is measured to happen every single time.
    // A row stamped with 0 was published without a live global-frame owner for
    // its extent (the mailbox and other early mappings are like this), so it
    // keeps the historical pointer-only behaviour — tightening those to "no
    // match" unmapped the syscall mailbox and killed the guest outright. Where a
    // row DOES carry an incarnation, that incarnation must be the live one.
    let matches = owner_host_addr != 0
        && owner_host_addr == host_addr
        && (generation == 0 || owner_generation == generation);
    if !matches {
        crate::probes::hvpatch_global_frame_owner_miss(
            ipa,
            length,
            host_addr as u64,
            owner_host_addr as u64,
        );
    }
    matches
}

/// Copy through the exact currently-owned reusable frame selected by a live
/// stage-1 leaf. The owner lock pins both the host mapping and its generation
/// for the duration of the copy; absence is authoritative failure, never a
/// reason to dereference a retired per-vCPU descriptor.
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
fn copy_from_global_frame_owner(ipa: u64, dst: &mut [u8]) -> Option<(u64, u64)> {
    let length = u64::try_from(dst.len()).ok()?;
    let end = ipa.checked_add(length)?;
    let owners = global_frame_host_owners().lock();
    let (&(owner_ipa, owner_length), owner) = owners
        .iter()
        .find(|((base, size), _)| ipa >= *base && end <= base.saturating_add(*size))?;
    let offset = usize::try_from(ipa.checked_sub(owner_ipa)?).ok()?;
    let host = owner._mapping.as_ptr();
    unsafe {
        volatile_copy_from_guest(host.add(offset), dst.as_mut_ptr(), dst.len());
    }
    Some((owner_ipa, owner_ipa.saturating_add(owner_length)))
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
fn is_reusable_global_frame_extent(ipa: u64, length: u64) -> bool {
    let base = carrick_mem::memory::LINUX_HVPATCH_GLOBAL_FRAME_BASE;
    let end = base.saturating_add(carrick_mem::memory::LINUX_HVPATCH_GLOBAL_FRAME_SIZE);
    ipa >= base
        && ipa
            .checked_add(length)
            .is_some_and(|extent_end| extent_end <= end)
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
fn global_frame_region_owner_matches(mapping: &HvfMappedRegion) -> bool {
    let Some(semantic_offset) = mapping.ipa.checked_sub(mapping.physical_ipa) else {
        return false;
    };
    let Ok(semantic_offset) = usize::try_from(semantic_offset) else {
        return false;
    };
    let Some(physical_host_addr) = (mapping.host_addr as usize).checked_sub(semantic_offset) else {
        return false;
    };
    let locally_owned = mapping.host_mapping.as_ref().is_some_and(|owner| {
        owner.as_ptr() as usize == physical_host_addr && owner.len() == mapping.physical_size
    }) && mapping.stage2_lease.as_ref().is_some_and(|lease| {
        lease.active
            && lease.mapped
            && lease.key() == (mapping.physical_ipa, mapping.physical_size as u64)
    });
    if locally_owned {
        return true;
    }
    global_frame_host_owner_matches(
        mapping.physical_ipa,
        mapping.physical_size as u64,
        physical_host_addr,
        mapping.owner_generation,
    )
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
type ReplayMappingKey = (u64, usize, usize, u64);

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
fn replay_mappings() -> &'static parking_lot::Mutex<std::collections::BTreeSet<ReplayMappingKey>> {
    static CELL: std::sync::OnceLock<
        parking_lot::Mutex<std::collections::BTreeSet<ReplayMappingKey>>,
    > = std::sync::OnceLock::new();
    CELL.get_or_init(|| parking_lot::Mutex::new(std::collections::BTreeSet::new()))
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
fn replay_mapping_key(backing: AliasBacking) -> ReplayMappingKey {
    (
        backing.physical_ipa,
        backing.physical_size,
        backing.physical_host_addr,
        backing.perms,
    )
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
fn forget_replay_extent(ipa: u64, size: usize) {
    mutate_external_alias_state(|replay, _| {
        replay.retain(|(mapped_ipa, mapped_size, _, _)| *mapped_ipa != ipa || *mapped_size != size);
    });
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
fn clear_replay_mappings() {
    mutate_external_alias_state(|replay, _| replay.clear());
}

/// Diagnostic: lazy-alias re-map count (the `debug-stats` feature logs every 256th).
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
pub static ALIAS_REMAP_COUNT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

/// Record an alias (any `map_host_alias` region — file OR private anon) so the
/// stage-2 lazy remap and the syscall-path cross-thread fallback can resolve it
/// from any thread. Idempotent per IPA: a re-register (e.g. a forked child
/// overwriting the inherited PARENT host_addr with its private snapshot pointer)
/// replaces the entry.
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
fn register_shared_alias(b: AliasBacking) {
    mutate_external_alias_state(|replay, registry| {
        replay.retain(|(ipa, _, _, _)| *ipa != b.physical_ipa);
        replay.insert(replay_mapping_key(b));
        if let Some(entry) = registry
            .iter_mut()
            .find(|entry| entry.ipa == b.ipa && entry.ownership_scope == b.ownership_scope)
        {
            *entry = b;
        } else {
            registry.push(b);
        }
    });
}

/// Is the host backing of an alias entry actually mapped in THIS process? The
/// `alias_registry` is a process-global `static` COW-inherited across `fork(2)`,
/// so a forked child inherits entries whose `host_addr` names the PARENT's
/// mapping — a host VA that is NOT backed in the child (a different process's
/// address space). Resolving a guest syscall (e.g. a `read_futex_word`) through
/// such an entry and dereferencing `host_addr` is a carrick HOST SIGSEGV
/// (EXC_BAD_ACCESS) inside the child — the cpython multiprocessing FORKSERVER
/// SyncManager crash. `mincore` returns `-1/ENOMEM` iff the range has an
/// unmapped page, so it cheaply rejects a dead inherited backing. Only ever
/// called on the alias FALLBACK (after the per-thread `self.mappings` fast path
/// misses), never per guest instruction. Conservative: on any other mincore
/// outcome treat the backing as live (the caller's read still bounds-checks).
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
fn alias_backing_is_live(host_addr: usize) -> bool {
    if host_addr == 0 {
        return false;
    }
    // macOS `mincore` is NO USE here: it returns 0/success even for an unmapped
    // page or an outright gap address. Use `mach_vm_region`, which returns the
    // region AT OR AFTER the queried address — `host_addr` is mapped iff that
    // region actually contains it. (This is the same query the crash report's
    // "0x… is not in any region" annotation came from.)
    const VM_REGION_BASIC_INFO_64: i32 = 9;
    const VM_REGION_BASIC_INFO_COUNT_64: u32 = 9;
    unsafe extern "C" {
        fn mach_vm_region(
            target_task: libc::vm_map_t,
            address: *mut libc::mach_vm_address_t,
            size: *mut libc::mach_vm_size_t,
            flavor: i32,
            info: *mut i32,
            info_count: *mut u32,
            object_name: *mut libc::mach_port_t,
        ) -> libc::kern_return_t;
    }
    let mut addr = host_addr as libc::mach_vm_address_t;
    let mut size: libc::mach_vm_size_t = 0;
    let mut info = [0i32; 16];
    let mut count = VM_REGION_BASIC_INFO_COUNT_64;
    let mut obj: libc::mach_port_t = 0;
    // SAFETY: queries this task's VM map; reads no guest data. mach_task_self_ is
    // the stable task port.
    #[allow(deprecated)]
    let kr = unsafe {
        mach_vm_region(
            libc::mach_task_self_,
            &mut addr,
            &mut size,
            VM_REGION_BASIC_INFO_64,
            info.as_mut_ptr(),
            &mut count,
            &mut obj,
        )
    };
    kr == 0
        && (addr as usize) <= host_addr
        && host_addr < (addr as usize).saturating_add(size as usize)
}

/// Find the registered alias whose `hv_vm_map`'d IPA window contains `ipa`.
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
fn lookup_shared_alias(ipa: u64) -> Option<AliasBacking> {
    alias_registry()
        .lock()
        .iter()
        .find(|e| {
            ipa >= e.ipa
                && ipa < e.ipa.saturating_add(e.size as u64)
                && alias_backing_is_live(e.host_addr)
        })
        .copied()
}

/// Find the registered alias whose guest-VA window FULLY contains `[va, va+len)`.
/// The cross-thread fallback's IPA key (`translate_va`) reads this thread's
/// software stage-1 model, which can lack a freshly-`MAP_FIXED`-committed high-VA
/// arena page that a sibling vCPU installed — even though `add_alias` already
/// registered the backing here, keyed by guest VA. The VA key resolves it.
///
/// Two safety rules make this never resolve to the WRONG backing (the failure the
/// `mapping_index_for_range` doc warns about):
/// - **Whole range in ONE entry**: a buffer straddling two aliases returns `None`
///   (→ EFAULT), never a partial backing.
/// - **Newest-first** (`.rev()`): a Go arena page is covered by BOTH the PROT_NONE
///   reservation entry AND the later `MAP_FIXED` commit; the commit is registered
///   last, and `add_alias`/`map_aliased` register the IPA they install into stage-1
///   in the same order — so the newest entry is exactly the backing the guest's own
///   page tables use.
///
/// The caller gates on `!range_no_access` so a still-PROT_NONE reservation page
/// (uncommitted) EFAULTs even though the reservation entry would contain its VA.
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
fn alias_matches_process_scope(
    ownership_scope: AliasOwnershipScope,
    mm_root_slot: Option<(u64, u64)>,
) -> bool {
    match ownership_scope {
        AliasOwnershipScope::Global => true,
        AliasOwnershipScope::Root => mm_root_slot.is_none(),
        AliasOwnershipScope::MmRootSlot { base, size } => mm_root_slot == Some((base, size)),
    }
}

/// Whether an alias is private to the address space being replaced/retired.
/// Global aliases may still be referenced by another mm and are removed only
/// when their physical extent reaches its final reference.
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
fn alias_is_owned_by_process(
    ownership_scope: AliasOwnershipScope,
    mm_root_slot: Option<(u64, u64)>,
) -> bool {
    match (ownership_scope, mm_root_slot) {
        (AliasOwnershipScope::Root, None) => true,
        (AliasOwnershipScope::MmRootSlot { base, size }, Some(root_slot)) => {
            (base, size) == root_slot
        }
        (AliasOwnershipScope::Global, _)
        | (AliasOwnershipScope::Root, Some(_))
        | (AliasOwnershipScope::MmRootSlot { .. }, None) => false,
    }
}

/// Alias-registry entries owned by sibling vCPUs but absent from the forking
/// vCPU's local mapping ledger. The caller additionally checks the live stage-1
/// translation and backing lifetime before copying them.
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
fn missing_process_aliases(
    local_ipas: &std::collections::HashSet<u64>,
    aliases: &[AliasBacking],
    mm_root_slot: Option<(u64, u64)>,
) -> Vec<AliasBacking> {
    aliases
        .iter()
        .copied()
        .filter(|alias| {
            !local_ipas.contains(&alias.ipa)
                && alias_matches_process_scope(alias.ownership_scope, mm_root_slot)
        })
        .collect()
}

/// Whether a per-vCPU mapping row belongs in a new process's address-space
/// inventory. Boot mappings are structural. Dynamic aliases are lifetime
/// owners as well as lookup rows, so a retired row may remain in `mappings`
/// after munmap; only an exact live-registry publication makes it semantic.
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
/// Exact-identity key of one process-scoped alias publication: the four
/// fields `mapping_is_current_for_process_fork` matches. Fork-path callers
/// walk EVERY mapping and previously linear-scanned the alias registry per
/// mapping — O(mappings x aliases) per fork, the dominant term of the
/// fork-cost-grows-with-live-count pathology (35 ms/fork at 1000 live
/// processes; futex_cmp_requeue01's 1000-waiter phase starves on it). The
/// index makes one pass over the registry and answers each mapping in O(1).
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
type ProcessAliasKey = (u64, u64, usize, usize);

/// One-pass index of the process-scoped alias publications, keyed by
/// [`ProcessAliasKey`]. First occurrence wins, mirroring the linear scans'
/// `.find` semantics this replaces.
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
fn process_alias_index(
    aliases: &[AliasBacking],
    mm_root_slot: Option<(u64, u64)>,
) -> std::collections::HashMap<ProcessAliasKey, AliasBacking> {
    let mut index = std::collections::HashMap::with_capacity(aliases.len());
    for alias in aliases {
        if alias_matches_process_scope(alias.ownership_scope, mm_root_slot) {
            index
                .entry((alias.start, alias.ipa, alias.host_addr, alias.size))
                .or_insert(*alias);
        }
    }
    index
}

/// Index-backed [`mapping_is_current_for_process_fork`].
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
fn mapping_is_current_for_process_fork_indexed(
    mapping: &HvfMappedRegion,
    index: &std::collections::HashMap<ProcessAliasKey, AliasBacking>,
) -> bool {
    !mapping.is_dynamic_alias
        || index.contains_key(&(
            mapping.start,
            mapping.ipa,
            mapping.host_addr as usize,
            semantic_extent_size(mapping.start, mapping.end),
        ))
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
fn current_dynamic_alias_ipas(
    mappings: &[HvfMappedRegion],
    aliases: &[AliasBacking],
    mm_root_slot: Option<(u64, u64)>,
) -> std::collections::HashSet<u64> {
    let index = process_alias_index(aliases, mm_root_slot);
    mappings
        .iter()
        .filter(|mapping| {
            mapping.is_dynamic_alias && mapping_is_current_for_process_fork_indexed(mapping, &index)
        })
        .map(|mapping| mapping.ipa)
        .collect()
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
fn lookup_shared_alias_by_va(
    va: u64,
    len: usize,
    mm_root_slot: Option<(u64, u64)>,
) -> Option<AliasBacking> {
    let end = va.saturating_add(len as u64);
    alias_registry()
        .lock()
        .iter()
        .rev()
        .find(|e| {
            alias_matches_process_scope(e.ownership_scope, mm_root_slot)
                && va >= e.start
                && end <= e.start.saturating_add(e.size as u64)
                // Reject an entry whose backing is not mapped in THIS process
                // (a parent's host_addr COW-inherited into a forked child) —
                // dereferencing it would HOST-SIGSEGV the child. See
                // `alias_backing_is_live`.
                && alias_backing_is_live(e.host_addr.saturating_add((va - e.start) as usize))
        })
        .copied()
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
fn lookup_live_alias_by_va_any_scope(va: u64, len: usize) -> Option<AliasBacking> {
    let end = va.saturating_add(len as u64);
    alias_registry()
        .lock()
        .iter()
        .rev()
        .find(|entry| {
            va >= entry.start
                && end <= entry.start.saturating_add(entry.size as u64)
                && alias_backing_is_live(
                    entry.host_addr.saturating_add((va - entry.start) as usize),
                )
        })
        .copied()
}

/// Drop the index entry for any alias whose guest-VA window overlaps
/// `[va, va+len)` — called on a guest `munmap` of a high-VA alias (the only point
/// the backing is actually freed), BEFORE the stage-1 invalidate, so a stale
/// `host_addr` is never resolved after the OwnedHostMapping unmaps it. A thread
/// exit LEAKS the backing (`impl Drop for HvfVmState` `mem::forget`s
/// `self.mappings`), so no unregister is needed there — and critically MUST not
/// `munmap` it, since the buffer is shared with sibling threads + this registry.
/// Keyed on the VA `start` because `munmap` supplies a VA.
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
fn unregister_alias_entries(
    registry: &mut Vec<AliasBacking>,
    va: u64,
    len: usize,
    mm_root_slot: Option<(u64, u64)>,
) -> std::collections::BTreeSet<(u64, u64)> {
    let end = va.saturating_add(len as u64);
    let mut replacement = Vec::with_capacity(registry.len().saturating_add(1));
    let mut candidates = std::collections::BTreeSet::new();
    for entry in registry.drain(..) {
        let entry_end = entry.start.saturating_add(entry.size as u64);
        if !alias_matches_process_scope(entry.ownership_scope, mm_root_slot)
            || entry_end <= va
            || entry.start >= end
        {
            replacement.push(entry);
            continue;
        }
        candidates.insert((entry.physical_ipa, entry.physical_size as u64));
        if entry.start < va {
            replacement.push(AliasBacking {
                size: usize::try_from(va - entry.start).unwrap_or_default(),
                ..entry
            });
        }
        if entry_end > end {
            let delta = end.saturating_sub(entry.start);
            replacement.push(AliasBacking {
                start: end,
                ipa: entry.ipa.saturating_add(delta),
                host_addr: entry.host_addr.saturating_add(delta as usize),
                size: usize::try_from(entry_end - end).unwrap_or_default(),
                shared_key_offset: entry.shared_key_offset.saturating_add(delta),
                ..entry
            });
        }
    }
    *registry = replacement;
    candidates.retain(|&(physical_ipa, physical_size)| {
        !registry.iter().any(|entry| {
            alias_matches_process_scope(entry.ownership_scope, mm_root_slot)
                && (entry.physical_ipa, entry.physical_size as u64) == (physical_ipa, physical_size)
        })
    });
    candidates
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
fn retained_private_reuse_alias_fragment(
    registry: &[AliasBacking],
    va: u64,
    ipa: u64,
    len: usize,
    mm_root_slot: Option<(u64, u64)>,
) -> Option<AliasBacking> {
    if len == 0 {
        return None;
    }
    let end = va.checked_add(len as u64)?;
    let ipa_end = ipa.checked_add(len as u64)?;
    // An existing semantic fragment is already an exact lifetime owner. Do not
    // replace a wider entry with this one-page reuse observation.
    if registry.iter().any(|entry| {
        alias_matches_process_scope(entry.ownership_scope, mm_root_slot)
            && va >= entry.start
            && end <= entry.start.saturating_add(entry.size as u64)
            && entry.ipa.checked_add(va.saturating_sub(entry.start)) == Some(ipa)
    }) {
        return None;
    }

    let source = registry.iter().rev().find(|entry| {
        entry.sharing == GuestMappingSharing::Private
            && alias_matches_process_scope(entry.ownership_scope, mm_root_slot)
            && ipa >= entry.physical_ipa
            && ipa_end
                <= entry
                    .physical_ipa
                    .saturating_add(entry.physical_size as u64)
    })?;
    let physical_offset = usize::try_from(ipa.checked_sub(source.physical_ipa)?).ok()?;
    Some(AliasBacking {
        start: va,
        ipa,
        host_addr: source.physical_host_addr.checked_add(physical_offset)?,
        size: len,
        physical_ipa: source.physical_ipa,
        physical_host_addr: source.physical_host_addr,
        physical_size: source.physical_size,
        perms: source.perms,
        guest_writable: true,
        sharing: GuestMappingSharing::Private,
        ownership_scope: alias_ownership_scope(GuestMappingSharing::Private, mm_root_slot),
        inventory_backing: source.inventory_backing,
        shared_key_base: 0,
        shared_key_offset: 0,
        owner_generation: global_frame_host_owner_generation(
            source.physical_ipa,
            source.physical_size as u64,
        ),
    })
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
fn retired_alias_disarm_spans(
    registry: &[AliasBacking],
    va: u64,
    len: usize,
    mm_root_slot: Option<(u64, u64)>,
    retired_leases: &std::collections::BTreeSet<(u64, u64)>,
) -> Vec<CowArmedSpan> {
    let end = va.saturating_add(len as u64);
    registry
        .iter()
        .filter(|entry| {
            alias_matches_process_scope(entry.ownership_scope, mm_root_slot)
                && retired_leases.contains(&(entry.physical_ipa, entry.physical_size as u64))
        })
        .filter_map(|entry| {
            let start = entry.start.max(va);
            let entry_end = entry.start.saturating_add(entry.size as u64);
            let span_end = entry_end.min(end);
            (start < span_end).then(|| CowArmedSpan {
                va: start,
                len: usize::try_from(span_end - start).unwrap_or_default(),
                executable: false,
                kernel_only: false,
            })
        })
        .collect()
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
fn unregister_alias(
    va: u64,
    len: usize,
    mm_root_slot: Option<(u64, u64)>,
) -> std::collections::BTreeSet<(u64, u64)> {
    mutate_external_alias_state(|_, registry| {
        unregister_alias_entries(registry, va, len, mm_root_slot)
    })
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
fn clear_alias_registry() {
    mutate_external_alias_state(|_, registry| registry.clear());
}

/// Bounds lazy alias remaps per backing IPA, not per guest-run interval.
///
/// Go's pprof mapping test can touch many distinct MAP_SHARED file aliases
/// before issuing another syscall; a small global cap turns the ninth valid
/// alias into SIGSEGV. Repeated faults on the same backing still terminate.
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
#[derive(Default)]
struct AliasRemapLimiter {
    attempts_by_ipa: std::collections::HashMap<u64, u32>,
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
impl AliasRemapLimiter {
    const MAX_ATTEMPTS_PER_IPA: u32 = 8;

    fn allow(&mut self, ipa: u64) -> bool {
        let attempts = self.attempts_by_ipa.entry(ipa).or_default();
        if *attempts >= Self::MAX_ATTEMPTS_PER_IPA {
            return false;
        }
        *attempts += 1;
        true
    }
}

/// A sibling vCPU's mapping, published during a fork quiesce so the forking
/// thread can re-map the UNION of every sibling's regions into the rebuilt
/// PARENT VM — not just its own. Threads share ONE `hv_vm`, but `fork()` rebuilds
/// it from only the forking thread's `mappings`; a per-thread alias a SIBLING
/// established (e.g. a Go heap-arena chunk mmap'd at high-VA on that thread) is
/// otherwise dropped from the rebuilt VM and the parent translation-faults on it
/// (DC ZVA on a missing stage-2 entry — the concurrent-os/exec crash).
///
/// `host_addr`/`perms` are stored as `usize`/`u64` (not the raw pointer / MemPerms)
/// so the registry is `Send` across the publishing siblings and the consuming
/// forker. Safe because publication happens in `release_vcpu_for_fork`, after
/// which the sibling PARKS (holding its `OwnedHostMapping` alive) until the fork
/// completes — so the forker always re-maps a live backing (no use-after-free).
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
#[derive(Clone, Copy)]
struct SiblingForkMapping {
    start: u64,
    ipa: u64,
    physical_ipa: u64,
    end: u64,
    host_addr: usize,
    size: usize,
    physical_size: usize,
    perms: u64,
    is_dynamic_alias: bool,
    sharing: GuestMappingSharing,
    guest_writable: bool,
    shared_key_base: u64,
    shared_key_offset: u64,
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
fn sibling_fork_mappings() -> &'static parking_lot::Mutex<Vec<SiblingForkMapping>> {
    static CELL: std::sync::OnceLock<parking_lot::Mutex<Vec<SiblingForkMapping>>> =
        std::sync::OnceLock::new();
    CELL.get_or_init(|| parking_lot::Mutex::new(Vec::new()))
}

/// Drop all published sibling mappings. Called by the forker at quiesce start
/// (before kicking siblings) so each fork round starts from a clean set.
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
pub fn clear_sibling_fork_mappings() {
    sibling_fork_mappings().lock().clear();
}

#[cfg(not(all(target_os = "macos", target_arch = "aarch64")))]
pub fn clear_sibling_fork_mappings() {}

/// Publish a quiescing sibling's regions so the forker re-maps them into the
/// rebuilt parent VM.
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
fn publish_sibling_fork_mappings(regions: &[HvfMappedRegion]) {
    let mut reg = sibling_fork_mappings().lock();
    reg.reserve(regions.len());
    for m in regions {
        reg.push(SiblingForkMapping {
            start: m.start,
            ipa: m.ipa,
            physical_ipa: m.physical_ipa,
            end: m.end,
            host_addr: m.host_addr as usize,
            size: m.size,
            physical_size: m.physical_size,
            perms: u64::from(m.perms),
            is_dynamic_alias: m.is_dynamic_alias,
            sharing: m.sharing,
            guest_writable: m.guest_writable,
            shared_key_base: m.shared_key_base,
            shared_key_offset: m.shared_key_offset,
        });
    }
}

/// Process-global count of live HVF vCPUs (created minus destroyed). Pure
/// diagnostic: reported in the fork__quiesce phase-2 probe so a `carrick trace`
/// shows exactly how many vCPUs are alive when the forker calls hv_vm_destroy.
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
pub static VCPU_LIVE: std::sync::atomic::AtomicI64 = std::sync::atomic::AtomicI64::new(0);
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
pub(crate) static VCPU_CREATED_TOTAL: std::sync::atomic::AtomicU64 =
    std::sync::atomic::AtomicU64::new(0);
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
thread_local! {
    static THREAD_VCPU_CREATED_TOTAL: std::cell::Cell<u64> = const { std::cell::Cell::new(0) };
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
pub(crate) fn current_thread_vcpu_created_total() -> u64 {
    THREAD_VCPU_CREATED_TOTAL.get()
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
fn vcpu_created() {
    VCPU_LIVE.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    VCPU_CREATED_TOTAL.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    THREAD_VCPU_CREATED_TOTAL.set(THREAD_VCPU_CREATED_TOTAL.get().saturating_add(1));
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum VmCreateAdmission {
    Initial,
    ForkRebuild { vfork: bool },
    ExecveRebuild,
    SharedWaitResume,
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
impl VmCreateAdmission {
    fn probe_code(self) -> i32 {
        match self {
            Self::Initial => 0,
            Self::ForkRebuild { vfork: false } => 1,
            Self::ForkRebuild { vfork: true } => 2,
            Self::ExecveRebuild => 3,
            Self::SharedWaitResume => 4,
        }
    }

    /// Soft pre-throttle on concurrently-CREATING HVF VMs across a fork tree.
    /// This bounds VM/vCPU *creation* only (the pre-block window of a fork storm),
    /// NOT guest *execution* — execution is already bounded by the per-process M:N
    /// scheduler gate and the Darwin kernel time-slicing cores across processes.
    ///
    /// Measured via `hvf_fork_probe concurrent-ceiling` (E4,
    /// `docs/2026-07-08-hvf-residency-e4-evidence.md`): the ceiling is a **per-VM
    /// slot budget**, not a system-wide vCPU budget. Exactly **127** VMs
    /// materialize across separate processes before `hv_vm_create`/
    /// `hv_vcpu_create` returns `HV_NO_RESOURCES`, and that 127 held flat in five
    /// quiet-host configurations while `total_vcpus` scaled 127 → 254 → 508
    /// (`vcpus_per_vm` 1/2/4) and mapped memory scaled 0 → 16 → 64 MiB — i.e. 508
    /// concurrent vCPUs ran fine at 127 VMs, so a materialized vCPU is not what
    /// the ceiling counts. It is also NOT `hv_vm_get_max_vcpu_count()` (64), which
    /// is the per-VM max vCPU count, not a system total. The old cap (12, clamped
    /// from `hvf_cap_budget()` = 64 − reserve) was ~10× too low: it was sourced
    /// from the wrong number and starved suites that need dozens of
    /// simultaneously-alive processes (e.g. `ltp-fcntl36` needs ~36). An earlier
    /// "~126" reading is superseded by the five exact-127 runs; why it read one
    /// lower is undetermined (plausibly a 128-slot machine-wide table with one
    /// slot consumed elsewhere, or stray live VMs on that host).
    ///
    /// The true hard limit is discovered at runtime by `HV_NO_RESOURCES` and
    /// handled with park+retry backpressure (`create_with_no_resources_backpressure`);
    /// 120 is a soft pre-throttle margin a little under the measured 127 to leave
    /// headroom for other system VM consumers.
    const GLOBAL_VCPU_CEILING: usize = 120;

    /// Resident-VM budget for the fork gate: same soft margin under the
    /// measured ~126-concurrent-VM HVF ceiling as the vCPU-permit budget.
    const GLOBAL_VM_CEILING: usize = 120;

    fn global_permit_budget(self) -> Option<usize> {
        match self {
            Self::Initial | Self::SharedWaitResume | Self::ForkRebuild { vfork: false } => {
                Some(Self::GLOBAL_VCPU_CEILING)
            }
            Self::ForkRebuild { vfork: true } | Self::ExecveRebuild => None,
        }
    }
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
struct GlobalVcpuPermit {
    slot: usize,
    fd: libc::c_int,
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
struct GlobalVcpuPermitBackoff {
    next_ms: u64,
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
impl Default for GlobalVcpuPermitBackoff {
    fn default() -> Self {
        Self { next_ms: 1 }
    }
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
impl GlobalVcpuPermitBackoff {
    const MAX_MS: u64 = 50;

    fn next_delay(&mut self) -> std::time::Duration {
        let delay = self.next_ms;
        self.next_ms = self.next_ms.saturating_mul(2).min(Self::MAX_MS);
        std::time::Duration::from_millis(delay)
    }
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
#[derive(Default)]
struct GlobalVcpuPermitState {
    live: HashMap<u64, GlobalVcpuPermit>,
    pending: Vec<usize>,
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
fn global_vcpu_permits() -> &'static std::sync::Mutex<GlobalVcpuPermitState> {
    static PERMITS: std::sync::OnceLock<std::sync::Mutex<GlobalVcpuPermitState>> =
        std::sync::OnceLock::new();
    PERMITS.get_or_init(|| std::sync::Mutex::new(GlobalVcpuPermitState::default()))
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
fn close_global_vcpu_permit(permit: GlobalVcpuPermit) {
    unsafe {
        let _ = libc::close(permit.fd);
    }
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
fn ensure_global_vcpu_slot_dir() {
    let dir = c"/tmp/carrick-hvf-vcpu-slots";
    unsafe {
        let _ = libc::mkdir(dir.as_ptr(), 0o700);
    }
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
fn open_global_vcpu_slot(slot: usize) -> Option<libc::c_int> {
    let Ok(path) = std::ffi::CString::new(format!("/tmp/carrick-hvf-vcpu-slots/slot-{slot}"))
    else {
        return None;
    };
    let fd = unsafe { libc::open(path.as_ptr(), libc::O_RDWR | libc::O_CREAT, 0o600) };
    if fd < 0 {
        return None;
    }
    let rc = unsafe { libc::flock(fd, libc::LOCK_EX | libc::LOCK_NB) };
    if rc == 0 {
        Some(fd)
    } else {
        unsafe {
            let _ = libc::close(fd);
        }
        None
    }
}

/// Total time an admission-permit acquire may park before declaring the host
/// exhausted and returning [`TrapError::HostResourceExhausted`] — the bound
/// that turns the historical SILENT UNBOUNDED permit stall (the sigwait-shaped
/// procladder_mt red: 160 blocked children, zero output, zero trace lines)
/// into a loud, typed error the fork path degrades to guest `EAGAIN`.
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
const ADMISSION_PERMIT_MAX_WAIT: std::time::Duration = std::time::Duration::from_secs(60);

/// Emit a gated admission-trace line on the FIRST park and every ~100th.
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
const ADMISSION_PERMIT_TRACE_EVERY: u32 = 100;

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
fn trace_permit_park(what: &str, budget: usize, parks: u32, waited: std::time::Duration) {
    if admission_trace_enabled()
        && (parks == 1 || parks.is_multiple_of(ADMISSION_PERMIT_TRACE_EVERY))
    {
        eprintln!(
            "[hvf-admission pid={}] {what} budget {budget} full; park #{parks} (waited {waited:?})",
            unsafe { libc::getpid() },
        );
    }
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
fn permit_exhausted(
    what: &str,
    budget: usize,
    parks: u32,
    waited: std::time::Duration,
) -> TrapError {
    if admission_trace_enabled() {
        eprintln!(
            "[hvf-admission pid={}] {what} budget {budget} still full after {waited:?} / {parks} park(s); host exhausted, propagating",
            unsafe { libc::getpid() },
        );
    }
    TrapError::HostResourceExhausted {
        what: format!("{what}: budget {budget} still full after {waited:?} / {parks} park(s)"),
    }
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
fn acquire_global_vcpu_permit(budget: usize) -> Result<GlobalVcpuPermit, TrapError> {
    // `hv_vm_get_max_vcpu_count` is a per-VM ceiling. A fork storm creates many
    // one-vCPU VMs, and HVF can exhaust host resources well below that per-VM count.
    // Admission classes choose the budget: plain fork needs the physical-core M:N
    // budget so forked waiters can reach their blocking syscall, while shared-wait
    // resume drains already-parked processes through a smaller gate.
    let budget = budget.max(1);
    ensure_global_vcpu_slot_dir();
    let mut backoff = GlobalVcpuPermitBackoff::default();
    let start = std::time::Instant::now();
    let mut parks: u32 = 0;
    loop {
        let mut state = global_vcpu_permits()
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        for slot in 0..budget {
            if state.pending.contains(&slot) || state.live.values().any(|p| p.slot == slot) {
                continue;
            }
            let Some(fd) = open_global_vcpu_slot(slot) else {
                continue;
            };
            state.pending.push(slot);
            return Ok(GlobalVcpuPermit { slot, fd });
        }
        drop(state);
        if start.elapsed() >= ADMISSION_PERMIT_MAX_WAIT {
            return Err(permit_exhausted(
                "vcpu permit (flock)",
                budget,
                parks,
                start.elapsed(),
            ));
        }
        parks += 1;
        trace_permit_park("vcpu permit (flock)", budget, parks, start.elapsed());
        std::thread::sleep(backoff.next_delay());
    }
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
fn forget_pending_global_vcpu_permit(state: &mut GlobalVcpuPermitState, slot: usize) {
    if let Some(pos) = state.pending.iter().position(|&s| s == slot) {
        state.pending.swap_remove(pos);
    }
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
fn register_global_vcpu_permit(vcpu_id: u64, permit: GlobalVcpuPermit) {
    let mut state = global_vcpu_permits()
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    forget_pending_global_vcpu_permit(&mut state, permit.slot);
    if let Some(old) = state.live.insert(vcpu_id, permit) {
        close_global_vcpu_permit(old);
    }
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
fn release_unregistered_global_vcpu_permit(permit: GlobalVcpuPermit) {
    let mut state = global_vcpu_permits()
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    forget_pending_global_vcpu_permit(&mut state, permit.slot);
    drop(state);
    close_global_vcpu_permit(permit);
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
fn release_global_vcpu_permit(vcpu_id: u64) {
    let permit = global_vcpu_permits()
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .live
        .remove(&vcpu_id);
    if let Some(permit) = permit {
        close_global_vcpu_permit(permit);
    }
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
fn reset_global_vcpu_permits_after_fork_child() {
    let mut state = global_vcpu_permits()
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    let inherited = std::mem::take(&mut state.live);
    state.pending.clear();
    drop(state);
    for (_, permit) in inherited {
        close_global_vcpu_permit(permit);
    }
}

// ===========================================================================
// Atomic vCPU admission permit (Option 3, Task 1) — the DEFAULT admission path.
// The flock permit above remains as a fallback, selectable with
// `CARRICK_HVF_ATOMIC_PERMIT=0` (`false`/`no` also accepted).
//
// The flock permit above gets its cross-process death-reclaim for free from the
// kernel (a slot lock releases when the holder's last fd closes on exit). A bare
// shared counter does NOT — that was the 3b leak (`cur=4 live_len=0`). So here
// OWNERSHIP is the source of truth: every admitted count IS a generation-stamped
// slot in a fork-shared table, published owner-first, so a crash between acquire
// and vcpu_create leaves a reclaimable owner record (reaped by Tasks 2/3). There
// is NO separate live counter; `occupied()` is DERIVED from non-free slots.
// ===========================================================================

/// Packed-slot bit layout for one `AtomicU64` entry in the shared table:
///
/// ```text
///   bits 63..62  state       (2 bits: 0=free, 1=acquiring, 2=registered)
///   bits 61..32  generation  (30 bits, from the shared monotonic counter)
///   bits 31..0   owner_pid    (32 bits)
/// ```
///
/// A `MAP_ANON` zero-filled word is therefore `state=free, gen=0, pid=0` — a
/// valid empty slot — and no live slot is ever all-zero (state is never free).
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
mod atomic_permit_slot {
    // Sized to cover `GLOBAL_VCPU_CEILING` (120) with headroom so the DEFAULT
    // atomic admission path honors the full measured system-wide vCPU budget;
    // at 64 the soft pre-throttle would silently clamp to 64 concurrent creators
    // (well below the real ~126 ceiling). Auto-sizes the shared table's mmap
    // (`size_of::<SharedPermitTable>()`) and every slot scan.
    pub(super) const MAX_SLOTS: usize = 128;

    pub(super) const STATE_SHIFT: u32 = 62;
    pub(super) const STATE_MASK: u64 = 0b11 << STATE_SHIFT;
    pub(super) const GEN_SHIFT: u32 = 32;
    pub(super) const GEN_BITS: u32 = 30;
    pub(super) const GEN_MASK: u64 = ((1u64 << GEN_BITS) - 1) << GEN_SHIFT;
    pub(super) const GEN_VALUE_MASK: u32 = (1u32 << GEN_BITS) - 1;
    pub(super) const PID_MASK: u64 = 0xFFFF_FFFF;

    pub(super) const STATE_FREE: u64 = 0;
    pub(super) const STATE_ACQUIRING: u64 = 1;
    pub(super) const STATE_REGISTERED: u64 = 2;

    /// A fully-free slot word (all zero).
    pub(super) const FREE_WORD: u64 = 0;

    pub(super) fn pack(state: u64, pid: u32, generation: u32) -> u64 {
        (state << STATE_SHIFT)
            | ((u64::from(generation) & ((1u64 << GEN_BITS) - 1)) << GEN_SHIFT)
            | u64::from(pid)
    }

    pub(super) fn state_of(word: u64) -> super::SlotState {
        match (word & STATE_MASK) >> STATE_SHIFT {
            STATE_FREE => super::SlotState::Free,
            STATE_ACQUIRING => super::SlotState::Acquiring,
            STATE_REGISTERED => super::SlotState::Registered,
            _ => super::SlotState::Free, // unused 0b11 encoding
        }
    }

    pub(super) fn pid_of(word: u64) -> u32 {
        (word & PID_MASK) as u32
    }

    pub(super) fn gen_of(word: u64) -> u32 {
        ((word & GEN_MASK) >> GEN_SHIFT) as u32
    }
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SlotState {
    Free,
    Acquiring,
    Registered,
}

/// A held atomic permit: proof that exactly one generation-stamped slot is owned
/// by `owner_pid`. `Copy` so events/tokens can be compared without consuming.
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
#[derive(Debug, Clone, Copy)]
struct PermitToken {
    slot: u16,
    generation: u32,
    owner_pid: u32,
}

/// The fork-shared slot table itself, laid out in the `MAP_ANON | MAP_SHARED`
/// page. `#[repr(C)]` so parent and child agree on the layout; every field is an
/// atomic so all cross-process access is well-defined. `next_generation` hands
/// out a monotonic (30-bit-wrapping) generation per acquire so a freed-then-
/// reused slot never collides with a stale token/event.
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
#[repr(C)]
struct SharedPermitTable {
    magic: std::sync::atomic::AtomicU32,
    version: std::sync::atomic::AtomicU32,
    next_generation: std::sync::atomic::AtomicU32,
    // `#[repr(C)]` inserts 4 bytes of padding here to 8-align `slots`.
    slots: [std::sync::atomic::AtomicU64; atomic_permit_slot::MAX_SLOTS],
}

/// Process-local handle onto the fork-shared [`SharedPermitTable`].
///
/// `table` is the shared page's address — identical in parent and child because
/// the region is `MAP_SHARED` and created before any guest fork. `local` is a
/// PROCESS-PRIVATE `vcpu_id -> PermitToken` map (fork copies it, and the child
/// clears it via [`PermitRegion::reset_local_after_fork_child`]) — it is the
/// authority for token-guarded release: only a `vcpu_id` that registered a token
/// can free the shared slot it named.
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
struct PermitRegion {
    table: usize,
    local: std::sync::Mutex<HashMap<u64, PermitToken>>,
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
impl PermitRegion {
    /// mmap a fresh zero-filled shared table and publish its header. Used only
    /// for injectable test regions; the process-global table lives in the
    /// carrick-kernel arena.
    #[cfg(test)]
    fn map_private_table_for_tests() -> usize {
        use std::sync::atomic::Ordering;
        let size = std::mem::size_of::<SharedPermitTable>();
        // SAFETY: MAP_ANON pages are zero-filled, so the region is a valid
        // `SharedPermitTable` with every slot `FREE_WORD`. MAP_SHARED + created
        // before any guest fork makes the mapping (and its address) inherited by
        // every fork child, so all processes share one slot table.
        let ptr = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                size,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_ANON | libc::MAP_SHARED,
                -1,
                0,
            )
        };
        assert!(
            ptr != libc::MAP_FAILED,
            "mmap(MAP_ANON|MAP_SHARED) for the vCPU permit table failed"
        );
        // SAFETY: `ptr` is a live, page-aligned, zero-filled mapping of exactly
        // `size_of::<SharedPermitTable>()` bytes, kept for the process lifetime.
        let table = unsafe { &*(ptr as *const SharedPermitTable) };
        // Generations start at 1 so 0 is reserved for "no owner".
        table.next_generation.store(1, Ordering::Relaxed);
        table
            .version
            .store(carrick_kernel::arena::PERMIT_VERSION, Ordering::Relaxed);
        // Publish the magic last (Release) so a reader that sees it also sees the
        // initialized header.
        table
            .magic
            .store(carrick_kernel::arena::PERMIT_MAGIC, Ordering::Release);
        ptr as usize
    }

    fn new_shared_global() -> PermitRegion {
        let arena = carrick_kernel::arena::KernelArena::global();
        PermitRegion {
            table: &arena.layout().permits as *const _ as usize,
            local: std::sync::Mutex::new(HashMap::new()),
        }
    }

    /// Same as [`Self::new_shared_global`] but over the arena's resident-VM
    /// slot section. One slot per live HVF VM, claimed/freed at the actual
    /// `hv_vm_create`/`hv_vm_destroy` transitions; occupancy is DERIVED from
    /// the slots (no separate counter to drift), and the death reaper
    /// reclaims a dead owner's slot exactly like a permit slot.
    fn new_shared_global_vm() -> PermitRegion {
        let arena = carrick_kernel::arena::KernelArena::global();
        PermitRegion {
            table: &arena.layout().vm_slots as *const _ as usize,
            local: std::sync::Mutex::new(HashMap::new()),
        }
    }

    fn table(&self) -> &SharedPermitTable {
        // SAFETY: `self.table` is either the arena permit section or a test-only
        // private mapping. Both are live mappings for the process lifetime; fork
        // children inherit the same VA.
        unsafe { &*(self.table as *const SharedPermitTable) }
    }

    /// DERIVED occupancy: the count of non-free slots across the whole fork tree.
    /// There is deliberately no separate `live` counter to drift from this.
    ///
    /// These per-slot loads are `SeqCst`, not `Acquire`, to forbid a
    /// store-buffering (SB) over-admit: two acquirers racing on DIFFERENT
    /// slots i != j each publish their own claim with a store, then read the
    /// other's slot to check the budget. With only `AcqRel`/`Acquire` (no
    /// total store order) each can observe the other's slot as still-free —
    /// both claims land, both pass the budget check, and occupancy transiently
    /// exceeds `budget`. `SeqCst` here plus `SeqCst` on the claim CAS's success
    /// case (below) puts both operations in one global total order, so at
    /// least one racer's occupancy scan is guaranteed to see the other's
    /// already-published claim and back out.
    fn occupied(&self) -> usize {
        use std::sync::atomic::Ordering;
        self.table()
            .slots
            .iter()
            .filter(|s| atomic_permit_slot::state_of(s.load(Ordering::SeqCst)) != SlotState::Free)
            .count()
    }

    /// Single acquire attempt. Publishes an OWNED slot FIRST (a crash after this
    /// is reclaimable), THEN counts occupancy: if the claim pushed occupancy over
    /// `budget`, it CASes that exact `(slot, gen)` back to free and returns `None`
    /// so the caller backs off. Returns `None` (no leak) on a full table too.
    ///
    /// The claim CAS's success ordering is `SeqCst` (paired with the `SeqCst`
    /// loads in `occupied()`) specifically to forbid the store-buffering
    /// over-admit race: with plain `AcqRel`/`Acquire`, two threads claiming
    /// slots i != j can each fail to observe the other's just-published claim
    /// when scanning for occupancy, so both slip past the `budget` check.
    /// `SeqCst` on both sides puts every claim-store and occupancy-load into
    /// one total order, so at least one of the two racers is guaranteed to
    /// see the other's slot occupied and back out.
    fn acquire(&self, budget: usize, pid: u32) -> Option<PermitToken> {
        use std::sync::atomic::Ordering;
        let budget = budget.max(1);
        let table = self.table();
        for (idx, slot) in table.slots.iter().enumerate() {
            let cur = slot.load(Ordering::Acquire);
            if atomic_permit_slot::state_of(cur) != SlotState::Free {
                continue;
            }
            let generation = table.next_generation.fetch_add(1, Ordering::AcqRel)
                & atomic_permit_slot::GEN_VALUE_MASK;
            let claimed =
                atomic_permit_slot::pack(atomic_permit_slot::STATE_ACQUIRING, pid, generation);
            if slot
                .compare_exchange(cur, claimed, Ordering::SeqCst, Ordering::Acquire)
                .is_err()
            {
                // Lost this slot to a concurrent acquirer; try the next free one.
                continue;
            }
            // An owned slot now exists; count occupancy (which includes it).
            if self.occupied() > budget {
                // Over budget: undo THIS exact claim and let the caller back off.
                let _ = slot.compare_exchange(
                    claimed,
                    atomic_permit_slot::FREE_WORD,
                    Ordering::AcqRel,
                    Ordering::Acquire,
                );
                return None;
            }
            return Some(PermitToken {
                slot: idx as u16,
                generation,
                owner_pid: pid,
            });
        }
        None
    }

    /// Transition `acquiring -> registered` for the same `(pid, gen)` and record
    /// `vcpu_id -> token` locally. The local entry is the release authority; the
    /// shared transition is best-effort (an acquiring slot already counts as
    /// occupied, so a lost race here cannot drop the count).
    fn register(&self, vcpu_id: u64, token: PermitToken) {
        use std::sync::atomic::Ordering;
        let slot = &self.table().slots[token.slot as usize];
        let acquiring = atomic_permit_slot::pack(
            atomic_permit_slot::STATE_ACQUIRING,
            token.owner_pid,
            token.generation,
        );
        let registered = atomic_permit_slot::pack(
            atomic_permit_slot::STATE_REGISTERED,
            token.owner_pid,
            token.generation,
        );
        let _ = slot.compare_exchange(acquiring, registered, Ordering::AcqRel, Ordering::Acquire);
        self.local
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .insert(vcpu_id, token);
    }

    /// Token-guarded release: only frees the shared slot if THIS `vcpu_id` holds
    /// a locally-recorded token. An unregistered sibling teardown is a no-op on
    /// the shared table (mirrors the flock `live`-set guard).
    fn release_token(&self, vcpu_id: u64) {
        let token = self
            .local
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .remove(&vcpu_id);
        if let Some(token) = token {
            self.free_exact(token);
        }
    }

    /// Free a slot iff it still holds this exact `(owner_pid, generation)` — the
    /// generation guard: a stale token or a late death event for a reused slot
    /// (now owned by a newer generation) will not match and cannot free it.
    fn free_exact(&self, token: PermitToken) -> bool {
        use std::sync::atomic::Ordering;
        let slot = &self.table().slots[token.slot as usize];
        loop {
            let cur = slot.load(Ordering::Acquire);
            if atomic_permit_slot::state_of(cur) == SlotState::Free
                || atomic_permit_slot::pid_of(cur) != token.owner_pid
                || atomic_permit_slot::gen_of(cur)
                    != (token.generation & atomic_permit_slot::GEN_VALUE_MASK)
            {
                return false;
            }
            match slot.compare_exchange_weak(
                cur,
                atomic_permit_slot::FREE_WORD,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => return true,
                Err(_) => continue,
            }
        }
    }

    /// Release a token that was acquired but never registered against a `vcpu_id`
    /// (VM- or vcpu-create failed after acquire). Frees the exact acquiring slot.
    fn release_unregistered(&self, token: PermitToken) {
        self.free_exact(token);
    }

    /// Reclaim (free) every non-free slot owned by `pid` — optionally restricted
    /// to a single `generation`. Used by the death-reclaim supervisor and the
    /// cooperative fork-child exit path (Tasks 2/3). Returns the number freed.
    #[allow(dead_code)] // consumed by the Task 2/3 reaper + cooperative exit.
    fn reclaim_owner(&self, pid: u32, generation: Option<u32>) -> usize {
        use std::sync::atomic::Ordering;
        let mut freed = 0;
        for slot in self.table().slots.iter() {
            loop {
                let cur = slot.load(Ordering::Acquire);
                if atomic_permit_slot::state_of(cur) == SlotState::Free
                    || atomic_permit_slot::pid_of(cur) != pid
                {
                    break;
                }
                if let Some(g) = generation {
                    if atomic_permit_slot::gen_of(cur) != (g & atomic_permit_slot::GEN_VALUE_MASK) {
                        break;
                    }
                }
                if slot
                    .compare_exchange_weak(
                        cur,
                        atomic_permit_slot::FREE_WORD,
                        Ordering::AcqRel,
                        Ordering::Acquire,
                    )
                    .is_ok()
                {
                    freed += 1;
                    break;
                }
                // CAS lost to a concurrent mutator; re-check this slot.
            }
        }
        freed
    }

    /// Fork-child reset: drop the inherited local token map WITHOUT touching any
    /// shared slot. The inherited tokens name the PARENT's live vCPUs; the shared
    /// (MAP_SHARED) slots still belong to the parent and must not be freed here.
    fn reset_local_after_fork_child(&self) {
        self.local.lock().unwrap_or_else(|e| e.into_inner()).clear();
    }

    /// Cooperative release of THIS process's atomic permits (Task 3). Called from
    /// the HVF engine's `process_exit_cleanup` on the exiting fork-child's own
    /// thread, BEFORE `_exit` skips Rust drops — the fast path that shrinks the
    /// churn window instead of waiting for the root reaper backstop.
    ///
    /// Precise + idempotent: it DRAINS the process-local token map and frees each
    /// named slot with the generation-guarded [`Self::free_exact`], so
    /// - a slot a normal `vcpu_destroyed` already freed is gone from the map (no
    ///   entry → nothing to free);
    /// - a slot the supervisor already reclaimed (now `Free`, or reused under an
    ///   advanced generation) fails the guard in `free_exact` → no double-free;
    /// - a second call finds an empty map → frees nothing.
    ///
    /// It can only free slots THIS process registered: after a fork the child
    /// cleared the inherited map via [`Self::reset_local_after_fork_child`] and
    /// re-acquired its own, so the map never names the PARENT's slots. Returns the
    /// number of slots actually freed (for tests/diagnostics).
    fn cooperative_release_local(&self) -> usize {
        let tokens: Vec<PermitToken> = {
            let mut map = self.local.lock().unwrap_or_else(|e| e.into_inner());
            map.drain().map(|(_, token)| token).collect()
        };
        tokens.iter().filter(|t| self.free_exact(**t)).count()
    }

    /// Diagnostic slot-state read (used by tests and the Task 2 supervisor).
    #[allow(dead_code)]
    fn slot_state(&self, slot: u16) -> SlotState {
        use std::sync::atomic::Ordering;
        atomic_permit_slot::state_of(self.table().slots[slot as usize].load(Ordering::Acquire))
    }

    #[cfg(test)]
    fn new_anon_for_test() -> PermitRegion {
        PermitRegion {
            table: Self::map_private_table_for_tests(),
            local: std::sync::Mutex::new(HashMap::new()),
        }
    }

    #[cfg(test)]
    fn local_token(&self, vcpu_id: u64) -> Option<PermitToken> {
        self.local
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get(&vcpu_id)
            .copied()
    }

    #[cfg(test)]
    fn force_owner_for_test(&self, slot: u16, pid: u32, generation: u32) {
        use std::sync::atomic::Ordering;
        let s = &self.table().slots[slot as usize];
        let cur = s.load(Ordering::Acquire);
        let state = (cur & atomic_permit_slot::STATE_MASK) >> atomic_permit_slot::STATE_SHIFT;
        s.store(
            atomic_permit_slot::pack(state, pid, generation),
            Ordering::Release,
        );
    }

    #[cfg(test)]
    fn try_free_exact_for_test(&self, token: PermitToken) -> bool {
        self.free_exact(token)
    }

    #[cfg(test)]
    fn table_addr_for_test(&self) -> usize {
        self.table
    }
}

/// Bridge the fork-shared slot table to the root death-reclaim supervisor
/// ([`crate::vcpu_permit_reaper`]). The reaper only ever needs the occupied
/// owners and a generation-guarded reclaim, so it works in `(pid, generation)`
/// tuples and never names the private slot types.
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
impl crate::vcpu_permit_reaper::PermitReclaimSource for PermitRegion {
    fn owner_slots(&self) -> Vec<(u32, u32)> {
        use std::sync::atomic::Ordering;
        let mut owners = Vec::new();
        for slot in self.table().slots.iter() {
            let word = slot.load(Ordering::SeqCst);
            if atomic_permit_slot::state_of(word) != SlotState::Free {
                owners.push((
                    atomic_permit_slot::pid_of(word),
                    atomic_permit_slot::gen_of(word),
                ));
            }
        }
        owners
    }

    fn reclaim(&self, pid: u32, generation: u32) -> usize {
        // `Some(generation)` is the generation guard: a late death event for a
        // dead owner cannot free a NEW slot held by a reused pid.
        self.reclaim_owner(pid, Some(generation))
    }
}

/// Start the root's atomic-permit death-reclaim supervisor (Task 2). The thin
/// re-export wired from `HvfHostBackend::pre_loop_setup`; idempotent, and it
/// binds the supervisor to the process-global permit region so the daemon frees
/// the slots of any owner that dies without a cooperative release.
/// Both slot tables feed ONE reaper: pid death must reclaim the dead owner's
/// vCPU-permit slots AND its resident-VM slot.
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
struct DualReclaimSource(&'static PermitRegion, &'static PermitRegion);

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
impl crate::vcpu_permit_reaper::PermitReclaimSource for DualReclaimSource {
    fn owner_slots(&self) -> Vec<(u32, u32)> {
        let mut owners = self.0.owner_slots();
        owners.extend(self.1.owner_slots());
        owners
    }
    fn reclaim(&self, pid: u32, generation: u32) -> usize {
        self.0.reclaim(pid, generation) + self.1.reclaim(pid, generation)
    }
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
pub fn start_vcpu_permit_reaper() {
    static DUAL: std::sync::OnceLock<DualReclaimSource> = std::sync::OnceLock::new();
    crate::vcpu_permit_reaper::spawn_reaper(
        DUAL.get_or_init(|| DualReclaimSource(permit_region(), vm_residency_region())),
    );
}

/// The process-global permit region. Initialized lazily on first use, but the
/// FIRST use is the `Initial` admission acquire during initial-VM creation, which
/// runs before the guest can execute any `fork` — so the region always exists,
/// `MAP_SHARED`, before any guest fork inherits it.
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
fn permit_region() -> &'static PermitRegion {
    static REGION: std::sync::OnceLock<PermitRegion> = std::sync::OnceLock::new();
    REGION.get_or_init(PermitRegion::new_shared_global)
}

/// The process-global resident-VM region. Same fork-inheritance property as
/// `permit_region`: first touched during initial-VM creation, before any
/// guest fork.
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
fn vm_residency_region() -> &'static PermitRegion {
    static REGION: std::sync::OnceLock<PermitRegion> = std::sync::OnceLock::new();
    REGION.get_or_init(PermitRegion::new_shared_global_vm)
}

/// The process-local registration key for THE resident VM (one VM per
/// process). `u64::MAX` cannot collide with an HVF vcpu_id in the shared
/// local map.
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
const VM_RESIDENCY_LOCAL_KEY: u64 = u64::MAX;

/// Record "this process now holds a live HVF VM". Called from the single
/// create funnel (`create_vm_with_admission` Ok arm). Recording is
/// UNCONDITIONAL (budget = MAX_SLOTS): the VM already exists; the budget is
/// enforced only by the fork-admission PROBE. A full table (impossible in
/// practice: 128 slots > the ~127-VM hard ceiling) logs and under-counts by
/// one rather than failing the create.
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
fn record_vm_resident() {
    if !atomic_permit_enabled() {
        return; // flock fallback: no residency table; the gate skips the VM probe too
    }
    let region = vm_residency_region();
    // A stale prior registration (should not happen: one VM per process,
    // destroy paths release first) would leak a slot until death-reclaim;
    // release defensively so the table can never double-count one process.
    region.release_token(VM_RESIDENCY_LOCAL_KEY);
    match region.acquire(atomic_permit_slot::MAX_SLOTS, std::process::id()) {
        Some(token) => region.register(VM_RESIDENCY_LOCAL_KEY, token),
        None => eprintln!(
            "[hvf-admission pid={}] resident-VM table full; VM unrecorded (fork gate will under-count by one)",
            unsafe { libc::getpid() }
        ),
    }
}

/// Record "this process's HVF VM is gone". Called after each SUCCESSFUL
/// `hv_vm_destroy`. Idempotent (token-guarded).
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
fn record_vm_released() {
    crate::probes::vm_lifecycle(3, -1);
    if !atomic_permit_enabled() {
        return;
    }
    vm_residency_region().release_token(VM_RESIDENCY_LOCAL_KEY);
}

/// Explicitly retire the one persistent HVPatch VM after every guest vCPU has
/// left the threaded loop. The VM wrapper is `ManuallyDrop`, so relying on host
/// process death would leave no authoritative destroy-success boundary.
pub fn destroy_persistent_vm_at_run_terminal() -> Result<(), TrapError> {
    crate::probes::vm_lifecycle(2, -1);
    let rc = unsafe { inventory_hv_vm_destroy() };
    if rc != 0 {
        return Err(TrapError::Hypervisor(format!(
            "terminal hv_vm_destroy rc={rc:#x}"
        )));
    }
    record_vm_released();
    Ok(())
}

/// Whether the atomic slot-table admission permit is active; cached once.
///
/// The atomic permit is the DEFAULT: it is enabled UNLESS
/// `CARRICK_HVF_ATOMIC_PERMIT` is explicitly set to a falsey value
/// (`0`/`false`/`no`, case-insensitive), which selects the legacy flock
/// permit path (byte-for-byte unchanged) as a fallback. Unset → atomic on.
/// `=1` (or any other value) → atomic on.
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
pub fn atomic_permit_enabled() -> bool {
    use std::sync::atomic::{AtomicU8, Ordering};
    static FLAG: AtomicU8 = AtomicU8::new(0);
    match FLAG.load(Ordering::Relaxed) {
        1 => true,
        2 => false,
        _ => {
            let on = atomic_permit_enabled_from_env(
                std::env::var("CARRICK_HVF_ATOMIC_PERMIT").ok().as_deref(),
            );
            FLAG.store(if on { 1 } else { 2 }, Ordering::Relaxed);
            on
        }
    }
}

/// Pure env → enabled mapping for [`atomic_permit_enabled`], factored out so it
/// can be unit-tested without touching the process-global `FLAG` cache or the
/// (unsafe, in edition 2024) `set_var`. Atomic is the default: enabled unless
/// the value is an explicit falsey token (`0`/`false`/`no`, case-insensitive).
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
fn atomic_permit_enabled_from_env(val: Option<&str>) -> bool {
    match val {
        Some(v) => !matches!(v.trim().to_ascii_lowercase().as_str(), "0" | "false" | "no"),
        None => true,
    }
}

/// Blocking acquire against the atomic slot table: retry the single-attempt
/// [`PermitRegion::acquire`] with the same exponential backoff as the flock path
/// until a slot is admitted, bounded at [`ADMISSION_PERMIT_MAX_WAIT`] like the
/// flock analogue [`acquire_global_vcpu_permit`].
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
fn acquire_atomic_vcpu_permit(budget: usize) -> Result<PermitToken, TrapError> {
    let region = permit_region();
    let pid = std::process::id();
    let mut backoff = GlobalVcpuPermitBackoff::default();
    let start = std::time::Instant::now();
    let mut parks: u32 = 0;
    loop {
        if let Some(token) = region.acquire(budget, pid) {
            return Ok(token);
        }
        if start.elapsed() >= ADMISSION_PERMIT_MAX_WAIT {
            return Err(permit_exhausted(
                "vcpu permit (atomic)",
                budget,
                parks,
                start.elapsed(),
            ));
        }
        parks += 1;
        trace_permit_park("vcpu permit (atomic)", budget, parks, start.elapsed());
        std::thread::sleep(backoff.next_delay());
    }
}

/// A held admission permit, either flock (default) or atomic (flag-gated). It
/// flows from `create_vm_with_admission` through `create_vcpu_with_permit` where
/// it is registered against the created `vcpu_id` (or released on failure).
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
enum HeldPermit {
    Flock(GlobalVcpuPermit),
    Atomic(PermitToken),
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
fn acquire_admission_permit(budget: usize) -> Result<HeldPermit, TrapError> {
    if atomic_permit_enabled() {
        Ok(HeldPermit::Atomic(acquire_atomic_vcpu_permit(budget)?))
    } else {
        Ok(HeldPermit::Flock(acquire_global_vcpu_permit(budget)?))
    }
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
fn register_admission_permit(vcpu_id: u64, permit: HeldPermit) {
    match permit {
        HeldPermit::Flock(permit) => register_global_vcpu_permit(vcpu_id, permit),
        HeldPermit::Atomic(token) => permit_region().register(vcpu_id, token),
    }
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
fn release_unregistered_admission_permit(permit: HeldPermit) {
    match permit {
        HeldPermit::Flock(permit) => release_unregistered_global_vcpu_permit(permit),
        HeldPermit::Atomic(token) => permit_region().release_unregistered(token),
    }
}

/// Dispatch a normal `vcpu_destroyed` release to whichever permit path is active.
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
fn release_admission_permit_for_vcpu(vcpu_id: u64) {
    if atomic_permit_enabled() {
        permit_region().release_token(vcpu_id);
    } else {
        release_global_vcpu_permit(vcpu_id);
    }
}

/// Dispatch the fork-child reset to whichever permit path is active.
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
fn reset_admission_permits_after_fork_child() {
    carrick_observability::vm_lifecycle::reset_after_fork_child();
    if atomic_permit_enabled() {
        permit_region().reset_local_after_fork_child();
        vm_residency_region().reset_local_after_fork_child();
    } else {
        reset_global_vcpu_permits_after_fork_child();
    }
}

/// Cooperative fast-path release of THIS process's atomic permit slots, invoked
/// from the HVF engine's `process_exit_cleanup` (Task 3) before a fork-child (or
/// signal-death) `_exit` skips Rust drops. No-op unless the atomic permit path is
/// active — on the default flock path the permit is fd-lifetime-bound, so the
/// engine hook stays the historical no-op. Idempotent with the token-guarded
/// `vcpu_destroyed` release and the root reaper's `reclaim_owner` (both are
/// generation-guarded). Returns the number of slots freed (for tests).
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
pub fn cooperative_release_atomic_permit() -> usize {
    if !atomic_permit_enabled() {
        return 0;
    }
    permit_region().cooperative_release_local() + vm_residency_region().cooperative_release_local()
}

/// True when park+retry admission tracing is requested (`CARRICK_HVF_ADMISSION_TRACE`).
/// Cached once; park+retry is rare, so this stays off the hot path.
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
fn admission_trace_enabled() -> bool {
    static ON: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *ON.get_or_init(|| std::env::var_os("CARRICK_HVF_ADMISSION_TRACE").is_some())
}

/// A fresh VM config (max-IPA-sized), rebuilt per creation attempt so
/// `HV_NO_RESOURCES` park+retry can re-run `hv_vm_create` (config is consumed on
/// each `with_config`, so a retry needs a new one).
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
fn fresh_vm_config() -> applevisor::error::Result<applevisor::vm::VirtualMachineConfig> {
    use applevisor::prelude::*;
    let max_ipa = VirtualMachineConfig::get_max_ipa_size()?;
    let mut config = VirtualMachineConfig::new();
    config.set_ipa_size(max_ipa)?;
    Ok(config)
}

/// Run a VM/vCPU creation, absorbing the TRUE hard limit (`HV_NO_RESOURCES`,
/// reachable if other system VMs consumed budget or a multithreaded guest pushed
/// total vCPUs past the measured ~126 even under the 120 soft budget) by PARKING
/// on the vcpu gate and RETRYING, rather than propagating a fatal error.
///
/// A sibling vCPU's `vcpu_destroyed` calls `vcpu_gate::notify()`, which wakes an
/// in-process waiter fast; the bounded per-park timeout also drives cross-process
/// recovery (a slot freed by a DIFFERENT process's teardown is picked up on the
/// next retry, since that process's notify can't reach this process's condvar).
/// Bounded by a total-wait deadline so a genuinely-full system propagates the
/// error instead of hanging forever. Any non-`NoResources` error is propagated
/// immediately. Gated logging makes the park+retry observable.
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
fn create_with_no_resources_backpressure<T>(
    what: &str,
    attempt: impl FnMut() -> applevisor::error::Result<T>,
) -> Result<T, TrapError> {
    /// One park between retries; also the cross-process retry cadence.
    const PARK: std::time::Duration = std::time::Duration::from_millis(25);
    /// Total time to keep parking+retrying before declaring the host genuinely full.
    const MAX_WAIT: std::time::Duration = std::time::Duration::from_secs(10);
    create_with_no_resources_backpressure_bounded(what, PARK, MAX_WAIT, attempt)
}

/// The bounded park+retry loop, split out with explicit `park`/`max_wait` so it
/// is unit-testable in milliseconds instead of the production 10s ceiling. See
/// [`create_with_no_resources_backpressure`] for the semantics.
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
fn create_with_no_resources_backpressure_bounded<T>(
    what: &str,
    park: std::time::Duration,
    max_wait: std::time::Duration,
    mut attempt: impl FnMut() -> applevisor::error::Result<T>,
) -> Result<T, TrapError> {
    use applevisor::error::HypervisorError;

    let start = std::time::Instant::now();
    let mut parks: u32 = 0;
    loop {
        match attempt() {
            Ok(v) => {
                if parks > 0 && admission_trace_enabled() {
                    eprintln!(
                        "[hvf-admission pid={}] {what} recovered from HV_NO_RESOURCES after {parks} park(s) / {:?}",
                        unsafe { libc::getpid() },
                        start.elapsed(),
                    );
                }
                return Ok(v);
            }
            Err(e) if e == HypervisorError::NoResources && start.elapsed() < max_wait => {
                parks += 1;
                if admission_trace_enabled() {
                    eprintln!(
                        "[hvf-admission pid={}] {what} HV_NO_RESOURCES; park+retry #{parks} (waited {:?})",
                        unsafe { libc::getpid() },
                        start.elapsed(),
                    );
                }
                vcpu_gate::park_for_slot(park);
            }
            Err(e) => {
                if e == HypervisorError::NoResources && admission_trace_enabled() {
                    eprintln!(
                        "[hvf-admission pid={}] {what} HV_NO_RESOURCES persisted {:?} after {parks} park(s); host full, propagating",
                        unsafe { libc::getpid() },
                        start.elapsed(),
                    );
                }
                return Err(hvf_error(e));
            }
        }
    }
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
fn create_vcpu_with_permit(
    vm: &applevisor::vm::VirtualMachineInstance<applevisor::vm::GicDisabled>,
    permit: Option<HeldPermit>,
) -> Result<applevisor::vcpu::Vcpu, TrapError> {
    // The permit (this process's admitted soft-budget slot) is held across all
    // retries; only the terminal outcome registers or releases it.
    match create_with_no_resources_backpressure("hv_vcpu_create", || vm.vcpu_create()) {
        Ok(vcpu) => {
            if let Some(permit) = permit {
                register_admission_permit(vcpu.id(), permit);
            }
            vcpu_created();
            Ok(vcpu)
        }
        Err(e) => {
            if let Some(permit) = permit {
                release_unregistered_admission_permit(permit);
            }
            Err(e)
        }
    }
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
fn create_vcpu(
    vm: &applevisor::vm::VirtualMachineInstance<applevisor::vm::GicDisabled>,
) -> Result<applevisor::vcpu::Vcpu, TrapError> {
    // Existing-VM vCPUs (thread siblings, reclaim/rebind, sibling fork rebuild)
    // are admitted by the in-process scheduler. The file-lock permit below gates
    // NEW HVF VMs/fork storms only; applying it here starves a multithreaded
    // fork child behind its own one-vCPU ancestors.
    match vm.vcpu_create() {
        Ok(vcpu) => {
            vcpu_created();
            Ok(vcpu)
        }
        Err(e) => Err(hvf_error(e)),
    }
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
fn create_vm_with_admission(
    admission: VmCreateAdmission,
) -> Result<
    (
        applevisor::vm::VirtualMachineInstance<applevisor::vm::GicDisabled>,
        Option<HeldPermit>,
    ),
    TrapError,
> {
    // Soft pre-throttle: acquire an admitted slot (bounded by GLOBAL_VCPU_CEILING)
    // BEFORE creating; held across HV_NO_RESOURCES retries below. The acquire is
    // bounded (ADMISSION_PERMIT_MAX_WAIT) — persistent exhaustion propagates as
    // a typed error instead of parking here forever.
    let permit = match admission.global_permit_budget() {
        Some(budget) => Some(acquire_admission_permit(budget)?),
        None => None,
    };
    // Config is rebuilt per attempt inside the closure because `with_config`
    // consumes it, so an HV_NO_RESOURCES retry needs a fresh one.
    crate::probes::vm_lifecycle(0, admission.probe_code());
    match create_with_no_resources_backpressure("hv_vm_create", || {
        let config = fresh_vm_config()?;
        virtual_machine_with_private_signals_blocked(config)
    }) {
        Ok(vm) => {
            record_vm_resident();
            crate::probes::vm_lifecycle(1, admission.probe_code());
            Ok((vm, permit))
        }
        Err(e) => {
            if let Some(permit) = permit {
                release_unregistered_admission_permit(permit);
            }
            Err(e)
        }
    }
}

/// Pre-fork admission gate (the `SyscallTrap::fork_admission_check` backend):
/// bounded-acquire ONE plain-fork admission permit and release it immediately.
/// The permit budget models exactly what the fork is about to consume — the
/// CHILD's post-fork `create_vm_with_admission(ForkRebuild)` — so a probe that
/// cannot get a slot within `ADMISSION_PERMIT_MAX_WAIT` proves the child's
/// rebuild would stall/fail too, and the fork degrades to guest `EAGAIN`
/// BEFORE any teardown (the parent VM is untouched; no child exists yet).
///
/// Probe-and-release rather than reserve-and-inherit: the released slot can in
/// principle be raced away before the child re-acquires it, but that window
/// falls back to the existing post-fork `HV_NO_RESOURCES` park+retry — the
/// persistent-exhaustion case (a parked fleet pinning every slot, the
/// procladder_mt pause-shaped red's fatal) is what this converts to `EAGAIN`.
/// Inheriting the permit across `libc::fork` is not sound today: the atomic
/// slot is generation-stamped with the PARENT's pid (the death-reaper would
/// free the child's slot when the parent exits), and the flock path's
/// in-process pending bookkeeping does not survive into the child.
///
/// CLOSED BLIND SPOT: permits alone UNDER-REPORT resident VMs — a vCPU-only
/// park releases its permit while keeping its VM, so a parked fleet could pin
/// the hard ~127-VM ceiling while the permit-only gate passed trivially (the
/// lease-off @160 fatal and the fd-veto capacity cost; evidence doc
/// docs/2026-07-09-mt-residency-lease-evidence.md, Next Track 1a). This gate
/// now ALSO probes the resident-VM slot table (`vm_residency_region()`,
/// Task 1) with a bounded `probe_vm_slot_budget` call: a pinned fleet with
/// free permits but no free VM slot now bounds out and degrades to guest
/// `EAGAIN` instead of reaching the post-fork `hv_vm_create` fatal.
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
pub fn probe_fork_vm_admission() -> Result<(), TrapError> {
    let Some(budget) = (VmCreateAdmission::ForkRebuild { vfork: false }).global_permit_budget()
    else {
        return Ok(());
    };
    let permit = acquire_admission_permit(budget)?;
    release_unregistered_admission_permit(permit);
    // Resident-VM budget: permits alone UNDER-REPORT residency (a vCPU-only
    // park frees its permit while keeping its VM — the lease-off @160 fatal
    // and the fd-veto capacity cost, evidence doc Next Track 1). Probe the
    // hard-slot table too. Flock fallback has no residency table; it keeps
    // the historical permit-only gate.
    if atomic_permit_enabled() {
        probe_vm_slot_budget(
            vm_residency_region(),
            VmCreateAdmission::GLOBAL_VM_CEILING,
            FORK_VM_PROBE_MAX_WAIT,
        )?;
    }
    Ok(())
}

/// Fork-gate bound for the resident-VM probe. Deliberately the SAME 10 s as
/// the post-fork `hv_vm_create` HV_NO_RESOURCES backpressure MAX_WAIT: the
/// pre-fork gate never waits longer than the post-fork path it replaces, so
/// a pinned fleet (lease off, or fd-veto-retained VMs) degrades to guest
/// EAGAIN in ~10 s instead of a rc=125 trap fatal. Lease-driven releases
/// land at the 2–8 s slice ticks, well inside the bound.
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
const FORK_VM_PROBE_MAX_WAIT: std::time::Duration = std::time::Duration::from_secs(10);

/// Bounded acquire-and-release of ONE slot in `region`: proves a hard slot
/// exists for the fork child's `hv_vm_create` under `budget`.
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
fn probe_vm_slot_budget(
    region: &PermitRegion,
    budget: usize,
    max_wait: std::time::Duration,
) -> Result<(), TrapError> {
    let pid = std::process::id();
    let mut backoff = GlobalVcpuPermitBackoff::default();
    let start = std::time::Instant::now();
    let mut parks: u32 = 0;
    loop {
        if let Some(token) = region.acquire(budget, pid) {
            region.release_unregistered(token);
            return Ok(());
        }
        if start.elapsed() >= max_wait {
            return Err(permit_exhausted(
                "resident-vm slot",
                budget,
                parks,
                start.elapsed(),
            ));
        }
        parks += 1;
        trace_permit_park("resident-vm slot", budget, parks, start.elapsed());
        std::thread::sleep(backoff.next_delay());
    }
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
fn virtual_machine_with_private_signals_blocked(
    config: applevisor::vm::VirtualMachineConfig,
) -> applevisor::error::Result<applevisor::vm::VirtualMachineInstance<applevisor::vm::GicDisabled>>
{
    let _guard = crate::host_signal::block_hvf_private_thread_signals();
    applevisor::vm::VirtualMachine::with_config(config)
}

/// Enable EL0 direct reads of `CNTVCT_EL0`/`CNTFRQ_EL0` (`CNTKCTL_EL1.EL0VCTEN |
/// EL0PCTEN`) on a freshly-created vCPU. Must run on EVERY vCPU — initial,
/// per-thread, fork/execve rebuild. If only some vCPUs have it, the others trap
/// CNTVCT and fall back to the host-`Instant` emulation, which is a DIFFERENT
/// clock basis (ns-since-process-start, not the hardware counter the vDSO
/// assumes). That skews the monotonic clock between Go's worker threads, so a
/// timer scheduled on one vCPU is checked against a wildly different time on
/// another and never fires — deadlocking `time.After`/timer tests with absurd
/// (e.g. "179h") waits. Best-effort.
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
fn enable_el0_counter_access(vcpu_id: applevisor_sys::hv_vcpu_t) {
    const CNTKCTL_EL1: applevisor_sys::hv_sys_reg_t = applevisor_sys::hv_sys_reg_t::CNTKCTL_EL1;
    unsafe {
        let _ = applevisor_sys::hv_vcpu_set_sys_reg(vcpu_id, CNTKCTL_EL1, (1 << 1) | (1 << 0));
    }
}
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
fn vcpu_destroyed(vcpu_id: u64) {
    release_admission_permit_for_vcpu(vcpu_id);
    VCPU_LIVE.fetch_sub(1, std::sync::atomic::Ordering::SeqCst);
    // A slot freed: wake a sibling thread blocked in the admission gate.
    vcpu_gate::notify();
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
thread_local! {
    /// Per-sibling vCPU snapshot held between `release_vcpu_for_fork` and
    /// `rebuild_vcpu_after_fork` (both run on the same thread, around the fork
    /// quiesce park).
    static FORK_VCPU_SNAPSHOT: std::cell::RefCell<Option<VcpuSnapshot>> =
        const { std::cell::RefCell::new(None) };

}

/// Whether the current owner pthread carries no legacy fork snapshot across an
/// executor switch. The persistent-executor backend calls this from its narrow
/// boundary-audit hook; runtime code does not reach into HVF TLS directly.
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
pub fn fork_vcpu_snapshot_is_empty_for_executor_boundary() -> bool {
    FORK_VCPU_SNAPSHOT.with(|snapshot| snapshot.borrow().is_none())
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
pub(crate) fn audit_hvpatch_executor_boundary(
    state: &HvfVmState,
    mailbox: &MailboxBinding,
) -> Result<(), TrapError> {
    if !fork_vcpu_snapshot_is_empty_for_executor_boundary() {
        return Err(TrapError::Hypervisor(
            "HVF executor boundary retained fork vCPU snapshot".to_owned(),
        ));
    }
    if state.reclaim_authority == ReclaimParkAuthority::Live {
        return Err(TrapError::Hypervisor(
            "HVF executor boundary retained live vCPU authority".to_owned(),
        ));
    }
    if !mailbox.is_released_for_executor_boundary() {
        return Err(TrapError::Hypervisor(
            "HVF executor boundary retained mailbox slot".to_owned(),
        ));
    }
    Ok(())
}

#[cfg(test)]
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
fn install_fork_vcpu_snapshot_for_executor_boundary_test() {
    let snapshot = VcpuSnapshot {
        core: Aarch64VcpuSnapshot {
            gprs: [0; 31],
            pc: 0,
            pstate: 0,
            sp_el0: 0,
            sp_el1: 0,
            elr_el1: 0,
            spsr_el1: 0,
            ttbr0: 0,
            ttbr1: 0,
            tcr: 0,
            sctlr: 0,
            mair: 0,
            vbar: 0,
            cpacr: 0,
            cntkctl_el1: 0,
            tpidr_el0: 0,
            tpidrro_el0: 0,
            tpidr_el1: 0,
            contextidr_el1: 0,
            actlr_el1: 0,
            vregs: [0; 32],
            fpsr: 0,
            fpcr: 0,
        },
        last_exit_class: 0,
    };
    FORK_VCPU_SNAPSHOT.with(|current| {
        assert!(current.borrow().is_none());
        *current.borrow_mut() = Some(snapshot);
    });
}

#[cfg(test)]
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
fn clear_fork_vcpu_snapshot_for_executor_boundary_test() {
    FORK_VCPU_SNAPSHOT.with(|snapshot| {
        snapshot.borrow_mut().take();
    });
}

#[cfg(test)]
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
mod executor_boundary_audit_tests {
    #[test]
    fn fork_snapshot_getter_detects_real_dirty_tls_and_clear() {
        assert!(super::fork_vcpu_snapshot_is_empty_for_executor_boundary());
        super::install_fork_vcpu_snapshot_for_executor_boundary_test();
        assert!(!super::fork_vcpu_snapshot_is_empty_for_executor_boundary());
        super::clear_fork_vcpu_snapshot_for_executor_boundary_test();
        assert!(super::fork_vcpu_snapshot_is_empty_for_executor_boundary());
    }
}

/// Clear the published fork VM (child path; the child is single-threaded).
pub fn clear_rebuilt_vm_for_fork() {
    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    {
        *rebuilt_vm_cell().lock() = None;
    }
}

/// V0–V31 SIMD/FP registers, saved/restored across signal delivery alongside
/// the GPRs so a handler that uses SIMD (aarch64 `memcpy`/`memset`, the guest's
/// own handler body) cannot corrupt the interrupted thread's vector state.
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
pub(crate) const SIMD_FP_TABLE: [applevisor::vcpu::SimdFpReg; 32] = {
    use applevisor_sys::hv_simd_fp_reg_t::*;
    [
        Q0, Q1, Q2, Q3, Q4, Q5, Q6, Q7, Q8, Q9, Q10, Q11, Q12, Q13, Q14, Q15, Q16, Q17, Q18, Q19,
        Q20, Q21, Q22, Q23, Q24, Q25, Q26, Q27, Q28, Q29, Q30, Q31,
    ]
};

/// Write a 128-bit value into a guest SIMD&FP (V) register.
///
/// Apple's `hv_simd_fp_uchar16_t` is `__attribute__((ext_vector_type(16)))
/// uint8_t` — a 16-byte SIMD vector, which AAPCS64 passes BY VALUE in a vector
/// (V) register. The `applevisor-sys` binding (without the nightly-only
/// `simd-nightly` feature) mistypes the by-value `set` parameter as `u128`,
/// which Rust passes in a general-purpose register PAIR (x2/x3). The kernel
/// then reads the value from a V register and gets unrelated bytes — in
/// practice zeroes — so `hv_vcpu_set_simd_fp_reg` silently corrupts the target
/// register while returning `HV_SUCCESS`. (`get` is unaffected: it is
/// pointer-based, so there is no register-class mismatch.)
///
/// This broke signal delivery: `restore_from_sigframe` could not restore the
/// interrupted thread's V registers, so any signal taken while the guest was
/// mid-SIMD (aarch64 `memmove`/`memequal`, FP math) resumed with zeroed vector
/// state. Under Go that surfaced as the async-preemption (SIGURG) corruption —
/// e.g. runtime `TestUserArena/largeScalar` comparing a buffer whose bytes are
/// intact but whose compare loop returns the wrong answer.
///
/// Passing a 16-byte vector by value across `extern "C"` from Rust needs the
/// nightly `simd_ffi` feature, so we route through a tiny C shim
/// (`carrick_shim.c`) that takes the 16 bytes by pointer and reconstructs the
/// `hv_simd_fp_uchar16_t` for the kernel call — C gets the vector ABI right on
/// stable. Returns the raw `hv_return_t` (0 = `HV_SUCCESS`).
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
pub(crate) fn set_simd_fp_reg_v(
    vcpu_id: u64,
    reg: applevisor_sys::hv_simd_fp_reg_t,
    value: u128,
) -> i32 {
    unsafe extern "C" {
        fn carrick_set_simd_fp_reg(vcpu: u64, reg: u32, bytes: *const u8) -> i32;
    }
    // u128 -> 16 little-endian bytes, matching the byte order `get_simd_fp_reg`
    // produces, so save/restore round-trips as identity.
    let bytes = value.to_le_bytes();
    unsafe { carrick_set_simd_fp_reg(vcpu_id, reg as u32, bytes.as_ptr()) }
}

/// Which privilege level a vCPU was executing at when carrick observed it. The
/// Full-speed diagnostic counters (the dtrace consumer perturbs the
/// SIGURG-vs-futex race away, so observe with cheap atomics instead). Dumped at
/// process teardown when built with the `debug-stats` feature (the USDT probe
/// fires always; only the stderr dump is gated).
pub static EL1_KICK_RESUMED: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
pub static INJECT_AT_EL1: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
pub static KICK_PATH_INJECT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

/// Whether to save/restore guest FP/SIMD across signal handlers (default on;
/// `CARRICK_NO_FPSIMD` disables it for differential measurement). Cached after
/// the first read so the signal hot path doesn't hit the environment.
pub fn fpsimd_save_enabled() -> bool {
    use std::sync::atomic::{AtomicU8, Ordering};
    static FLAG: AtomicU8 = AtomicU8::new(0);
    match FLAG.load(Ordering::Relaxed) {
        1 => true,
        2 => false,
        _ => {
            let on = std::env::var_os("CARRICK_NO_FPSIMD").is_none();
            FLAG.store(if on { 1 } else { 2 }, Ordering::Relaxed);
            on
        }
    }
}

pub fn dump_kick_stats() {
    use std::sync::atomic::Ordering;
    let (el1, inject, at_el1) = (
        EL1_KICK_RESUMED.load(Ordering::Relaxed),
        KICK_PATH_INJECT.load(Ordering::Relaxed),
        INJECT_AT_EL1.load(Ordering::Relaxed),
    );
    // Surface the cumulative totals through one cheap USDT fire at exit, so a
    // trace can read them without the per-event `kick-in-kernel` probe cost.
    crate::probes::kick_stats(el1, inject, at_el1);
    #[cfg(feature = "debug-stats")]
    eprintln!(
        "[kick_stats pid={}] el1_kick_resumed={el1} kick_path_inject={inject} inject_at_el1={at_el1}",
        unsafe { libc::getpid() },
    );
}

/// The HVF VM half: the live `applevisor` VM + the per-thread mapping list +
/// the process-shared PROT_NONE / page-table state, plus the fork/reclaim
/// bookkeeping. The `vcpu` lives separately in `HvfAarch64Vcpu` (the shared
/// engine owns it), so the trap loop, register walk, fork/execve/sibling
/// SEQUENCING and threaded lifecycle live ONCE in `carrick-aarch64`; the
/// methods here take the vCPU as a parameter when they touch it.
///
/// The VM is held in a no-op `ManuallyDrop` — exactly the old
/// `ManuallyDrop<HvfInner>` discipline, now per-half: once a single `fork(2)`
/// has run inside the trap loop, applevisor's `VirtualMachine` destructor no
/// longer matches HVF and panics ("no VM or vCPU available"). The process is
/// exiting either way; the kernel reclaims the VM.
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
enum InventoryBackingIdentity {
    Private(u64),
    /// One unique anonymous object whose host mapping is inherited through an
    /// explicit fork-child descriptor. Unlike `SharedFile`, this identity is
    /// never looked up globally or deduplicated across independently-created
    /// mappings.
    SharedAnon(u64),
    SharedFile {
        device: u64,
        inode: u64,
        offset: u64,
        length: u64,
    },
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
#[derive(Clone, Copy, Debug)]
struct InventoryExtent {
    frame: carrick_hal::FrameId,
    mapping: carrick_hal::MappingId,
    backing: InventoryBackingIdentity,
    /// Physical stage-2 lease that contains this exact logical mapping. COW
    /// can split one large per-mm mapping into 16 KiB coverage fragments while
    /// the original host/HVF extent remains installed exactly once.
    stage2_base: u64,
    stage2_length: u64,
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
#[derive(Debug)]
struct CowInventorySplitShape {
    old_key: (u64, u64),
    old: InventoryExtent,
    fragments: Vec<(u64, u64)>,
    retire_old_frame: bool,
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
#[derive(Clone, Copy, Debug)]
struct InventoryMappingStage {
    gpa: u64,
    length: u64,
    permissions: carrick_hal::MemPerms,
    backing: InventoryBackingIdentity,
    inherited_frame: Option<carrick_hal::FrameId>,
    stage2_lease: Option<(u64, u64)>,
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
#[derive(Clone, Copy, Debug)]
struct CowInventoryFragment {
    gpa: u64,
    length: u64,
    mapping: carrick_hal::MappingId,
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
#[derive(Debug)]
struct CowInventorySplit {
    old_key: (u64, u64),
    old: InventoryExtent,
    fragments: Vec<CowInventoryFragment>,
    new_key: (u64, u64),
    new_extent: InventoryExtent,
    retire_old_frame: bool,
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
#[derive(Debug)]
struct InventoryLeaseRetirement {
    mappings: Vec<((u64, u64), InventoryExtent)>,
    frames: std::collections::BTreeSet<carrick_hal::FrameId>,
    stage2_leases: std::collections::BTreeSet<(u64, u64)>,
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
fn decrement_inventory_reference<K: Ord + Copy + std::fmt::Debug>(
    map: &mut std::collections::BTreeMap<K, usize>,
    key: K,
) -> Result<(), TrapError> {
    let count = map.get_mut(&key).ok_or_else(|| {
        TrapError::Hypervisor(format!("HVPatch COW backend reference {key:?} disappeared"))
    })?;
    *count = count.checked_sub(1).ok_or_else(|| {
        TrapError::Hypervisor(format!("HVPatch COW backend reference {key:?} underflow"))
    })?;
    if *count == 0 {
        map.remove(&key);
    }
    Ok(())
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
fn increment_inventory_reference<K: Ord + Copy + std::fmt::Debug>(
    map: &mut std::collections::BTreeMap<K, usize>,
    key: K,
) -> Result<(), TrapError> {
    let next = map
        .get(&key)
        .copied()
        .unwrap_or_default()
        .checked_add(1)
        .ok_or_else(|| {
            TrapError::Hypervisor(format!("HVPatch COW backend reference {key:?} exhausted"))
        })?;
    map.insert(key, next);
    Ok(())
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
#[derive(Debug, Default)]
struct InventoryFrameRegistry {
    shared: std::collections::BTreeMap<InventoryBackingIdentity, carrick_hal::FrameId>,
    references: std::collections::BTreeMap<carrick_hal::FrameId, usize>,
    extent_references: std::collections::BTreeMap<(carrick_hal::FrameId, u64, u64), usize>,
    stage2_references: std::collections::BTreeMap<(u64, u64), usize>,
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
#[derive(Debug, Default)]
struct HvpatchFrameInventory {
    initialized: bool,
    extents: std::collections::BTreeMap<(u64, u64), InventoryExtent>,
    frames: std::sync::Arc<parking_lot::Mutex<InventoryFrameRegistry>>,
    alias_reservation: Option<carrick_hal::FrameInventoryReservation>,
    alias_commit: Option<carrick_hal::FrameInventoryCommit<()>>,
    /// Extents `stage_mapping` inserted for the alias transaction currently in
    /// flight. They name MappingIds the authority does not learn about until the
    /// commit is applied, so a CANCELLED transaction has to take them back out —
    /// see `cancel_alias_inventory`.
    alias_staged: Vec<((u64, u64), InventoryExtent)>,
    process_reservation: Option<carrick_hal::FrameInventoryReservation>,
    process_commit: Option<carrick_hal::FrameInventoryCommit<()>>,
    retired_reservation: Option<carrick_hal::FrameInventoryReservation>,
    replacement_reservation: Option<carrick_hal::FrameInventoryReservation>,
    exec_commits: Option<(
        Option<carrick_hal::FrameInventoryCommit<()>>,
        carrick_hal::FrameInventoryCommit<()>,
    )>,
    retirement_reservation: Option<carrick_hal::FrameInventoryReservation>,
    retirement_commit: Option<carrick_hal::FrameInventoryCommit<()>>,
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
impl HvpatchFrameInventory {
    fn with_frames(frames: std::sync::Arc<parking_lot::Mutex<InventoryFrameRegistry>>) -> Self {
        Self {
            frames,
            ..Self::default()
        }
    }
}

/// One engine state's handle onto the process-shared frame ledger.
///
/// The diagnostic arm is deliberately local to this handle. Sibling engines
/// share the authoritative mapping ledger but cannot consume one another's
/// selected-target failure injection.
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
struct HvpatchFrameInventoryState {
    ledger: std::sync::Arc<parking_lot::Mutex<HvpatchFrameInventory>>,
    fail_next_begin_exec_inventory: bool,
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct CowArmedSpan {
    va: u64,
    len: usize,
    executable: bool,
    kernel_only: bool,
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
#[derive(Clone, Debug, Default)]
struct CowArmedRanges {
    ranges: Vec<carrick_aarch64::vmm::ForkCowRange>,
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
impl CowArmedRanges {
    const COMPOUND_SIZE: u64 = 16 * 1024;

    fn arm(&mut self, ranges: &[carrick_aarch64::vmm::ForkCowRange]) {
        self.ranges.extend_from_slice(ranges);
        self.ranges.sort_by_key(|range| (range.va, range.len));
        self.ranges.dedup();
    }

    fn snapshot(&self) -> Vec<carrick_aarch64::vmm::ForkCowRange> {
        self.ranges.clone()
    }

    fn restore(&mut self, snapshot: Vec<carrick_aarch64::vmm::ForkCowRange>) {
        self.ranges = snapshot;
    }

    fn span_for(&self, va: u64) -> Option<CowArmedSpan> {
        let compound_start = va & !(Self::COMPOUND_SIZE - 1);
        let compound_end = compound_start.checked_add(Self::COMPOUND_SIZE)?;
        // A boot arena row can remain as a broad structural mapping while
        // exact post-COW/post-unmap alias fragments overlap it. The live
        // stage-1 leaf belongs to the most-specific fragment: greatest start,
        // then shortest length for equal starts. Choosing the broad row here
        // repointed an adjacent frame across the fragment boundary (a write in
        // a8-aa replaced aa-ac and corrupted musl's allocation header).
        let range = self
            .ranges
            .iter()
            .filter(|range| {
                range
                    .va
                    .checked_add(range.len as u64)
                    .is_some_and(|range_end| va >= range.va && va < range_end)
            })
            .max_by(|left, right| {
                left.va
                    .cmp(&right.va)
                    .then_with(|| right.len.cmp(&left.len))
            })?;
        let range_end = range.va.checked_add(range.len as u64)?;
        let start = range.va.max(compound_start);
        let end = range_end.min(compound_end);
        Some(CowArmedSpan {
            va: start,
            len: usize::try_from(end.checked_sub(start)?).ok()?,
            executable: range.executable,
            kernel_only: range.kernel_only,
        })
    }

    fn disarm(&mut self, span: CowArmedSpan) {
        let span_end = span.va.saturating_add(span.len as u64);
        let mut replacement = Vec::with_capacity(self.ranges.len().saturating_add(1));
        for range in self.ranges.drain(..) {
            let range_end = range.va.saturating_add(range.len as u64);
            if range_end <= span.va || range.va >= span_end {
                replacement.push(range);
                continue;
            }
            if range.va < span.va {
                replacement.push(carrick_aarch64::vmm::ForkCowRange {
                    va: range.va,
                    len: usize::try_from(span.va - range.va).unwrap_or_default(),
                    executable: range.executable,
                    kernel_only: range.kernel_only,
                });
            }
            if range_end > span_end {
                replacement.push(carrick_aarch64::vmm::ForkCowRange {
                    va: span_end,
                    len: usize::try_from(range_end - span_end).unwrap_or_default(),
                    executable: range.executable,
                    kernel_only: range.kernel_only,
                });
            }
        }
        self.ranges = replacement;
    }

    fn overlapping(&self, va: u64, len: usize) -> Vec<carrick_aarch64::vmm::ForkCowRange> {
        let end = va.saturating_add(len as u64);
        self.ranges
            .iter()
            .filter_map(|range| {
                let range_end = range.va.saturating_add(range.len as u64);
                let start = range.va.max(va);
                let overlap_end = range_end.min(end);
                (start < overlap_end).then(|| carrick_aarch64::vmm::ForkCowRange {
                    va: start,
                    len: usize::try_from(overlap_end - start).unwrap_or_default(),
                    executable: range.executable,
                    kernel_only: range.kernel_only,
                })
            })
            .collect()
    }

    #[cfg(test)]
    fn disarm_ranges(&mut self, ranges: &[carrick_aarch64::vmm::ForkCowRange]) {
        for range in ranges {
            self.disarm(CowArmedSpan {
                va: range.va,
                len: range.len,
                executable: range.executable,
                kernel_only: range.kernel_only,
            });
        }
    }
}

/// Whether repointing one semantic COW span leaves another Linux leaf in this
/// address space naming the same 16 KiB physical source frame.
///
/// The frame inventory is physical while Linux permissions and mappings are
/// 4 KiB-semantic. A `brk`, `mprotect`, or partial-unmap boundary can therefore
/// make one COW transaction repoint only part of a host compound. The old
/// physical frame must remain inventoried until every sibling leaf has moved;
/// otherwise the last child reference can retire stage-2 while the parent PTE
/// still names that frame.
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
fn cow_source_has_retained_sibling(
    span: CowArmedSpan,
    old_ipa: u64,
    old_physical_ipa: u64,
    mut retained_translation: impl FnMut(u64) -> Option<u64>,
) -> bool {
    const PAGE_SIZE: u64 = 4 * 1024;
    let Some(source_offset) = old_ipa.checked_sub(old_physical_ipa) else {
        return false;
    };
    let Some(source_va) = span.va.checked_sub(source_offset) else {
        return false;
    };
    let repoint_start = span.va & !(PAGE_SIZE - 1);
    let Some(span_end) = span.va.checked_add(span.len as u64) else {
        return false;
    };
    let Some(repoint_end) = span_end
        .checked_add(PAGE_SIZE - 1)
        .map(|end| end & !(PAGE_SIZE - 1))
    else {
        return false;
    };

    (0..CowArmedRanges::COMPOUND_SIZE)
        .step_by(PAGE_SIZE as usize)
        .any(|offset| {
            let Some(page_va) = source_va.checked_add(offset) else {
                return false;
            };
            if page_va >= repoint_start && page_va < repoint_end {
                return false;
            }
            let Some(expected_ipa) = old_physical_ipa.checked_add(offset) else {
                return false;
            };
            retained_translation(page_va)
                .is_some_and(|translated| align_down(translated, PAGE_SIZE) == expected_ipa)
        })
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
impl HvpatchFrameInventoryState {
    fn new(ledger: std::sync::Arc<parking_lot::Mutex<HvpatchFrameInventory>>) -> Self {
        Self {
            ledger,
            fail_next_begin_exec_inventory: false,
        }
    }

    fn lock(&self) -> parking_lot::MutexGuard<'_, HvpatchFrameInventory> {
        self.ledger.lock()
    }

    fn shared_ledger(&self) -> std::sync::Arc<parking_lot::Mutex<HvpatchFrameInventory>> {
        std::sync::Arc::clone(&self.ledger)
    }

    fn inject_next_begin_exec_inventory_failure(&mut self) {
        self.fail_next_begin_exec_inventory = true;
    }

    fn begin_process_inventory(
        &mut self,
        reservation: carrick_hal::FrameInventoryReservation,
    ) -> Result<(), TrapError> {
        let mut inventory = self.ledger.lock();
        if inventory.process_reservation.is_some() || inventory.process_commit.is_some() {
            return Err(TrapError::Hypervisor(
                "overlapping HVPatch child inventory transaction".to_owned(),
            ));
        }
        inventory.process_reservation = Some(reservation);
        Ok(())
    }

    fn cancel_process_inventory(&mut self) -> bool {
        self.ledger.lock().process_reservation.take().is_some()
    }

    fn begin_alias_inventory(
        &mut self,
        reservation: carrick_hal::FrameInventoryReservation,
    ) -> Result<(), TrapError> {
        let mut inventory = self.ledger.lock();
        if inventory.alias_reservation.is_some() || inventory.alias_commit.is_some() {
            return Err(TrapError::Hypervisor(
                "overlapping HVPatch alias inventory transaction".to_owned(),
            ));
        }
        inventory.alias_reservation = Some(reservation);
        Ok(())
    }

    /// Discard whatever alias staging a FAILED install left armed, so the next
    /// guest `mmap` can arm its own transaction instead of being rejected as
    /// overlapping.
    ///
    /// Both slots are cleared because the failure can land on either side of the
    /// hand-off: `add_alias_with_sharing` returning early leaves the
    /// `alias_reservation` it never consumed, while a stage-1 `map_aliased`
    /// failure after a successful stage-2 install leaves the `alias_commit` it
    /// already staged.
    ///
    /// Dropping the reservation really is free — reservations are pointer-free
    /// data whose only cost is burning candidate IDs the monotonic registry
    /// never reissues. Dropping the COMMIT is NOT. By the time one exists,
    /// `stage_mapping` has already inserted an `InventoryExtent` into
    /// `extents`, and that extent names a MappingId the authority only learns
    /// about when the commit is applied. Discarding the commit alone therefore
    /// left the backend ledger holding an extent for a mapping the authority
    /// had never seen, and the next `munmap` of that VA staged an
    /// `UnmapMapping` for it and aborted the carrier with
    /// `mapping MappingId(N) is not live`. So the staged extents are rolled
    /// back here too, which is what makes this discard leave no residue.
    fn cancel_alias_inventory(&mut self) -> bool {
        let mut inventory = self.ledger.lock();
        let reservation = inventory.alias_reservation.take();
        let commit = inventory.alias_commit.take();
        let staged = std::mem::take(&mut inventory.alias_staged);
        tracing::trace!(
            staged = staged.len(),
            reservation = reservation.is_some(),
            commit = commit.is_some(),
            "hvpatch alias cancel"
        );
        if !staged.is_empty()
            && let Err(error) = HvfVmState::rollback_unpublished_mappings(&mut inventory, &staged)
        {
            // The ledger and the authority have already diverged; continuing
            // would hand a later retirement an extent naming a mapping that
            // does not exist, which aborts anyway but much further from the
            // cause.
            eprintln!(
                "carrick: FATAL: roll back cancelled HVPatch alias staging: {error} staged={staged:?}"
            );
            std::process::abort();
        }
        reservation.is_some() || commit.is_some()
    }

    fn begin_exec_inventory(
        &mut self,
        retired: Option<carrick_hal::FrameInventoryReservation>,
        replacement: carrick_hal::FrameInventoryReservation,
    ) -> Result<(), TrapError> {
        if std::mem::take(&mut self.fail_next_begin_exec_inventory) {
            return Err(TrapError::Hypervisor(
                "injected HVPatch begin_exec_inventory failure".to_owned(),
            ));
        }
        let mut inventory = self.ledger.lock();
        if inventory.retired_reservation.is_some()
            || inventory.replacement_reservation.is_some()
            || inventory.exec_commits.is_some()
        {
            return Err(TrapError::Hypervisor(
                "overlapping HVPatch exec inventory transaction".to_owned(),
            ));
        }
        inventory.retired_reservation = retired;
        inventory.replacement_reservation = Some(replacement);
        Ok(())
    }
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
fn final_exec_physical_extents(
    inventory: &HvpatchFrameInventory,
) -> Result<std::collections::BTreeSet<(u64, usize)>, TrapError> {
    let frames = inventory.frames.lock();
    let mut physical = std::collections::BTreeSet::new();
    let mut local_stage2_references = std::collections::BTreeMap::new();
    for extent in inventory.extents.values() {
        *local_stage2_references
            .entry((extent.stage2_base, extent.stage2_length))
            .or_insert(0usize) += 1;
    }
    for (lease, local) in local_stage2_references {
        let references = frames
            .stage2_references
            .get(&lease)
            .copied()
            .ok_or_else(|| {
                TrapError::Hypervisor(format!(
                    "HVPatch stage-2 lease {lease:?} has no backend reference"
                ))
            })?;
        if references == local {
            physical.insert((
                lease.0,
                usize::try_from(lease.1).map_err(|_| TrapError::MappingTooLarge(lease.1))?,
            ));
        }
    }
    Ok(physical)
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ReclaimParkAuthority {
    Live,
    InitialRunnerParked,
    VcpuParked,
    VmParked,
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
impl ReclaimParkAuthority {
    fn mark_initial_runner_parked(&mut self) -> Result<(), TrapError> {
        if *self != Self::Live {
            return Err(TrapError::Hypervisor(
                "initial runner park attempted without live executor authority".to_owned(),
            ));
        }
        *self = Self::InitialRunnerParked;
        Ok(())
    }

    fn mark_vcpu_parked(&mut self) -> Result<(), TrapError> {
        if *self != Self::Live {
            return Err(TrapError::Hypervisor(
                "vCPU reclaim park attempted without live executor authority".to_owned(),
            ));
        }
        *self = Self::VcpuParked;
        Ok(())
    }

    fn mark_vm_parked(&mut self) -> Result<(), TrapError> {
        if *self != Self::VcpuParked {
            return Err(TrapError::Hypervisor(
                "VM reclaim park attempted without parked vCPU authority".to_owned(),
            ));
        }
        *self = Self::VmParked;
        Ok(())
    }

    fn destination_vcpu_is_live(self) -> Result<(), TrapError> {
        (self == Self::Live).then_some(()).ok_or_else(|| {
            TrapError::Hypervisor("destination executor vCPU is not live".to_owned())
        })
    }

    fn mark_live_after_recreate(&mut self) -> Result<(), TrapError> {
        if *self == Self::Live {
            return Err(TrapError::Hypervisor(
                "reclaim resume attempted to recreate a live destination vCPU".to_owned(),
            ));
        }
        *self = Self::Live;
        Ok(())
    }
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
pub(crate) struct HvfVmState {
    _vm:
        std::mem::ManuallyDrop<applevisor::vm::VirtualMachineInstance<applevisor::vm::GicDisabled>>,
    pub(crate) task: HvfTaskState,
    /// VM-global Carrick control mappings owned by the persistent carrier.
    /// This is executor-local authority: load/save swaps it with the worker,
    /// while a logical task binding always carries `None`.
    carrier_mappings: Option<std::sync::Arc<PersistentCarrierMappings>>,
    /// Executor-local lifecycle only. Task registers are owned exclusively by
    /// the Kernel's typed execution lease and never stashed in this backend.
    reclaim_authority: ReclaimParkAuthority,
    /// Carrick-owned logical mailbox slots shared by every vCPU in this VM.
    /// Slot identity is deliberately independent of opaque/recycled HVF ids.
    mailbox_slots: std::sync::Arc<MailboxSlotAllocator>,
    /// Internal diagnostic transport selection, parsed once before first entry
    /// and inherited by every sibling/rebuild. This is not public CLI policy.
    syscall_transport: HvfSyscallTransport,
    /// Raw worker-local vCPU identity used by teardown and exact kick audit.
    vcpu_id: applevisor_sys::hv_vcpu_t,
    /// Cloneable worker-local handle for `hv_vcpus_exit`.
    vcpu_handle: applevisor::vcpu::VcpuHandle,
}

/// Every backend field whose authority follows a logical HVPatch task rather
/// than a Task4 worker. Keeping this as one value makes load/save a literal
/// swap: the carrier VM, reclaim/mailbox transport, and live vCPU identity stay
/// on the worker while MM mappings, stage-1, inventory, and per-thread COW
/// authority move with the binding.
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
pub(crate) struct HvfTaskState {
    mappings: Vec<HvfMappedRegion>,
    /// Per-mm stage-1 root-table slot. It contains page-table/control backing
    /// only; guest data frames live at stable global IPAs outside the slot.
    /// Ordinary VMM engines leave this unset.
    mm_root_slot: Option<(u64, u64)>,
    pending_exec_mm_root_slot: Option<(u64, u64)>,
    pending_exec_asid: Option<u16>,
    pending_exec_stage2_cleanup: Option<PendingExecStage2Cleanup>,
    /// A distinct Linux process edge onto another process's live CLONE_VM MM.
    /// Exit/exec drops this projection without retiring shared stage-2 state.
    shared_process_mm: bool,
    /// The exception class of the most recent vCPU exit. We need to remember
    /// whether the trap came in via EL0 `svc` (`EC = 0x15`) or the EL1 vector
    /// stub's `hvc` (`EC = 0x16`) so `complete_syscall` knows whether to
    /// advance PC past the HVC before resuming. Carried in the `VcpuSnapshot` so
    /// fork/clone/reclaim round-trip it.
    last_exit_class: u64,
    /// ESR_EL1 of the most recent EL0 synchronous fault. The arm64 kernel puts
    /// it in the signal frame's `esr_context`; Apple Rosetta's signal handler
    /// requires that record. Captured at fault detection, consumed by
    /// `inject_signal` when building a fault signal's ucontext. Only meaningful
    /// between fault-detect and the immediately following delivery, so it is
    /// reset to 0 across fork/clone/execve.
    last_fault_esr: u64,
    /// True iff this engine was produced by a `fork(2)` returning into a
    /// child. The runtime checks this when the guest exits and calls
    /// `_exit(2)` instead of running normal Rust drops — applevisor's
    /// Vcpu Drop unwraps `hv_vcpu_destroy` and panics in the
    /// post-fork child's HVF context (the new VM HVF tracks for the
    /// child got swapped in by `fork()`; ordering of `_vm` vs `vcpu`
    /// Drop trips a "no VM or vCPU available" assertion).
    is_forked_child: bool,
    /// Like `is_forked_child`, but RESET on execve: true only for a LIVE forked
    /// child that has not yet exec'd. Drives the `forked=` diagnostic probes
    /// (stale-stage2 reasoning); distinct from the sticky shutdown flag above,
    /// which must stay set across execve to keep the `_exit`-without-JSON path.
    forked_no_exec: bool,
    /// Process-wide guest ranges currently mapped `PROT_NONE`.
    /// Thread siblings share this metadata so syscall-path memory access checks
    /// observe `mprotect(PROT_NONE)` changes made by any guest thread.
    protections: std::sync::Arc<MemoryProtections>,
    /// Lazily-built editor over the EL1 stage-1 page-table image, used to give
    /// `mprotect`/`PROT_NONE`/`munmap` guest-visible semantics. Built from the
    /// page-table region's host backing on first edit; reset to `None` on
    /// fork/execve (fresh tables). SHARED across sibling vCPU threads (one HVF
    /// VM ⇒ one set of stage-1 tables): the mutex serializes edits so the
    /// spare-table allocator stays consistent, and `sync_to_host` orders the
    /// descriptor stores so a concurrent sibling hardware walk stays safe
    /// without quiescing.
    page_tables: std::sync::Arc<parking_lot::Mutex<Option<crate::page_table::PageTableManager>>>,
    /// The Linux syscall number (x8) and original arg0 (x0) of the most recent
    /// `svc` trap, captured before the dispatcher overwrites x0 with the retval.
    /// Used to restart an `EINTR`'d restartable syscall under SA_RESTART: the
    /// handler-injection path rewinds PC to the `svc` and restores this x0.
    last_syscall_nr: Option<u64>,
    last_syscall_orig_x0: u64,
    /// The vfork (`CLONE_VM`) flag for the NEXT fork: the child SHARES the
    /// parent's guest RAM instead of snapshotting private regions. Set by the
    /// engine's `set_vfork_share`, read by `fork_prepare_and_teardown`.
    vfork_share: bool,
    /// Fork descriptor stash, captured by `fork_prepare_and_teardown` (the
    /// pre-`libc::fork` half) and consumed by `fork_rebuild` (the post-fork
    /// half). The parent re-maps `mapping_descs` (its own buffers); the child
    /// re-maps `child_descs` (the private snapshots / shared originals). Only
    /// populated between the two halves of a single fork.
    fork_mapping_descs: Vec<ForkMappingDesc>,
    fork_child_descs: Vec<ForkMappingDesc>,
    /// HvPatch owns one process-wide HVF VM across guest exec/fork lifecycle;
    /// ordinary VMM preserves the mature destroy/recreate behavior.
    persistent_vm_lifecycle: bool,
    /// HVPatch-only exact sparse-extent inventory. Sibling vCPUs share this
    /// ledger; VM/vCPU recreation reuses it and therefore emits no logical
    /// mapping events.
    frame_inventory: HvpatchFrameInventoryState,
    /// Per-engine runtime authority. Sibling vCPUs bind their own Linux TID;
    /// the underlying mm/frame inventory remains shared.
    cow_authority: Option<std::sync::Arc<dyn carrick_hal::FrameCowAuthority>>,
    cow_identity: Option<carrick_hal::FrameCowIdentity>,
    cow_armed: std::sync::Arc<parking_lot::Mutex<CowArmedRanges>>,
    cow_deferred_publications: std::sync::Arc<parking_lot::Mutex<Vec<PendingFrameCowPublication>>>,
    pending_fork_frame_receipts: Vec<PendingForkFrameReceipt>,
    /// Child aliases withheld until fresh-vCPU register restoration succeeds.
    pending_process_aliases: Vec<AliasBacking>,
    /// Recycled buffer for the frame-COW rollback pre-image.
    ///
    /// `perform_frame_cow` snapshots the whole stage-1 manager before it edits,
    /// so a failed publication can restore the exact pre-transaction image. That
    /// snapshot is unchanged; only its allocation is reused. A fresh
    /// `PageTableManager::clone()` costs an `mmap` of 1.75 MiB, a zero-fill
    /// fault per page as the copy touches it, and a `munmap`/`madvise` on drop
    /// — measured at ~6 COW faults per guest fork+wait round trip, which put
    /// that whole host-VM churn on the COW path. Taken for the duration of one
    /// COW and returned on success; a rollback consumes it (it becomes the live
    /// manager) and the next COW allocates one again.
    cow_rollback_scratch: Option<crate::page_table::PageTableManager>,
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
struct PendingExecStage2Cleanup {
    mappings: Vec<HvfMappedRegion>,
    extents: std::collections::BTreeSet<(u64, usize)>,
    mm_root_slot: Option<(u64, u64)>,
    shared_projection: bool,
    armed: bool,
}

// SAFETY: cleanup moves with the stopped logical task and is consumed only on
// a Task4 owner worker after save/detach. Its raw mapping pointers remain owned
// by the contained HvfMappedRegion backings until cleanup runs.
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
unsafe impl Send for PendingExecStage2Cleanup {}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
impl PendingExecStage2Cleanup {
    fn retire(&mut self) -> Result<(), TrapError> {
        if self.shared_projection {
            // A CLONE_VM process edge owns only unowned descriptors into the
            // parent's still-live MM. Exec drops that projection; it must not
            // unmap stage-2, retire aliases, or release parent backing.
            self.mappings.clear();
            self.armed = false;
            return Ok(());
        }
        for &(ipa, size) in &self.extents {
            HvfVmState::retire_stage2_extent_from_mappings(&mut self.mappings, ipa, size as u64)?;
        }
        mutate_external_alias_state(|_, registry| {
            registry.retain(|alias| {
                !alias_is_owned_by_process(alias.ownership_scope, self.mm_root_slot)
                    && !self
                        .extents
                        .contains(&(alias.physical_ipa, alias.physical_size))
            });
        });
        let mut retained_backings = Vec::new();
        for mapping in self.mappings.drain(..) {
            if self
                .extents
                .contains(&(mapping.physical_ipa, mapping.physical_size))
            {
                drop(mapping);
            } else {
                retained_backings.push(mapping);
            }
        }
        std::mem::forget(retained_backings);
        self.armed = false;
        Ok(())
    }
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
impl Drop for PendingExecStage2Cleanup {
    fn drop(&mut self) {
        if self.armed
            && let Err(error) = self.retire()
        {
            eprintln!("carrick: FATAL: drop detached exec predecessor cleanup: {error}");
            std::process::abort();
        }
    }
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
impl std::ops::Deref for HvfVmState {
    type Target = HvfTaskState;

    fn deref(&self) -> &Self::Target {
        &self.task
    }
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
impl std::ops::DerefMut for HvfVmState {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.task
    }
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
pub(crate) fn swap_hvpatch_task_state(live: &mut HvfTaskState, parked: &mut HvfTaskState) {
    std::mem::swap(live, parked);
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
impl HvfTaskState {
    pub(crate) fn runtime_authorities_match(
        &self,
        page_tables: &std::sync::Arc<
            parking_lot::Mutex<Option<crate::page_table::PageTableManager>>,
        >,
        protections: &std::sync::Arc<MemoryProtections>,
    ) -> bool {
        std::sync::Arc::ptr_eq(page_tables, &self.page_tables)
            && std::sync::Arc::ptr_eq(protections, &self.protections)
    }

    fn neutral() -> Self {
        Self {
            mappings: Vec::new(),
            mm_root_slot: None,
            pending_exec_mm_root_slot: None,
            pending_exec_asid: None,
            pending_exec_stage2_cleanup: None,
            shared_process_mm: false,
            last_exit_class: 0,
            last_fault_esr: 0,
            is_forked_child: false,
            forked_no_exec: false,
            protections: std::sync::Arc::new(MemoryProtections::default()),
            page_tables: std::sync::Arc::new(parking_lot::Mutex::new(None)),
            last_syscall_nr: None,
            last_syscall_orig_x0: 0,
            vfork_share: false,
            fork_mapping_descs: Vec::new(),
            fork_child_descs: Vec::new(),
            persistent_vm_lifecycle: false,
            frame_inventory: HvpatchFrameInventoryState::new(std::sync::Arc::new(
                parking_lot::Mutex::new(HvpatchFrameInventory::default()),
            )),
            cow_authority: None,
            cow_identity: None,
            cow_armed: std::sync::Arc::new(parking_lot::Mutex::new(CowArmedRanges::default())),
            cow_deferred_publications: std::sync::Arc::new(parking_lot::Mutex::new(Vec::new())),
            pending_fork_frame_receipts: Vec::new(),
            pending_process_aliases: Vec::new(),
            cow_rollback_scratch: None,
        }
    }

    fn audit_neutral(&self) -> Result<(), TrapError> {
        let protections = self.protections.snapshot_all();
        let inventory = self.frame_inventory.ledger.lock();
        let frames = inventory.frames.lock();
        let neutral = self.mappings.is_empty()
            && self.mm_root_slot.is_none()
            && self.pending_exec_mm_root_slot.is_none()
            && self.pending_exec_asid.is_none()
            && self.pending_exec_stage2_cleanup.is_none()
            && self.last_exit_class == 0
            && self.last_fault_esr == 0
            && !self.is_forked_child
            && !self.forked_no_exec
            && protections.no_access.is_empty()
            && protections.unmapped.is_empty()
            && protections.no_write.is_empty()
            && protections.executable.is_empty()
            && protections.bus_fault.is_empty()
            && protections.mutable_shared_backing.is_empty()
            && self.page_tables.lock().is_none()
            && self.last_syscall_nr.is_none()
            && self.last_syscall_orig_x0 == 0
            && !self.vfork_share
            && self.fork_mapping_descs.is_empty()
            && self.fork_child_descs.is_empty()
            && !self.persistent_vm_lifecycle
            && !inventory.initialized
            && inventory.extents.is_empty()
            && frames.shared.is_empty()
            && frames.references.is_empty()
            && frames.extent_references.is_empty()
            && frames.stage2_references.is_empty()
            && inventory.alias_reservation.is_none()
            && inventory.alias_commit.is_none()
            && inventory.alias_staged.is_empty()
            && inventory.process_reservation.is_none()
            && inventory.process_commit.is_none()
            && inventory.retired_reservation.is_none()
            && inventory.replacement_reservation.is_none()
            && inventory.exec_commits.is_none()
            && inventory.retirement_reservation.is_none()
            && inventory.retirement_commit.is_none()
            && self.cow_authority.is_none()
            && self.cow_identity.is_none()
            && self.cow_armed.lock().ranges.is_empty()
            && self.cow_deferred_publications.lock().is_empty()
            && self.pending_fork_frame_receipts.is_empty()
            && self.pending_process_aliases.is_empty()
            && self.cow_rollback_scratch.is_none();
        drop(frames);
        drop(inventory);
        neutral.then_some(()).ok_or_else(|| {
            TrapError::Hypervisor("idle HVPatch worker retained task authority".to_owned())
        })
    }

    /// Whether an execve on this task retires the old mm's extents.
    ///
    /// A vfork / `CLONE_VM` child shares its mm with a live sharer that keeps
    /// every mapping, so its exec retires nothing: the replacement gets a fresh
    /// ledger and the old one stays whole. Callers must arm no retirement
    /// transaction in that case — a reservation filled with zero events is
    /// rejected by the Kernel authority, and the exec is already past its point
    /// of no return by the time the commit is applied.
    pub(crate) fn exec_retires_old_mm(&self) -> bool {
        !self.shared_process_mm
    }

    /// Extents this task's execve will retire from the old mm: none when a
    /// live sharer still owns it.
    pub(crate) fn exec_retired_extent_count(&self) -> usize {
        if self.exec_retires_old_mm() {
            self.frame_inventory.lock().extents.len()
        } else {
            0
        }
    }

    fn begin_exec_inventory(
        &mut self,
        retired: Option<carrick_hal::FrameInventoryReservation>,
        replacement: carrick_hal::FrameInventoryReservation,
    ) -> Result<(), TrapError> {
        if self.shared_process_mm {
            // The parent still owns this ledger. Exec starts a fresh backend
            // ledger for the replacement MM so it cannot remove the parent's
            // mappings. Nothing is retired, so `retired` is `None` here:
            // reserving a retirement would stage zero events against the fresh
            // ledger, and the Kernel authority rejects a zero-event commit.
            let frames = self.frame_inventory.lock().frames.clone();
            self.frame_inventory = HvpatchFrameInventoryState::new(std::sync::Arc::new(
                parking_lot::Mutex::new(HvpatchFrameInventory::with_frames(frames)),
            ));
        }
        self.frame_inventory
            .begin_exec_inventory(retired, replacement)
    }
}

#[cfg(test)]
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
pub(crate) fn hvpatch_task_state_test_fixture(
    mm_slot: u64,
    mapping_start: u64,
    linux_tid: i32,
) -> HvfTaskState {
    let cow_authority: std::sync::Arc<dyn carrick_hal::FrameCowAuthority> =
        std::sync::Arc::new(task_only_carrier_directory_tests::TestCowAuthority);
    HvfTaskState {
        mappings: vec![HvfMappedRegion {
            start: mapping_start,
            end: mapping_start + 0x1000,
            ipa: mapping_start + 0x10_0000,
            physical_ipa: mapping_start + 0x10_0000,
            host_addr: std::ptr::null_mut(),
            size: 0x1000,
            physical_size: 0x1000,
            perms: applevisor::memory::MemPerms::ReadWrite,
            memory: None,
            host_mapping: None,
            stage2_lease: None,
            is_dynamic_alias: false,
            sharing: GuestMappingSharing::Private,
            guest_writable: true,
            shared_key_base: 0,
            shared_key_offset: 0,
            owner_generation: mm_slot,
        }],
        mm_root_slot: Some((mm_slot << 20, 0x20_0000)),
        pending_exec_mm_root_slot: None,
        pending_exec_asid: None,
        pending_exec_stage2_cleanup: None,
        shared_process_mm: false,
        last_exit_class: 0,
        last_fault_esr: 0,
        is_forked_child: false,
        forked_no_exec: false,
        protections: std::sync::Arc::new(MemoryProtections::default()),
        page_tables: std::sync::Arc::new(parking_lot::Mutex::new(None)),
        last_syscall_nr: None,
        last_syscall_orig_x0: 0,
        vfork_share: false,
        fork_mapping_descs: Vec::new(),
        fork_child_descs: Vec::new(),
        persistent_vm_lifecycle: true,
        frame_inventory: HvpatchFrameInventoryState::new(std::sync::Arc::new(
            parking_lot::Mutex::new(HvpatchFrameInventory::default()),
        )),
        cow_authority: Some(cow_authority),
        cow_identity: Some(carrick_hal::FrameCowIdentity {
            linux_pid: 7,
            linux_tid,
            mm: mm_slot,
            asid: u16::try_from(mm_slot).unwrap(),
        }),
        cow_armed: std::sync::Arc::new(parking_lot::Mutex::new(CowArmedRanges::default())),
        cow_deferred_publications: std::sync::Arc::new(parking_lot::Mutex::new(Vec::new())),
        pending_fork_frame_receipts: Vec::new(),
        pending_process_aliases: Vec::new(),
        cow_rollback_scratch: None,
    }
}

#[cfg(test)]
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
pub(crate) fn hvpatch_task_state_test_identity(
    state: &HvfTaskState,
) -> (Option<(u64, u64)>, u64, i32, usize, usize, usize) {
    let authority = state
        .cow_authority
        .as_ref()
        .map(|authority| std::sync::Arc::as_ptr(authority) as *const () as usize)
        .unwrap_or_default();
    (
        state.mm_root_slot,
        state.mappings.first().map_or(0, |mapping| mapping.start),
        state.cow_identity.map_or(0, |identity| identity.linux_tid),
        std::sync::Arc::as_ptr(&state.page_tables) as usize,
        std::sync::Arc::as_ptr(&state.frame_inventory.ledger) as usize,
        authority,
    )
}

#[cfg(test)]
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
pub(crate) fn hvpatch_neutral_task_state_for_test() -> HvfTaskState {
    HvfTaskState::neutral()
}

#[cfg(test)]
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
pub(crate) fn audit_hvpatch_neutral_task_state_for_test(
    state: &HvfTaskState,
) -> Result<(), TrapError> {
    state.audit_neutral()
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
impl HvfVmState {
    pub(crate) fn prepare_exec_address_space(
        &mut self,
        root_slot_base: u64,
        root_slot_size: u64,
        asid: u16,
    ) -> Result<(), TrapError> {
        if !root_slot_base.is_multiple_of(HVF_PAGE_SIZE) || root_slot_size == 0 || asid == 0 {
            return Err(TrapError::Hypervisor(
                "invalid exact HVPatch exec MM lease".to_owned(),
            ));
        }
        if self.pending_exec_mm_root_slot.is_some() || self.pending_exec_asid.is_some() {
            return Err(TrapError::Hypervisor(
                "duplicate exact HVPatch exec MM lease".to_owned(),
            ));
        }
        self.pending_exec_mm_root_slot = Some((root_slot_base, root_slot_size));
        self.pending_exec_asid = Some(asid);
        Ok(())
    }

    pub(crate) fn swap_persistent_executor_local(&mut self, other: &mut Self) {
        std::mem::swap(&mut self._vm, &mut other._vm);
        std::mem::swap(&mut self.carrier_mappings, &mut other.carrier_mappings);
        std::mem::swap(&mut self.reclaim_authority, &mut other.reclaim_authority);
        std::mem::swap(&mut self.mailbox_slots, &mut other.mailbox_slots);
        std::mem::swap(&mut self.syscall_transport, &mut other.syscall_transport);
        std::mem::swap(&mut self.vcpu_id, &mut other.vcpu_id);
        std::mem::swap(&mut self.vcpu_handle, &mut other.vcpu_handle);
    }
}

/// Thread/process exit must LEAK the per-thread host backings, never `munmap`
/// them. All sibling threads share ONE host address space, and the
/// process-global [`alias_registry`] holds NON-OWNING raw `host_addr`s into
/// these same buffers. A clone thread exiting (its `run_vcpu_until_exit` returns
/// → this `Drop` runs on its `HvfVmState`) that `munmap`'d a buffer it happens
/// to OWN — e.g. a `kind=SharedFile` `MAP_SHARED` semaphore alias it
/// `add_alias`'d — would yank that buffer out from under every sibling thread
/// AND leave a DANGLING registry entry that a later syscall (`read_futex_word`
/// on the process-shared semaphore) resolves to a dead pointer → a carrick HOST
/// SIGSEGV. That is the cpython multiprocessing FORKSERVER SyncManager crash:
/// the Manager's pool teardown exits a clone thread whose `self.mappings` owned
/// the live sem buffer. The kernel reclaims every mapping at process exit; the
/// fork/execve rebuilds already `mem::forget` `self.mappings` for exactly this
/// reason. (Restores the leak-until-exit discipline the pre-`Aarch64EngineCore`
/// refactor's no-op engine `Drop` provided — see the `unregister_alias` doc.)
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
impl Drop for HvfVmState {
    fn drop(&mut self) {
        std::mem::forget(std::mem::take(&mut self.mappings));
    }
}

/// Owns ONLY the three vCPU-touching associated functions the shared engine
/// reaches through the `Aarch64Vcpu` trait — the native-exit decode
/// (`run_to_exit`) and the snapshot/restore I/O — so they are free of
/// `HvfVmState` (they take the bare `applevisor` vCPU). The name is kept so the
/// new module's `HvfInner::snapshot_vcpu_from` / `restore_vcpu_into` /
/// `run_to_exit` paths resolve unchanged.
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
pub(crate) struct HvfInner;

/// Overwrite `slot`'s VM in place WITHOUT running applevisor's `VirtualMachine`
/// Drop on the old (already raw-destroyed) handle — the single no-drop VM
/// replacement point (the fork/execve rebuilds). `mem::forget` the old (it was
/// `hv_vm_destroy`'d via the raw API; running its wrapper Drop now would panic).
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
fn replace_destroyed_vm(
    slot: &mut HvfVmState,
    new_vm: applevisor::vm::VirtualMachineInstance<applevisor::vm::GicDisabled>,
) {
    let old = std::mem::replace(&mut slot._vm, std::mem::ManuallyDrop::new(new_vm));
    std::mem::forget(std::mem::ManuallyDrop::into_inner(old));
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
#[derive(Debug)]
pub(crate) struct HvfMappedRegion {
    /// Guest VIRTUAL start (the syscall-path lookup key). Differs from `ipa`
    /// only for the Rosetta high-VA alias.
    start: u64,
    end: u64,
    /// IPA this region was `hv_vm_map`'d at — needed to re-map across fork(2).
    /// Identity (== `start`) for every region but the Rosetta window.
    ipa: u64,
    /// Exact HVF stage-2 extent. `ipa`/`size` are the live semantic projection;
    /// a partial 4 KiB Linux mapping can retain a 16 KiB physical owner whose
    /// base precedes that projection. Lifetime decisions must use this tuple.
    physical_ipa: u64,
    physical_size: usize,
    /// Which incarnation of the global-frame lease this row was published
    /// against — see [`GlobalFrameHostOwner::generation`].
    owner_generation: u64,
    /// Host VA of the buffer backing this guest-physical mapping. We
    /// record this explicitly so the fork(2) path can re-issue
    /// `hv_vm_map` in the child against the same (COW'd) host pages
    /// without going through `applevisor::Memory::new` (which would
    /// allocate a fresh buffer).
    host_addr: *mut u8,
    /// Size of the mapping in bytes (matches the size HVF was given).
    size: usize,
    /// Stage-2 permissions used to map the region. Same value that
    /// `hvf_perms` returned; the child rebuilds the mapping with these
    /// exact permissions.
    perms: applevisor::memory::MemPerms,
    /// `Memory` owns the host allocation and the hv_vm_unmap that
    /// fires on Drop. In a freshly-forked CHILD we replace this with
    /// `None` (after `mem::forget` on the inherited inner) — the host
    /// pages stay alive via COW; the unmap would target the parent's
    /// HVF context which no longer exists in the child.
    ///
    /// `#[allow(dead_code)]`: these are RAII ownership holders, kept alive for
    /// their `Drop` side effects (freeing host pages), not read. Every region
    /// is now built by `map_region_raw` with `memory: None` +
    /// `host_mapping: Some(..)`.
    #[allow(dead_code)]
    memory: Option<applevisor::memory::Memory>,
    #[allow(dead_code)]
    host_mapping: Option<crate::host_mapping::OwnedHostMapping>,
    /// Owning rollback/retirement handle for a fresh HVPatch stage-2 extent.
    /// Inherited mappings and dynamic aliases owned by the process-global
    /// host-owner registry carry `None`.
    stage2_lease: Option<GlobalFrameStage2Lease>,
    /// True only for a post-boot alias published through `add_alias`. Retired
    /// aliases deliberately remain in `mappings` to keep their host/stage-2
    /// owners alive, but the live alias registry decides whether they enter a
    /// fork child's address-space inventory.
    is_dynamic_alias: bool,
    /// Separates host/fork visibility from VM-global IPA and futex identity.
    /// Both shared variants keep one host backing across guest fork, while only
    /// `GlobalShared` participates in the historical global alias namespace.
    sharing: GuestMappingSharing,
    /// The guest's INTENDED writability (Linux PROT_WRITE), tracked separately
    /// from `perms` — alias regions force `perms` to RWX for the HVF stage-2
    /// translation quirk, so it cannot be used to detect a read-only mapping.
    /// The syscall write-path (`write_guest_bytes_checked`) rejects a write into
    /// a non-writable mapping with EFAULT instead of faulting the host (SIGBUS on
    /// a PROT_READ MAP_SHARED file alias) or corrupting a carrick-owned
    /// `write:false` region. (audit M1; probe `rosharedbus`)
    guest_writable: bool,
    shared_key_base: u64,
    shared_key_offset: u64,
}

/// A copyable projection of the scalar fields of an [`HvfMappedRegion`] that the
/// syscall-path accessors actually read (`start`/`end`/`ipa`/`host_addr`/`size`/
/// `guest_writable`/sharing). [`HvfInner::mapping_for_range`] returns this
/// by value instead of `&HvfMappedRegion` so a lookup that resolves through the
/// PROCESS-SHARED `alias_registry` fallback (a high-VA alias another thread
/// mapped, absent from THIS thread's per-thread `mappings`) can synthesize a view
/// with no borrow into `self.mappings`. The copy loops compute
/// `host_addr + (addr - start)`, so a synthetic view sets `start` to the alias VA
/// base and `host_addr` to its backing base — identical offset math to a real
/// region.
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
#[derive(Clone, Copy)]
struct MappingView {
    start: u64,
    end: u64,
    ipa: u64,
    host_addr: *mut u8,
    guest_writable: bool,
    sharing: GuestMappingSharing,
    shared_key_base: u64,
    shared_key_offset: u64,
}

/// Snapshot of vCPU register state captured before fork(2). The child restores
/// from this after rebuilding the HVF context so it resumes exactly where the
/// parent left off (post-clone syscall).
///
/// The architectural register file lives in the ISA-neutral
/// [`Aarch64VcpuSnapshot`] `core` — the SAME type the shared engine and the KVM
/// lane trade in — so the HVF lane no longer duplicates those 21 fields. The
/// only thing HVF carries on top is the backend-owned `last_exit_class` (the
/// trap class latched at the exit the snapshot was taken on), which the neutral
/// type deliberately does NOT model. This is the "neutral core + backend extra"
/// shape: the per-VMM HVF↔neutral mapping (CPSR ↔ `core.pstate` and the `*_EL1`
/// sysreg names ↔ their neutral aliases) lives in
/// `snapshot_vcpu_from`/`restore_vcpu*`; mailbox rebinding owns SP_EL1. The
/// TTBR1_EL1 (Rosetta x86-64 high-half
/// root) / ACTLR_EL1 (Rosetta EnTSO) / TPIDR*_EL0 (musl TLS, vDSO/rseq) capture
/// rationales are documented on the neutral fields.
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
#[derive(Debug, Clone)]
pub(crate) struct VcpuSnapshot {
    /// The ISA-neutral architectural register file (GPRs, EL1 sysregs, V-regs, FP
    /// control) shared with the engine and the KVM lane.
    pub(crate) core: Aarch64VcpuSnapshot,
    /// Backend-only: the HVF trap class latched at the exit this snapshot was
    /// taken on. Engine-owned and intentionally absent from the neutral snapshot;
    /// restored onto the rebuilt vCPU's `last_exit_class` so a reclaim/fork
    /// resumes with the correct exit-class context.
    pub(crate) last_exit_class: u64,
}

// Off macOS/aarch64 the HVF backend is cfg'd out entirely (no `applevisor`, no
// `HvfTrapEngine` alias, no register-access helpers), so there is no non-macOS
// `HvfInner` marker to carry — `HvfInner` exists ONLY on the macOS/HVF lane.

/// One mapping descriptor for a thread sibling: the guest-physical range,
/// the host VA backing it, its size, and the stage-2 perms. The sibling vCPU
/// lives in the same HVF VM as the parent, so the stage-2 entries are already
/// present; the descriptor only re-materialises local syscall-path metadata as
/// `HvfMappedRegion { memory: None }` (UNOWNED) so the sibling never
/// unmaps/frees buffers the main engine owns.
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
#[derive(Debug, Clone, Copy)]
struct ThreadMappingDesc {
    start: u64,
    ipa: u64,
    end: u64,
    host_addr: *mut u8,
    size: usize,
    physical_ipa: u64,
    physical_host_addr: *mut u8,
    physical_size: usize,
    perms: applevisor::memory::MemPerms,
    is_dynamic_alias: bool,
    sharing: GuestMappingSharing,
    guest_writable: bool,
    shared_key_base: u64,
    shared_key_offset: u64,
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ForkMappingDisposition {
    /// Parent and child keep the same frame and the same writable permissions.
    SharedFrameWritable,
    /// Parent and child name the same private frame, with both stage-1 leaves
    /// armed read-only until one mm takes the write-permission COW fault.
    SharedFrameReadOnly,
    /// Carrick-owned stage-1 tables are per-mm mutable kernel state, so the
    /// child receives an independent table frame before publication.
    IndependentPageTables,
    /// Carrick-owned EL1 identity/mailbox state is never guest-accessible and
    /// must be writable before the exception vector can run.  Give the child a
    /// fresh per-mm frame before entry rather than depending on recovery from a
    /// current-EL write-permission fault.
    IndependentKernelState,
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
fn fork_mapping_disposition(
    mapping: &ThreadMappingDesc,
    shares_mm: bool,
) -> ForkMappingDisposition {
    if mapping.sharing.shares_across_fork() {
        ForkMappingDisposition::SharedFrameWritable
    } else if mapping.start == crate::memory::LINUX_PAGE_TABLES_BASE {
        ForkMappingDisposition::IndependentPageTables
    } else if mapping.guest_writable && is_kernel_only_stage1_range(mapping.start, mapping.size) {
        ForkMappingDisposition::IndependentKernelState
    } else if shares_mm && !is_kernel_only_stage1_range(mapping.start, mapping.size) {
        ForkMappingDisposition::SharedFrameWritable
    } else {
        ForkMappingDisposition::SharedFrameReadOnly
    }
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
fn is_stage1_cow_write_fault(syndrome: u64) -> bool {
    const EXCEPTION_CLASS_MASK: u64 = 0x3f;
    const DATA_ABORT_LOWER_EL: u64 = 0x24;
    const WRITE_NOT_READ: u64 = 1 << 6;
    const FAULT_STATUS_MASK: u64 = 0x3f;
    let exception_class = (syndrome >> 26) & EXCEPTION_CLASS_MASK;
    let fault_status = syndrome & FAULT_STATUS_MASK;
    matches!(exception_class, DATA_ABORT_LOWER_EL | 0x25)
        && syndrome & WRITE_NOT_READ != 0
        && matches!(fault_status, 0x0d..=0x0f)
}

fn frame_cow_write_is_denied(
    write_denied: bool,
    intent: carrick_aarch64::vmm::FrameCowWriteIntent,
) -> bool {
    write_denied && intent == carrick_aarch64::vmm::FrameCowWriteIntent::GuestVisible
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum FrameCowWriteRoute {
    Direct,
    CopyOnWrite,
    MaterializeRetired,
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum UnarmedPermissionFaultRoute {
    NotCow,
    RetryCommittedWinner,
    MissingArm,
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
fn unarmed_permission_fault_route(
    private_writable_mapping: bool,
    write_denied: bool,
    any_arms: bool,
    live_leaf_is_writable: bool,
) -> UnarmedPermissionFaultRoute {
    if !private_writable_mapping || write_denied {
        UnarmedPermissionFaultRoute::NotCow
    } else if live_leaf_is_writable {
        UnarmedPermissionFaultRoute::RetryCommittedWinner
    } else if !any_arms {
        UnarmedPermissionFaultRoute::NotCow
    } else {
        UnarmedPermissionFaultRoute::MissingArm
    }
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
fn frame_cow_write_route(
    intent: carrick_aarch64::vmm::FrameCowWriteIntent,
    armed: bool,
    retained_output_has_no_physical_source: bool,
    retained_output_source_is_shared: bool,
) -> FrameCowWriteRoute {
    // A maintenance write whose retained output names a frame OTHER mms still
    // reference must MATERIALIZE a private replacement, exactly like the
    // no-source case — never write through. The armed-set cannot make this
    // call: it is derived at fork from alias rows and is known-omissive
    // (`mtforkcorrupt`), and an unarmed Direct write through a shared frame
    // zeroed one process's live memory during another's mmap reuse (the
    // CPython forkserver interned-dict corruption). The frame inventory's
    // reference count is the authority that actually knows who shares.
    if intent == carrick_aarch64::vmm::FrameCowWriteIntent::BackingMaintenance
        && (retained_output_has_no_physical_source || retained_output_source_is_shared)
    {
        FrameCowWriteRoute::MaterializeRetired
    } else if armed {
        FrameCowWriteRoute::CopyOnWrite
    } else {
        FrameCowWriteRoute::Direct
    }
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
#[derive(Clone, Copy, Debug)]
struct FrameCowTrigger {
    class: carrick_observability::probes::HvpatchFrameCowTriggerClass,
    syndrome: u64,
    far: u64,
    ttbr0: u64,
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
#[derive(Debug)]
struct GlobalFrameIpaAllocator {
    next: u64,
    free: Vec<(u64, u64)>,
    live: std::collections::BTreeMap<u64, u64>,
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
impl GlobalFrameIpaAllocator {
    fn new() -> Self {
        Self {
            next: carrick_mem::memory::LINUX_HVPATCH_GLOBAL_FRAME_BASE,
            free: Vec::new(),
            live: std::collections::BTreeMap::new(),
        }
    }

    fn allocate(&mut self, length: u64, alignment: u64) -> Result<u64, TrapError> {
        let length = align_up(length, CowArmedRanges::COMPOUND_SIZE)?;
        if length == 0 {
            return Err(TrapError::Hypervisor(
                "cannot reserve an empty global frame IPA extent".to_owned(),
            ));
        }
        let mut best: Option<(u64, u64, usize, u64, u64)> = None;
        for (index, &(free_base, free_len)) in self.free.iter().enumerate() {
            let base = align_up(free_base, alignment)?;
            let Some(end) = base.checked_add(length) else {
                continue;
            };
            let free_end = free_base.saturating_add(free_len);
            if end > free_end {
                continue;
            }

            // Preserve the large contiguous holes needed by HVPatch exec
            // frames: use the smallest fitting extent, with the lowest base as
            // a deterministic tie-breaker.  The exact live-extent ledger below
            // remains the fail-closed authority for release validation.
            if best.is_none_or(|(best_len, best_base, ..)| {
                (free_len, free_base) < (best_len, best_base)
            }) {
                best = Some((free_len, free_base, index, base, end));
            }
        }
        if let Some((free_len, free_base, index, base, end)) = best {
            let free_end = free_base.saturating_add(free_len);
            self.free.swap_remove(index);
            if base > free_base {
                self.free.push((free_base, base - free_base));
            }
            if end < free_end {
                self.free.push((end, free_end - end));
            }
            self.live.insert(base, length);
            return Ok(base);
        }

        let base = align_up(self.next, alignment)?;
        let end = base
            .checked_add(length)
            .ok_or_else(|| TrapError::Hypervisor("global frame IPA overflow".to_owned()))?;
        let limit = carrick_mem::memory::LINUX_HVPATCH_GLOBAL_FRAME_BASE
            .checked_add(carrick_mem::memory::LINUX_HVPATCH_GLOBAL_FRAME_SIZE)
            .ok_or_else(|| TrapError::Hypervisor("global frame IPA limit overflow".to_owned()))?;
        if end > limit {
            return Err(TrapError::Hypervisor(
                "global frame IPA arena exhausted".to_owned(),
            ));
        }
        self.next = end;
        self.live.insert(base, length);
        Ok(base)
    }

    fn release(&mut self, base: u64, length: u64) -> Result<(), TrapError> {
        let arena_base = carrick_mem::memory::LINUX_HVPATCH_GLOBAL_FRAME_BASE;
        let arena_end =
            arena_base.saturating_add(carrick_mem::memory::LINUX_HVPATCH_GLOBAL_FRAME_SIZE);
        let length = align_up(length, CowArmedRanges::COMPOUND_SIZE)?;
        if length == 0 {
            return Err(TrapError::Hypervisor(
                "cannot release an empty global frame IPA extent".to_owned(),
            ));
        }
        let end = base
            .checked_add(length)
            .ok_or_else(|| TrapError::Hypervisor("global frame IPA release overflow".to_owned()))?;
        if base < arena_base || end > arena_end {
            return Err(TrapError::Hypervisor(format!(
                "global frame IPA release is outside the arena: base=0x{base:x} length=0x{length:x}"
            )));
        }
        if self.live.get(&base).copied() != Some(length) {
            return Err(TrapError::Hypervisor(format!(
                "global frame IPA release does not match a live exact extent: base=0x{base:x} length=0x{length:x}"
            )));
        }
        self.live.remove(&base);
        self.free.push((base, length));
        self.free.sort_unstable_by_key(|extent| extent.0);
        let mut merged: Vec<(u64, u64)> = Vec::with_capacity(self.free.len());
        for (extent_base, extent_len) in self.free.drain(..) {
            if let Some((last_base, last_len)) = merged.last_mut()
                && last_base.saturating_add(*last_len) == extent_base
            {
                *last_len = last_len.saturating_add(extent_len);
            } else {
                merged.push((extent_base, extent_len));
            }
        }
        self.free = merged;
        Ok(())
    }
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
fn global_frame_ipa_allocator() -> &'static parking_lot::Mutex<GlobalFrameIpaAllocator> {
    static ALLOCATOR: std::sync::OnceLock<parking_lot::Mutex<GlobalFrameIpaAllocator>> =
        std::sync::OnceLock::new();
    ALLOCATOR.get_or_init(|| parking_lot::Mutex::new(GlobalFrameIpaAllocator::new()))
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
fn reserve_global_frame_ipa_aligned(length: u64, alignment: u64) -> Result<u64, TrapError> {
    global_frame_ipa_allocator()
        .lock()
        .allocate(length, alignment)
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
fn release_global_frame_ipa(base: u64, length: u64) -> Result<(), TrapError> {
    global_frame_ipa_allocator().lock().release(base, length)
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
fn release_retired_stage2_ipa(base: u64, length: u64) -> Result<(), TrapError> {
    // Boot identity mappings and fixed root slots are stage-2 extents but were
    // never allocated from the reusable global-frame arena. They still need
    // unmapping; they must not be presented as allocator releases.
    if !is_reusable_global_frame_extent(base, length) {
        return Ok(());
    }
    release_global_frame_ipa(base, length)
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
#[derive(Debug)]
struct GlobalFrameStage2Lease {
    base: u64,
    length: u64,
    mapped: bool,
    active: bool,
    release_ipa: bool,
    #[cfg(test)]
    drop_backing_audit: Option<(usize, std::sync::Arc<std::sync::atomic::AtomicBool>)>,
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
impl GlobalFrameStage2Lease {
    fn reserve(length: u64, alignment: u64) -> Result<Self, TrapError> {
        let length = align_up(length, CowArmedRanges::COMPOUND_SIZE)?;
        Ok(Self {
            base: reserve_global_frame_ipa_aligned(length, alignment)?,
            length,
            mapped: false,
            active: true,
            release_ipa: true,
            #[cfg(test)]
            drop_backing_audit: None,
        })
    }

    fn fixed(base: u64, length: u64) -> Self {
        Self {
            base,
            length,
            mapped: false,
            active: true,
            release_ipa: false,
            #[cfg(test)]
            drop_backing_audit: None,
        }
    }

    fn mark_mapped(&mut self) {
        self.mapped = true;
    }

    fn key(&self) -> (u64, u64) {
        (self.base, self.length)
    }
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
impl Drop for GlobalFrameStage2Lease {
    fn drop(&mut self) {
        #[cfg(test)]
        if let Some((host_addr, observed)) = &self.drop_backing_audit {
            observed.store(
                alias_backing_is_live(*host_addr),
                std::sync::atomic::Ordering::SeqCst,
            );
        }
        if !self.active {
            return;
        }
        if self.mapped {
            let size = usize::try_from(self.length).unwrap_or_else(|_| {
                eprintln!("carrick: FATAL: global frame stage-2 lease is too large");
                std::process::abort();
            });
            let rc = unsafe { inventory_hv_vm_unmap(self.base, size) };
            if rc != 0 {
                eprintln!(
                    "carrick: FATAL: rollback global frame stage-2 lease IPA 0x{:x} size {} failed: 0x{rc:x}",
                    self.base, self.length
                );
                std::process::abort();
            }
        }
        if self.release_ipa {
            release_global_frame_ipa(self.base, self.length).unwrap_or_else(|error| {
                eprintln!("carrick: FATAL: release global frame stage-2 lease: {error}");
                std::process::abort();
            });
        }
    }
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
impl ThreadMappingDesc {
    /// Project a live region into a `Send`-safe descriptor for a `ThreadSpec` (the
    /// sibling thread mirrors it as an UNOWNED `HvfMappedRegion`). Called by
    /// `HvfVmState::build_thread_spec` (the per-VMM `build_sibling_builder`).
    fn from_region(region: &HvfMappedRegion) -> Self {
        Self {
            start: region.start,
            ipa: region.ipa,
            end: region.end,
            host_addr: region.host_addr,
            size: semantic_extent_size(region.start, region.end),
            physical_ipa: region.physical_ipa,
            physical_host_addr: region.host_addr,
            physical_size: region.physical_size,
            perms: region.perms,
            is_dynamic_alias: region.is_dynamic_alias,
            sharing: region.sharing,
            guest_writable: region.guest_writable,
            shared_key_base: region.shared_key_base,
            shared_key_offset: region.shared_key_offset,
        }
    }

    fn from_alias(alias: AliasBacking) -> Option<Self> {
        let perms = match alias.perms {
            0 => applevisor::memory::MemPerms::None,
            1 => applevisor::memory::MemPerms::Read,
            2 => applevisor::memory::MemPerms::Write,
            3 => applevisor::memory::MemPerms::ReadWrite,
            4 => applevisor::memory::MemPerms::Exec,
            5 => applevisor::memory::MemPerms::ReadExec,
            6 => applevisor::memory::MemPerms::WriteExec,
            7 => applevisor::memory::MemPerms::ReadWriteExec,
            _ => return None,
        };
        Some(Self {
            start: alias.start,
            ipa: alias.ipa,
            end: alias.start.saturating_add(alias.size as u64),
            host_addr: alias.host_addr as *mut u8,
            size: alias.size,
            physical_ipa: alias.physical_ipa,
            physical_host_addr: alias.physical_host_addr as *mut u8,
            physical_size: alias.physical_size,
            perms,
            is_dynamic_alias: true,
            sharing: alias.sharing,
            guest_writable: alias.guest_writable,
            shared_key_base: alias.shared_key_base,
            shared_key_offset: alias.shared_key_offset,
        })
    }

    fn into_unowned_region(self) -> HvfMappedRegion {
        HvfMappedRegion {
            start: self.start,
            ipa: self.ipa,
            physical_ipa: self.physical_ipa,
            end: self.end,
            host_addr: self.host_addr,
            size: self.physical_size,
            physical_size: self.physical_size,
            perms: self.perms,
            memory: None,
            host_mapping: None,
            stage2_lease: None,
            is_dynamic_alias: self.is_dynamic_alias,
            sharing: self.sharing,
            guest_writable: self.guest_writable,
            shared_key_base: self.shared_key_base,
            shared_key_offset: self.shared_key_offset,
            owner_generation: global_frame_host_owner_generation(
                self.physical_ipa,
                self.physical_size as u64,
            ),
        }
    }
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
fn is_persistent_executor_carrier_mapping(mapping: &HvfMappedRegion) -> bool {
    is_persistent_executor_carrier_address(mapping.start)
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
fn is_persistent_executor_carrier_guest_mapping(mapping: &GuestMapping) -> bool {
    is_persistent_executor_carrier_address(mapping.guest_start)
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
fn mapping_belongs_to_task_inventory(
    persistent_vm_lifecycle: bool,
    mapping: &HvfMappedRegion,
) -> bool {
    !persistent_vm_lifecycle || !is_persistent_executor_carrier_mapping(mapping)
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
fn is_persistent_executor_carrier_address(address: u64) -> bool {
    matches!(
        address,
        carrick_mem::memory::LINUX_EL0_TRAMPOLINE_BASE
            | carrick_mem::memory::LINUX_EL1_VECTORS_BASE
            | carrick_mem::memory::LINUX_EL1_MAINT_BASE
            | carrick_mem::memory::LINUX_SYSCALL_MAILBOX_BASE
    )
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
fn persistent_executor_carrier_mappings(mappings: &[HvfMappedRegion]) -> Vec<ThreadMappingDesc> {
    mappings
        .iter()
        .filter(|mapping| is_persistent_executor_carrier_mapping(mapping))
        .map(ThreadMappingDesc::from_region)
        .collect()
}

/// Owning carrier-wide lifetime for the four fixed HVPatch control mappings.
/// Logical MM/task cleanup never sees these rows. The last factory/worker Arc
/// drops only after every worker vCPU has been joined and destroyed.
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
struct PersistentCarrierMappings {
    mappings: Vec<HvfMappedRegion>,
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
impl PersistentCarrierMappings {
    fn extract(task_mappings: &mut Vec<HvfMappedRegion>) -> Result<Self, TrapError> {
        let mut carrier = Vec::with_capacity(4);
        let mut task = Vec::with_capacity(task_mappings.len());
        for mapping in std::mem::take(task_mappings) {
            if is_persistent_executor_carrier_mapping(&mapping) {
                carrier.push(mapping);
            } else {
                task.push(mapping);
            }
        }
        *task_mappings = task;
        let authority = Self { mappings: carrier };
        authority.audit()?;
        if authority.mappings.len() != 4 {
            return Err(TrapError::Hypervisor(format!(
                "persistent executor carrier owns {} mappings, expected 4",
                authority.mappings.len()
            )));
        }
        Ok(authority)
    }

    fn host_pointer(&self, address: u64, length: usize) -> Option<std::ptr::NonNull<u8>> {
        let end = address.checked_add(u64::try_from(length).ok()?)?;
        let mapping = self
            .mappings
            .iter()
            .find(|mapping| address >= mapping.start && end <= mapping.end)?;
        let offset = usize::try_from(address.checked_sub(mapping.start)?).ok()?;
        std::ptr::NonNull::new(unsafe { mapping.host_addr.add(offset) })
    }

    fn host_pointer_for_ipa(&self, ipa: u64, length: usize) -> Option<*mut u8> {
        let mapping = HvfVmState::mapping_for_ipa_range(&self.mappings, ipa, length.max(1))?;
        let offset = usize::try_from(ipa.checked_sub(mapping.ipa)?).ok()?;
        Some(unsafe { mapping.host_addr.add(offset) })
    }

    fn audit(&self) -> Result<(), TrapError> {
        let descriptors = persistent_executor_carrier_mappings(&self.mappings);
        audit_persistent_executor_carrier_mappings(&descriptors)
    }
}

// SAFETY: the owning mappings name VM-global MAP_SHARED host allocations. The
// carrier Arc is immutable after extraction; only its final Drop mutates the
// mapping owners, after all worker threads have joined.
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
unsafe impl Send for PersistentCarrierMappings {}
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
unsafe impl Sync for PersistentCarrierMappings {}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
impl Drop for PersistentCarrierMappings {
    fn drop(&mut self) {
        for mut mapping in self.mappings.drain(..) {
            if let Some(lease) = mapping.stage2_lease.take() {
                drop(lease);
            } else {
                let rc =
                    unsafe { inventory_hv_vm_unmap(mapping.physical_ipa, mapping.physical_size) };
                if rc != 0 {
                    eprintln!(
                        "carrick: FATAL: retire persistent carrier stage-2 IPA 0x{:x} size {} failed: 0x{rc:x}",
                        mapping.physical_ipa, mapping.physical_size
                    );
                    std::process::abort();
                }
            }
            // Stage-2 is gone before OwnedHostMapping releases the backing.
            drop(mapping);
        }
    }
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
fn persistent_carrier_host_pointer(
    mappings: &[ThreadMappingDesc],
    address: u64,
    length: usize,
) -> Option<std::ptr::NonNull<u8>> {
    let end = address.checked_add(u64::try_from(length).ok()?)?;
    let mapping = mappings
        .iter()
        .find(|mapping| address >= mapping.start && end <= mapping.end)?;
    let offset = usize::try_from(address.checked_sub(mapping.start)?).ok()?;
    std::ptr::NonNull::new(unsafe { mapping.host_addr.add(offset) })
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
fn audit_persistent_executor_carrier_mappings(
    mappings: &[ThreadMappingDesc],
) -> Result<(), TrapError> {
    for (name, start, size) in [
        (
            "EL0 trampoline",
            carrick_mem::memory::LINUX_EL0_TRAMPOLINE_BASE,
            carrick_mem::memory::LINUX_EL0_TRAMPOLINE_SIZE,
        ),
        (
            "EL1 vectors",
            carrick_mem::memory::LINUX_EL1_VECTORS_BASE,
            carrick_mem::memory::LINUX_EL1_VECTORS_SIZE,
        ),
        (
            "EL1 maintenance",
            carrick_mem::memory::LINUX_EL1_MAINT_BASE,
            carrick_mem::memory::LINUX_EL1_MAINT_SIZE,
        ),
        (
            "syscall mailbox",
            carrick_mem::memory::LINUX_SYSCALL_MAILBOX_BASE,
            carrick_mem::memory::LINUX_SYSCALL_MAILBOX_ARENA_SIZE,
        ),
    ] {
        let size = usize::try_from(size).map_err(|_| {
            TrapError::Hypervisor(format!("persistent executor {name} extent is too large"))
        })?;
        if persistent_carrier_host_pointer(mappings, start, size).is_none() {
            return Err(TrapError::Hypervisor(format!(
                "persistent executor carrier {name} mapping is absent"
            )));
        }
    }
    Ok(())
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
struct ForkMappingDesc {
    start: u64,
    ipa: u64,
    physical_ipa: u64,
    end: u64,
    host: ForkMappingHost,
    size: usize,
    physical_size: usize,
    perms: applevisor::memory::MemPerms,
    is_dynamic_alias: bool,
    sharing: GuestMappingSharing,
    guest_writable: bool,
    shared_key_base: u64,
    shared_key_offset: u64,
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
enum ForkMappingHost {
    Borrowed(*mut u8),
    Owned(crate::host_mapping::OwnedHostMapping),
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
impl ForkMappingHost {
    fn ptr(&self) -> *mut u8 {
        match self {
            ForkMappingHost::Borrowed(ptr) => *ptr,
            ForkMappingHost::Owned(mapping) => mapping.as_ptr(),
        }
    }

    fn into_owned(self) -> Option<crate::host_mapping::OwnedHostMapping> {
        match self {
            ForkMappingHost::Borrowed(_) => None,
            ForkMappingHost::Owned(mapping) => Some(mapping),
        }
    }
}

/// Everything a freshly-spawned host thread needs to stand up its own vCPU
/// in the SHARED process VM and resume the cloned guest thread.
///
/// `vm` is a `vm.clone()` handle: the applevisor VM is Arc-refcounted, so
/// holding a clone keeps the single process VM alive and lets the new thread
/// call `vcpu_create()` against it (HVF requires vCPU create on the owning
/// thread). `mappings` are raw descriptors of the SAME host buffers the main
/// engine mapped; they are local syscall-path metadata only, because the
/// stage-2 entries live on the shared HVF VM, not on each vCPU.
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
#[derive(Clone)]
pub struct ThreadSpec {
    vm: applevisor::vm::VirtualMachineInstance<applevisor::vm::GicDisabled>,
    mappings: Vec<ThreadMappingDesc>,
    protections: std::sync::Arc<MemoryProtections>,
    /// Shared stage-1 page-table editor (one VM ⇒ one set of tables; siblings
    /// share this so concurrent edits serialize through its mutex).
    page_tables: std::sync::Arc<parking_lot::Mutex<Option<crate::page_table::PageTableManager>>>,
    mailbox_slots: std::sync::Arc<MailboxSlotAllocator>,
    syscall_transport: HvfSyscallTransport,
    persistent_vm_lifecycle: bool,
    mm_root_slot: Option<(u64, u64)>,
    frame_inventory: std::sync::Arc<parking_lot::Mutex<HvpatchFrameInventory>>,
    cow_authority: Option<std::sync::Arc<dyn carrick_hal::FrameCowAuthority>>,
    cow_identity: Option<carrick_hal::FrameCowIdentity>,
    cow_armed: std::sync::Arc<parking_lot::Mutex<CowArmedRanges>>,
    cow_deferred_publications: std::sync::Arc<parking_lot::Mutex<Vec<PendingFrameCowPublication>>>,
}

/// Factory authority for one Task4 worker. It deliberately carries only the
/// carrier VM and executor-local mailbox transport configuration; no task MM,
/// stage-1 editor, mapping descriptor, frame inventory, or COW authority can be
/// retained by the factory or copied into an idle worker.
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
#[derive(Clone)]
pub(crate) struct PersistentExecutorSpec {
    vm: applevisor::vm::VirtualMachineInstance<applevisor::vm::GicDisabled>,
    /// VM-global Carrick control mappings needed before any task projection is
    /// loaded: entry trampoline, EL1 vectors/scratch path, maintenance code,
    /// and the executor mailbox arena. The Arc is their exact carrier-wide
    /// stage-2/backing owner; task mappings, page tables, MM/root, inventory,
    /// and COW authority stay out of the factory.
    carrier_mappings: std::sync::Arc<PersistentCarrierMappings>,
    mailbox_slots: std::sync::Arc<MailboxSlotAllocator>,
    syscall_transport: HvfSyscallTransport,
}

// SAFETY: PersistentCarrierMappings owns immutable VM-global MAP_SHARED
// buffers. Worker threads only resolve pointers while their Arc is live.
unsafe impl Send for PersistentExecutorSpec {}
unsafe impl Sync for PersistentExecutorSpec {}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
struct ProcessMappingDesc {
    start: u64,
    ipa: u64,
    end: u64,
    // Drop the stage-2 authority before the host owner on every implicit
    // prepare-error path. Named initializers make declaration order otherwise
    // invisible, but Rust field destruction follows this order.
    stage2_lease: Option<GlobalFrameStage2Lease>,
    host: ForkMappingHost,
    size: usize,
    physical_ipa: u64,
    physical_host_addr: *mut u8,
    physical_size: usize,
    inventory_backing: InventoryBackingIdentity,
    perms: applevisor::memory::MemPerms,
    is_dynamic_alias: bool,
    sharing: GuestMappingSharing,
    guest_writable: bool,
    shared_key_base: u64,
    shared_key_offset: u64,
    inherited_frame: Option<carrick_hal::FrameId>,
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
#[derive(Clone, Copy, Debug)]
struct ProcessInventoryDesc {
    gpa: u64,
    length: u64,
    permissions: carrick_hal::MemPerms,
    inherited_frame: Option<carrick_hal::FrameId>,
    inherited_mapping: Option<carrick_hal::MappingId>,
    backing: InventoryBackingIdentity,
    stage2_lease: (u64, u64),
    sharing: GuestMappingSharing,
    guest_writable: bool,
    shared_mm: bool,
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
fn inherited_fork_inventory_extents(
    mapping: &ThreadMappingDesc,
    inventory: &std::collections::BTreeMap<(u64, u64), InventoryExtent>,
) -> Vec<((u64, u64), InventoryExtent)> {
    inventory
        .iter()
        .filter(|(_, extent)| {
            (extent.stage2_base, extent.stage2_length)
                == (mapping.physical_ipa, mapping.physical_size as u64)
        })
        .map(|(&key, &extent)| (key, extent))
        .collect()
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
fn fork_translation_has_overlay_owner(
    mappings: &[ProcessMappingDesc],
    candidate_index: usize,
    va: u64,
    translated: u64,
) -> bool {
    mappings.iter().enumerate().any(|(index, overlay)| {
        index != candidate_index
            && va >= overlay.start
            && va < overlay.end
            && overlay
                .ipa
                .checked_add(va - overlay.start)
                .is_some_and(|ipa| ipa == translated)
    })
}

/// The boot-time shared aperture is a physical stage-2 owner, not one dense
/// guest-visible mapping. Linux `MAP_SHARED` sub-allocations install sparse
/// stage-1 leaves anywhere inside it, so the aperture's first VA may be absent
/// even while later leaves are live. Fork copies the parent's stage-1 graph
/// separately; do not treat the missing *base* leaf as a corrupt child graph.
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
fn fork_mapping_requires_base_translation(start: u64, size: usize, is_dynamic_alias: bool) -> bool {
    is_dynamic_alias
        || start != crate::memory::LINUX_SHARED_FILE_BASE
        || size != crate::memory::LINUX_SHARED_FILE_SIZE as usize
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
#[derive(Clone, Copy, Debug)]
struct PendingForkFrameReceipt {
    transaction: carrick_hal::KernelTransactionId,
    kind: carrick_observability::probes::HvpatchForkFrameKind,
    parent_mapping: carrick_hal::MappingId,
    child_mapping: carrick_hal::MappingId,
    frame: carrick_hal::FrameId,
    ipa: u64,
    length: u64,
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
fn authenticate_pending_fork_receipts(
    receipts: &[PendingForkFrameReceipt],
    receipt: &carrick_hal::FrameInventoryApplyReceipt,
) -> bool {
    receipts.iter().enumerate().all(|(index, pending)| {
        pending.transaction == receipt.transaction()
            && receipt.authorizes(pending.child_mapping, pending.frame)
            && pending.length != 0
            && pending.parent_mapping != pending.child_mapping
            && !receipts[..index].iter().any(|prior| {
                prior.child_mapping == pending.child_mapping
                    || (prior.ipa, prior.length) == (pending.ipa, pending.length)
            })
    })
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
fn authenticate_pending_retirement(
    expected: &[(carrick_hal::MappingId, carrick_hal::FrameId)],
    pending: &[PendingForkFrameReceipt],
    receipt: &carrick_hal::FrameInventoryRetirementReceipt,
) -> bool {
    receipt.mm_empty_at_revision()
        && !expected.is_empty()
        && expected.len() == receipt.mapping_set().len()
        && expected
            .iter()
            .all(|&(mapping, frame)| receipt.authorizes(mapping, frame))
        && pending
            .iter()
            .all(|pending| receipt.authorizes(pending.child_mapping, pending.frame))
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct PendingFrameCowPublication {
    va: u64,
    len: usize,
    expected_ipa: u64,
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
fn process_mapping_needs_stage2_install(inherited_frame: Option<carrick_hal::FrameId>) -> bool {
    inherited_frame.is_none()
}

/// A fork child address space waiting for vCPU materialization on its owning
/// host thread. Private mappings initially retain the parent's FrameId/global
/// IPA and are read-only in each mm's independent stage-1 graph; the first
/// writer receives a new compound frame. A CLONE_VM child instead retains user
/// frames writable while keeping its stage-1 tables and EL1 control state
/// independent. Guest-shared mappings retain their existing IPA and frame
/// without entering private COW. Shared-anonymous aliases remain mm-scoped; only
/// shared-file mappings use the VM-global alias namespace.
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
pub struct ProcessSpec {
    vm: applevisor::vm::VirtualMachineInstance<applevisor::vm::GicDisabled>,
    mappings: Vec<ProcessMappingDesc>,
    inventory_mappings: Vec<ProcessInventoryDesc>,
    protections: std::sync::Arc<MemoryProtections>,
    // No `page_tables`: the child's stage-1 graph reaches the backend through
    // `bind_stage1_page_tables`, which the shared engine calls with the SAME
    // manager it puts in its own process spec, immediately after
    // `from_process_spec` returns. Carrying a second copy here meant cloning
    // the whole 1.75 MiB `LINUX_PAGE_TABLES_SIZE` image once per fork only to
    // overwrite it unread a few instructions later.
    mailbox_slots: std::sync::Arc<MailboxSlotAllocator>,
    syscall_transport: HvfSyscallTransport,
    persistent_vm_lifecycle: bool,
    mm_root_slot: (u64, u64),
    frame_inventory: std::sync::Arc<parking_lot::Mutex<HvpatchFrameInventory>>,
    cow_armed: std::sync::Arc<parking_lot::Mutex<CowArmedRanges>>,
}

/// Deferred HVPatch task backend state. Its variants deliberately contain no
/// vCPU, mailbox allocator/binding, vCPU handle/id, reclaim authority, or host
/// owner identity; those belong exclusively to a Task4 worker pthread.
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
pub struct HvpatchTaskOnlyBackendState {
    registration: Option<HvpatchTaskRegistration>,
}

impl HvpatchTaskOnlyBackendState {
    pub(crate) fn runtime_task_state(
        &self,
        page_tables: std::sync::Arc<
            parking_lot::Mutex<Option<crate::page_table::PageTableManager>>,
        >,
        protections: std::sync::Arc<MemoryProtections>,
    ) -> Result<HvfTaskState, TrapError> {
        self.registration
            .as_ref()
            .ok_or_else(|| TrapError::Hypervisor("retired HVPatch registration".to_owned()))?
            .runtime_task_state(page_tables, protections)
    }

    pub(crate) fn apply_inventory(
        &self,
        apply: impl FnOnce(
            carrick_hal::FrameInventoryCommit<()>,
        ) -> Result<carrick_hal::FrameInventoryApplyReceipt, TrapError>,
    ) -> Result<(), TrapError> {
        self.registration
            .as_ref()
            .ok_or_else(|| TrapError::Hypervisor("retired HVPatch registration".to_owned()))?
            .apply_inventory(apply)
    }

    pub(crate) fn prepare_inventory_retirement(
        &self,
        commit: carrick_hal::FrameInventoryCommit<()>,
    ) -> Result<(), TrapError> {
        self.registration
            .as_ref()
            .ok_or_else(|| TrapError::Hypervisor("retired HVPatch registration".to_owned()))?
            .prepare_inventory_retirement(commit)
    }

    pub(crate) fn apply_inventory_retirement(
        &self,
        apply: impl FnOnce(
            carrick_hal::FrameInventoryCommit<()>,
        ) -> Result<carrick_hal::FrameInventoryRetirementReceipt, TrapError>,
    ) -> Result<(), TrapError> {
        self.registration
            .as_ref()
            .ok_or_else(|| TrapError::Hypervisor("retired HVPatch registration".to_owned()))?
            .apply_inventory_retirement(apply)
    }

    pub(crate) fn bind_child_kernel(
        &mut self,
        binding: HvpatchChildKernelBinding,
    ) -> Result<(), TrapError> {
        self.registration
            .as_mut()
            .ok_or_else(|| TrapError::Hypervisor("retired HVPatch registration".to_owned()))?
            .bind_child_kernel(binding)
    }

    pub(crate) fn activate(&self) -> Result<(), TrapError> {
        self.registration
            .as_ref()
            .ok_or_else(|| TrapError::Hypervisor("retired HVPatch registration".to_owned()))?
            .activate()
    }

    fn cleanup_exact(&mut self) {
        let Some(registration) = self.registration.take() else {
            return;
        };
        registration.cleanup().unwrap_or_else(|error| {
            eprintln!("carrick: FATAL: exact deferred HVPatch task cleanup: {error}");
            std::process::abort();
        });
    }
}

impl Drop for HvpatchTaskOnlyBackendState {
    fn drop(&mut self) {
        self.cleanup_exact();
    }
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct HvpatchCarrierTaskIdentity {
    pub task_serial: u64,
    pub thread_serial: u64,
    pub execution_generation: u64,
    pub linux_pid: i32,
    pub linux_tid: i32,
    pub asid: u16,
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
pub use carrick_hal::HvpatchChildKernelToken as HvpatchChildKernelBinding;

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub(crate) struct HvpatchCarrierTaskStateKey {
    directory_instance: std::num::NonZeroU64,
    task_serial: u64,
    thread_serial: u64,
    execution_generation: u64,
    nonce: std::num::NonZeroU64,
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
#[allow(dead_code)]
enum HvpatchCarrierTaskState {
    Sibling {
        vm: applevisor::vm::VirtualMachineInstance<applevisor::vm::GicDisabled>,
    },
    /// A distinct Linux process which retains an already-published MM.  The
    /// existing carrier-MM row owns the VM/stage-2 lifecycle; this edge owns no
    /// replacement carrier authority of its own.
    SharedProcess {
        vm: applevisor::vm::VirtualMachineInstance<applevisor::vm::GicDisabled>,
    },
    Process {
        vm: applevisor::vm::VirtualMachineInstance<applevisor::vm::GicDisabled>,
        stage2_leases: Vec<GlobalFrameStage2Lease>,
    },
    #[cfg(test)]
    Test {
        rollbacks: std::sync::Arc<std::sync::atomic::AtomicUsize>,
        order: Option<std::sync::Arc<parking_lot::Mutex<Vec<&'static str>>>>,
    },
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
enum HvpatchCarrierMmAuthority {
    Live {
        // Keys into `carrier_stage2_leases()`. `Drop::drop` runs BEFORE any
        // field drops, so releasing them there still issues every
        // `hv_vm_unmap` while the carrier VM below is alive. Retirement may
        // have taken some already; this is the backstop for the rest.
        stage2_lease_keys: Vec<(u64, u64)>,
        _vm: applevisor::vm::VirtualMachineInstance<applevisor::vm::GicDisabled>,
    },
    #[cfg(test)]
    Test {
        order: std::sync::Arc<parking_lot::Mutex<Vec<&'static str>>>,
    },
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
impl Drop for HvpatchCarrierMmAuthority {
    fn drop(&mut self) {
        match self {
            Self::Live {
                stage2_lease_keys, ..
            } => {
                for key in std::mem::take(stage2_lease_keys) {
                    drop(take_carrier_stage2_lease(key.0, key.1));
                }
            }
            #[cfg(test)]
            Self::Test { order } => {
                order.lock().push("carrier");
            }
        }
    }
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
struct HvpatchCarrierTaskRow {
    _mm: Option<std::sync::Arc<HvpatchCarrierMmAuthority>>,
    #[cfg(test)]
    rollbacks: Option<std::sync::Arc<std::sync::atomic::AtomicUsize>>,
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct HvpatchMmAuthorityKey {
    task_serial: u64,
    mm_root_slot: Option<(u64, u64)>,
    shared_kernel_mm: Option<u64>,
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
#[allow(dead_code)] // consumed by the worker-side binding load transaction in the next slice
struct HvpatchTaskMappingState {
    start: u64,
    ipa: u64,
    physical_ipa: u64,
    end: u64,
    host_addr: *mut u8,
    physical_host_addr: *mut u8,
    size: usize,
    physical_size: usize,
    perms: applevisor::memory::MemPerms,
    guest_writable: bool,
    host_mapping: Option<crate::host_mapping::OwnedHostMapping>,
    is_dynamic_alias: bool,
    sharing: GuestMappingSharing,
    shared_key_base: u64,
    shared_key_offset: u64,
    owner_generation: u64,
}
unsafe impl Send for HvpatchTaskMappingState {}
// SAFETY: these pointers are immutable address metadata naming MM-owned host
// mappings. Access is authenticated through the stage-1/frame authority and
// synchronized by the worker transaction; the descriptor never dereferences
// them on its own.
unsafe impl Sync for HvpatchTaskMappingState {}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
impl HvpatchTaskMappingState {
    fn unowned_runtime_region(&self) -> HvfMappedRegion {
        HvfMappedRegion {
            start: self.start,
            ipa: self.ipa,
            physical_ipa: self.physical_ipa,
            end: self.end,
            host_addr: self.host_addr,
            size: self.physical_size,
            physical_size: self.physical_size,
            perms: self.perms,
            memory: None,
            host_mapping: None,
            stage2_lease: None,
            is_dynamic_alias: self.is_dynamic_alias,
            sharing: self.sharing,
            guest_writable: self.guest_writable,
            shared_key_base: self.shared_key_base,
            shared_key_offset: self.shared_key_offset,
            owner_generation: self.owner_generation,
        }
    }
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
#[derive(Default)]
#[allow(dead_code)] // retained task authority; worker-side load consumes these fields
struct HvpatchPreparedTaskAuthority {
    mappings: Vec<HvpatchTaskMappingState>,
    mm_root_slot: Option<(u64, u64)>,
    /// Shared processes use the Kernel's exact MM identity to intern one MM
    /// projection even when the root parent has no task-only directory row.
    shared_kernel_mm: Option<u64>,
    inventory: HvpatchTaskInventoryAuthority,
    cow_authority: Option<std::sync::Arc<dyn carrick_hal::FrameCowAuthority>>,
    cow_identity: Option<carrick_hal::FrameCowIdentity>,
    cow_armed: Option<std::sync::Arc<parking_lot::Mutex<CowArmedRanges>>>,
    cow_deferred_publications:
        Option<std::sync::Arc<parking_lot::Mutex<Vec<PendingFrameCowPublication>>>>,
    pending_receipts: Vec<PendingForkFrameReceipt>,
    pending_aliases: Vec<AliasBacking>,
    #[cfg(test)]
    drop_order: Option<std::sync::Arc<parking_lot::Mutex<Vec<&'static str>>>>,
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
#[derive(Default)]
#[allow(dead_code)] // publication/activation is consumed by the next runtime wiring slice
enum HvpatchTaskInventoryAuthority {
    #[default]
    Absent,
    SiblingShared {
        ledger: std::sync::Arc<parking_lot::Mutex<HvpatchFrameInventory>>,
    },
    SharedProcess {
        ledger: std::sync::Arc<parking_lot::Mutex<HvpatchFrameInventory>>,
    },
    ProcessPrepared {
        ledger: std::sync::Arc<parking_lot::Mutex<HvpatchFrameInventory>>,
        staged: Vec<((u64, u64), InventoryExtent)>,
        commit: Option<carrick_hal::FrameInventoryCommit<()>>,
        challenge: Option<carrick_hal::FrameInventoryReceiptChallenge>,
    },
    InventoryPublished {
        ledger: std::sync::Arc<parking_lot::Mutex<HvpatchFrameInventory>>,
        staged: Vec<((u64, u64), InventoryExtent)>,
        receipt: carrick_hal::FrameInventoryApplyReceipt,
    },
    Active {
        ledger: std::sync::Arc<parking_lot::Mutex<HvpatchFrameInventory>>,
        receipt: carrick_hal::FrameInventoryApplyReceipt,
        retirement: Option<HvpatchPreparedInventoryRetirement>,
    },
    Retired,
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
struct HvpatchPreparedInventoryRetirement {
    commit: carrick_hal::FrameInventoryCommit<()>,
    challenge: carrick_hal::FrameInventoryReceiptChallenge,
    expected_mappings: Vec<(carrick_hal::MappingId, carrick_hal::FrameId)>,
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
#[allow(dead_code)] // transitions are exposed to the next publication wiring slice
impl HvpatchTaskInventoryAuthority {
    fn shared_runtime_ledger(
        &self,
    ) -> Option<std::sync::Arc<parking_lot::Mutex<HvpatchFrameInventory>>> {
        match self {
            Self::SiblingShared { ledger }
            | Self::SharedProcess { ledger }
            | Self::ProcessPrepared { ledger, .. }
            | Self::InventoryPublished { ledger, .. }
            | Self::Active { ledger, .. } => Some(std::sync::Arc::clone(ledger)),
            Self::Absent | Self::Retired => None,
        }
    }

    fn apply_process_inventory(
        &mut self,
        apply: impl FnOnce(
            carrick_hal::FrameInventoryCommit<()>,
        ) -> Result<carrick_hal::FrameInventoryApplyReceipt, TrapError>,
        expected_mm: std::num::NonZeroU64,
    ) -> Result<(), TrapError> {
        let current = std::mem::replace(self, Self::Retired);
        match current {
            Self::ProcessPrepared {
                ledger,
                staged,
                mut commit,
                mut challenge,
            } => {
                if let (Some(commit), Some(challenge)) = (commit.take(), challenge.take()) {
                    match apply(commit) {
                        Ok(receipt) if challenge.authenticate_apply(&receipt, expected_mm) => {
                            *self = Self::InventoryPublished {
                                ledger,
                                staged,
                                receipt,
                            };
                            Ok(())
                        }
                        Ok(_) => {
                            eprintln!(
                                "carrick: FATAL: Kernel returned a malformed successful HVPatch inventory receipt"
                            );
                            std::process::abort();
                        }
                        Err(_) => {
                            let mut inventory = ledger.lock();
                            HvfVmState::rollback_unpublished_mappings(&mut inventory, &staged)?;
                            Err(TrapError::Hypervisor(
                                "kernel rejected or mis-authenticated HVPatch inventory apply"
                                    .to_owned(),
                            ))
                        }
                    }
                } else {
                    *self = Self::ProcessPrepared {
                        ledger,
                        staged,
                        commit,
                        challenge,
                    };
                    Err(TrapError::Hypervisor(
                        "prepared HVPatch process inventory lost its commit".to_owned(),
                    ))
                }
            }
            other => {
                *self = other;
                Err(TrapError::Hypervisor(
                    "only a prepared process owner may publish HVPatch inventory".to_owned(),
                ))
            }
        }
    }

    fn activate(&mut self, pending_receipts: &[PendingForkFrameReceipt]) -> Result<(), TrapError> {
        let current = std::mem::replace(self, Self::Retired);
        match current {
            Self::SiblingShared { ledger } => {
                *self = Self::SiblingShared { ledger };
                Ok(())
            }
            Self::SharedProcess { ledger } => {
                *self = Self::SharedProcess { ledger };
                Ok(())
            }
            Self::InventoryPublished {
                ledger,
                staged,
                receipt,
            } => {
                if authenticate_pending_fork_receipts(pending_receipts, &receipt) {
                    *self = Self::Active {
                        ledger,
                        receipt,
                        retirement: None,
                    };
                    Ok(())
                } else {
                    *self = Self::InventoryPublished {
                        ledger,
                        staged,
                        receipt,
                    };
                    Err(TrapError::Hypervisor(
                        "HVPatch fork receipts failed inventory authentication".to_owned(),
                    ))
                }
            }
            other => {
                *self = other;
                Err(TrapError::Hypervisor(
                    "HVPatch inventory activation requires published inventory".to_owned(),
                ))
            }
        }
    }

    fn prepare_retirement(
        &mut self,
        commit: carrick_hal::FrameInventoryCommit<()>,
    ) -> Result<(), TrapError> {
        match self {
            Self::Active {
                ledger, retirement, ..
            } if retirement.is_none() => {
                let mut expected_mappings: Vec<_> = ledger
                    .lock()
                    .extents
                    .values()
                    .map(|extent| (extent.mapping, extent.frame))
                    .collect();
                expected_mappings.sort_unstable();
                expected_mappings.dedup();
                let mut committed_unmaps: Vec<_> = commit
                    .batch()
                    .events()
                    .iter()
                    .filter_map(|event| match *event {
                        carrick_hal::FrameInventoryEvent::UnmapMapping { mapping, .. } => {
                            Some(mapping)
                        }
                        _ => None,
                    })
                    .collect();
                committed_unmaps.sort_unstable();
                committed_unmaps.dedup();
                let expected_ids: Vec<_> = expected_mappings
                    .iter()
                    .map(|(mapping, _)| *mapping)
                    .collect();
                if expected_mappings.is_empty() || committed_unmaps != expected_ids {
                    return Err(TrapError::Hypervisor(
                        "retirement commit does not cover exact current HVPatch MM ledger"
                            .to_owned(),
                    ));
                }
                let challenge = commit.receipt_challenge();
                *retirement = Some(HvpatchPreparedInventoryRetirement {
                    commit,
                    challenge,
                    expected_mappings,
                });
                Ok(())
            }
            _ => Err(TrapError::Hypervisor(
                "HVPatch inventory retirement is duplicate or not active".to_owned(),
            )),
        }
    }

    fn apply_retirement(
        &mut self,
        expected_mm: std::num::NonZeroU64,
        pending_receipts: &[PendingForkFrameReceipt],
        apply: impl FnOnce(
            carrick_hal::FrameInventoryCommit<()>,
        ) -> Result<carrick_hal::FrameInventoryRetirementReceipt, TrapError>,
    ) -> Result<(), TrapError> {
        let current = std::mem::replace(self, Self::Retired);
        match current {
            Self::Active {
                ledger,
                receipt,
                retirement: Some(retirement),
            } => match apply(retirement.commit) {
                Ok(retired)
                    if retirement
                        .challenge
                        .authenticate_retirement(&retired, expected_mm)
                        && retired.revision() > receipt.revision()
                        && retired.transaction() != receipt.transaction()
                        && authenticate_pending_retirement(
                            &retirement.expected_mappings,
                            pending_receipts,
                            &retired,
                        ) =>
                {
                    Ok(())
                }
                Ok(_) => {
                    eprintln!(
                        "carrick: FATAL: Kernel returned a malformed successful HVPatch retirement receipt"
                    );
                    std::process::abort();
                }
                Err(error) => {
                    *self = Self::Active {
                        ledger,
                        receipt,
                        retirement: None,
                    };
                    Err(error)
                }
            },
            other => {
                *self = other;
                Err(TrapError::Hypervisor(
                    "HVPatch inventory retirement lacks an owned prepared commit".to_owned(),
                ))
            }
        }
    }

    fn rollback_unpublished(&mut self) -> Result<(), TrapError> {
        match std::mem::replace(self, Self::Retired) {
            Self::Absent
            | Self::SiblingShared { .. }
            | Self::SharedProcess { .. }
            | Self::Retired => Ok(()),
            Self::ProcessPrepared {
                ledger,
                staged,
                commit,
                challenge: _,
            } => {
                let mut inventory = ledger.lock();
                HvfVmState::rollback_unpublished_mappings(&mut inventory, &staged)?;
                drop(commit);
                Ok(())
            }
            Self::InventoryPublished { .. } | Self::Active { .. } => Err(TrapError::Hypervisor(
                "published HVPatch inventory dropped before exact retirement".to_owned(),
            )),
        }
    }

    fn phase_name(&self) -> &'static str {
        match self {
            Self::Absent => "absent",
            Self::SiblingShared { .. } => "sibling_shared",
            Self::SharedProcess { .. } => "shared_process",
            Self::ProcessPrepared { .. } => "prepared",
            Self::InventoryPublished { .. } => "inventory_published",
            Self::Active { .. } => "active",
            Self::Retired => "retired",
        }
    }
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
#[allow(dead_code)] // retained MM authority; worker-side load consumes these fields
struct HvpatchTaskMmAuthority {
    mappings: Vec<HvpatchTaskMappingState>,
    mm_root_slot: Option<(u64, u64)>,
    inventory: parking_lot::Mutex<HvpatchTaskInventoryAuthority>,
    kernel_mm: parking_lot::Mutex<Option<std::num::NonZeroU64>>,
    cow_armed: Option<std::sync::Arc<parking_lot::Mutex<CowArmedRanges>>>,
    cow_deferred_publications:
        Option<std::sync::Arc<parking_lot::Mutex<Vec<PendingFrameCowPublication>>>>,
    pending_receipts: Vec<PendingForkFrameReceipt>,
    alias_receipts: parking_lot::Mutex<Vec<AliasPublicationReceipt>>,
    #[cfg(test)]
    drop_order: Option<std::sync::Arc<parking_lot::Mutex<Vec<&'static str>>>>,
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
#[allow(dead_code)] // next publication slice invokes these exact MM transitions
impl HvpatchTaskMmAuthority {
    fn from_prepared(
        mut prepared: HvpatchPreparedTaskAuthority,
        alias_receipt: AliasPublicationReceipt,
    ) -> Self {
        Self {
            mappings: std::mem::take(&mut prepared.mappings),
            mm_root_slot: prepared.mm_root_slot,
            inventory: parking_lot::Mutex::new(std::mem::take(&mut prepared.inventory)),
            kernel_mm: parking_lot::Mutex::new(None),
            cow_armed: prepared.cow_armed.take(),
            cow_deferred_publications: prepared.cow_deferred_publications.take(),
            pending_receipts: std::mem::take(&mut prepared.pending_receipts),
            alias_receipts: parking_lot::Mutex::new(vec![alias_receipt]),
            #[cfg(test)]
            drop_order: prepared.drop_order.take(),
        }
    }

    fn apply_inventory(
        &self,
        apply: impl FnOnce(
            carrick_hal::FrameInventoryCommit<()>,
        ) -> Result<carrick_hal::FrameInventoryApplyReceipt, TrapError>,
    ) -> Result<(), TrapError> {
        let mm = (*self.kernel_mm.lock()).ok_or_else(|| {
            TrapError::Hypervisor("HVPatch MM has no exact Kernel binding".to_owned())
        })?;
        self.inventory.lock().apply_process_inventory(apply, mm)
    }

    fn activate(&self) -> Result<(), TrapError> {
        self.inventory.lock().activate(&self.pending_receipts)
    }

    fn prepare_retirement(
        &self,
        commit: carrick_hal::FrameInventoryCommit<()>,
    ) -> Result<(), TrapError> {
        self.inventory.lock().prepare_retirement(commit)
    }

    fn apply_retirement(
        &self,
        apply: impl FnOnce(
            carrick_hal::FrameInventoryCommit<()>,
        ) -> Result<carrick_hal::FrameInventoryRetirementReceipt, TrapError>,
    ) -> Result<(), TrapError> {
        let mm = (*self.kernel_mm.lock()).ok_or_else(|| {
            TrapError::Hypervisor("HVPatch MM has no exact Kernel binding".to_owned())
        })?;
        self.inventory
            .lock()
            .apply_retirement(mm, &self.pending_receipts, apply)
    }

    fn bind_kernel_mm(&self, mm: std::num::NonZeroU64) -> Result<(), TrapError> {
        let mut bound = self.kernel_mm.lock();
        match *bound {
            None => {
                *bound = Some(mm);
                Ok(())
            }
            Some(existing) if existing == mm => Ok(()),
            Some(_) => Err(TrapError::Hypervisor(
                "HVPatch MM binding changed across sibling registrations".to_owned(),
            )),
        }
    }
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
impl Drop for HvpatchTaskMmAuthority {
    fn drop(&mut self) {
        for receipt in self.alias_receipts.get_mut().drain(..).rev() {
            receipt.retire_exact();
        }
        let phase = self.inventory.get_mut().phase_name();
        let mm_root_slot = self.mm_root_slot;
        let kernel_mm = *self.kernel_mm.get_mut();
        self.inventory
            .get_mut()
            .rollback_unpublished()
            .unwrap_or_else(|error| {
                eprintln!(
                    "carrick: FATAL: drop HVPatch MM authority \
                     (phase={phase} mm_root_slot={mm_root_slot:?} kernel_mm={kernel_mm:?}): {error}"
                );
                std::process::abort();
            });
        #[cfg(test)]
        if let Some(order) = &self.drop_order {
            order.lock().push("task");
        }
        // `mappings` (and their host owners) drop only after the inventory is
        // retired.  The registration removes the carrier MM first, so its
        // stage-2 leases have already unmapped before this destructor runs.
    }
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
impl HvpatchPreparedTaskAuthority {
    /// COW arming and COW deferred publication are ONE authority: a task that
    /// can arm a COW range must also own the slot its deferred publications
    /// land in. Publication is the last boundary that can still reject a task
    /// cheaply — past it the child is live and a missing half aborts the
    /// carrier when a worker activates it.
    fn validate_cow_authority_pairing(&self) -> Result<(), TrapError> {
        match (
            self.cow_armed.is_some(),
            self.cow_deferred_publications.is_some(),
        ) {
            (true, true) | (false, false) => Ok(()),
            (true, false) => Err(TrapError::Hypervisor(
                "HVPatch prepared task authority armed COW without publication state".to_owned(),
            )),
            (false, true) => Err(TrapError::Hypervisor(
                "HVPatch prepared task authority holds COW publication state without arming"
                    .to_owned(),
            )),
        }
    }

    fn abort(self) -> Result<(), TrapError> {
        let mut this = self;
        // Pending aliases have never touched either global registry.  The
        // publication receipt owns exact preimages only after commit.
        this.inventory.rollback_unpublished()?;
        Ok(())
    }
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
fn abort_prepared_task_and_carrier(
    task: HvpatchPreparedTaskAuthority,
    state: HvpatchCarrierTaskState,
) -> Result<(), TrapError> {
    // Carrier teardown owns stage-2 and must complete before task teardown can
    // release an owned host mapping backing that stage-2 entry.
    let state_result = state.abort();
    let task_result = task.abort();
    state_result?;
    task_result
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
#[derive(Default)]
struct AliasPublicationReceipt {
    versions: Vec<AliasPublicationVersionId>,
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct AliasPublicationVersionId {
    owner: HvpatchCarrierTaskStateKey,
    ordinal: u32,
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
struct OwnedAliasVersion {
    id: AliasPublicationVersionId,
    value: AliasBacking,
    epoch: u64,
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
struct AliasVersionChain {
    ipa: u64,
    scope: AliasOwnershipScope,
    base: Option<AliasBacking>,
    versions: Vec<OwnedAliasVersion>,
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
struct OwnedReplayVersion {
    id: AliasPublicationVersionId,
    value: ReplayMappingKey,
    epoch: u64,
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
struct ReplayVersionChain {
    physical_ipa: u64,
    base: Vec<ReplayMappingKey>,
    versions: Vec<OwnedReplayVersion>,
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
#[derive(Default)]
struct AliasVersionRegistry {
    aliases: Vec<AliasVersionChain>,
    replays: Vec<ReplayVersionChain>,
    alias_epochs: Vec<((u64, AliasOwnershipScope), u64)>,
    replay_epochs: Vec<(u64, u64)>,
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
fn alias_version_registry() -> &'static parking_lot::Mutex<AliasVersionRegistry> {
    static CELL: std::sync::OnceLock<parking_lot::Mutex<AliasVersionRegistry>> =
        std::sync::OnceLock::new();
    CELL.get_or_init(|| parking_lot::Mutex::new(AliasVersionRegistry::default()))
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
fn bump_version_epoch<K: Copy + Eq>(epochs: &mut Vec<(K, u64)>, key: K) -> Option<u64> {
    if let Some((_, epoch)) = epochs.iter_mut().find(|(candidate, _)| *candidate == key) {
        *epoch = epoch.checked_add(1)?;
        Some(*epoch)
    } else {
        epochs.push((key, 1));
        Some(1)
    }
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
fn mutate_external_alias_state<R>(
    mutate: impl FnOnce(&mut std::collections::BTreeSet<ReplayMappingKey>, &mut Vec<AliasBacking>) -> R,
) -> R {
    // All external writers use the same replay -> alias -> version lock order
    // as receipt publication/retirement. A mutation becomes the new effective
    // base and invalidates every older receipt version for the touched key.
    let mut replay = replay_mappings().lock();
    let mut registry = alias_registry().lock();
    let replay_before = replay.clone();
    let registry_before = registry.clone();
    let result = mutate(&mut replay, &mut registry);
    let mut versions = alias_version_registry().lock();

    let mut alias_keys = Vec::new();
    for alias in registry_before.iter().chain(registry.iter()) {
        let key = (alias.ipa, alias.ownership_scope);
        if !alias_keys.contains(&key) {
            alias_keys.push(key);
        }
    }
    let mut affected_physical_ipas = Vec::new();
    for key in alias_keys {
        let before = registry_before
            .iter()
            .find(|entry| (entry.ipa, entry.ownership_scope) == key)
            .copied();
        let after = registry
            .iter()
            .find(|entry| (entry.ipa, entry.ownership_scope) == key)
            .copied();
        if before == after {
            continue;
        }
        for alias in before.into_iter().chain(after) {
            if !affected_physical_ipas.contains(&alias.physical_ipa) {
                affected_physical_ipas.push(alias.physical_ipa);
            }
        }
        bump_version_epoch(&mut versions.alias_epochs, key).unwrap_or_else(|| {
            eprintln!("carrick: FATAL: external alias mutation epoch exhausted");
            std::process::abort();
        });
        if let Some(chain) = versions
            .aliases
            .iter_mut()
            .find(|chain| (chain.ipa, chain.scope) == key)
        {
            chain.base = after;
            chain.versions.clear();
        }
    }
    for (ipa, _, _, _) in replay_before.iter().chain(replay.iter()) {
        if !affected_physical_ipas.contains(ipa) {
            let before: Vec<_> = replay_before
                .iter()
                .filter(|(candidate, _, _, _)| candidate == ipa)
                .copied()
                .collect();
            let after: Vec<_> = replay
                .iter()
                .filter(|(candidate, _, _, _)| candidate == ipa)
                .copied()
                .collect();
            if before != after {
                affected_physical_ipas.push(*ipa);
            }
        }
    }
    for physical_ipa in affected_physical_ipas {
        bump_version_epoch(&mut versions.replay_epochs, physical_ipa).unwrap_or_else(|| {
            eprintln!("carrick: FATAL: external replay mutation epoch exhausted");
            std::process::abort();
        });
        if let Some(chain) = versions
            .replays
            .iter_mut()
            .find(|chain| chain.physical_ipa == physical_ipa)
        {
            chain.base = replay
                .iter()
                .filter(|(ipa, _, _, _)| *ipa == physical_ipa)
                .copied()
                .collect();
            chain.versions.clear();
        }
    }
    result
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
impl AliasPublicationReceipt {
    fn commit(
        owner: HvpatchCarrierTaskStateKey,
        aliases: &[AliasBacking],
    ) -> Result<Self, TrapError> {
        let mut replay = replay_mappings().lock();
        let mut registry = alias_registry().lock();
        let mut versions = alias_version_registry().lock();
        let mut alias_increments = Vec::<((u64, AliasOwnershipScope), u64)>::new();
        let mut replay_increments = Vec::<(u64, u64)>::new();
        for alias in aliases {
            let alias_key = (alias.ipa, alias.ownership_scope);
            if let Some((_, count)) = alias_increments
                .iter_mut()
                .find(|(key, _)| *key == alias_key)
            {
                *count = count.checked_add(1).unwrap_or(u64::MAX);
            } else {
                alias_increments.push((alias_key, 1));
            }
            if let Some((_, count)) = replay_increments
                .iter_mut()
                .find(|(ipa, _)| *ipa == alias.physical_ipa)
            {
                *count = count.checked_add(1).unwrap_or(u64::MAX);
            } else {
                replay_increments.push((alias.physical_ipa, 1));
            }
        }
        let alias_exhausted = alias_increments.iter().any(|(key, count)| {
            let current = versions
                .alias_epochs
                .iter()
                .find(|(candidate, _)| candidate == key)
                .map_or(0, |(_, epoch)| *epoch);
            current.checked_add(*count).is_none()
        });
        let replay_exhausted = replay_increments.iter().any(|(ipa, count)| {
            let current = versions
                .replay_epochs
                .iter()
                .find(|(candidate, _)| candidate == ipa)
                .map_or(0, |(_, epoch)| *epoch);
            current.checked_add(*count).is_none()
        });
        if aliases.len() > u32::MAX as usize || alias_exhausted || replay_exhausted {
            return Err(TrapError::Hypervisor(
                "alias publication version identity exhausted".to_owned(),
            ));
        }
        let mut receipt = Self::default();
        for (ordinal, alias) in aliases.iter().enumerate() {
            let ordinal = u32::try_from(ordinal).map_err(|_| {
                TrapError::Hypervisor("alias publication ordinal exhausted".to_owned())
            })?;
            let id = AliasPublicationVersionId { owner, ordinal };
            let alias_key = (alias.ipa, alias.ownership_scope);
            let alias_epoch = bump_version_epoch(&mut versions.alias_epochs, alias_key)
                .ok_or_else(|| TrapError::Hypervisor("alias version epoch exhausted".to_owned()))?;
            let replay_epoch = bump_version_epoch(&mut versions.replay_epochs, alias.physical_ipa)
                .ok_or_else(|| {
                    TrapError::Hypervisor("replay version epoch exhausted".to_owned())
                })?;
            let alias_chain_index = versions
                .aliases
                .iter()
                .position(|chain| chain.ipa == alias.ipa && chain.scope == alias.ownership_scope)
                .unwrap_or_else(|| {
                    let base = registry
                        .iter()
                        .find(|entry| {
                            entry.ipa == alias.ipa && entry.ownership_scope == alias.ownership_scope
                        })
                        .copied();
                    versions.aliases.push(AliasVersionChain {
                        ipa: alias.ipa,
                        scope: alias.ownership_scope,
                        base,
                        versions: Vec::new(),
                    });
                    versions.aliases.len() - 1
                });
            versions.aliases[alias_chain_index]
                .versions
                .push(OwnedAliasVersion {
                    id,
                    value: *alias,
                    epoch: alias_epoch,
                });
            let replay_chain_index = versions
                .replays
                .iter()
                .position(|chain| chain.physical_ipa == alias.physical_ipa)
                .unwrap_or_else(|| {
                    let base = replay
                        .iter()
                        .filter(|(ipa, _, _, _)| *ipa == alias.physical_ipa)
                        .copied()
                        .collect();
                    versions.replays.push(ReplayVersionChain {
                        physical_ipa: alias.physical_ipa,
                        base,
                        versions: Vec::new(),
                    });
                    versions.replays.len() - 1
                });
            versions.replays[replay_chain_index]
                .versions
                .push(OwnedReplayVersion {
                    id,
                    value: replay_mapping_key(*alias),
                    epoch: replay_epoch,
                });
            replay.retain(|(ipa, _, _, _)| *ipa != alias.physical_ipa);
            replay.insert(replay_mapping_key(*alias));
            if let Some(entry) = registry.iter_mut().find(|entry| {
                entry.ipa == alias.ipa && entry.ownership_scope == alias.ownership_scope
            }) {
                *entry = *alias;
            } else {
                registry.push(*alias);
            }
            receipt.versions.push(id);
        }
        Ok(receipt)
    }

    fn retire_exact(self) {
        let mut replay = replay_mappings().lock();
        let mut registry = alias_registry().lock();
        let mut versions = alias_version_registry().lock();
        for id in self.versions.into_iter().rev() {
            if let Some(chain_index) = versions
                .aliases
                .iter()
                .position(|chain| chain.versions.iter().any(|version| version.id == id))
            {
                let (ipa, scope, base, removed, was_top, previous, empty) = {
                    let chain = &mut versions.aliases[chain_index];
                    let version_index = chain
                        .versions
                        .iter()
                        .position(|version| version.id == id)
                        .unwrap_or_else(|| std::process::abort());
                    let was_top = version_index + 1 == chain.versions.len();
                    let removed = chain.versions.remove(version_index);
                    (
                        chain.ipa,
                        chain.scope,
                        chain.base,
                        removed,
                        was_top,
                        chain.versions.last().map(|version| version.value),
                        chain.versions.is_empty(),
                    )
                };
                let current_epoch = versions
                    .alias_epochs
                    .iter()
                    .find(|(key, _)| *key == (ipa, scope))
                    .map(|(_, epoch)| *epoch);
                let current_value = registry
                    .iter()
                    .find(|entry| entry.ipa == ipa && entry.ownership_scope == scope)
                    .copied();
                if was_top
                    && current_epoch == Some(removed.epoch)
                    && current_value == Some(removed.value)
                {
                    registry.retain(|entry| !(entry.ipa == ipa && entry.ownership_scope == scope));
                    if let Some(previous) = previous.or(base) {
                        registry.push(previous);
                    }
                    bump_version_epoch(&mut versions.alias_epochs, (ipa, scope))
                        .unwrap_or_else(|| std::process::abort());
                }
                if empty {
                    versions.aliases.remove(chain_index);
                }
            }
            if let Some(chain_index) = versions
                .replays
                .iter()
                .position(|chain| chain.versions.iter().any(|version| version.id == id))
            {
                let (physical_ipa, base, removed, was_top, previous, empty) = {
                    let chain = &mut versions.replays[chain_index];
                    let version_index = chain
                        .versions
                        .iter()
                        .position(|version| version.id == id)
                        .unwrap_or_else(|| std::process::abort());
                    let was_top = version_index + 1 == chain.versions.len();
                    let removed = chain.versions.remove(version_index);
                    (
                        chain.physical_ipa,
                        chain.base.clone(),
                        removed,
                        was_top,
                        chain.versions.last().map(|version| version.value),
                        chain.versions.is_empty(),
                    )
                };
                let current_epoch = versions
                    .replay_epochs
                    .iter()
                    .find(|(ipa, _)| *ipa == physical_ipa)
                    .map(|(_, epoch)| *epoch);
                let current: Vec<_> = replay
                    .iter()
                    .filter(|(ipa, _, _, _)| *ipa == physical_ipa)
                    .copied()
                    .collect();
                if was_top && current_epoch == Some(removed.epoch) && current == vec![removed.value]
                {
                    replay.retain(|(ipa, _, _, _)| *ipa != physical_ipa);
                    if let Some(previous) = previous {
                        replay.insert(previous);
                    } else {
                        replay.extend(base);
                    }
                    bump_version_epoch(&mut versions.replay_epochs, physical_ipa)
                        .unwrap_or_else(|| std::process::abort());
                }
                if empty {
                    versions.replays.remove(chain_index);
                }
            }
        }
    }
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
pub struct HvpatchCarrierTaskStateDirectory {
    instance: std::num::NonZeroU64,
    child_token_verifier: std::sync::Arc<carrick_hal::HvpatchChildTokenVerifier>,
    next: std::sync::atomic::AtomicU64,
    inner: parking_lot::Mutex<HvpatchCarrierTaskDirectoryInner>,
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
#[derive(Default)]
struct HvpatchCarrierTaskDirectoryInner {
    states: std::collections::BTreeMap<HvpatchCarrierTaskStateKey, HvpatchCarrierTaskRow>,
    carrier_mms: std::collections::BTreeMap<
        HvpatchMmAuthorityKey,
        std::sync::Weak<HvpatchCarrierMmAuthority>,
    >,
    task_mms:
        std::collections::BTreeMap<HvpatchMmAuthorityKey, std::sync::Weak<HvpatchTaskMmAuthority>>,
}

#[cfg(test)]
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
impl Default for HvpatchCarrierTaskStateDirectory {
    fn default() -> Self {
        static NEXT_DIRECTORY_INSTANCE: std::sync::atomic::AtomicU64 =
            std::sync::atomic::AtomicU64::new(1);
        let instance = NEXT_DIRECTORY_INSTANCE
            .fetch_update(
                std::sync::atomic::Ordering::AcqRel,
                std::sync::atomic::Ordering::Acquire,
                |current| current.checked_add(1),
            )
            .unwrap_or_else(|_| {
                eprintln!("carrick: FATAL: HVPatch carrier directory identity exhausted");
                std::process::abort();
            });
        let instance = std::num::NonZeroU64::new(instance).unwrap_or_else(|| {
            eprintln!("carrick: FATAL: zero HVPatch carrier directory identity");
            std::process::abort();
        });
        let (_, verifier) = carrick_hal::HvpatchChildTokenIssuer::new_pair();
        Self::new(instance, verifier)
    }
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
impl HvpatchCarrierTaskStateDirectory {
    pub fn new(
        instance: std::num::NonZeroU64,
        child_token_verifier: std::sync::Arc<carrick_hal::HvpatchChildTokenVerifier>,
    ) -> Self {
        Self {
            instance,
            child_token_verifier,
            next: std::sync::atomic::AtomicU64::new(1),
            inner: parking_lot::Mutex::new(HvpatchCarrierTaskDirectoryInner::default()),
        }
    }
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
struct HvpatchTaskRegistration {
    directory: std::sync::Arc<HvpatchCarrierTaskStateDirectory>,
    key: HvpatchCarrierTaskStateKey,
    expected_identity: HvpatchCarrierTaskIdentity,
    task_mm: Option<std::sync::Arc<HvpatchTaskMmAuthority>>,
    cow_authority: Option<std::sync::Arc<dyn carrick_hal::FrameCowAuthority>>,
    cow_identity: Option<carrick_hal::FrameCowIdentity>,
    cow_authority_identity: Option<std::num::NonZeroU64>,
    child_token_verifier: std::sync::Arc<carrick_hal::HvpatchChildTokenVerifier>,
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
impl HvpatchTaskRegistration {
    fn runtime_task_state(
        &self,
        page_tables: std::sync::Arc<
            parking_lot::Mutex<Option<crate::page_table::PageTableManager>>,
        >,
        protections: std::sync::Arc<MemoryProtections>,
    ) -> Result<HvfTaskState, TrapError> {
        let task_mm = self
            .task_mm
            .as_ref()
            .ok_or_else(|| TrapError::Hypervisor("missing HVPatch task MM".to_owned()))?;
        let inventory = task_mm.inventory.lock();
        let shared_process_mm = matches!(
            *inventory,
            HvpatchTaskInventoryAuthority::SharedProcess { .. }
        );
        let ledger = inventory
            .shared_runtime_ledger()
            .ok_or_else(|| TrapError::Hypervisor("inactive HVPatch task inventory".to_owned()))?;
        drop(inventory);
        let cow_authority = self.cow_authority.clone().ok_or_else(|| {
            TrapError::Hypervisor("HVPatch task lacks live COW authority".to_owned())
        })?;
        let cow_identity = self.cow_identity.ok_or_else(|| {
            TrapError::Hypervisor("HVPatch task lacks live COW identity".to_owned())
        })?;
        let cow_armed = task_mm.cow_armed.as_ref().cloned().ok_or_else(|| {
            TrapError::Hypervisor("HVPatch task lacks COW armed state".to_owned())
        })?;
        let cow_deferred_publications = task_mm
            .cow_deferred_publications
            .as_ref()
            .cloned()
            .ok_or_else(|| {
                TrapError::Hypervisor("HVPatch task lacks COW publication state".to_owned())
            })?;
        Ok(HvfTaskState {
            mappings: task_mm
                .mappings
                .iter()
                .map(HvpatchTaskMappingState::unowned_runtime_region)
                .collect(),
            mm_root_slot: task_mm.mm_root_slot,
            pending_exec_mm_root_slot: None,
            pending_exec_asid: None,
            pending_exec_stage2_cleanup: None,
            shared_process_mm,
            last_exit_class: 0,
            last_fault_esr: 0,
            is_forked_child: false,
            forked_no_exec: false,
            protections,
            page_tables,
            last_syscall_nr: None,
            last_syscall_orig_x0: 0,
            vfork_share: false,
            fork_mapping_descs: Vec::new(),
            fork_child_descs: Vec::new(),
            persistent_vm_lifecycle: true,
            frame_inventory: HvpatchFrameInventoryState::new(ledger),
            cow_authority: Some(cow_authority),
            cow_identity: Some(cow_identity),
            cow_armed,
            cow_deferred_publications,
            pending_fork_frame_receipts: task_mm.pending_receipts.clone(),
            pending_process_aliases: Vec::new(),
            cow_rollback_scratch: None,
        })
    }

    fn apply_inventory(
        &self,
        apply: impl FnOnce(
            carrick_hal::FrameInventoryCommit<()>,
        ) -> Result<carrick_hal::FrameInventoryApplyReceipt, TrapError>,
    ) -> Result<(), TrapError> {
        self.task_mm
            .as_ref()
            .ok_or_else(|| TrapError::Hypervisor("missing HVPatch task MM".to_owned()))?
            .apply_inventory(apply)
    }

    fn prepare_inventory_retirement(
        &self,
        commit: carrick_hal::FrameInventoryCommit<()>,
    ) -> Result<(), TrapError> {
        self.task_mm
            .as_ref()
            .ok_or_else(|| TrapError::Hypervisor("missing HVPatch task MM".to_owned()))?
            .prepare_retirement(commit)
    }

    fn apply_inventory_retirement(
        &self,
        apply: impl FnOnce(
            carrick_hal::FrameInventoryCommit<()>,
        ) -> Result<carrick_hal::FrameInventoryRetirementReceipt, TrapError>,
    ) -> Result<(), TrapError> {
        self.task_mm
            .as_ref()
            .ok_or_else(|| TrapError::Hypervisor("missing HVPatch task MM".to_owned()))?
            .apply_retirement(apply)
    }

    fn bind_child_kernel(&mut self, binding: HvpatchChildKernelBinding) -> Result<(), TrapError> {
        let binding = self
            .child_token_verifier
            .verify_and_open(binding)
            .ok_or_else(|| {
                TrapError::Hypervisor(
                    "child Kernel token issuer does not match carrier verifier".to_owned(),
                )
            })?;
        let cow_identity = binding.cow_identity();
        if binding.task_serial() != self.key.task_serial
            || binding.thread_serial() != self.key.thread_serial
            || binding.execution_generation() != self.key.execution_generation
            || cow_identity.linux_pid != self.expected_identity.linux_pid
            || cow_identity.linux_tid != self.expected_identity.linux_tid
            || cow_identity.asid != self.expected_identity.asid
            || self.cow_authority.is_some()
            || self.cow_identity.is_some()
            || self.cow_authority_identity.is_some()
        {
            return Err(TrapError::Hypervisor(
                "duplicate or mismatched exact child Kernel binding".to_owned(),
            ));
        }
        let mm = std::num::NonZeroU64::new(cow_identity.mm).ok_or_else(|| {
            TrapError::Hypervisor("child Kernel token contains zero MM".to_owned())
        })?;
        self.task_mm
            .as_ref()
            .ok_or_else(|| TrapError::Hypervisor("missing HVPatch task MM".to_owned()))?
            .bind_kernel_mm(mm)?;
        self.cow_authority_identity = Some(binding.authority_identity());
        self.cow_identity = Some(cow_identity);
        self.cow_authority = Some(binding.into_cow_authority());
        Ok(())
    }

    fn activate(&self) -> Result<(), TrapError> {
        if self.cow_authority.is_none() || self.cow_identity.is_none() {
            return Err(TrapError::Hypervisor(
                "HVPatch child activation requires exact tid/kicker/COW authority".to_owned(),
            ));
        }
        self.task_mm
            .as_ref()
            .ok_or_else(|| TrapError::Hypervisor("missing HVPatch task MM".to_owned()))?
            .activate()
    }

    fn cleanup(mut self) -> Result<(), TrapError> {
        // Removing the carrier row drops this binding's carrier-MM reference.
        // If it is the final MM binding, every stage-2 lease unmaps here, before
        // the final task-MM Arc below releases any host mapping owner.
        self.directory.retire(self.key)?;
        drop(self.task_mm.take());
        Ok(())
    }
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
pub(crate) struct HvpatchPreparedCarrierTaskState {
    identity: HvpatchCarrierTaskIdentity,
    state: Option<HvpatchCarrierTaskState>,
    task: Option<HvpatchPreparedTaskAuthority>,
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
impl HvpatchPreparedCarrierTaskState {
    fn new(
        identity: HvpatchCarrierTaskIdentity,
        state: HvpatchCarrierTaskState,
        task: HvpatchPreparedTaskAuthority,
    ) -> Self {
        Self {
            identity,
            state: Some(state),
            task: Some(task),
        }
    }

    pub(crate) fn sibling(
        identity: HvpatchCarrierTaskIdentity,
        spec: ThreadSpec,
    ) -> Result<Self, TrapError> {
        Self::shared_mm_projection(identity, None, spec)
    }

    pub(crate) fn shared_process(
        identity: HvpatchCarrierTaskIdentity,
        shared_kernel_mm: u64,
        spec: ThreadSpec,
    ) -> Result<Self, TrapError> {
        if shared_kernel_mm == 0 {
            return Err(TrapError::Hypervisor(
                "shared-process HVPatch MM identity is invalid".to_owned(),
            ));
        }
        Self::shared_mm_projection(identity, Some(shared_kernel_mm), spec)
    }

    fn shared_mm_projection(
        identity: HvpatchCarrierTaskIdentity,
        shared_kernel_mm: Option<u64>,
        spec: ThreadSpec,
    ) -> Result<Self, TrapError> {
        if !spec.persistent_vm_lifecycle {
            return Err(TrapError::Hypervisor(
                "task-only shared-MM projection requires persistent HVPatch VM".to_owned(),
            ));
        }
        let ThreadSpec {
            vm,
            mappings,
            protections: _,
            page_tables: _,
            mailbox_slots: _,
            syscall_transport: _,
            persistent_vm_lifecycle: _,
            mm_root_slot,
            frame_inventory,
            cow_authority: _,
            cow_identity: _,
            cow_armed,
            cow_deferred_publications,
        } = spec;
        let mappings = mappings
            .into_iter()
            .map(|mapping| HvpatchTaskMappingState {
                start: mapping.start,
                ipa: mapping.ipa,
                physical_ipa: mapping.physical_ipa,
                end: mapping.end,
                host_addr: mapping.host_addr,
                physical_host_addr: mapping.physical_host_addr,
                size: mapping.size,
                physical_size: mapping.physical_size,
                perms: mapping.perms,
                guest_writable: mapping.guest_writable,
                host_mapping: None,
                is_dynamic_alias: mapping.is_dynamic_alias,
                sharing: mapping.sharing,
                shared_key_base: mapping.shared_key_base,
                shared_key_offset: mapping.shared_key_offset,
                owner_generation: global_frame_host_owner_generation(
                    mapping.physical_ipa,
                    mapping.physical_size as u64,
                ),
            })
            .collect();
        Ok(Self::new(
            identity,
            if shared_kernel_mm.is_some() {
                HvpatchCarrierTaskState::SharedProcess { vm }
            } else {
                HvpatchCarrierTaskState::Sibling { vm }
            },
            HvpatchPreparedTaskAuthority {
                mappings,
                mm_root_slot,
                shared_kernel_mm,
                inventory: if shared_kernel_mm.is_some() {
                    HvpatchTaskInventoryAuthority::SharedProcess {
                        ledger: frame_inventory,
                    }
                } else {
                    HvpatchTaskInventoryAuthority::SiblingShared {
                        ledger: frame_inventory,
                    }
                },
                cow_armed: Some(cow_armed),
                cow_deferred_publications: Some(cow_deferred_publications),
                ..HvpatchPreparedTaskAuthority::default()
            },
        ))
    }

    pub(crate) fn process(
        identity: HvpatchCarrierTaskIdentity,
        spec: ProcessSpec,
    ) -> Result<Self, TrapError> {
        if !spec.persistent_vm_lifecycle {
            return Err(TrapError::Hypervisor(
                "task-only process requires persistent HVPatch VM".to_owned(),
            ));
        }
        let (state, task) = HvfVmState::prepare_task_only_process_spec(spec)?;
        Ok(Self::new(identity, state, task))
    }

    pub(crate) fn commit(
        mut self,
        directory: std::sync::Arc<HvpatchCarrierTaskStateDirectory>,
    ) -> Result<HvpatchTaskOnlyBackendState, TrapError> {
        let state = self.state.take().unwrap_or_else(|| std::process::abort());
        let task = self.task.take().unwrap_or_else(|| std::process::abort());
        directory.publish(self.identity, state, task)
    }

    pub(crate) fn abort(mut self) -> Result<(), TrapError> {
        if let Some(state) = self.state.take() {
            let task = self.task.take().unwrap_or_else(|| std::process::abort());
            abort_prepared_task_and_carrier(task, state)?;
        }
        Ok(())
    }
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
impl Drop for HvpatchPreparedCarrierTaskState {
    fn drop(&mut self) {
        if let Some(state) = self.state.take() {
            let task = self.task.take().unwrap_or_else(|| std::process::abort());
            abort_prepared_task_and_carrier(task, state).unwrap_or_else(|error| {
                eprintln!("carrick: FATAL: abort deferred HVPatch task/carrier state: {error}");
                std::process::abort();
            });
        }
    }
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
impl HvpatchCarrierTaskStateDirectory {
    fn publish(
        self: &std::sync::Arc<Self>,
        identity: HvpatchCarrierTaskIdentity,
        state: HvpatchCarrierTaskState,
        task: HvpatchPreparedTaskAuthority,
    ) -> Result<HvpatchTaskOnlyBackendState, TrapError> {
        self.publish_inner(identity, state, task, 0)
    }

    fn publish_inner(
        self: &std::sync::Arc<Self>,
        identity: HvpatchCarrierTaskIdentity,
        state: HvpatchCarrierTaskState,
        task: HvpatchPreparedTaskAuthority,
        failpoint: u8,
    ) -> Result<HvpatchTaskOnlyBackendState, TrapError> {
        if identity.task_serial == 0
            || identity.thread_serial == 0
            || identity.execution_generation == 0
        {
            abort_prepared_task_and_carrier(task, state)?;
            return Err(TrapError::Hypervisor(
                "deferred HVPatch task identity contains zero".to_owned(),
            ));
        }
        if let Err(error) = task.validate_cow_authority_pairing() {
            abort_prepared_task_and_carrier(task, state)?;
            return Err(error);
        }
        let nonce = match self.next.fetch_update(
            std::sync::atomic::Ordering::AcqRel,
            std::sync::atomic::Ordering::Acquire,
            |current| current.checked_add(1),
        ) {
            Ok(nonce) => nonce,
            Err(_) => {
                abort_prepared_task_and_carrier(task, state)?;
                return Err(TrapError::Hypervisor(
                    "carrier task-state key exhausted".to_owned(),
                ));
            }
        };
        let Some(nonce) = std::num::NonZeroU64::new(nonce) else {
            abort_prepared_task_and_carrier(task, state)?;
            return Err(TrapError::Hypervisor(
                "carrier task-state key exhausted".to_owned(),
            ));
        };
        let key = HvpatchCarrierTaskStateKey {
            directory_instance: self.instance,
            task_serial: identity.task_serial,
            thread_serial: identity.thread_serial,
            execution_generation: identity.execution_generation,
            nonce,
        };
        let mut inner = self.inner.lock();
        if inner.states.keys().any(|key| {
            (key.task_serial, key.thread_serial, key.execution_generation)
                == (
                    identity.task_serial,
                    identity.thread_serial,
                    identity.execution_generation,
                )
        }) {
            drop(inner);
            abort_prepared_task_and_carrier(task, state)?;
            return Err(TrapError::Hypervisor(
                "duplicate exact carrier task-state publication".to_owned(),
            ));
        }
        let alias_receipt = match AliasPublicationReceipt::commit(key, &task.pending_aliases) {
            Ok(receipt) => receipt,
            Err(error) => {
                drop(inner);
                abort_prepared_task_and_carrier(task, state)?;
                return Err(error);
            }
        };
        if failpoint == 1 {
            alias_receipt.retire_exact();
            drop(inner);
            abort_prepared_task_and_carrier(task, state)?;
            return Err(TrapError::Hypervisor(
                "injected carrier task-state failure after alias commit".to_owned(),
            ));
        }
        let mm_key = HvpatchMmAuthorityKey {
            // A concrete root slot is the exact MM identity and is shared by
            // every thread binding. Root/no-slot tasks fall back to the task
            // serial so unrelated roots never alias one MM authority.
            task_serial: if task.shared_kernel_mm.is_some() {
                0
            } else {
                task.mm_root_slot.map_or(identity.task_serial, |_| 0)
            },
            mm_root_slot: task.mm_root_slot,
            shared_kernel_mm: task.shared_kernel_mm,
        };
        let process_owner = matches!(
            task.inventory,
            HvpatchTaskInventoryAuthority::ProcessPrepared { .. }
        );
        let existing_carrier_mm = inner
            .carrier_mms
            .get(&mm_key)
            .and_then(std::sync::Weak::upgrade);
        let existing_task_mm = inner
            .task_mms
            .get(&mm_key)
            .and_then(std::sync::Weak::upgrade);
        if process_owner && (existing_carrier_mm.is_some() || existing_task_mm.is_some()) {
            alias_receipt.retire_exact();
            drop(inner);
            abort_prepared_task_and_carrier(task, state)?;
            return Err(TrapError::Hypervisor(
                "duplicate process owner for exact HVPatch MM".to_owned(),
            ));
        }
        if task.cow_authority.is_some() || task.cow_identity.is_some() {
            alias_receipt.retire_exact();
            drop(inner);
            abort_prepared_task_and_carrier(task, state)?;
            return Err(TrapError::Hypervisor(
                "prepared HVPatch child retained parent COW authority".to_owned(),
            ));
        }
        let (carrier_mm, test_rollbacks): (
            Option<std::sync::Arc<HvpatchCarrierMmAuthority>>,
            Option<std::sync::Arc<std::sync::atomic::AtomicUsize>>,
        ) = match state {
            HvpatchCarrierTaskState::Sibling { vm } => (
                existing_carrier_mm.or_else(|| {
                    Some(std::sync::Arc::new(HvpatchCarrierMmAuthority::Live {
                        _vm: vm,
                        stage2_lease_keys: Vec::new(),
                    }))
                }),
                None,
            ),
            HvpatchCarrierTaskState::SharedProcess { vm } => (
                existing_carrier_mm.or_else(|| {
                    Some(std::sync::Arc::new(HvpatchCarrierMmAuthority::Live {
                        _vm: vm,
                        stage2_lease_keys: Vec::new(),
                    }))
                }),
                None,
            ),
            HvpatchCarrierTaskState::Process { vm, stage2_leases } => {
                let mut stage2_lease_keys = Vec::with_capacity(stage2_leases.len());
                for lease in stage2_leases {
                    match register_carrier_stage2_lease(lease) {
                        Ok(key) => stage2_lease_keys.push(key),
                        Err(error) => {
                            for key in stage2_lease_keys {
                                drop(take_carrier_stage2_lease(key.0, key.1));
                            }
                            abort_prepared_task_and_carrier(
                                task,
                                HvpatchCarrierTaskState::Process {
                                    vm,
                                    stage2_leases: Vec::new(),
                                },
                            )?;
                            return Err(error);
                        }
                    }
                }
                (
                    Some(std::sync::Arc::new(HvpatchCarrierMmAuthority::Live {
                        _vm: vm,
                        stage2_lease_keys,
                    })),
                    None,
                )
            }
            #[cfg(test)]
            HvpatchCarrierTaskState::Test { rollbacks, order } => (
                existing_carrier_mm.or_else(|| {
                    order
                        .map(|order| std::sync::Arc::new(HvpatchCarrierMmAuthority::Test { order }))
                }),
                Some(rollbacks),
            ),
        };
        #[cfg(not(test))]
        let _ = &test_rollbacks;
        let mut task = task;
        task.pending_aliases.clear();
        let task_mm = if let Some(existing) = existing_task_mm {
            task.abort()?;
            existing.alias_receipts.lock().push(alias_receipt);
            existing
        } else {
            std::sync::Arc::new(HvpatchTaskMmAuthority::from_prepared(task, alias_receipt))
        };
        if inner
            .states
            .insert(
                key,
                HvpatchCarrierTaskRow {
                    _mm: carrier_mm.clone(),
                    #[cfg(test)]
                    rollbacks: test_rollbacks,
                },
            )
            .is_some()
        {
            std::process::abort();
        }
        if failpoint == 2 {
            let row = inner
                .states
                .remove(&key)
                .unwrap_or_else(|| std::process::abort());
            #[cfg(test)]
            if let Some(rollbacks) = &row.rollbacks {
                rollbacks.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            }
            drop(row);
            drop(carrier_mm);
            drop(inner);
            drop(task_mm);
            return Err(TrapError::Hypervisor(
                "injected carrier task-state failure after directory publication".to_owned(),
            ));
        }
        if let Some(carrier_mm) = carrier_mm {
            inner
                .carrier_mms
                .insert(mm_key, std::sync::Arc::downgrade(&carrier_mm));
        }
        inner
            .task_mms
            .insert(mm_key, std::sync::Arc::downgrade(&task_mm));
        drop(inner);
        Ok(HvpatchTaskOnlyBackendState {
            registration: Some(HvpatchTaskRegistration {
                directory: std::sync::Arc::clone(self),
                key,
                expected_identity: identity,
                task_mm: Some(task_mm),
                cow_authority: None,
                cow_identity: None,
                cow_authority_identity: None,
                child_token_verifier: std::sync::Arc::clone(&self.child_token_verifier),
            }),
        })
    }

    pub(crate) fn retire(&self, key: HvpatchCarrierTaskStateKey) -> Result<(), TrapError> {
        if key.directory_instance != self.instance {
            return Err(TrapError::Hypervisor(
                "cross-directory HVPatch carrier token rejected".to_owned(),
            ));
        }
        let row = self.inner.lock().states.remove(&key).ok_or_else(|| {
            TrapError::Hypervisor("missing exact carrier task-state retirement".to_owned())
        })?;
        #[cfg(test)]
        if let Some(rollbacks) = &row.rollbacks {
            rollbacks.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        }
        drop(row);
        Ok(())
    }
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
impl HvpatchCarrierTaskState {
    fn abort(self) -> Result<(), TrapError> {
        match self {
            Self::Sibling { .. } | Self::SharedProcess { .. } | Self::Process { .. } => Ok(()),
            #[cfg(test)]
            Self::Test { rollbacks, .. } => {
                rollbacks.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                Ok(())
            }
        }
    }
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
struct GlobalExecPlan {
    plan: GuestMappingPlan,
    stage2_leases: std::collections::BTreeMap<(u64, u64), GlobalFrameStage2Lease>,
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ExecStage2Install {
    ipa: u64,
    size: usize,
    host: *mut u8,
    perms: u64,
    replay_registered: bool,
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ExecLeaseFingerprint {
    base: u64,
    length: u64,
    mapped: bool,
    active: bool,
    release_ipa: bool,
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
impl From<&GlobalFrameStage2Lease> for ExecLeaseFingerprint {
    fn from(lease: &GlobalFrameStage2Lease) -> Self {
        Self {
            base: lease.base,
            length: lease.length,
            mapped: lease.mapped,
            active: lease.active,
            release_ipa: lease.release_ipa,
        }
    }
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
#[derive(Clone, Debug, Eq, PartialEq)]
struct ExecOwnerFingerprint {
    key: (u64, u64),
    host: usize,
    host_len: usize,
    perms: u64,
    lease: ExecLeaseFingerprint,
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ExecBackendExtentFingerprint {
    key: (u64, u64),
    frame: carrick_hal::FrameId,
    mapping: carrick_hal::MappingId,
    backing: InventoryBackingIdentity,
    stage2_base: u64,
    stage2_length: u64,
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
#[derive(Clone, Debug, Eq, PartialEq)]
struct ExecMappingFingerprint {
    start: u64,
    ipa: u64,
    physical_ipa: u64,
    end: u64,
    host: usize,
    size: usize,
    physical_size: usize,
    perms: u64,
    has_memory: bool,
    host_owner: Option<(usize, usize)>,
    stage2_lease: Option<ExecLeaseFingerprint>,
    is_dynamic_alias: bool,
    sharing: GuestMappingSharing,
    guest_writable: bool,
    shared_key_base: u64,
    shared_key_offset: u64,
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
#[derive(Clone, Debug, Eq, PartialEq)]
struct ExecAllocatorFingerprint {
    next: u64,
    free: Vec<(u64, u64)>,
    live: Vec<(u64, u64)>,
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
#[derive(Clone, Debug, Eq, PartialEq)]
struct ExecAuthorityFingerprint {
    owners: Vec<ExecOwnerFingerprint>,
    inventory_initialized: bool,
    backend_extents: Vec<ExecBackendExtentFingerprint>,
    frame_references: Vec<(carrick_hal::FrameId, usize)>,
    extent_references: Vec<((carrick_hal::FrameId, u64, u64), usize)>,
    stage2_references: Vec<((u64, u64), usize)>,
    mappings: Vec<ExecMappingFingerprint>,
    allocator: ExecAllocatorFingerprint,
    replay_mappings: Vec<ReplayMappingKey>,
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
fn verify_exec_authority_rollback(
    before: &ExecAuthorityFingerprint,
    after: &ExecAuthorityFingerprint,
) -> Result<(), TrapError> {
    if before == after {
        Ok(())
    } else {
        Err(TrapError::Hypervisor(
            "HVPatch exec stage-2 rollback changed published authority".to_owned(),
        ))
    }
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
impl ExecStage2Install {
    fn replay_key(&self) -> Option<ReplayMappingKey> {
        self.replay_registered
            .then_some((self.ipa, self.size, self.host as usize, self.perms))
    }

    #[cfg(test)]
    fn key(&self) -> (u64, u64) {
        (self.ipa, self.size as u64)
    }

    #[cfg(test)]
    fn for_test(ipa: u64, size: usize) -> Self {
        Self {
            ipa,
            size,
            host: std::ptr::null_mut(),
            perms: 0,
            replay_registered: false,
        }
    }
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
fn switch_exec_stage2_transaction(
    old: &[ExecStage2Install],
    new: &[ExecStage2Install],
    fail_after_maps: Option<usize>,
    mut unmap: impl FnMut(&ExecStage2Install) -> Result<(), TrapError>,
    mut map: impl FnMut(&ExecStage2Install) -> Result<(), TrapError>,
) -> Result<(), TrapError> {
    for (old_unmapped, extent) in old.iter().enumerate() {
        if let Err(error) = unmap(extent) {
            for restore in &old[..old_unmapped] {
                map(restore).unwrap_or_else(|rollback| {
                    eprintln!(
                        "carrick: FATAL: restore HVPatch exec predecessor after unmap failure: {rollback}"
                    );
                    std::process::abort();
                });
            }
            return Err(error);
        }
    }

    let rollback =
        |mapped: usize,
         unmap: &mut dyn FnMut(&ExecStage2Install) -> Result<(), TrapError>,
         map: &mut dyn FnMut(&ExecStage2Install) -> Result<(), TrapError>| {
            for replacement in new[..mapped].iter().rev() {
                unmap(replacement).unwrap_or_else(|error| {
                    eprintln!(
                        "carrick: FATAL: rollback HVPatch exec replacement stage-2 mapping: {error}"
                    );
                    std::process::abort();
                });
            }
            for predecessor in old {
                map(predecessor).unwrap_or_else(|error| {
                    eprintln!(
                        "carrick: FATAL: restore HVPatch exec predecessor stage-2 mapping: {error}"
                    );
                    std::process::abort();
                });
            }
        };

    for (new_mapped, extent) in new.iter().enumerate() {
        if fail_after_maps == Some(new_mapped) {
            rollback(new_mapped, &mut unmap, &mut map);
            return Err(TrapError::Hypervisor(format!(
                "injected HVPatch exec stage-2 map failure after {new_mapped} maps"
            )));
        }
        if let Err(error) = map(extent) {
            rollback(new_mapped, &mut unmap, &mut map);
            return Err(error);
        }
    }
    Ok(())
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
fn exec_stage2_fail_after_maps() -> Option<usize> {
    std::env::var("CARRICK_HVPATCH_EXEC_FAIL_AFTER_MAPS")
        .ok()
        .and_then(|value| value.parse().ok())
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
fn global_frame_exec_lease_order(mappings: &[GuestMapping], table_index: usize) -> Vec<usize> {
    let mut order: Vec<usize> = (0..mappings.len())
        .filter(|&index| {
            !is_sparse_hvpatch_mmap_mapping(&mappings[index])
                && !is_persistent_executor_carrier_guest_mapping(&mappings[index])
        })
        .collect();
    order.sort_by_key(|&index| {
        (
            u8::from(index != table_index),
            std::cmp::Reverse(mappings[index].mapped_size),
            mappings[index].guest_start,
            index,
        )
    });
    order
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
fn prepare_global_exec_plan(
    plan: &GuestMappingPlan,
    mm_root_slot: Option<(u64, u64)>,
) -> Result<GlobalExecPlan, TrapError> {
    let old_root = plan.stage1_page_tables_base.ok_or_else(|| {
        TrapError::Hypervisor("hvpatch exec image has no stage-1 tables".to_owned())
    })?;
    let table_index = plan
        .mappings
        .iter()
        .position(|mapping| mapping.guest_start == old_root)
        .ok_or_else(|| {
            TrapError::Hypervisor("hvpatch exec page-table mapping absent".to_owned())
        })?;
    let mut global = plan.clone();
    let mut stage2_leases = std::collections::BTreeMap::new();
    let mut page_tables = crate::page_table::PageTableManager::new(
        global.mappings[table_index].image.as_ref().clone(),
        old_root,
    );
    const TWO_MIB: u64 = 2 * 1024 * 1024;
    let mut order = global_frame_exec_lease_order(&global.mappings, table_index);
    if mm_root_slot.is_none() {
        // The root's table is allocator-owned after its first exec, unlike a
        // child's fixed root-slot table. Preserve scarce large holes by giving
        // the largest root mappings first choice before reserving the table.
        order.sort_by_key(|&index| {
            (
                std::cmp::Reverse(global.mappings[index].mapped_size),
                global.mappings[index].guest_start,
                index,
            )
        });
    }
    for index in order {
        let mapping = &mut global.mappings[index];
        let lease = if let Some((root_slot_base, root_slot_size)) = mm_root_slot
            && index == table_index
        {
            if mapping.mapped_size > root_slot_size {
                return Err(TrapError::Hypervisor(format!(
                    "hvpatch stage-1 root needs {} bytes, slot has {root_slot_size}",
                    mapping.mapped_size
                )));
            }
            let lease = GlobalFrameStage2Lease::fixed(root_slot_base, mapping.mapped_size);
            if lease
                .base
                .checked_add(mapping.mapped_size)
                .is_none_or(|end| end > root_slot_base.saturating_add(root_slot_size))
            {
                return Err(TrapError::Hypervisor(format!(
                    "hvpatch stage-1 root mapping escapes slot 0x{root_slot_base:x}..0x{:x}",
                    root_slot_base.saturating_add(root_slot_size)
                )));
            }
            lease
        } else {
            let alignment =
                if mapping.guest_start.is_multiple_of(TWO_MIB) && mapping.mapped_size >= TWO_MIB {
                    TWO_MIB
                } else {
                    HVF_PAGE_SIZE
                };
            GlobalFrameStage2Lease::reserve(mapping.mapped_size, alignment)?
        };
        let ipa = lease.base;
        mapping.ipa_start = ipa;
        if stage2_leases
            .insert((ipa, mapping.mapped_size), lease)
            .is_some()
        {
            return Err(TrapError::Hypervisor(format!(
                "duplicate HVPatch exec stage-2 lease IPA 0x{ipa:x} size {}",
                mapping.mapped_size
            )));
        }
    }
    let root = global.mappings[table_index].ipa_start;
    page_tables.rebase(root).map_err(|error| {
        TrapError::Hypervisor(format!("rebase HVPatch exec page tables: {error:?}"))
    })?;
    for mapping in global
        .mappings
        .iter()
        .filter(|mapping| !is_sparse_hvpatch_mmap_mapping(mapping))
    {
        let remap = if (crate::memory::LINUX_KERNEL_REGION_BASE
            ..crate::memory::LINUX_KERNEL_REGION_BASE + TWO_MIB)
            .contains(&mapping.guest_start)
        {
            page_tables.map_kernel_aliased(
                mapping.guest_start,
                mapping.ipa_start,
                mapping.mapped_size,
            )
        } else {
            page_tables.map_aliased(
                mapping.guest_start,
                mapping.ipa_start,
                mapping.mapped_size,
                mapping.perms.write,
            )
        };
        remap.map_err(|error| {
            TrapError::Hypervisor(format!(
                "plan global-frame HVPatch exec VA 0x{:x}: {error:?}",
                mapping.guest_start
            ))
        })?;
    }
    page_tables
        .set_prot_none(
            crate::memory::LINUX_MMAP_BASE,
            crate::memory::mmap_arena_size() as usize,
        )
        .map_err(|error| {
            TrapError::Hypervisor(format!("reserve sparse HVPatch mmap arena: {error:?}"))
        })?;
    reapply_global_exec_readonly_spans(&mut page_tables, &global.ro_spans)?;
    for mapping in &global.mappings {
        let expected = (!is_sparse_hvpatch_mmap_mapping(mapping)).then_some(mapping.ipa_start);
        if page_tables.translate(mapping.guest_start) != expected {
            return Err(TrapError::Hypervisor(format!(
                "hvpatch exec translation mismatch for VA 0x{:x}: expected={expected:x?}",
                mapping.guest_start,
            )));
        }
    }
    carrick_aarch64::engine::reserve_hvpatch_process_apertures(&mut page_tables).map_err(
        |error| {
            TrapError::Hypervisor(format!(
                "reserve hvpatch exec root-slot/global-frame apertures: {error:?}"
            ))
        },
    )?;
    let table_bytes = page_tables.into_bytes();
    {
        let table = &mut global.mappings[table_index];
        if table.ipa_start != root || table_bytes.len() > table.mapped_size as usize {
            return Err(TrapError::Hypervisor(
                "hvpatch exec page-table root-slot layout mismatch".to_owned(),
            ));
        }
        table.image = table_bytes.into();
        table.payload_size = table.image.len() as u64;
    }
    global.stage1_page_tables_base = Some(root);
    Ok(GlobalExecPlan {
        plan: global,
        stage2_leases,
    })
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
fn is_sparse_hvpatch_mmap_mapping(mapping: &GuestMapping) -> bool {
    mapping.guest_start == crate::memory::LINUX_MMAP_BASE
        && mapping.mapped_size == crate::memory::mmap_arena_size()
        && !mapping.shared
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
fn next_vdso_rng_generation() -> u64 {
    // A host PID distinguished the historical one-guest-process-per-host-process
    // VMM fork path, but HVPatch materializes many Linux processes inside one
    // Carrick host process. A process-local monotonic generation distinguishes
    // every such child; the vDSO uses it only as a reseed epoch, not as entropy.
    static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);
    NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
fn reapply_global_exec_readonly_spans(
    page_tables: &mut crate::page_table::PageTableManager,
    ro_spans: &[carrick_mem::elf::RoSpan],
) -> Result<(), TrapError> {
    for span in ro_spans {
        let len = usize::try_from(span.len).map_err(|_| {
            TrapError::Hypervisor(format!(
                "HVPatch exec read-only span at 0x{:x} is too large: {}",
                span.start, span.len
            ))
        })?;
        page_tables
            .set_readonly(span.start, len, span.exec)
            .map_err(|error| {
                TrapError::Hypervisor(format!(
                    "restore HVPatch exec read-only span at 0x{:x}: {error:?}",
                    span.start
                ))
            })?;
    }
    Ok(())
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
#[derive(Default)]
struct GlobalFrameOwnerRollback {
    keys: Vec<(u64, u64)>,
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
impl GlobalFrameOwnerRollback {
    fn record(&mut self, key: (u64, u64)) {
        self.keys.push(key);
    }

    fn commit(mut self) {
        self.keys.clear();
    }
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
impl Drop for GlobalFrameOwnerRollback {
    fn drop(&mut self) {
        for &(ipa, length) in self.keys.iter().rev() {
            let retired = retire_global_frame_host_owner(ipa, length);
            if !retired {
                eprintln!(
                    "carrick: FATAL: rollback lost global frame owner IPA 0x{ipa:x} size {length}"
                );
                std::process::abort();
            }
        }
    }
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
unsafe impl Send for ProcessSpec {}

// SAFETY: `ThreadSpec` carries raw `*mut u8` host pointers (inside the
// mapping descriptors). Those pointers name buffers that are valid for the
// entire host process address space — they outlive every guest thread and
// are never reallocated for the life of the VM. The seeded register snapshot
// rides the engine's `Aarch64SiblingSpec`, NOT here (the engine restores it
// onto the sibling vCPU). The applevisor VM handle is itself `Send` (Arc-backed).
// Moving the spec to another thread to materialise a vCPU there is exactly
// the supported HVF pattern (create the vCPU on its owning thread), so the
// raw pointers crossing the thread boundary is sound.
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
unsafe impl Send for ThreadSpec {}

#[cfg(not(all(target_os = "macos", target_arch = "aarch64")))]
pub struct ThreadSpec;

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum PersistentExecutorInvariantRegister {
    VbarEl1,
    SctlrEl1,
    MairEl1,
    CpacrEl1,
    CntkctlEl1,
    TpidrEl1,
    SpEl1,
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
const PERSISTENT_EXECUTOR_CONFIGURED_REGISTERS: [PersistentExecutorInvariantRegister; 6] = [
    PersistentExecutorInvariantRegister::VbarEl1,
    PersistentExecutorInvariantRegister::SctlrEl1,
    PersistentExecutorInvariantRegister::MairEl1,
    PersistentExecutorInvariantRegister::CpacrEl1,
    PersistentExecutorInvariantRegister::CntkctlEl1,
    PersistentExecutorInvariantRegister::TpidrEl1,
];

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
const PERSISTENT_EXECUTOR_INVARIANT_REGISTERS: [PersistentExecutorInvariantRegister; 7] = [
    PersistentExecutorInvariantRegister::VbarEl1,
    PersistentExecutorInvariantRegister::SctlrEl1,
    PersistentExecutorInvariantRegister::MairEl1,
    PersistentExecutorInvariantRegister::CpacrEl1,
    PersistentExecutorInvariantRegister::CntkctlEl1,
    PersistentExecutorInvariantRegister::TpidrEl1,
    PersistentExecutorInvariantRegister::SpEl1,
];

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
fn persistent_executor_invariant_value(
    register: PersistentExecutorInvariantRegister,
    mailbox_sp: u64,
) -> u64 {
    use carrick_hal::GuestArch as _;

    let boot = <HvfTrapEngine as carrick_hal::ThreadedEngine>::Arch::bootstrap_sysregs();
    match register {
        PersistentExecutorInvariantRegister::VbarEl1 => carrick_mem::memory::LINUX_EL1_VECTORS_BASE,
        PersistentExecutorInvariantRegister::SctlrEl1 => boot.sctlr_el1,
        PersistentExecutorInvariantRegister::MairEl1 => boot.mair_el1,
        PersistentExecutorInvariantRegister::CpacrEl1 => boot.cpacr_el1,
        PersistentExecutorInvariantRegister::CntkctlEl1 => (1 << 1) | (1 << 0),
        // The EL1 vector uses TPIDR_EL1 only as transient executor-local x16
        // scratch. A newly published worker must not inherit task residue.
        PersistentExecutorInvariantRegister::TpidrEl1 => 0,
        PersistentExecutorInvariantRegister::SpEl1 => mailbox_sp,
    }
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
fn configure_persistent_executor_invariant_registers(
    mut write: impl FnMut(PersistentExecutorInvariantRegister, u64) -> Result<(), TrapError>,
) -> Result<(), TrapError> {
    for register in PERSISTENT_EXECUTOR_CONFIGURED_REGISTERS {
        write(register, persistent_executor_invariant_value(register, 0))?;
    }
    Ok(())
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
fn restore_persistent_executor_invariant_registers(
    mut write: impl FnMut(PersistentExecutorInvariantRegister, u64) -> Result<(), TrapError>,
    mailbox_sp: u64,
) -> Result<(), TrapError> {
    for register in PERSISTENT_EXECUTOR_INVARIANT_REGISTERS {
        write(
            register,
            persistent_executor_invariant_value(register, mailbox_sp),
        )?;
    }
    Ok(())
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
fn audit_persistent_executor_invariant_registers(
    mut read: impl FnMut(PersistentExecutorInvariantRegister) -> Result<u64, TrapError>,
    mailbox_sp: u64,
) -> Result<(), TrapError> {
    for register in PERSISTENT_EXECUTOR_INVARIANT_REGISTERS {
        let actual = read(register)?;
        let expected = persistent_executor_invariant_value(register, mailbox_sp);
        if actual != expected {
            return Err(TrapError::Hypervisor(format!(
                "persistent executor invariant {register:?} mismatch: {actual:#x}/{expected:#x}"
            )));
        }
    }
    Ok(())
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
impl HvfVmState {
    fn configure_executor_invariants(vcpu: &applevisor::vcpu::Vcpu) -> Result<(), TrapError> {
        use applevisor::prelude::SysReg;

        configure_persistent_executor_invariant_registers(|register, value| {
            let register = match register {
                PersistentExecutorInvariantRegister::VbarEl1 => SysReg::VBAR_EL1,
                PersistentExecutorInvariantRegister::SctlrEl1 => SysReg::SCTLR_EL1,
                PersistentExecutorInvariantRegister::MairEl1 => SysReg::MAIR_EL1,
                PersistentExecutorInvariantRegister::CpacrEl1 => SysReg::CPACR_EL1,
                PersistentExecutorInvariantRegister::CntkctlEl1 => SysReg::CNTKCTL_EL1,
                PersistentExecutorInvariantRegister::TpidrEl1 => SysReg::TPIDR_EL1,
                PersistentExecutorInvariantRegister::SpEl1 => {
                    unreachable!("SP_EL1 is mailbox-owned")
                }
            };
            vcpu.set_sys_reg(register, value).map_err(hvf_error)
        })
    }

    fn audit_executor_invariants(
        vcpu: &applevisor::vcpu::Vcpu,
        mailbox_sp: u64,
    ) -> Result<(), TrapError> {
        use applevisor::prelude::SysReg;

        audit_persistent_executor_invariant_registers(
            |register| {
                let register = match register {
                    PersistentExecutorInvariantRegister::VbarEl1 => SysReg::VBAR_EL1,
                    PersistentExecutorInvariantRegister::SctlrEl1 => SysReg::SCTLR_EL1,
                    PersistentExecutorInvariantRegister::MairEl1 => SysReg::MAIR_EL1,
                    PersistentExecutorInvariantRegister::CpacrEl1 => SysReg::CPACR_EL1,
                    PersistentExecutorInvariantRegister::CntkctlEl1 => SysReg::CNTKCTL_EL1,
                    PersistentExecutorInvariantRegister::TpidrEl1 => SysReg::TPIDR_EL1,
                    PersistentExecutorInvariantRegister::SpEl1 => SysReg::SP_EL1,
                };
                vcpu.get_sys_reg(register).map_err(hvf_error)
            },
            mailbox_sp,
        )
    }

    fn exec_authority_fingerprint(&self) -> ExecAuthorityFingerprint {
        let inventory = self.frame_inventory.lock();
        let backend_extents = inventory
            .extents
            .iter()
            .map(|(&key, extent)| ExecBackendExtentFingerprint {
                key,
                frame: extent.frame,
                mapping: extent.mapping,
                backing: extent.backing,
                stage2_base: extent.stage2_base,
                stage2_length: extent.stage2_length,
            })
            .collect();
        let inventory_initialized = inventory.initialized;
        let frames = inventory.frames.lock();
        let frame_references = frames
            .references
            .iter()
            .map(|(&key, &value)| (key, value))
            .collect();
        let extent_references = frames
            .extent_references
            .iter()
            .map(|(&key, &value)| (key, value))
            .collect();
        let stage2_references = frames
            .stage2_references
            .iter()
            .map(|(&key, &value)| (key, value))
            .collect();
        drop(frames);
        drop(inventory);
        let owners = global_frame_host_owners()
            .lock()
            .iter()
            .map(|(&key, owner)| ExecOwnerFingerprint {
                key,
                host: owner._mapping.as_ptr() as usize,
                host_len: owner._mapping.len(),
                perms: owner.perms,
                lease: (&owner._lease).into(),
            })
            .collect();
        let mappings = self
            .mappings
            .iter()
            .map(|mapping| ExecMappingFingerprint {
                start: mapping.start,
                ipa: mapping.ipa,
                physical_ipa: mapping.physical_ipa,
                end: mapping.end,
                host: mapping.host_addr as usize,
                size: mapping.size,
                physical_size: mapping.physical_size,
                perms: u64::from(mapping.perms),
                has_memory: mapping.memory.is_some(),
                host_owner: mapping
                    .host_mapping
                    .as_ref()
                    .map(|owner| (owner.as_ptr() as usize, owner.len())),
                stage2_lease: mapping.stage2_lease.as_ref().map(Into::into),
                is_dynamic_alias: mapping.is_dynamic_alias,
                sharing: mapping.sharing,
                guest_writable: mapping.guest_writable,
                shared_key_base: mapping.shared_key_base,
                shared_key_offset: mapping.shared_key_offset,
            })
            .collect();
        let allocator = global_frame_ipa_allocator().lock();
        let allocator = ExecAllocatorFingerprint {
            next: allocator.next,
            free: allocator.free.clone(),
            live: allocator
                .live
                .iter()
                .map(|(&key, &value)| (key, value))
                .collect(),
        };
        let replay_mappings = replay_mappings().lock().iter().copied().collect();
        ExecAuthorityFingerprint {
            owners,
            inventory_initialized,
            backend_extents,
            frame_references,
            extent_references,
            stage2_references,
            mappings,
            allocator,
            replay_mappings,
        }
    }

    fn retire_stage2_extent(&mut self, ipa: u64, length: u64) -> Result<(), TrapError> {
        Self::retire_stage2_extent_from_mappings(&mut self.mappings, ipa, length)
    }

    fn retire_stage2_extent_from_mappings(
        mappings: &mut [HvfMappedRegion],
        ipa: u64,
        length: u64,
    ) -> Result<(), TrapError> {
        if retire_global_frame_host_owner(ipa, length) {
            return Ok(());
        }
        if let Some(lease) = mappings.iter_mut().find_map(|mapping| {
            (mapping
                .stage2_lease
                .as_ref()
                .is_some_and(|lease| lease.key() == (ipa, length)))
            .then(|| mapping.stage2_lease.take())
            .flatten()
        }) {
            drop(lease);
            return Ok(());
        }
        // A forked process parks its fresh kernel-state leases on the carrier,
        // not on a mapping row. Without this the fallback below released an IPA
        // whose lease was still live, and the lease's `Drop` then released it
        // again.
        if let Some(lease) = take_carrier_stage2_lease(ipa, length) {
            drop(lease);
            return Ok(());
        }
        let size = usize::try_from(length).map_err(|_| TrapError::MappingTooLarge(length))?;
        let rc = unsafe { inventory_hv_vm_unmap(ipa, size) };
        if rc != 0 {
            return Err(TrapError::Hypervisor(format!(
                "retire HVPatch stage-2 extent IPA 0x{ipa:x} size {size} failed: 0x{rc:x}"
            )));
        }
        release_retired_stage2_ipa(ipa, length)?;
        Ok(())
    }

    fn inventory_generation(raw: u64) -> carrick_hal::MappingGeneration {
        let Some(raw) = std::num::NonZeroU64::new(raw) else {
            std::process::abort();
        };
        carrick_hal::MappingGeneration::from_backend_counter(raw)
    }

    fn private_backing_identity() -> InventoryBackingIdentity {
        static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);
        let serial = NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        if serial == 0 {
            eprintln!("carrick: FATAL: HVPatch private backing identity exhausted");
            std::process::abort();
        }
        InventoryBackingIdentity::Private(serial)
    }

    fn shared_anon_backing_identity() -> InventoryBackingIdentity {
        static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);
        let serial = NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        if serial == 0 {
            eprintln!("carrick: FATAL: HVPatch shared-anonymous backing identity exhausted");
            std::process::abort();
        }
        InventoryBackingIdentity::SharedAnon(serial)
    }

    fn region_permissions(region: &HvfMappedRegion) -> carrick_hal::MemPerms {
        let raw = u64::from(region.perms);
        carrick_hal::MemPerms {
            read: raw & 1 != 0,
            write: raw & 2 != 0,
            exec: raw & 4 != 0,
        }
    }

    fn reservation_error(error: carrick_hal::FrameInventoryReservationError) -> TrapError {
        TrapError::Hypervisor(format!("HVPatch frame inventory staging failed: {error}"))
    }

    fn push_exact_mapping_events(
        reservation: &mut carrick_hal::FrameInventoryReservation,
        frame: carrick_hal::FrameId,
        gpa: u64,
        length: u64,
        permissions: carrick_hal::MemPerms,
    ) -> Result<carrick_hal::MappingId, TrapError> {
        let mapping = reservation
            .claim_mapping()
            .map_err(Self::reservation_error)?;
        let length = std::num::NonZeroU64::new(length).ok_or_else(|| {
            TrapError::Hypervisor("HVPatch inventory received an empty mapping extent".to_owned())
        })?;
        let transaction = reservation.transaction();
        reservation
            .push(carrick_hal::FrameInventoryEvent::PrepareMapping {
                transaction,
                frame,
                mapping,
                generation: Self::inventory_generation(1),
                gpa: carrick_guest_mem::Gpa(gpa),
                length: carrick_hal::FrameLength::from_mapping_extent(length),
                permissions,
            })
            .map_err(Self::reservation_error)?;
        reservation
            .push(carrick_hal::FrameInventoryEvent::PublishMapping {
                transaction,
                mapping,
                generation: Self::inventory_generation(1),
            })
            .map_err(Self::reservation_error)?;
        Ok(mapping)
    }

    fn cow_inventory_split_shape(
        inventory: &HvpatchFrameInventory,
        compound_gpa: u64,
        retain_compound: bool,
    ) -> Result<CowInventorySplitShape, TrapError> {
        let compound_end = compound_gpa
            .checked_add(CowArmedRanges::COMPOUND_SIZE)
            .ok_or_else(|| TrapError::Hypervisor("HVPatch COW compound overflow".to_owned()))?;
        let (&old_key, &old) = inventory
            .extents
            .iter()
            .find(|((base, length), _)| {
                compound_gpa >= *base && compound_end <= base.saturating_add(*length)
            })
            .ok_or_else(|| {
                TrapError::Hypervisor(format!(
                    "HVPatch COW compound IPA 0x{compound_gpa:x} has no exact inventory coverage"
                ))
            })?;
        let old_end = old_key.0.checked_add(old_key.1).ok_or_else(|| {
            TrapError::Hypervisor("HVPatch old inventory extent overflow".to_owned())
        })?;
        let mut fragments = Vec::with_capacity(2);
        if old_key.0 < compound_gpa {
            fragments.push((old_key.0, compound_gpa - old_key.0));
        }
        if retain_compound {
            fragments.push((compound_gpa, CowArmedRanges::COMPOUND_SIZE));
        }
        if compound_end < old_end {
            fragments.push((compound_end, old_end - compound_end));
        }
        let global_references = inventory
            .frames
            .lock()
            .references
            .get(&old.frame)
            .copied()
            .ok_or_else(|| {
                TrapError::Hypervisor(format!(
                    "HVPatch COW frame {:?} lacks backend references",
                    old.frame
                ))
            })?;
        let retire_old_frame = global_references == 1 && fragments.is_empty();
        Ok(CowInventorySplitShape {
            old_key,
            old,
            fragments,
            retire_old_frame,
        })
    }

    /// Plan which mappings, frames and stage-2 leases a munmap retires.
    ///
    /// `authority_mapping_count` reports the authority's VM-WIDE live-mapping
    /// count for a frame. It is not redundant with the backend reference
    /// counts consulted below: `inventory.extents` is per-mm, the authority's
    /// count spans every mm, and `RetireFrame` is rejected unless the frame
    /// reaches zero mappings there. Retiring on the per-mm population alone
    /// aborts the carrier the moment a second Linux process maps the same
    /// frame, which is precisely what a forking guest does.
    fn inventory_lease_retirement_shape(
        inventory: &HvpatchFrameInventory,
        leases: &std::collections::BTreeSet<(u64, u64)>,
        authority_mapping_count: &dyn Fn(carrick_hal::FrameId) -> Option<usize>,
    ) -> Result<InventoryLeaseRetirement, TrapError> {
        let mappings: Vec<_> = inventory
            .extents
            .iter()
            .filter(|(_, extent)| leases.contains(&(extent.stage2_base, extent.stage2_length)))
            .map(|(&key, &extent)| (key, extent))
            .collect();
        let mut removed_frames = std::collections::BTreeMap::new();
        let mut removed_leases = std::collections::BTreeMap::new();
        for (_, extent) in &mappings {
            *removed_frames.entry(extent.frame).or_insert(0usize) += 1;
            *removed_leases
                .entry((extent.stage2_base, extent.stage2_length))
                .or_insert(0usize) += 1;
        }
        let registry = inventory.frames.lock();
        let mut frames = std::collections::BTreeSet::new();
        for (&frame, &removed) in &removed_frames {
            let live = registry.references.get(&frame).copied().ok_or_else(|| {
                TrapError::Hypervisor(format!(
                    "HVPatch alias retirement frame {frame:?} has no backend reference"
                ))
            })?;
            if removed > live {
                return Err(TrapError::Hypervisor(format!(
                    "HVPatch alias retirement frame {frame:?} reference underflow"
                )));
            }
            // Both populations must agree. `removed == live` says this mm
            // dropped the last backend reference it knows about; the authority
            // count says no OTHER mm still maps the frame. Requiring both can
            // only decline a retirement, never invent one, and a frame left
            // live is reclaimed by a later unmap where a wrong retirement
            // aborts the whole carrier.
            if removed == live && authority_mapping_count(frame) == Some(removed) {
                frames.insert(frame);
            }
        }
        let mut stage2_leases = std::collections::BTreeSet::new();
        for (&lease, &removed) in &removed_leases {
            let live = registry
                .stage2_references
                .get(&lease)
                .copied()
                .ok_or_else(|| {
                    TrapError::Hypervisor(format!(
                        "HVPatch alias retirement stage-2 lease {lease:?} has no backend reference"
                    ))
                })?;
            if removed > live {
                return Err(TrapError::Hypervisor(format!(
                    "HVPatch alias retirement stage-2 lease {lease:?} reference underflow"
                )));
            }
            if removed == live {
                stage2_leases.insert(lease);
            }
        }
        Ok(InventoryLeaseRetirement {
            mappings,
            frames,
            stage2_leases,
        })
    }

    fn stage_inventory_lease_retirement(
        reservation: &mut carrick_hal::FrameInventoryReservation,
        retirement: &InventoryLeaseRetirement,
    ) -> Result<(), TrapError> {
        let transaction = reservation.transaction();
        for (_, extent) in &retirement.mappings {
            reservation
                .push(carrick_hal::FrameInventoryEvent::UnmapMapping {
                    transaction,
                    mapping: extent.mapping,
                    generation: Self::inventory_generation(2),
                })
                .map_err(Self::reservation_error)?;
        }
        for &frame in &retirement.frames {
            reservation
                .push(carrick_hal::FrameInventoryEvent::RetireFrame {
                    transaction,
                    frame,
                    generation: Self::inventory_generation(2),
                })
                .map_err(Self::reservation_error)?;
        }
        Ok(())
    }

    fn commit_inventory_lease_retirement(
        inventory: &mut HvpatchFrameInventory,
        retirement: &InventoryLeaseRetirement,
    ) -> Result<(), TrapError> {
        let mut removed = Vec::with_capacity(retirement.mappings.len());
        for &(key, expected) in &retirement.mappings {
            let actual = inventory.extents.remove(&key).ok_or_else(|| {
                TrapError::Hypervisor(format!(
                    "HVPatch alias retirement mapping {key:?} disappeared"
                ))
            })?;
            if actual.mapping != expected.mapping || actual.frame != expected.frame {
                return Err(TrapError::Hypervisor(format!(
                    "HVPatch alias retirement mapping {key:?} identity drifted"
                )));
            }
            removed.push((key, actual));
        }
        let mut registry = inventory.frames.lock();
        for (key, extent) in removed {
            decrement_inventory_reference(&mut registry.references, extent.frame)?;
            decrement_inventory_reference(
                &mut registry.extent_references,
                (extent.frame, key.0, key.1),
            )?;
            decrement_inventory_reference(
                &mut registry.stage2_references,
                (extent.stage2_base, extent.stage2_length),
            )?;
            if retirement.frames.contains(&extent.frame)
                && matches!(extent.backing, InventoryBackingIdentity::SharedFile { .. })
            {
                registry.shared.remove(&extent.backing);
            }
        }
        for frame in &retirement.frames {
            if registry.references.contains_key(frame) {
                return Err(TrapError::Hypervisor(format!(
                    "HVPatch retired alias frame {frame:?} retains backend references"
                )));
            }
        }
        for lease in &retirement.stage2_leases {
            if registry.stage2_references.contains_key(lease) {
                return Err(TrapError::Hypervisor(format!(
                    "HVPatch retired stage-2 lease {lease:?} retains backend references"
                )));
            }
        }
        Ok(())
    }

    fn stage_cow_inventory_split(
        reservation: &mut carrick_hal::FrameInventoryReservation,
        old_key: (u64, u64),
        old: InventoryExtent,
        fragment_shapes: &[(u64, u64)],
        retire_old_frame: bool,
        new_gpa: u64,
        new_backing: InventoryBackingIdentity,
    ) -> Result<CowInventorySplit, TrapError> {
        let transaction = reservation.transaction();
        reservation
            .push(carrick_hal::FrameInventoryEvent::UnmapMapping {
                transaction,
                mapping: old.mapping,
                generation: Self::inventory_generation(2),
            })
            .map_err(Self::reservation_error)?;
        let permissions = carrick_hal::MemPerms {
            read: true,
            write: true,
            exec: true,
        };
        let mut fragments = Vec::with_capacity(fragment_shapes.len());
        for &(gpa, length) in fragment_shapes {
            let mapping =
                Self::push_exact_mapping_events(reservation, old.frame, gpa, length, permissions)?;
            fragments.push(CowInventoryFragment {
                gpa,
                length,
                mapping,
            });
        }
        let new_frame = reservation.claim_frame().map_err(Self::reservation_error)?;
        let new_mapping = Self::push_exact_mapping_events(
            reservation,
            new_frame,
            new_gpa,
            CowArmedRanges::COMPOUND_SIZE,
            permissions,
        )?;
        if retire_old_frame {
            reservation
                .push(carrick_hal::FrameInventoryEvent::RetireFrame {
                    transaction,
                    frame: old.frame,
                    generation: Self::inventory_generation(2),
                })
                .map_err(Self::reservation_error)?;
        }
        Ok(CowInventorySplit {
            old_key,
            old,
            fragments,
            new_key: (new_gpa, CowArmedRanges::COMPOUND_SIZE),
            new_extent: InventoryExtent {
                frame: new_frame,
                mapping: new_mapping,
                backing: new_backing,
                stage2_base: new_gpa,
                stage2_length: CowArmedRanges::COMPOUND_SIZE,
            },
            retire_old_frame,
        })
    }

    fn commit_cow_inventory_split(
        inventory: &mut HvpatchFrameInventory,
        split: &CowInventorySplit,
    ) -> Result<bool, TrapError> {
        let removed = inventory.extents.remove(&split.old_key).ok_or_else(|| {
            TrapError::Hypervisor("HVPatch COW old inventory mapping disappeared".to_owned())
        })?;
        if removed.mapping != split.old.mapping || removed.frame != split.old.frame {
            return Err(TrapError::Hypervisor(
                "HVPatch COW old inventory identity drifted".to_owned(),
            ));
        }
        let mut frames = inventory.frames.lock();
        decrement_inventory_reference(&mut frames.references, split.old.frame)?;
        decrement_inventory_reference(
            &mut frames.extent_references,
            (split.old.frame, split.old_key.0, split.old_key.1),
        )?;
        decrement_inventory_reference(
            &mut frames.stage2_references,
            (split.old.stage2_base, split.old.stage2_length),
        )?;
        for fragment in &split.fragments {
            increment_inventory_reference(&mut frames.references, split.old.frame)?;
            increment_inventory_reference(
                &mut frames.extent_references,
                (split.old.frame, fragment.gpa, fragment.length),
            )?;
            increment_inventory_reference(
                &mut frames.stage2_references,
                (split.old.stage2_base, split.old.stage2_length),
            )?;
            inventory.extents.insert(
                (fragment.gpa, fragment.length),
                InventoryExtent {
                    frame: split.old.frame,
                    mapping: fragment.mapping,
                    backing: split.old.backing,
                    stage2_base: split.old.stage2_base,
                    stage2_length: split.old.stage2_length,
                },
            );
        }
        increment_inventory_reference(&mut frames.references, split.new_extent.frame)?;
        increment_inventory_reference(
            &mut frames.extent_references,
            (split.new_extent.frame, split.new_key.0, split.new_key.1),
        )?;
        increment_inventory_reference(
            &mut frames.stage2_references,
            (split.new_extent.stage2_base, split.new_extent.stage2_length),
        )?;
        if split.retire_old_frame && frames.references.contains_key(&split.old.frame) {
            return Err(TrapError::Hypervisor(
                "HVPatch COW retired old frame retains backend mappings".to_owned(),
            ));
        }
        let retire_old_stage2 = !frames
            .stage2_references
            .contains_key(&(split.old.stage2_base, split.old.stage2_length));
        drop(frames);
        if inventory
            .extents
            .insert(split.new_key, split.new_extent)
            .is_some()
        {
            return Err(TrapError::Hypervisor(
                "HVPatch COW new inventory extent collided".to_owned(),
            ));
        }
        Ok(retire_old_stage2)
    }

    fn stage_mapping(
        inventory: &mut HvpatchFrameInventory,
        reservation: &mut carrick_hal::FrameInventoryReservation,
        stage: InventoryMappingStage,
    ) -> Result<InventoryExtent, TrapError> {
        let InventoryMappingStage {
            gpa,
            length,
            permissions,
            backing,
            inherited_frame,
            stage2_lease,
        } = stage;
        if inventory.extents.contains_key(&(gpa, length)) {
            return Err(TrapError::Hypervisor(format!(
                "HVPatch inventory extent IPA 0x{gpa:x} size {length} is duplicated"
            )));
        }
        let transaction = reservation.transaction();
        let mapping = reservation
            .claim_mapping()
            .map_err(Self::reservation_error)?;
        let frame = if let Some(frame) = inherited_frame {
            frame
        } else if matches!(backing, InventoryBackingIdentity::SharedFile { .. }) {
            let existing = inventory.frames.lock().shared.get(&backing).copied();
            match existing {
                Some(frame) => frame,
                None => reservation.claim_frame().map_err(Self::reservation_error)?,
            }
        } else {
            reservation.claim_frame().map_err(Self::reservation_error)?
        };
        let Some(length_value) = std::num::NonZeroU64::new(length) else {
            return Err(TrapError::Hypervisor(
                "HVPatch inventory received an empty mapping extent".to_owned(),
            ));
        };
        let length_typed = carrick_hal::FrameLength::from_mapping_extent(length_value);
        reservation
            .push(carrick_hal::FrameInventoryEvent::PrepareMapping {
                transaction,
                frame,
                mapping,
                generation: Self::inventory_generation(1),
                gpa: carrick_guest_mem::Gpa(gpa),
                length: length_typed,
                permissions,
            })
            .map_err(Self::reservation_error)?;
        reservation
            .push(carrick_hal::FrameInventoryEvent::PublishMapping {
                transaction,
                mapping,
                generation: Self::inventory_generation(1),
            })
            .map_err(Self::reservation_error)?;
        let mut frames = inventory.frames.lock();
        let frame_references = frames
            .references
            .get(&frame)
            .copied()
            .unwrap_or_default()
            .checked_add(1)
            .ok_or_else(|| {
                TrapError::Hypervisor(format!(
                    "HVPatch frame {frame:?} backend reference count exhausted"
                ))
            })?;
        let extent_key = (frame, gpa, length);
        let extent_references = frames
            .extent_references
            .get(&extent_key)
            .copied()
            .unwrap_or_default()
            .checked_add(1)
            .ok_or_else(|| {
                TrapError::Hypervisor(format!(
                    "HVPatch physical extent {extent_key:?} reference count exhausted"
                ))
            })?;
        frames.references.insert(frame, frame_references);
        frames
            .extent_references
            .insert(extent_key, extent_references);
        let stage2_lease = stage2_lease.unwrap_or((gpa, length));
        let stage2_references = frames
            .stage2_references
            .get(&stage2_lease)
            .copied()
            .unwrap_or_default()
            .checked_add(1)
            .ok_or_else(|| {
                TrapError::Hypervisor(format!(
                    "HVPatch stage-2 lease {stage2_lease:?} reference count exhausted"
                ))
            })?;
        frames
            .stage2_references
            .insert(stage2_lease, stage2_references);
        if matches!(backing, InventoryBackingIdentity::SharedFile { .. }) {
            frames.shared.entry(backing).or_insert(frame);
        }
        drop(frames);
        let extent = InventoryExtent {
            frame,
            mapping,
            backing,
            stage2_base: stage2_lease.0,
            stage2_length: stage2_lease.1,
        };
        inventory.extents.insert((gpa, length), extent);
        Ok(extent)
    }

    fn rollback_unpublished_mappings(
        inventory: &mut HvpatchFrameInventory,
        mappings: &[((u64, u64), InventoryExtent)],
    ) -> Result<(), TrapError> {
        let mut registry = inventory.frames.lock();
        for &(key, expected) in mappings.iter().rev() {
            let actual = inventory.extents.remove(&key).ok_or_else(|| {
                TrapError::Hypervisor(format!("HVPatch unpublished mapping rollback lost {key:?}"))
            })?;
            if actual.mapping != expected.mapping || actual.frame != expected.frame {
                return Err(TrapError::Hypervisor(format!(
                    "HVPatch unpublished mapping rollback identity drifted at {key:?}"
                )));
            }
            decrement_inventory_reference(&mut registry.references, actual.frame)?;
            decrement_inventory_reference(
                &mut registry.extent_references,
                (actual.frame, key.0, key.1),
            )?;
            decrement_inventory_reference(
                &mut registry.stage2_references,
                (actual.stage2_base, actual.stage2_length),
            )?;
            if matches!(actual.backing, InventoryBackingIdentity::SharedFile { .. })
                && !registry.references.contains_key(&actual.frame)
            {
                registry.shared.remove(&actual.backing);
            }
        }
        Ok(())
    }

    fn stage_retirement(
        inventory: &mut HvpatchFrameInventory,
        reservation: &mut carrick_hal::FrameInventoryReservation,
    ) -> Result<(), TrapError> {
        let transaction = reservation.transaction();
        let mut local_frame_references =
            std::collections::BTreeMap::<carrick_hal::FrameId, usize>::new();
        for (&(gpa, length), extent) in &inventory.extents {
            reservation
                .push(carrick_hal::FrameInventoryEvent::UnmapMapping {
                    transaction,
                    mapping: extent.mapping,
                    generation: Self::inventory_generation(2),
                })
                .map_err(Self::reservation_error)?;
            let local = local_frame_references.entry(extent.frame).or_default();
            *local = local.checked_add(1).ok_or_else(|| {
                TrapError::Hypervisor(format!(
                    "HVPatch frame {:?} local retirement count exhausted",
                    extent.frame
                ))
            })?;
            if length == 0 {
                return Err(TrapError::Hypervisor(format!(
                    "HVPatch retirement contains empty extent at IPA 0x{gpa:x}"
                )));
            }
        }
        let mut local_stage2_references = std::collections::BTreeMap::new();
        for extent in inventory.extents.values() {
            *local_stage2_references
                .entry((extent.stage2_base, extent.stage2_length))
                .or_insert(0usize) += 1;
        }

        let mut frames = inventory.frames.lock();
        let mut retired = std::collections::BTreeSet::new();
        for (&frame, &local) in &local_frame_references {
            let global = frames.references.get(&frame).copied().ok_or_else(|| {
                TrapError::Hypervisor(format!("HVPatch frame {frame:?} has no backend reference"))
            })?;
            if global < local {
                return Err(TrapError::Hypervisor(format!(
                    "HVPatch frame {frame:?} backend reference count underflow"
                )));
            }
            if global == local {
                retired.insert(frame);
            }
        }
        for (&(gpa, length), extent) in &inventory.extents {
            let key = (extent.frame, gpa, length);
            let references = frames.extent_references.get(&key).copied().ok_or_else(|| {
                TrapError::Hypervisor(format!(
                    "HVPatch physical extent {key:?} has no backend reference"
                ))
            })?;
            if references == 0 {
                return Err(TrapError::Hypervisor(format!(
                    "HVPatch physical extent {key:?} reference count underflow"
                )));
            }
        }
        for (&lease, &local) in &local_stage2_references {
            let global = frames
                .stage2_references
                .get(&lease)
                .copied()
                .ok_or_else(|| {
                    TrapError::Hypervisor(format!(
                        "HVPatch stage-2 lease {lease:?} has no backend reference"
                    ))
                })?;
            if global < local {
                return Err(TrapError::Hypervisor(format!(
                    "HVPatch stage-2 lease {lease:?} reference count underflow"
                )));
            }
        }
        for &frame in &retired {
            reservation
                .push(carrick_hal::FrameInventoryEvent::RetireFrame {
                    transaction,
                    frame,
                    generation: Self::inventory_generation(2),
                })
                .map_err(Self::reservation_error)?;
        }

        for (&frame, &local) in &local_frame_references {
            let remaining = frames.references[&frame] - local;
            if remaining == 0 {
                frames.references.remove(&frame);
            } else {
                frames.references.insert(frame, remaining);
            }
        }
        for (&(gpa, length), extent) in &inventory.extents {
            let key = (extent.frame, gpa, length);
            let remaining = frames.extent_references[&key] - 1;
            if remaining == 0 {
                frames.extent_references.remove(&key);
            } else {
                frames.extent_references.insert(key, remaining);
            }
            if retired.contains(&extent.frame)
                && matches!(extent.backing, InventoryBackingIdentity::SharedFile { .. })
            {
                frames.shared.remove(&extent.backing);
            }
        }
        for (&lease, &local) in &local_stage2_references {
            let remaining = frames.stage2_references[&lease] - local;
            if remaining == 0 {
                frames.stage2_references.remove(&lease);
            } else {
                frames.stage2_references.insert(lease, remaining);
            }
        }
        drop(frames);
        inventory.extents.clear();
        Ok(())
    }

    pub(crate) fn frame_inventory_extent_count(&self) -> usize {
        let inventory = self.frame_inventory.lock();
        if inventory.initialized {
            inventory.extents.len()
        } else {
            self.mappings
                .iter()
                .filter(|mapping| {
                    mapping_belongs_to_task_inventory(self.persistent_vm_lifecycle, mapping)
                })
                .count()
        }
    }

    pub(crate) fn inventory_initial_mappings(
        &mut self,
        mut reservation: carrick_hal::FrameInventoryReservation,
    ) -> Result<carrick_hal::FrameInventoryCommit<()>, TrapError> {
        let mut inventory = self.frame_inventory.lock();
        if !inventory.extents.is_empty() {
            return Ok(reservation.commit(()));
        }
        for region in &self.mappings {
            if !mapping_belongs_to_task_inventory(self.persistent_vm_lifecycle, region) {
                continue;
            }
            Self::stage_mapping(
                &mut inventory,
                &mut reservation,
                InventoryMappingStage {
                    gpa: region.physical_ipa,
                    length: region.physical_size as u64,
                    permissions: Self::region_permissions(region),
                    backing: Self::private_backing_identity(),
                    inherited_frame: None,
                    stage2_lease: None,
                },
            )?;
        }
        inventory.initialized = true;
        Ok(reservation.commit(()))
    }

    pub(crate) fn begin_alias_inventory(
        &mut self,
        reservation: carrick_hal::FrameInventoryReservation,
    ) -> Result<(), TrapError> {
        self.frame_inventory.begin_alias_inventory(reservation)
    }

    pub(crate) fn take_alias_inventory(&mut self) -> Option<carrick_hal::FrameInventoryCommit<()>> {
        let mut inventory = self.frame_inventory.lock();
        // Handing the commit off makes the staged extents the authority's
        // business, so they are no longer this transaction's to roll back.
        tracing::trace!(
            staged = inventory.alias_staged.len(),
            commit = inventory.alias_commit.is_some(),
            "hvpatch alias take"
        );
        inventory.alias_staged.clear();
        inventory.alias_commit.take()
    }

    pub(crate) fn abandon_alias_inventory(&mut self) -> bool {
        self.frame_inventory.cancel_alias_inventory()
    }

    pub(crate) fn begin_exec_inventory(
        &mut self,
        retired: Option<carrick_hal::FrameInventoryReservation>,
        replacement: carrick_hal::FrameInventoryReservation,
    ) -> Result<(), TrapError> {
        self.task.begin_exec_inventory(retired, replacement)
    }

    pub(crate) fn inject_next_begin_exec_inventory_failure(&mut self) {
        self.frame_inventory
            .inject_next_begin_exec_inventory_failure();
    }

    pub(crate) fn frame_inventory_exec_extent_counts(
        &self,
        new_image: &crate::memory::AddressSpace,
    ) -> (usize, usize) {
        let replacement = GuestMappingPlan::from_address_space(new_image)
            .map(|plan| {
                plan.mappings
                    .iter()
                    .filter(|mapping| !is_sparse_hvpatch_mmap_mapping(mapping))
                    .count()
            })
            .unwrap_or(0);
        (self.exec_retired_extent_count(), replacement)
    }

    pub(crate) fn take_exec_inventory(
        &mut self,
    ) -> Option<(
        Option<carrick_hal::FrameInventoryCommit<()>>,
        carrick_hal::FrameInventoryCommit<()>,
    )> {
        self.frame_inventory.lock().exec_commits.take()
    }

    pub(crate) fn begin_process_inventory(
        &mut self,
        reservation: carrick_hal::FrameInventoryReservation,
    ) -> Result<(), TrapError> {
        self.frame_inventory.begin_process_inventory(reservation)
    }

    pub(crate) fn cancel_process_inventory(&mut self) -> bool {
        self.frame_inventory.cancel_process_inventory()
    }

    pub(crate) fn take_process_inventory(
        &mut self,
    ) -> Option<carrick_hal::FrameInventoryCommit<()>> {
        self.frame_inventory.lock().process_commit.take()
    }

    pub(crate) fn commit_process_materialization(&mut self) -> Result<(), TrapError> {
        if self.frame_inventory.lock().process_commit.is_none() {
            return Err(TrapError::Hypervisor(
                "HVPatch process materialization has no inventory commit".to_owned(),
            ));
        }
        // Register only after the fresh vCPU register restore succeeds. Until
        // this point the aliases remain an owned, unpublished vector.
        for alias in self.pending_process_aliases.drain(..) {
            register_shared_alias(alias);
        }
        Ok(())
    }

    pub(crate) fn refresh_fork_process_state(
        &mut self,
        flush_stage1: &mut dyn FnMut() -> Result<(), TrapError>,
    ) -> Result<(), TrapError> {
        // A logical HVPatch child shares Carrick's host PID with its parent, so
        // the historical post-host-fork PID stamp cannot distinguish their
        // inherited vDSO getrandom states. Split the child's private vvar frame
        // before stamping a fresh generation; direct backing writes would
        // otherwise mutate the parent's still-shared frame as well. The runtime
        // invokes this only after it publishes the child inventory and binds
        // exact MM/COW authority, but before the start-gated vCPU enters guest
        // code.
        let generation_address =
            crate::vdso::LINUX_VVAR_BASE + crate::vdso::VVAR_OFF_RNG_GENERATION as u64;
        self.ensure_frame_cow_write(
            generation_address,
            core::mem::size_of::<u64>(),
            carrick_aarch64::vmm::FrameCowWriteIntent::PrivilegedInternal,
            flush_stage1,
        )?;
        self.stamp_rng_generation().map_err(|error| {
            TrapError::Hypervisor(format!("stamp HVPatch child vDSO RNG generation: {error}"))
        })
    }

    pub(crate) fn abort_process_materialization(&mut self) -> Result<(), TrapError> {
        self.pending_process_aliases.clear();
        self.pending_fork_frame_receipts.clear();
        {
            let mut inventory = self.frame_inventory.lock();
            let staged: Vec<_> = inventory
                .extents
                .iter()
                .map(|(&key, &extent)| (key, extent))
                .collect();
            Self::rollback_unpublished_mappings(&mut inventory, &staged)?;
            drop(inventory.process_commit.take());
        }
        // Fresh per-mm mappings own their stage-2 leases; inherited mappings
        // are non-owning. Dropping this vector therefore unmaps/releases only
        // unpublished child-local extents.
        drop(std::mem::take(&mut self.mappings));
        self.mm_root_slot = None;
        Ok(())
    }

    pub(crate) fn begin_retirement_inventory(
        &mut self,
        reservation: carrick_hal::FrameInventoryReservation,
    ) -> Result<(), TrapError> {
        let mut inventory = self.frame_inventory.lock();
        if inventory.retirement_reservation.is_some() {
            return Err(TrapError::Hypervisor(
                "overlapping HVPatch retirement inventory transaction".to_owned(),
            ));
        }
        inventory.retirement_reservation = Some(reservation);
        Ok(())
    }

    pub(crate) fn take_retirement_inventory(
        &mut self,
    ) -> Option<carrick_hal::FrameInventoryCommit<()>> {
        self.frame_inventory.lock().retirement_commit.take()
    }

    pub(crate) fn set_persistent_vm_lifecycle(&mut self, enabled: bool) {
        self.persistent_vm_lifecycle = enabled;
    }

    pub(crate) fn sparse_mmap_arena_enabled(&self) -> bool {
        self.persistent_vm_lifecycle
    }

    /// Retire the generic boot loader's hidden 32 GiB mmap backing after the
    /// runtime selects HVPatch, but before initial frame inventory publication.
    /// Mature VMM never enables the persistent lifecycle and keeps its existing
    /// eager identity mapping unchanged.
    pub(crate) fn retire_initial_mmap_arena(&mut self) -> Result<(), TrapError> {
        if !self.persistent_vm_lifecycle {
            return Ok(());
        }
        let Some(index) = self.mappings.iter().position(|mapping| {
            mapping.start == crate::memory::LINUX_MMAP_BASE
                && mapping.end
                    == crate::memory::LINUX_MMAP_BASE
                        .saturating_add(crate::memory::mmap_arena_size())
                && mapping.physical_ipa == crate::memory::LINUX_MMAP_BASE
                && mapping.physical_size as u64 == crate::memory::mmap_arena_size()
                && !mapping.is_dynamic_alias
        }) else {
            return Err(TrapError::Hypervisor(
                "HVPatch initial mmap arena backing is absent or has unexpected shape".to_owned(),
            ));
        };
        let mapping = &self.mappings[index];
        if mapping.stage2_lease.is_some() || mapping.host_mapping.is_none() {
            return Err(TrapError::Hypervisor(
                "HVPatch initial mmap arena has unexpected ownership".to_owned(),
            ));
        }
        let rc = unsafe { inventory_hv_vm_unmap(mapping.physical_ipa, mapping.physical_size) };
        if rc != 0 {
            return Err(TrapError::Hypervisor(format!(
                "unmap HVPatch initial sparse mmap arena: 0x{rc:x}"
            )));
        }
        drop(self.mappings.remove(index));
        Ok(())
    }

    pub(crate) fn page_tables_snapshot(&self) -> Option<crate::page_table::PageTableManager> {
        self.page_tables.lock().clone()
    }

    pub(crate) fn bind_stage1_page_tables(
        &mut self,
        page_tables: std::sync::Arc<
            parking_lot::Mutex<Option<crate::page_table::PageTableManager>>,
        >,
    ) {
        self.page_tables = page_tables;
    }

    pub(crate) fn task_runtime_authorities_match(
        &self,
        page_tables: &std::sync::Arc<
            parking_lot::Mutex<Option<crate::page_table::PageTableManager>>,
        >,
        protections: &std::sync::Arc<MemoryProtections>,
    ) -> bool {
        self.task
            .runtime_authorities_match(page_tables, protections)
    }

    pub(crate) fn task_protections_authority(&self) -> std::sync::Arc<MemoryProtections> {
        std::sync::Arc::clone(&self.protections)
    }

    /// Tell `manager` whether THIS thread's edit is exclusive, before an
    /// HVPatch mapping publication that locks `self.page_tables` directly.
    ///
    /// `Aarch64EngineCore::pt_edit_locked` pushes the same answer for every
    /// edit that goes through the engine, but the HVPatch publications below
    /// take the lock themselves and would otherwise allocate spare sub-tables
    /// under whatever marker the PREVIOUS editor happened to leave behind.
    /// The marker gates `alloc_table`'s last-resort reclaim sweep, so a stale
    /// `false` turns a recoverable pool into `OutOfTables` -> guest `ENOMEM`:
    /// cpython `concurrent_futures` raised `MemoryError` out of a 16 KiB
    /// anonymous `mmap` whose own syscall dispatch DID hold exclusivity.
    ///
    /// Only exclusivity is refreshed. `multi_vcpu` gates the EAGER coalescing
    /// scan, which is a throughput decision this path must not silently flip
    /// (enabling it cost `go-net_http` 50 s -> over 200 s).
    fn refresh_stage1_exclusivity(manager: &mut crate::page_table::PageTableManager) {
        manager.set_stage1_exclusive(
            carrick_hal::stage1_exclusive::current_thread_edits_exclusively(),
        );
    }

    /// Complete pre-transaction image of `manager`, taken into the recycled
    /// buffer when one is available.
    ///
    /// This is byte-for-byte what `manager.clone()` produced before; the only
    /// change is that a returned buffer is refilled in place instead of asking
    /// the allocator for another 1.75 MiB region. See `cow_rollback_scratch`.
    fn rollback_pre_image(
        scratch: &mut Option<crate::page_table::PageTableManager>,
        manager: &crate::page_table::PageTableManager,
    ) -> crate::page_table::PageTableManager {
        match scratch.take() {
            Some(mut reused) => {
                reused.clone_from(manager);
                reused
            }
            None => manager.clone(),
        }
    }

    pub(crate) fn retire_process_mappings(&mut self) -> Result<(), TrapError> {
        Self::retire_task_state_process_mappings(&mut self.task)
    }

    pub(crate) fn retire_task_state_process_mappings(
        task: &mut HvfTaskState,
    ) -> Result<(), TrapError> {
        // Mature VMM processes own a private VM and retain the historical
        // teardown path; only the persistent single-VM HVPatch lane publishes
        // per-process frame-inventory retirement.
        if !task.persistent_vm_lifecycle {
            return Ok(());
        }
        // The runtime holds the process-wide HVPatch topology lock across this
        // method. Select exact extents whose final logical owner is this mm;
        // global shared aliases are therefore retired by their actual last
        // owner rather than being omitted merely because they are globally
        // addressed outside this mm's stage-1 root slot.
        let extents = {
            let inventory = task.frame_inventory.lock();
            if inventory.extents.is_empty() {
                if task.mappings.is_empty() {
                    return Ok(());
                }
                return Err(TrapError::Hypervisor(
                    "HVPatch process retirement has mappings without frame inventory authority"
                        .to_owned(),
                ));
            }
            if inventory.retirement_reservation.is_none() {
                return Err(TrapError::Hypervisor(
                    "HVPatch retirement began without frame inventory reservation".to_owned(),
                ));
            }
            final_exec_physical_extents(&inventory)?
        };

        for &(ipa, size) in &extents {
            Self::retire_stage2_extent_from_mappings(&mut task.mappings, ipa, size as u64)?;
        }
        mutate_external_alias_state(|_, registry| {
            registry.retain(|alias| {
                !alias_is_owned_by_process(alias.ownership_scope, task.mm_root_slot)
                    && !extents.contains(&(alias.physical_ipa, alias.physical_size))
            });
        });

        // A retained shared extent still points at its original host allocation.
        // Reclaim only exact extents removed above and preserve the remaining
        // backing until the single VM is finally destroyed.
        let mut retained_backings = Vec::new();
        for mapping in std::mem::take(&mut task.mappings) {
            if extents.contains(&(mapping.physical_ipa, mapping.physical_size)) {
                drop(mapping);
            } else {
                retained_backings.push(mapping);
            }
        }
        std::mem::forget(retained_backings);
        task.mm_root_slot = None;

        let mut inventory = task.frame_inventory.lock();
        let mut reservation = inventory.retirement_reservation.take().unwrap_or_else(|| {
            eprintln!("carrick: FATAL: validated HVPatch retirement reservation disappeared");
            std::process::abort();
        });
        if let Err(error) = Self::stage_retirement(&mut inventory, &mut reservation) {
            eprintln!("carrick: FATAL: stage inventory after HVPatch retirement: {error}");
            std::process::abort();
        }
        inventory.retirement_commit = Some(reservation.commit(()));
        Ok(())
    }

    pub(crate) fn take_task_state_retirement_inventory(
        task: &mut HvfTaskState,
    ) -> Option<carrick_hal::FrameInventoryCommit<()>> {
        task.frame_inventory.lock().retirement_commit.take()
    }

    pub(crate) fn retire_task_state_exec_predecessor(
        task: &mut HvfTaskState,
    ) -> Result<(), TrapError> {
        let mut cleanup = task.pending_exec_stage2_cleanup.take().ok_or_else(|| {
            TrapError::Hypervisor(
                "detached exec successor lost predecessor stage-2 cleanup authority".to_owned(),
            )
        })?;
        cleanup.retire()
    }

    fn seed_readonly_spans_from_plan(&self, plan: &GuestMappingPlan) {
        for span in &plan.ro_spans {
            let Ok(len) = usize::try_from(span.len) else {
                continue;
            };
            self.protections.set_no_write(span.start, len, true);
        }
    }

    /// Create the VM + the (one) vCPU, map the guest address space, program the
    /// initial vCPU sysregs/trampoline, and return the `(state_without_vcpu,
    /// vcpu)` pair the shared engine owns separately. Consolidates the old
    /// `HvfTrapEngine::new_platform` + `map_plan` + the initial-PC/SPSR/SCTLR/
    /// TTBR/CPACR/CNTKCTL/VBAR/SP/vdso setup into one constructor.
    pub(crate) fn new_with_plan(
        plan: &GuestMappingPlan,
    ) -> Result<(HvfVmState, applevisor::vcpu::Vcpu, MailboxBinding), TrapError> {
        use applevisor::prelude::*;

        let (vm, permit) = create_vm_with_admission(VmCreateAdmission::Initial)?;
        let vcpu = create_vcpu_with_permit(&vm, permit)?;
        enable_el0_counter_access(vcpu.id());

        let syscall_transport = HvfSyscallTransport::from_env()
            .map_err(|error| TrapError::Hypervisor(error.to_string()))?;
        let mut state = HvfVmState {
            _vm: std::mem::ManuallyDrop::new(vm),
            task: HvfTaskState {
                mappings: Vec::new(),
                mm_root_slot: None,
                pending_exec_mm_root_slot: None,
                pending_exec_asid: None,
                pending_exec_stage2_cleanup: None,
                shared_process_mm: false,
                last_exit_class: 0,
                last_fault_esr: 0,
                is_forked_child: false,
                forked_no_exec: false,
                protections: std::sync::Arc::new(MemoryProtections::default()),
                page_tables: std::sync::Arc::new(parking_lot::Mutex::new(None)),
                last_syscall_nr: None,
                last_syscall_orig_x0: 0,
                vfork_share: false,
                fork_mapping_descs: Vec::new(),
                fork_child_descs: Vec::new(),
                persistent_vm_lifecycle: false,
                frame_inventory: HvpatchFrameInventoryState::new(std::sync::Arc::new(
                    parking_lot::Mutex::new(HvpatchFrameInventory::default()),
                )),
                cow_authority: None,
                cow_identity: None,
                cow_armed: std::sync::Arc::new(parking_lot::Mutex::new(CowArmedRanges::default())),
                cow_deferred_publications: std::sync::Arc::new(parking_lot::Mutex::new(Vec::new())),
                pending_fork_frame_receipts: Vec::new(),
                pending_process_aliases: Vec::new(),
                cow_rollback_scratch: None,
            },
            carrier_mappings: None,
            reclaim_authority: ReclaimParkAuthority::Live,
            mailbox_slots: std::sync::Arc::new(MailboxSlotAllocator::new()),
            syscall_transport,
            vcpu_id: vcpu.id(),
            vcpu_handle: vcpu.get_handle(),
        };
        state.seed_readonly_spans_from_plan(plan);

        for mapping in &plan.mappings {
            #[cfg(feature = "trace-hvf")]
            eprintln!(
                "MAP guest_start=0x{:x} mapped_size=0x{:x} payload_size=0x{:x} perms=r{}w{}x{}",
                mapping.guest_start,
                mapping.mapped_size,
                mapping.payload_size,
                if mapping.perms.read { '+' } else { '-' },
                if mapping.perms.write { '+' } else { '-' },
                if mapping.perms.execute { '+' } else { '-' },
            );
            let region = map_region_raw(mapping, false)?;
            state.mappings.push(region);
        }

        // Start PC: if an EL0 entry trampoline is installed, the vCPU begins
        // at the trampoline page (in EL1h) and executes the single `eret`
        // there to drop into EL0t at the real user entry. Otherwise the vCPU
        // starts directly at the user entry (used by the existing EL1-only
        // unit tests).
        let initial_pc = plan.el0_trampoline_entry.unwrap_or(plan.entry);
        vcpu.set_reg(Reg::PC, initial_pc).map_err(hvf_error)?;
        // M[3:0]=0b0101 = EL1h (AArch64 EL1 using SP_EL1) + DAIF masked.
        // HVF reset CPSR is also EL1h; we set it explicitly so a re-entry
        // after a syscall trap doesn't depend on whatever HVF left in place.
        // The vCPU stays at EL1h until the trampoline `eret` swaps PSTATE
        // for the SPSR_EL1 value programmed below.
        const AARCH64_PSTATE_EL1H_DAIF_MASKED: u64 = 0x3c5;
        vcpu.set_reg(Reg::CPSR, AARCH64_PSTATE_EL1H_DAIF_MASKED)
            .map_err(hvf_error)?;
        // When using the trampoline, stage SPSR_EL1 with "AArch64 EL0t, DAIF
        // masked" (M[3:0]=0b0000) and ELR_EL1 with the user-mode entry. The
        // `eret` at the trampoline page then transitions to EL0t with
        // PC=plan.entry, which is the state Linux user code expects so the
        // first `svc #0` raises a "lower EL using AArch64" synchronous
        // exception that HVF surfaces to the host.
        if let Some(_trampoline) = plan.el0_trampoline_entry {
            const AARCH64_PSTATE_EL0T_DAIF_MASKED: u64 = 0x3c0;
            vcpu.set_sys_reg(SysReg::SPSR_EL1, AARCH64_PSTATE_EL0T_DAIF_MASKED)
                .map_err(hvf_error)?;
            vcpu.set_sys_reg(SysReg::ELR_EL1, plan.entry)
                .map_err(hvf_error)?;
        }
        // Disable stage-1 MMU translation for the EL0/EL1 guest. Without this,
        // the vCPU's reset value of SCTLR_EL1 has .M=1, which makes every
        // instruction fetch translate through page tables we never built, and
        // the first fetch faults with FSC=Translation fault, level 3. With
        // .M=0 the guest sees stage-2 mappings directly. Bits C/I (caches) are
        // also cleared since we have no maintenance ops yet.
        // SCTLR_EL1 layout:
        //   bit  0 = M  (MMU enable)        — 0: stage-1 MMU off, identity
        //   bit  2 = C  (D-cache enable)    — 1: data accesses cacheable
        //   bit 12 = I  (I-cache enable)    — 1: instruction fetches cacheable
        //   bits 22..21 = SED/UCT etc. (default 0 is fine)
        //   bits 28..23 = RES1 (reserved-as-one); HVF accepts 0 for them.
        // We keep M=0 (no page tables) but set C=1 and I=1 so the memory we
        // use is treated as cacheable Normal memory. ARMv8-A defines
        // exclusive load/store on non-cacheable memory as UNPREDICTABLE,
        // and Apple HVF appears to abort externally rather than treat it as
        // implementation-defined; musl's `ldaxr` on first mutex acquire
        // depends on this.
        // If a stage-1 page-table region is installed, program TTBR0_EL1,
        // TCR_EL1 and MAIR_EL1 to point at our identity-mapping tables,
        // and set SCTLR_EL1.M = 1 so EL0/EL1 data accesses go through
        // the Normal-cacheable mapping. ARMv8-A treats data accesses as
        // Device-nGnRnE memory whenever stage-1 is disabled, and
        // `ldaxr`/`stlxr` on Device memory abort externally — which is
        // exactly the wall musl's pthread_mutex_lock hits otherwise.
        // C=1, I=1 (caches); UCI=1 (bit 26: EL0 cache-maintenance ops DC CVAU/
        // CIVAC/CVAC, IC IVAU — glibc __clear_cache), UCT=1 (bit 15: EL0 read of
        // CTR_EL0 — glibc 2.41 reads cache line sizes at startup; without this
        // the MRS traps to EL1 and crashed CPython), DZE=1 (bit 14: EL0 DC ZVA +
        // DCZID_EL0 read — glibc memset). Matches Linux's SCTLR_EL1 for EL0.
        // Shared bootstrap SCTLR (via GuestArch; canonical rationale in
        // carrick_mem::arch_sysregs) carries M=1 (stage-1 on); HVF enables M
        // only when stage-1 tables exist (below), so start from the value with
        // M cleared and OR M back in there. HVF leaves SPAN(23) CLEAR and
        // forces PSTATE.PAN=1 (FEAT_PAN3) — SPAN is KVM glue, NOT part of the
        // shared value.
        use carrick_hal::GuestArch as _;
        let boot = <HvfTrapEngine as carrick_hal::ThreadedEngine>::Arch::bootstrap_sysregs();
        let mut sctlr_el1: u64 = boot.sctlr_el1 & !1;
        // Stage-1 MMU is on by default. The identity tables use AP=00 for
        // kernel pages (trampoline/vectors/PT) and AP=01+PXN=1 for user
        // pages, which is required on Apple Silicon because HVF starts
        // vCPUs with PSTATE.PAN=1 and FEAT_PAN3 turns any EL1 fetch from
        // an AP[1]=1 page into a permission fault. See
        // `stage1_identity_page_tables` in src/memory.rs.
        if let Some(pt_base) = plan.stage1_page_tables_base {
            // MAIR_EL1 slot 0 = Normal memory, Inner & Outer Write-Back
            // Cacheable, RW-allocate (0xFF). Slot 1..7 stay 0 (Device-
            // nGnRnE), unused for now.
            vcpu.set_sys_reg(SysReg::MAIR_EL1, boot.mair_el1)
                .map_err(hvf_error)?;
            // TCR_EL1: TTBR0 (lower half) and TTBR1 (upper half) BOTH active.
            //   T0SZ = T1SZ = 16 (48-bit VA each half) — wide enough for
            //              Rosetta's fixed ET_EXEC load base at 2^47 AND the
            //              x86-64 high-half (negative) addresses it maps into.
            //   IRGN0/1 = 0b11, ORGN0/1 = 0b11, SH0/1 = 0b11 (Inner WB, Inner
            //              Shareable) for both halves; TG0 = 0b00 (4K),
            //              TG1 = 0b10 (4K — note TG1's encoding differs!).
            //   EPD1 = 0 (TTBR1 walks ENABLED). TTBR1 shares the TTBR0 page-
            //              table root: a walk indexes VA[47:0] regardless of
            //              which TTBR selected it, and carrick's lower-half
            //              mappings + the upper-half alias projections occupy
            //              disjoint L0 slots.
            //   IPS = 0b010 (40-bit IPA, max for M-series HVF — output stays
            //              <=40 bits; high VAs are mapped down to a low IPA).
            //   TBI0/TBI1 = 1: the MMU ignores the top byte on translation —
            //              Rosetta tags pointers in the top byte and asserts
            //              unless hardware ignores it (pairs with the 16-bit
            //              software tag strip in mapping_for_range / mmap).
            // boot.tcr_el1 is the shared bootstrap value via GuestArch
            // (canonical rationale in carrick_mem::arch_sysregs).
            vcpu.set_sys_reg(SysReg::TCR_EL1, boot.tcr_el1)
                .map_err(hvf_error)?;
            vcpu.set_sys_reg(SysReg::TTBR0_EL1, pt_base)
                .map_err(hvf_error)?;
            // TTBR1 shares the same root (see the TCR comment above).
            vcpu.set_sys_reg(SysReg::TTBR1_EL1, pt_base)
                .map_err(hvf_error)?;
            // Enable stage-1 MMU (M=1) on top of the C=1, I=1 flags above.
            sctlr_el1 |= 1;
        }
        vcpu.set_sys_reg(SysReg::SCTLR_EL1, sctlr_el1)
            .map_err(hvf_error)?;
        // Enable FP/SIMD for the guest. Without this, CPACR_EL1.FPEN defaults
        // to "trap at EL0", and musl's `memset` (which uses NEON `dup`/`stp`
        // instructions) faults on its very first call — the trap is misrouted
        // through our EL1 vector as if it were an SVC, the dispatcher sees
        // garbage syscall numbers, and the guest spins forever. FPEN=0b11
        // turns the trap off; the bottom two bits of each TRC* field are kept
        // at zero (trace unsupported, no SME).
        // boot.cpacr_el1 (FPEN=0b11, no FP/SIMD trap at EL0) is shared.
        vcpu.set_sys_reg(SysReg::CPACR_EL1, boot.cpacr_el1)
            .map_err(hvf_error)?;
        // Allow EL0 to read the virtual (EL0VCTEN, bit 1) and physical
        // (EL0PCTEN, bit 0) counters directly without trapping to EL1. This is
        // the foundation for the vDSO fast clock path: `__kernel_clock_gettime`
        // reads CNTVCT_EL0 in userspace, so it must NOT vmexit. The
        // emulate_el0_sys64_read path stays as a fallback for any guest whose
        // read still traps. Harmless for guests that don't read the counter.
        const CNTKCTL_EL1_EL0_COUNTER_ACCESS: u64 = (1 << 1) | (1 << 0);
        vcpu.set_sys_reg(SysReg::CNTKCTL_EL1, CNTKCTL_EL1_EL0_COUNTER_ACCESS)
            .map_err(hvf_error)?;
        // Route lower-EL synchronous exceptions (EL0 `svc #0`) through our
        // vector page. Without this, VBAR_EL1 defaults to 0 (or whatever
        // HVF leaves it at) and the SVC fetch faults on an unmapped page.
        if let Some(vectors_base) = plan.el1_vectors_base {
            vcpu.set_sys_reg(SysReg::VBAR_EL1, vectors_base)
                .map_err(hvf_error)?;
        }
        if let Some(stack_pointer) = plan.initial_stack_pointer {
            // SP_EL0 is the Linux userspace stack. SP_EL1 is reserved for the
            // per-vCPU syscall mailbox and is bound after mappings are live.
            vcpu.set_sys_reg(SysReg::SP_EL0, stack_pointer)
                .map_err(hvf_error)?;
        }
        // Fill the vDSO vvar page so __kernel_clock_gettime can derive time from
        // CNTVCT_EL0 in userspace. Best-effort: if the page isn't mapped (a load
        // path without with_vdso) just skip — the guest falls back to syscalls.
        state.populate_vdso_data_page();
        let mailbox = state.allocate_mailbox_for_vcpu(&vcpu)?;
        Ok((state, vcpu, mailbox))
    }
}

/// Volatile copy out of guest-shared memory. Guest RAM is MAP_SHARED and the
/// guest vCPU can mutate it concurrently on another host thread; a plain
/// (non-volatile) read racing that write is UB in Rust's memory model (the
/// optimizer may assume the bytes are stable and tear/hoist/elide the read).
/// `read_volatile` forbids that. This does NOT make the data race semantically
/// correct — the guest owns its own synchronization — it only removes the
/// language-level UB on the host side.
///
/// Word-accelerated: the guest (`src`) side is read with aligned word-sized
/// `read_volatile` (with byte-volatile head/tail around the unaligned edges),
/// which preserves the UB guarantee while doing ~`size_of::<usize>()`× fewer
/// guest accesses than a byte loop — this copy is on every guest→host transfer
/// (sockets, pipes, file reads) and the byte loop was a measured hot spot
/// (~33µs of a 59µs loopback `sendto`). The private host `dst` is not shared,
/// so it uses plain unaligned writes.
///
/// SAFETY: `src` must be valid for reads of `len` bytes and `dst` valid for
/// writes of `len` bytes; the two regions must not overlap.
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
#[inline]
unsafe fn volatile_copy_from_guest(src: *const u8, dst: *mut u8, len: usize) {
    const W: usize = core::mem::size_of::<usize>();
    let mut i = 0usize;
    unsafe {
        // Head: byte-volatile until the guest pointer is word-aligned.
        while i < len && !(src.add(i) as usize).is_multiple_of(W) {
            dst.add(i).write(src.add(i).read_volatile());
            i += 1;
        }
        // Bulk: aligned word-volatile reads from guest, unaligned plain writes
        // to the private host buffer.
        while i + W <= len {
            let word = (src.add(i) as *const usize).read_volatile();
            (dst.add(i) as *mut usize).write_unaligned(word);
            i += W;
        }
        // Tail.
        while i < len {
            dst.add(i).write(src.add(i).read_volatile());
            i += 1;
        }
    }
}

/// Volatile copy INTO guest-shared memory. See [`volatile_copy_from_guest`] for
/// why volatile is required and the word-acceleration rationale. Here the guest
/// (`dst`) side takes aligned word-sized `write_volatile`; the private host
/// `src` uses plain unaligned reads.
///
/// SAFETY: `src` must be valid for reads of `len` bytes and `dst` valid for
/// writes of `len` bytes; the two regions must not overlap.
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
#[inline]
unsafe fn volatile_copy_to_guest(src: *const u8, dst: *mut u8, len: usize) {
    const W: usize = core::mem::size_of::<usize>();
    let mut i = 0usize;
    unsafe {
        // Head: byte-volatile until the guest pointer is word-aligned.
        while i < len && !(dst.add(i) as usize).is_multiple_of(W) {
            dst.add(i).write_volatile(src.add(i).read());
            i += 1;
        }
        // Bulk: unaligned plain reads from the private host buffer, aligned
        // word-volatile writes to guest.
        while i + W <= len {
            let word = (src.add(i) as *const usize).read_unaligned();
            (dst.add(i) as *mut usize).write_volatile(word);
            i += W;
        }
        // Tail.
        while i < len {
            dst.add(i).write_volatile(src.add(i).read());
            i += 1;
        }
    }
}

#[cfg(test)]
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
mod volatile_copy_tests {
    use super::{volatile_copy_from_guest, volatile_copy_to_guest};

    // Exercise every src/dst alignment combo and a spread of lengths (crossing
    // the word boundary and the head/bulk/tail seams), comparing against the
    // obvious byte copy and asserting no overrun past `len`.
    const LENS: &[usize] = &[0, 1, 7, 8, 9, 15, 16, 17, 31, 63, 64, 65, 255, 256];

    #[test]
    fn from_guest_matches_reference() {
        let src: Vec<u8> = (0..512u32)
            .map(|i| (i.wrapping_mul(31).wrapping_add(7)) as u8)
            .collect();
        for &len in LENS {
            for s in 0..8usize {
                for d in 0..8usize {
                    if s + len > src.len() {
                        continue;
                    }
                    let mut dst = vec![0xCDu8; d + len + 1];
                    unsafe {
                        volatile_copy_from_guest(src.as_ptr().add(s), dst.as_mut_ptr().add(d), len);
                    }
                    assert_eq!(&dst[d..d + len], &src[s..s + len], "len={len} s={s} d={d}");
                    assert_eq!(dst[d + len], 0xCD, "overrun len={len} d={d}");
                }
            }
        }
    }

    #[test]
    fn to_guest_matches_reference() {
        let src: Vec<u8> = (0..512u32)
            .map(|i| (i.wrapping_mul(17).wrapping_add(3)) as u8)
            .collect();
        for &len in LENS {
            for s in 0..8usize {
                for d in 0..8usize {
                    if s + len > src.len() {
                        continue;
                    }
                    let mut dst = vec![0xABu8; d + len + 1];
                    unsafe {
                        volatile_copy_to_guest(src.as_ptr().add(s), dst.as_mut_ptr().add(d), len);
                    }
                    assert_eq!(&dst[d..d + len], &src[s..s + len], "len={len} s={s} d={d}");
                    assert_eq!(dst[d + len], 0xAB, "overrun len={len} d={d}");
                }
            }
        }
    }
}

/// Strip a 16-bit pointer tag (bits 63:48) from a guest virtual address.
/// Apple Rosetta tags pointers in the top 16 bits (a 48-bit `TaggedPointer`
/// value space, broader than the 8-bit hardware TBI), so syscall-path region
/// lookups must mask the tag to resolve a tagged pointer to its 48-bit backing
/// mapping. Pairs with TCR_EL1.TBI0/TBI1 (hardware ignores the top byte for the
/// guest's own accesses) and the mmap-hint strip in dispatch/mem.rs. A no-op
/// for native (top-byte-zero) guests.
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
#[inline]
fn strip_pointer_tag(address: u64) -> u64 {
    address & 0x0000_FFFF_FFFF_FFFF
}

/// Resolve a syscall/core copy through the descriptor key preferred by the
/// translated private-overlay path, then through the Linux semantic VA used by
/// boot mappings whose stage-1 leaf now names a global frame.
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
fn resolve_guest_copy_mapping<T>(
    translated: u64,
    semantic: u64,
    mut resolve: impl FnMut(u64) -> Option<T>,
) -> Option<(u64, T)> {
    resolve(translated)
        .map(|mapping| (translated, mapping))
        .or_else(|| {
            (translated != semantic)
                .then(|| resolve(semantic).map(|mapping| (semantic, mapping)))?
        })
}

#[cfg(test)]
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
mod guest_copy_mapping_tests {
    use super::resolve_guest_copy_mapping;

    #[test]
    fn translated_descriptor_wins_and_semantic_va_is_the_exact_fallback() {
        let mut translated_calls = Vec::new();
        let translated = resolve_guest_copy_mapping(0x9000, 0x4000, |key| {
            translated_calls.push(key);
            (key == 0x9000).then_some("overlay")
        });
        assert_eq!(translated, Some((0x9000, "overlay")));
        assert_eq!(translated_calls, vec![0x9000]);

        let mut semantic_calls = Vec::new();
        let semantic = resolve_guest_copy_mapping(0x9000, 0x4000, |key| {
            semantic_calls.push(key);
            (key == 0x4000).then_some("boot-heap")
        });
        assert_eq!(semantic, Some((0x4000, "boot-heap")));
        assert_eq!(semantic_calls, vec![0x9000, 0x4000]);
    }
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
impl HvfVmState {
    /// The process-wide PROT_NONE bookkeeping (the engine's EFAULT gate).
    pub(crate) fn protections_ref(&self) -> &MemoryProtections {
        &self.protections
    }

    /// A `Send`/`Sync` kick handle for THIS thread's live vCPU. The engine's
    /// `ThreadedEngine::kick_handle` routes through the Vmm, which does not hold
    /// the vCPU, so HVF stashes the handle on every vCPU create (see the
    /// `vcpu_handle` field) and hands it out here.
    pub(crate) fn vcpu_kick_handle(&self) -> crate::vcpu_kick::VcpuKickHandle {
        crate::vcpu_kick::VcpuKickHandle::new(self.vcpu_handle.clone())
    }

    /// Set the vfork (`CLONE_VM`) flag for the NEXT fork.
    pub(crate) fn set_vfork_share(&mut self, share_vm: bool) {
        self.vfork_share = share_vm;
    }

    /// Emit pre-host-fork resident footprint by guest mapping class. The expensive
    /// `mincore` walk runs only when DTrace enables `fork-footprint-class`; normal
    /// fork performance gates do not pay the scan.
    pub(crate) fn emit_fork_footprint_attribution(&self, arena_high_water: u64) {
        carrick_observability::probes::with_fork_footprint_class_probe(|| {
            let mut classes = [ForkFootprintClassSample::default(); 10];
            for m in &self.mappings {
                let class_id = fork_footprint_class_id(
                    m.start,
                    m.sharing.shares_across_fork(),
                    m.guest_writable,
                );
                let Ok(index) = usize::try_from(class_id) else {
                    continue;
                };
                let Some(sample) = classes.get_mut(index) else {
                    continue;
                };
                let scan_len = fork_footprint_scan_len(m, class_id, arena_high_water);
                sample.region_count = sample.region_count.saturating_add(1);
                sample.scan_bytes = sample.scan_bytes.saturating_add(scan_len as u64);
                sample.resident_bytes = sample
                    .resident_bytes
                    .saturating_add(resident_bytes_for_host_range(m.host_addr, scan_len));
                sample.flags |= fork_footprint_flags(m);
            }

            for (class_id, sample) in classes.iter().enumerate() {
                if sample.region_count == 0 {
                    continue;
                }
                carrick_observability::probes::fork_footprint_class(
                    class_id as i32,
                    sample.region_count,
                    sample.scan_bytes,
                    sample.resident_bytes,
                    sample.flags,
                );
            }
        });
    }

    /// Live private semantic mappings that a process fork must arm read-only in
    /// both stage-1 graphs. This includes a currently-read-only or PROT_NONE
    /// mapping: a later mprotect-to-write must still take frame COW rather than
    /// silently sharing the parent's frame. The alias registry supplies mappings
    /// installed by sibling vCPUs and filters retired lifetime-owner rows.
    pub(crate) fn fork_cow_ranges(&self) -> Vec<carrick_aarch64::vmm::ForkCowRange> {
        let aliases = alias_registry().lock().clone();
        let alias_index = process_alias_index(&aliases, self.mm_root_slot);
        let mut ranges: Vec<_> = self
            .mappings
            .iter()
            .filter(|mapping| {
                mapping.sharing == GuestMappingSharing::Private
                    && mapping.start != crate::memory::LINUX_PAGE_TABLES_BASE
                    && !is_kernel_only_stage1_range(
                        mapping.start,
                        semantic_extent_size(mapping.start, mapping.end),
                    )
                    && mapping_is_current_for_process_fork_indexed(mapping, &alias_index)
            })
            .map(|mapping| carrick_aarch64::vmm::ForkCowRange {
                va: mapping.start,
                len: semantic_extent_size(mapping.start, mapping.end),
                executable: u64::from(mapping.perms) & 4 != 0,
                kernel_only: is_kernel_only_stage1_range(
                    mapping.start,
                    semantic_extent_size(mapping.start, mapping.end),
                ),
            })
            .collect();
        let local_ipas = current_dynamic_alias_ipas(&self.mappings, &aliases, self.mm_root_slot);
        ranges.extend(
            missing_process_aliases(&local_ipas, &aliases, self.mm_root_slot)
                .into_iter()
                .filter(|mapping| {
                    mapping.sharing == GuestMappingSharing::Private
                        && !is_kernel_only_stage1_range(mapping.start, mapping.size)
                })
                .map(|mapping| carrick_aarch64::vmm::ForkCowRange {
                    va: mapping.start,
                    len: mapping.size,
                    executable: mapping.perms & 4 != 0,
                    kernel_only: is_kernel_only_stage1_range(mapping.start, mapping.size),
                }),
        );
        ranges.sort_by_key(|range| (range.va, range.len));
        ranges.dedup_by_key(|range| (range.va, range.len));
        ranges
    }

    pub(crate) fn arm_frame_cow_ranges(&mut self, ranges: &[carrick_aarch64::vmm::ForkCowRange]) {
        self.cow_armed.lock().arm(ranges);
    }

    pub(crate) fn frame_cow_arm_snapshot(&self) -> Vec<carrick_aarch64::vmm::ForkCowRange> {
        self.cow_armed.lock().snapshot()
    }

    pub(crate) fn restore_frame_cow_arm_snapshot(
        &mut self,
        snapshot: Vec<carrick_aarch64::vmm::ForkCowRange>,
    ) {
        self.cow_armed.lock().restore(snapshot);
    }

    pub(crate) fn armed_frame_cow_ranges(
        &self,
        va: u64,
        len: usize,
    ) -> Vec<carrick_aarch64::vmm::ForkCowRange> {
        self.cow_armed.lock().overlapping(va, len)
    }

    pub(crate) fn publish_private_repoint(
        &mut self,
        va: u64,
        overlay_ipa: u64,
        len: usize,
    ) -> Result<(), TrapError> {
        let overlay_end = overlay_ipa.checked_add(len as u64).ok_or_else(|| {
            TrapError::Hypervisor("private repoint semantic IPA overflow".to_owned())
        })?;
        let (mapping_ipa, physical_ipa, mapping_host, physical_size, perms) = self
            .mappings
            .iter()
            .rev()
            .find(|mapping| {
                overlay_ipa >= mapping.ipa
                    && mapping
                        .ipa
                        .checked_add(mapping.size as u64)
                        .is_some_and(|end| overlay_end <= end)
            })
            .map(|mapping| {
                (
                    mapping.ipa,
                    mapping.physical_ipa,
                    mapping.host_addr as usize,
                    mapping.physical_size,
                    mapping.perms,
                )
            })
            .ok_or_else(|| {
                TrapError::Hypervisor(format!(
                    "private repoint IPA 0x{overlay_ipa:x} size {len} has no physical owner"
                ))
            })?;
        let semantic_offset = overlay_ipa.checked_sub(physical_ipa).ok_or_else(|| {
            TrapError::Hypervisor("private repoint precedes its physical extent".to_owned())
        })?;
        let physical_host_addr = mapping_host
            .checked_sub(mapping_ipa.checked_sub(physical_ipa).ok_or_else(|| {
                TrapError::Hypervisor(
                    "private repoint mapping precedes its physical extent".to_owned(),
                )
            })? as usize)
            .ok_or_else(|| {
                TrapError::Hypervisor("private repoint physical host underflow".to_owned())
            })?;
        let host_addr = physical_host_addr
            .checked_add(semantic_offset as usize)
            .ok_or_else(|| {
                TrapError::Hypervisor("private repoint semantic host overflow".to_owned())
            })?;
        let inventory_backing = self
            .frame_inventory
            .lock()
            .extents
            .get(&(physical_ipa, physical_size as u64))
            .map(|extent| extent.backing)
            .or_else(|| (!self.persistent_vm_lifecycle).then(Self::private_backing_identity))
            .ok_or_else(|| {
                TrapError::Hypervisor(format!(
                    "private repoint physical IPA 0x{:x} size {} lacks frame inventory",
                    physical_ipa, physical_size
                ))
            })?;
        let sharing = GuestMappingSharing::Private;
        register_shared_alias(AliasBacking {
            start: va,
            ipa: overlay_ipa,
            host_addr,
            size: len,
            physical_ipa,
            physical_host_addr,
            physical_size,
            perms: u64::from(perms),
            guest_writable: true,
            sharing,
            ownership_scope: alias_ownership_scope(sharing, self.mm_root_slot),
            inventory_backing,
            shared_key_base: 0,
            shared_key_offset: 0,
            owner_generation: global_frame_host_owner_generation(
                physical_ipa,
                physical_size as u64,
            ),
        });
        Ok(())
    }

    pub(crate) fn bind_frame_cow(
        &mut self,
        authority: std::sync::Arc<dyn carrick_hal::FrameCowAuthority>,
        identity: carrick_hal::FrameCowIdentity,
    ) {
        for receipt in std::mem::take(&mut self.pending_fork_frame_receipts) {
            let length = carrick_hal::FrameLength::from_mapping_extent(
                std::num::NonZeroU64::new(receipt.length).unwrap_or_else(|| {
                    eprintln!("carrick: FATAL: pending fork-frame receipt has zero length");
                    std::process::abort();
                }),
            );
            match authority.mapping_is_live(
                receipt.child_mapping,
                receipt.frame,
                carrick_guest_mem::Gpa(receipt.ipa),
                length,
            ) {
                Ok(true) => {}
                Ok(false) => {
                    eprintln!(
                        "carrick: FATAL: fork-frame receipt child mapping {:?} is not live",
                        receipt.child_mapping
                    );
                    std::process::abort();
                }
                Err(error) => {
                    eprintln!(
                        "carrick: FATAL: authenticate fork-frame receipt mapping {:?}: {error}",
                        receipt.child_mapping
                    );
                    std::process::abort();
                }
            }
            let event = carrick_observability::probes::HvpatchForkFrameShare::new(
                identity.linux_pid,
                identity.linux_tid,
                identity.mm,
                u32::from(identity.asid),
                receipt.kind,
                receipt.parent_mapping.raw(),
                receipt.child_mapping.raw(),
                receipt.frame.raw(),
                receipt.ipa,
                receipt.length,
            )
            .unwrap_or_else(|error| {
                eprintln!("carrick: FATAL: construct authenticated fork-frame receipt: {error}");
                std::process::abort();
            });
            crate::probes::hvpatch_fork_frame_share(event);
        }
        self.cow_authority = Some(authority);
        self.cow_identity = Some(identity);
    }

    /// Whether the frame backing `ipa` is referenced by MORE than one extent in
    /// the shared backend registry — i.e., some other mm (a fork parent or
    /// child) still lives on it. The registry `Arc` is shared across every
    /// engine in the carrier and its counts drive retirement, so it is the
    /// authority for "shared", where the per-engine armed-set is only a
    /// derived (and known-omissive) approximation.
    /// Whether this mm may write DIRECTLY through the frame its retained
    /// stage-1 output names. Two ways to lose that right:
    ///
    /// - This mm's inventory holds NO extent covering the IPA at all: the leaf
    ///   is stale — it survived a retirement/replacement of the mapping it
    ///   belonged to — and whatever lives behind that IPA now belongs to
    ///   someone else. The forkserver worker's scrub had exactly this shape
    ///   (606 own extents, none covering the retained IPA) and its Direct
    ///   write zeroed the SERVER's live interned-dict granule.
    /// - An extent exists but the backend registry counts more than one
    ///   reference on its frame: a fork peer still lives on it, and a direct
    ///   write would be visible through the other mm.
    ///
    /// In both cases the maintenance write must MATERIALIZE a private zeroed
    /// replacement instead. The registry `Arc` is shared carrier-wide and its
    /// counts drive retirement, so it is the authority; the per-engine
    /// armed-set is a derived, known-omissive approximation
    /// (`mtforkcorrupt`).
    fn retained_output_lacks_exclusive_claim(&self, ipa: u64) -> bool {
        // Only REUSABLE global-frame IPAs carry claims at all. Boot and
        // identity regions (the heap, the low arena's fixed backing, page
        // tables) are per-mm by construction and never enter the extent map;
        // treating their absence as a lost claim routed every brk-heap scrub
        // into materialization and broke `ltp-brk02`/`ltp-tgkill01` outright.
        if !is_reusable_global_frame_extent(ipa, 1) {
            return false;
        }
        let inventory = self.frame_inventory.lock();
        let extent = inventory
            .extents
            .iter()
            .find(|(key, _)| key.0 <= ipa && ipa < key.0.saturating_add(key.1))
            .map(|(_, extent)| *extent);
        let Some(extent) = extent else {
            return true;
        };
        // DELIBERATE sharing is not a lost claim. A `SharedAnon`/`SharedFile`
        // backing is MAP_SHARED semantics: every mapper must keep seeing the
        // same bytes, and materializing a private replacement under it breaks
        // exactly what the guest asked for (measured: multiprocessing's
        // Barrier hung when a shared semaphore page was privatized here).
        // Only a PRIVATE backing observed by more than one mm is fork-COW
        // sharing that a maintenance write must not write through.
        if !matches!(extent.backing, InventoryBackingIdentity::Private(_)) {
            return false;
        }
        inventory
            .frames
            .lock()
            .references
            .get(&extent.frame)
            .copied()
            .unwrap_or(0)
            > 1
    }

    fn physical_cow_source(&self, semantic_va: u64, ipa: u64) -> Option<(*mut u8, u64)> {
        let physical_ipa = align_down(ipa, CowArmedRanges::COMPOUND_SIZE);
        let physical_end = physical_ipa.checked_add(CowArmedRanges::COMPOUND_SIZE)?;
        if let Some(alias) = alias_registry().lock().iter().rev().find(|alias| {
            alias_matches_process_scope(alias.ownership_scope, self.mm_root_slot)
                && semantic_va >= alias.start
                && semantic_va < alias.start.saturating_add(alias.size as u64)
                && alias
                    .ipa
                    .checked_add(semantic_va.saturating_sub(alias.start))
                    == Some(ipa)
                && physical_ipa >= alias.physical_ipa
                && physical_end
                    <= alias
                        .physical_ipa
                        .saturating_add(alias.physical_size as u64)
                && if self.persistent_vm_lifecycle
                    && is_reusable_global_frame_extent(
                        alias.physical_ipa,
                        alias.physical_size as u64,
                    )
                {
                    global_frame_host_owner_matches(
                        alias.physical_ipa,
                        alias.physical_size as u64,
                        alias.physical_host_addr,
                        alias.owner_generation,
                    )
                } else {
                    alias_backing_is_live(alias.physical_host_addr)
                }
        }) {
            let offset = usize::try_from(physical_ipa - alias.physical_ipa).ok()?;
            return Some((
                unsafe { (alias.physical_host_addr as *mut u8).add(offset) },
                physical_ipa,
            ));
        }
        let mapping = self.mappings.iter().rev().find(|mapping| {
            let mapping_end = mapping.ipa.checked_add(mapping.size as u64);
            mapping.contains_range(semantic_va, 1)
                && mapping
                    .ipa
                    .checked_add(semantic_va.saturating_sub(mapping.start))
                    == Some(ipa)
                && physical_ipa >= mapping.ipa
                && mapping_end.is_some_and(|limit| physical_end <= limit)
                && (!self.persistent_vm_lifecycle
                    || !is_reusable_global_frame_extent(
                        mapping.physical_ipa,
                        mapping.physical_size as u64,
                    )
                    || global_frame_region_owner_matches(mapping))
        })?;
        let offset = usize::try_from(physical_ipa - mapping.ipa).ok()?;
        Some((unsafe { mapping.host_addr.add(offset) }, physical_ipa))
    }

    /// Materialize private zero backing for the exact accessible pieces of the
    /// sparse HVPatch mmap arena. One VMA hole becomes one host mapping, one
    /// stage-2 lease, and one inventory frame; there is no shared source frame
    /// and therefore no shared-zero COW authority.
    pub(crate) fn ensure_sparse_mmap_backing(
        &mut self,
        va: u64,
        len: usize,
        flush_stage1: &mut dyn FnMut() -> Result<(), TrapError>,
    ) -> Result<(), TrapError> {
        const PAGE_SIZE: u64 = 4 * 1024;
        if !self.persistent_vm_lifecycle || len == 0 {
            return Ok(());
        }
        let arena_start = crate::memory::LINUX_MMAP_BASE;
        let arena_end = arena_start
            .checked_add(crate::memory::mmap_arena_size())
            .ok_or_else(|| TrapError::Hypervisor("HVPatch mmap arena overflow".to_owned()))?;
        let requested_end = va
            .checked_add(len as u64)
            .ok_or_else(|| TrapError::Hypervisor("sparse mmap range overflow".to_owned()))?;
        if va < arena_start || requested_end > arena_end {
            return Ok(());
        }
        let mut current = align_down(va, PAGE_SIZE);
        let end = align_up(requested_end, PAGE_SIZE)?;
        while current < end {
            if let Some(mapping) = self.mapping_for_range(current, 1) {
                let next = mapping.end.min(end);
                if next <= current {
                    return Err(TrapError::Hypervisor(format!(
                        "sparse mmap live mapping made no progress at VA 0x{current:x}"
                    )));
                }
                current = next;
                continue;
            }

            // Preserve already-materialized neighbours. The topology lock in
            // the materializer rechecks this shape before publication.
            let next_local = self
                .mappings
                .iter()
                .filter(|mapping| mapping.start > current && mapping.start < end)
                .map(|mapping| mapping.start)
                .min();
            let next_alias = alias_registry()
                .lock()
                .iter()
                .filter(|alias| {
                    alias_matches_process_scope(alias.ownership_scope, self.mm_root_slot)
                        && alias.start > current
                        && alias.start < end
                        && alias_backing_is_live(alias.physical_host_addr)
                })
                .map(|alias| alias.start)
                .min();
            let hole_end = next_local
                .into_iter()
                .chain(next_alias)
                .min()
                .unwrap_or(end);
            current = self.materialize_sparse_mmap_extent(current, hole_end, flush_stage1)?;
        }
        Ok(())
    }

    fn materialize_sparse_mmap_extent(
        &mut self,
        start: u64,
        end: u64,
        flush_stage1: &mut dyn FnMut() -> Result<(), TrapError>,
    ) -> Result<u64, TrapError> {
        const PAGE_SIZE: u64 = 4 * 1024;
        const VALID: u64 = 1;
        const AP_MASK: u64 = 0b11 << 6;
        const AP_USER_RO: u64 = 0b11 << 6;
        const NON_GLOBAL: u64 = 1 << 11;

        if start >= end || !start.is_multiple_of(PAGE_SIZE) || !end.is_multiple_of(PAGE_SIZE) {
            return Err(TrapError::Hypervisor(format!(
                "invalid sparse mmap materialization 0x{start:x}..0x{end:x}"
            )));
        }
        let identity = self.cow_identity.ok_or_else(|| {
            TrapError::Hypervisor("HVPatch sparse mmap has no bound mm identity".to_owned())
        })?;
        let authority = self.cow_authority.clone().ok_or_else(|| {
            TrapError::Hypervisor("HVPatch sparse mmap has no inventory authority".to_owned())
        })?;
        let _quiesce = authority.quiesce().map_err(|error| {
            TrapError::Hypervisor(format!("quiesce HVPatch sparse mmap: {error}"))
        })?;
        let _topology = crate::fork_quiesce::acquire_topology_lock(
            carrick_observability::probes::HvpatchTopologyOperation::AliasMap,
            identity.linux_pid,
            identity.linux_tid,
        );
        if let Some(mapping) = self.mapping_for_range(start, 1) {
            return Ok(mapping.end.min(end));
        }

        // Another vCPU in this mm can publish the physical alias while its
        // stage-1 receipt is deliberately still invalid.  Such an alias is
        // invisible to `mapping_for_range` on this sibling until the later
        // protection commit, so authenticate the process-shared physical owner
        // directly before allocating a second overlapping frame.
        let live_alias_end = alias_registry()
            .lock()
            .iter()
            .rev()
            .find(|alias| {
                alias_matches_process_scope(alias.ownership_scope, self.mm_root_slot)
                    && start >= alias.start
                    && start < alias.start.saturating_add(alias.size as u64)
                    && global_frame_host_owner_matches(
                        alias.physical_ipa,
                        alias.physical_size as u64,
                        alias.physical_host_addr,
                        alias.owner_generation,
                    )
            })
            .map(|alias| alias.start.saturating_add(alias.size as u64));
        if let Some(alias_end) = live_alias_end {
            return Ok(alias_end.min(end));
        }

        // The caller found this hole before quiescing. Recompute its upper
        // boundary under the topology lock so a sibling publication between
        // those two points cannot be overlapped.
        let next_local = self
            .mappings
            .iter()
            .filter(|mapping| {
                mapping.start > start
                    && mapping.start < end
                    && global_frame_region_owner_matches(mapping)
            })
            .map(|mapping| mapping.start)
            .min();
        let next_alias = alias_registry()
            .lock()
            .iter()
            .filter(|alias| {
                alias_matches_process_scope(alias.ownership_scope, self.mm_root_slot)
                    && alias.start > start
                    && alias.start < end
                    && global_frame_host_owner_matches(
                        alias.physical_ipa,
                        alias.physical_size as u64,
                        alias.physical_host_addr,
                        alias.owner_generation,
                    )
            })
            .map(|alias| alias.start)
            .min();
        let end = next_local
            .into_iter()
            .chain(next_alias)
            .min()
            .unwrap_or(end);

        let semantic_len =
            usize::try_from(end - start).map_err(|_| TrapError::MappingTooLarge(end - start))?;
        let page_table_host = self
            .mapping_for_range(
                crate::memory::LINUX_PAGE_TABLES_BASE,
                carrick_mem::memory::LINUX_PAGE_TABLES_SIZE as usize,
            )
            .map(|mapping| mapping.host_addr)
            .ok_or_else(|| {
                TrapError::Hypervisor("sparse HVPatch mmap has no page-table backing".to_owned())
            })?;
        if self.page_tables.lock().is_none() {
            return Err(TrapError::Hypervisor(
                "sparse HVPatch mmap page tables are absent".to_owned(),
            ));
        }
        let mut reservation = authority.reserve(1, 1, 2).map_err(|error| {
            TrapError::Hypervisor(format!("reserve sparse HVPatch mmap inventory: {error}"))
        })?;

        // A 2 MiB-aligned global-frame base plus the semantic VA's 2 MiB
        // offset preserves VA/IPA alignment. The stage-1 editor can therefore
        // use block leaves for the aligned bulk and needs 4 KiB leaves only at
        // the two edges. This is still one physical/stage-2 lease per VMA.
        const TWO_MIB: u64 = 2 * 1024 * 1024;
        let physical_offset = start & (TWO_MIB - 1);
        let physical_len = align_up(
            physical_offset
                .checked_add(end - start)
                .ok_or_else(|| TrapError::Hypervisor("sparse mmap size overflow".to_owned()))?,
            HVF_PAGE_SIZE,
        )?;
        let physical_size =
            usize::try_from(physical_len).map_err(|_| TrapError::MappingTooLarge(physical_len))?;
        let host_mapping = crate::host_mapping::OwnedHostMapping::map_shared_anon(
            physical_size,
            crate::host_mapping::HostMappingKind::PrivateAnon,
        )
        .map_err(|error| {
            TrapError::Hypervisor(format!("allocate sparse HVPatch mmap backing: {error}"))
        })?;
        let physical_host = host_mapping.as_ptr();
        let semantic_host = unsafe { physical_host.add(physical_offset as usize) };
        let mut lease = GlobalFrameStage2Lease::reserve(physical_len, TWO_MIB)?;
        let physical_ipa = lease.base;
        let semantic_ipa = physical_ipa
            .checked_add(physical_offset)
            .ok_or_else(|| TrapError::Hypervisor("sparse mmap IPA overflow".to_owned()))?;
        let stage2_perms = applevisor::memory::MemPerms::ReadWriteExec;
        let map_result = unsafe {
            inventory_hv_vm_map(
                physical_host.cast(),
                physical_ipa,
                physical_size,
                u64::from(stage2_perms),
            )
        };
        if map_result != 0 {
            return Err(TrapError::Hypervisor(format!(
                "map sparse HVPatch mmap IPA 0x{physical_ipa:x}: 0x{map_result:x}"
            )));
        }
        lease.mark_mapped();
        register_global_frame_host_owner(lease, host_mapping, u64::from(stage2_perms))?;
        let mut owner_rollback = GlobalFrameOwnerRollback::default();
        owner_rollback.record((physical_ipa, physical_len));

        let inventory_mapping = {
            let mut inventory = self.frame_inventory.lock();
            Self::stage_mapping(
                &mut inventory,
                &mut reservation,
                InventoryMappingStage {
                    gpa: physical_ipa,
                    length: physical_len,
                    permissions: carrick_hal::MemPerms {
                        read: true,
                        write: true,
                        exec: true,
                    },
                    backing: Self::private_backing_identity(),
                    inherited_frame: None,
                    stage2_lease: Some((physical_ipa, physical_len)),
                },
            )?
        };
        let inventory_entry = ((physical_ipa, physical_len), inventory_mapping);
        // Fill the recycled pre-image buffer rather than allocating a fresh
        // 1.75 MiB one per transaction (see `cow_rollback_scratch`).
        let mut rollback_scratch = self.cow_rollback_scratch.take();
        let mut rollback_page_tables = None;
        let publication = (|| {
            let mut page_tables = self.page_tables.lock();
            let manager = page_tables.as_mut().ok_or_else(|| {
                TrapError::Hypervisor("sparse HVPatch mmap page tables are absent".to_owned())
            })?;
            rollback_page_tables = Some(Self::rollback_pre_image(&mut rollback_scratch, manager));
            Self::refresh_stage1_exclusivity(manager);
            let aligned_start = align_up(start, TWO_MIB)?.min(end);
            if start < aligned_start {
                manager
                    .map_private_aliased(start, semantic_ipa, aligned_start - start, false)
                    .map_err(|error| {
                        TrapError::Hypervisor(format!(
                            "plan sparse HVPatch mmap leading stage-1 output: {error:?}"
                        ))
                    })?;
            }
            let aligned_len = (end - aligned_start) / TWO_MIB * TWO_MIB;
            if aligned_len != 0 {
                manager
                    .map_private_aliased(
                        aligned_start,
                        semantic_ipa + (aligned_start - start),
                        aligned_len,
                        false,
                    )
                    .map_err(|error| {
                        TrapError::Hypervisor(format!(
                            "plan sparse HVPatch mmap bulk stage-1 output: {error:?}"
                        ))
                    })?;
            }
            let tail_start = aligned_start + aligned_len;
            if tail_start < end {
                manager
                    .map_private_aliased(
                        tail_start,
                        semantic_ipa + (tail_start - start),
                        end - tail_start,
                        false,
                    )
                    .map_err(|error| {
                        TrapError::Hypervisor(format!(
                            "plan sparse HVPatch mmap trailing stage-1 output: {error:?}"
                        ))
                    })?;
            }
            manager
                .set_prot_none(start, semantic_len)
                .map_err(|error| {
                    TrapError::Hypervisor(format!(
                        "keep sparse HVPatch mmap stage-1 invalid: {error:?}"
                    ))
                })?;
            unsafe { manager.sync_to_host(page_table_host) };
            let mut page = start;
            while page < end {
                let expected_ipa = semantic_ipa + (page - start);
                let shadow = manager.debug_walk(page);
                let live = unsafe { manager.debug_walk_host(page_table_host.cast_const(), page) };
                let leaf = carrick_mem::page_table::terminal_descriptor(live);
                if shadow != live
                    || manager.translate(page).is_some()
                    || manager.translate_retained_output(page) != Some(expected_ipa)
                    || leaf & VALID != 0
                    || leaf & AP_MASK != AP_USER_RO
                    || leaf & NON_GLOBAL == 0
                {
                    return Err(TrapError::Hypervisor(format!(
                        "sparse HVPatch mmap publication failed at VA 0x{page:x}: leaf=0x{leaf:x} expected_ipa=0x{expected_ipa:x}"
                    )));
                }
                page = page.saturating_add(PAGE_SIZE);
            }
            Ok::<(), TrapError>(())
        })();
        if let Err(error) = publication {
            if let Some(snapshot) = rollback_page_tables {
                {
                    let mut page_tables = self.page_tables.lock();
                    unsafe { snapshot.restore_quiesced_snapshot_to_host(page_table_host) };
                    *page_tables = Some(snapshot);
                }
                if let Err(flush_error) = flush_stage1() {
                    eprintln!(
                        "carrick: FATAL: sparse HVPatch mmap rollback TLBI failed: {flush_error}"
                    );
                    std::process::abort();
                }
            }
            Self::rollback_unpublished_mappings(
                &mut self.frame_inventory.lock(),
                &[inventory_entry],
            )?;
            return Err(error);
        }
        // Publication succeeded: nothing needs the pre-image any more, so hand
        // its buffer back to the recycler for the next transaction.
        self.cow_rollback_scratch = rollback_page_tables.take().or(rollback_scratch);
        if let Err(error) = flush_stage1() {
            eprintln!("carrick: FATAL: sparse HVPatch mmap TLBI failed: {error}");
            std::process::abort();
        }
        if let Err(error) = authority.apply(reservation.commit(())) {
            eprintln!("carrick: FATAL: sparse HVPatch mmap inventory commit failed: {error}");
            std::process::abort();
        }
        owner_rollback.commit();

        match authority.mapping_is_live(
            inventory_mapping.mapping,
            inventory_mapping.frame,
            carrick_guest_mem::Gpa(physical_ipa),
            carrick_hal::FrameLength::from_mapping_extent(
                std::num::NonZeroU64::new(physical_len).unwrap_or_else(|| std::process::abort()),
            ),
        ) {
            Ok(true) => {}
            Ok(false) => {
                eprintln!("carrick: FATAL: sparse HVPatch mmap absent after commit");
                std::process::abort();
            }
            Err(error) => {
                eprintln!("carrick: FATAL: authenticate sparse HVPatch mmap: {error}");
                std::process::abort();
            }
        }

        let sharing = GuestMappingSharing::Private;
        register_shared_alias(AliasBacking {
            start,
            ipa: semantic_ipa,
            host_addr: semantic_host as usize,
            size: semantic_len,
            physical_ipa,
            physical_host_addr: physical_host as usize,
            physical_size,
            perms: u64::from(stage2_perms),
            guest_writable: true,
            sharing,
            ownership_scope: alias_ownership_scope(sharing, self.mm_root_slot),
            inventory_backing: Self::private_backing_identity(),
            shared_key_base: 0,
            shared_key_offset: 0,
            owner_generation: global_frame_host_owner_generation(
                physical_ipa,
                physical_size as u64,
            ),
        });
        self.mappings.push(HvfMappedRegion {
            start,
            ipa: semantic_ipa,
            physical_ipa,
            end,
            host_addr: semantic_host,
            size: semantic_len,
            physical_size,
            perms: stage2_perms,
            memory: None,
            host_mapping: None,
            stage2_lease: None,
            is_dynamic_alias: true,
            sharing,
            guest_writable: true,
            shared_key_base: 0,
            shared_key_offset: 0,
            owner_generation: global_frame_host_owner_generation(
                physical_ipa,
                physical_size as u64,
            ),
        });
        self.supersede_cow_receipts("sparse-mmap-extent", start, semantic_len as u64);
        self.cow_deferred_publications
            .lock()
            .push(PendingFrameCowPublication {
                va: start,
                len: semantic_len,
                expected_ipa: semantic_ipa,
            });
        Ok(end)
    }

    /// Void every pending deferred-COW receipt naming `[va, va+len)`.
    ///
    /// A receipt is a promise about ONE `(VA -> IPA)` publication, redeemed by
    /// the `protect_range` that completes it. The moment a later transaction
    /// repoints those leaves the promise is void: authenticating it compares
    /// the live translation against an owner that has been DELIBERATELY
    /// replaced, and `observe_frame_cow_protection` then fails a publication
    /// that is in fact correct — which the dispatcher can only lower to a
    /// guest `ENOMEM`. That is how CPython's thread stacks came back
    /// MAP_FAILED ("Can't start 20 threads, only 4 threads started"): a
    /// sparse-mmap extent's receipt was falsified by a frame COW running
    /// between its publication and its protection commit.
    ///
    /// Every stage-1 repointer calls this before publishing its own receipt.
    /// No authentication coverage is lost: each repointer verifies its own
    /// leaves inline and leaves a receipt for the state that actually
    /// survives. A receipt only partly covered is split, never widened.
    fn supersede_cow_receipts(&self, site: &'static str, va: u64, len: u64) {
        let Some(end) = va.checked_add(len) else {
            return;
        };
        let mut receipts = self.cow_deferred_publications.lock();
        if receipts.is_empty() {
            return;
        }
        let mut remaining = Vec::with_capacity(receipts.len());
        for receipt in receipts.drain(..) {
            let receipt_end = receipt.va.saturating_add(receipt.len as u64);
            if receipt_end <= va || receipt.va >= end {
                remaining.push(receipt);
                continue;
            }
            tracing::debug!(
                target: "carrick::cow",
                site,
                repoint = format_args!("{va:#x}+{len:#x}"),
                receipt = format_args!("{:#x}+{:#x}", receipt.va, receipt.len),
                expected_ipa = format_args!("{:#x}", receipt.expected_ipa),
                "superseding deferred COW receipt",
            );
            let overlap_start = receipt.va.max(va);
            let overlap_end = receipt_end.min(end);
            if receipt.va < overlap_start
                && let Ok(prefix) = usize::try_from(overlap_start - receipt.va)
            {
                remaining.push(PendingFrameCowPublication {
                    va: receipt.va,
                    len: prefix,
                    expected_ipa: receipt.expected_ipa,
                });
            }
            if overlap_end < receipt_end
                && let Ok(suffix) = usize::try_from(receipt_end - overlap_end)
                && let Some(expected_ipa) =
                    receipt.expected_ipa.checked_add(overlap_end - receipt.va)
            {
                remaining.push(PendingFrameCowPublication {
                    va: overlap_end,
                    len: suffix,
                    expected_ipa,
                });
            }
        }
        *receipts = remaining;
    }

    /// Replace an invalid stage-1 output whose exact stage-2 lease was retired
    /// by `munmap` with a fresh zero frame before low-arena same-VA reuse.
    ///
    /// `munmap` deliberately preserves the descriptor output address while
    /// clearing VALID. That is useful while a partially unmapped compound still
    /// owns its physical lease, but a *full* semantic unmap now retires that
    /// lease exactly. A later anonymous mmap may reuse the same low VA without
    /// going through `add_alias`; merely setting VALID would resurrect an IPA
    /// that no longer exists in stage-2. Materialize a new global frame and
    /// repoint the still-invalid leaves transactionally. The later
    /// `protect_range` publication authenticates the deferred PTE receipts.
    fn materialize_retired_reuse(
        &mut self,
        va: u64,
        requested_end: u64,
        flush_stage1: &mut dyn FnMut() -> Result<(), TrapError>,
    ) -> Result<Option<u64>, TrapError> {
        const PAGE_SIZE: u64 = 4 * 1024;
        const PA_MASK_4KIB: u64 = 0x0000_FFFF_FFFF_F000;
        const VALID: u64 = 1;
        const AP_MASK: u64 = 0b11 << 6;
        const AP_USER_RO: u64 = 0b11 << 6;
        const NON_GLOBAL: u64 = 1 << 11;

        if !self.persistent_vm_lifecycle {
            return Ok(None);
        }
        let page_va = align_down(va, PAGE_SIZE);
        let retained_ipa = self
            .page_tables
            .lock()
            .as_ref()
            .and_then(|manager| manager.translate_retained_output(page_va));
        let Some(retained_ipa) = retained_ipa else {
            return Ok(None);
        };
        if self.physical_cow_source(page_va, retained_ipa).is_some()
            && !self.retained_output_lacks_exclusive_claim(retained_ipa)
        {
            return Ok(None);
        }
        if !self.protections.range_unmapped(page_va, 1) {
            return Err(TrapError::Hypervisor(format!(
                "HVPatch live VA 0x{page_va:x} names retired stage-2 IPA 0x{retained_ipa:x}"
            )));
        }

        let identity = self.cow_identity.ok_or_else(|| {
            TrapError::Hypervisor("HVPatch retained reuse has no bound mm identity".to_owned())
        })?;
        let authority = self.cow_authority.clone().ok_or_else(|| {
            TrapError::Hypervisor("HVPatch retained reuse has no inventory authority".to_owned())
        })?;
        let _quiesce = authority.quiesce().map_err(|error| {
            TrapError::Hypervisor(format!("quiesce HVPatch retained reuse: {error}"))
        })?;
        let _topology = crate::fork_quiesce::acquire_topology_lock(
            carrick_observability::probes::HvpatchTopologyOperation::AliasMap,
            identity.linux_pid,
            identity.linux_tid,
        );

        // Another sibling may have repaired the leaf while this thread waited.
        let retained_ipa = self
            .page_tables
            .lock()
            .as_ref()
            .and_then(|manager| manager.translate_retained_output(page_va));
        let Some(retained_ipa) = retained_ipa else {
            return Ok(None);
        };
        if self.physical_cow_source(page_va, retained_ipa).is_some()
            && !self.retained_output_lacks_exclusive_claim(retained_ipa)
        {
            // A live PRIVATE source means a sibling repaired the leaf; nothing
            // to materialize. A live SHARED source is the case this exists
            // for: the mm must get its own zeroed replacement rather than
            // writing through (corruption) or reading through (disclosure)
            // the other mm's frame.
            return Ok(None);
        }

        let compound_va = align_down(page_va, CowArmedRanges::COMPOUND_SIZE);
        let compound_end = compound_va
            .checked_add(CowArmedRanges::COMPOUND_SIZE)
            .ok_or_else(|| {
                TrapError::Hypervisor("HVPatch retained reuse compound overflow".to_owned())
            })?;
        // Extend past the trigger page only across pages in EXACTLY its state.
        //
        // The predicate above (a retained stage-1 output naming no live
        // physical source) selected `page_va` alone; the rest of the compound
        // was taken on trust. That is wrong, because a page whose backing was
        // published moments earlier by `materialize_sparse_mmap_extent` is
        // indistinguishable from a retired one AT THE LEAF: sparse
        // materialization deliberately leaves its stage-1 receipts invalid
        // until the protection commit. Repointing such a page replaces a live
        // physical owner and falsifies the `PendingFrameCowPublication` that
        // names it, so the `protect_range` that follows in the same guest
        // `mmap` fails to authenticate its own receipt and the guest gets
        // MAP_FAILED — with, before this, no explanation anywhere. That is the
        // shape that broke every CPython `dlopen` of a DSO whose PROT_NONE
        // reservation started one page into a 16 KiB compound.
        //
        // Authenticate each page against the live translation and the exact
        // current owner instead, and stop at the first page that already has
        // one. Splitting a compound across frames is already supported — the
        // repoint covers exactly `[page_va, span_end)`.
        let mut span_end = requested_end.min(compound_end);
        let mut probe = page_va.saturating_add(PAGE_SIZE);
        while probe < span_end {
            let retained = self
                .page_tables
                .lock()
                .as_ref()
                .and_then(|manager| manager.translate_retained_output(probe));
            let needs_materialization = retained.is_some_and(|ipa| {
                self.physical_cow_source(probe, ipa).is_none()
                    || self.retained_output_lacks_exclusive_claim(ipa)
            }) && self.protections.range_unmapped(probe, 1);
            if !needs_materialization {
                span_end = probe;
                break;
            }
            probe = probe.saturating_add(PAGE_SIZE);
        }
        let span_len = usize::try_from(span_end.checked_sub(page_va).ok_or_else(|| {
            TrapError::Hypervisor("HVPatch retained reuse span underflow".to_owned())
        })?)
        .map_err(|_| TrapError::MappingTooLarge(span_end.saturating_sub(page_va)))?;
        if span_len == 0 {
            return Ok(None);
        }
        let physical_offset = page_va.checked_sub(compound_va).ok_or_else(|| {
            TrapError::Hypervisor("HVPatch retained reuse offset underflow".to_owned())
        })?;
        let page_table_host = self
            .mapping_for_range(
                crate::memory::LINUX_PAGE_TABLES_BASE,
                carrick_mem::memory::LINUX_PAGE_TABLES_SIZE as usize,
            )
            .map(|mapping| mapping.host_addr)
            .ok_or_else(|| {
                TrapError::Hypervisor("HVPatch retained reuse has no page-table backing".to_owned())
            })?;

        let mut reservation = authority.reserve(1, 1, 2).map_err(|error| {
            TrapError::Hypervisor(format!("reserve HVPatch retained reuse inventory: {error}"))
        })?;
        let backing = Self::private_backing_identity();
        let new_host = crate::host_mapping::OwnedHostMapping::map_shared_anon(
            CowArmedRanges::COMPOUND_SIZE as usize,
            crate::host_mapping::HostMappingKind::FrameCow,
        )
        .map_err(|error| {
            TrapError::Hypervisor(format!("allocate HVPatch retained reuse backing: {error}"))
        })?;
        let new_host_ptr = new_host.as_ptr();
        let mut new_lease = GlobalFrameStage2Lease::reserve(
            CowArmedRanges::COMPOUND_SIZE,
            CowArmedRanges::COMPOUND_SIZE,
        )?;
        let new_physical_ipa = new_lease.base;
        let new_ipa = new_physical_ipa
            .checked_add(physical_offset)
            .ok_or_else(|| TrapError::Hypervisor("retained reuse IPA overflow".to_owned()))?;
        let stage2_perms = applevisor::memory::MemPerms::ReadWriteExec;
        let map_result = unsafe {
            inventory_hv_vm_map(
                new_host_ptr.cast(),
                new_physical_ipa,
                CowArmedRanges::COMPOUND_SIZE as usize,
                u64::from(stage2_perms),
            )
        };
        if map_result != 0 {
            return Err(TrapError::Hypervisor(format!(
                "map retained reuse IPA 0x{new_physical_ipa:x}: 0x{map_result:x}"
            )));
        }
        new_lease.mark_mapped();
        register_global_frame_host_owner(new_lease, new_host, u64::from(stage2_perms))?;
        let mut owner_rollback = GlobalFrameOwnerRollback::default();
        owner_rollback.record((new_physical_ipa, CowArmedRanges::COMPOUND_SIZE));

        let inventory_mapping = {
            let mut inventory = self.frame_inventory.lock();
            Self::stage_mapping(
                &mut inventory,
                &mut reservation,
                InventoryMappingStage {
                    gpa: new_physical_ipa,
                    length: CowArmedRanges::COMPOUND_SIZE,
                    permissions: carrick_hal::MemPerms {
                        read: true,
                        write: true,
                        exec: true,
                    },
                    backing,
                    inherited_frame: None,
                    stage2_lease: Some((new_physical_ipa, CowArmedRanges::COMPOUND_SIZE)),
                },
            )?
        };
        let inventory_entry = (
            (new_physical_ipa, CowArmedRanges::COMPOUND_SIZE),
            inventory_mapping,
        );

        // Fill the recycled pre-image buffer rather than allocating a fresh
        // 1.75 MiB one per transaction (see `cow_rollback_scratch`).
        let mut rollback_scratch = self.cow_rollback_scratch.take();
        let mut rollback_page_tables = None;
        let publication = (|| {
            let mut page_tables = self.page_tables.lock();
            let manager = page_tables.as_mut().ok_or_else(|| {
                TrapError::Hypervisor("HVPatch retained reuse page tables are absent".to_owned())
            })?;
            rollback_page_tables = Some(Self::rollback_pre_image(&mut rollback_scratch, manager));
            Self::refresh_stage1_exclusivity(manager);
            manager
                .repoint_preserving_attributes(page_va, new_ipa, span_len as u64)
                .map_err(|error| {
                    TrapError::Hypervisor(format!(
                        "repoint HVPatch retained reuse leaves: {error:?}"
                    ))
                })?;
            // `PtOp::Invalidate` intentionally preserves AP. A retired overlay
            // may therefore carry invalid+RW attributes, while the deferred
            // PROT_NONE publication is required to authenticate invalid+RO.
            // Normalize the unpublished leaves to fork-RO/nG now; a later RW
            // protect changes AP while preserving the exact fresh IPA.
            manager
                .set_fork_readonly(page_va, span_len, false)
                .map_err(|error| {
                    TrapError::Hypervisor(format!(
                        "restrict HVPatch retained reuse leaves: {error:?}"
                    ))
                })?;
            unsafe { manager.sync_to_host(page_table_host) };
            let mut current = page_va;
            while current < span_end {
                let expected_ipa = new_ipa.checked_add(current - page_va).ok_or_else(|| {
                    TrapError::Hypervisor("retained reuse leaf IPA overflow".to_owned())
                })?;
                let shadow = manager.debug_walk(current);
                let live =
                    unsafe { manager.debug_walk_host(page_table_host.cast_const(), current) };
                if shadow != live {
                    return Err(TrapError::Hypervisor(format!(
                        "HVPatch retained reuse shadow/live mismatch at VA 0x{current:x}"
                    )));
                }
                let leaf = live[3];
                if leaf & VALID != 0
                    || leaf & PA_MASK_4KIB != expected_ipa & PA_MASK_4KIB
                    || leaf & AP_MASK != AP_USER_RO
                    || leaf & NON_GLOBAL == 0
                {
                    return Err(TrapError::Hypervisor(format!(
                        "HVPatch retained reuse leaf authentication failed at VA 0x{current:x}: leaf=0x{leaf:x} expected_ipa=0x{expected_ipa:x}"
                    )));
                }
                current = current.saturating_add(PAGE_SIZE);
            }
            Ok::<(), TrapError>(())
        })();
        if let Err(error) = publication {
            if let Some(snapshot) = rollback_page_tables {
                {
                    let mut page_tables = self.page_tables.lock();
                    unsafe { snapshot.restore_quiesced_snapshot_to_host(page_table_host) };
                    *page_tables = Some(snapshot);
                }
                if let Err(flush_error) = flush_stage1() {
                    eprintln!("carrick: FATAL: retained reuse rollback TLBI failed: {flush_error}");
                    std::process::abort();
                }
            }
            Self::rollback_unpublished_mappings(
                &mut self.frame_inventory.lock(),
                &[inventory_entry],
            )?;
            return Err(error);
        }
        // Publication succeeded: nothing needs the pre-image any more, so hand
        // its buffer back to the recycler for the next transaction.
        self.cow_rollback_scratch = rollback_page_tables.take().or(rollback_scratch);
        if let Err(error) = flush_stage1() {
            eprintln!("carrick: FATAL: retained reuse stage-1 TLBI failed: {error}");
            std::process::abort();
        }
        if let Err(error) = authority.apply(reservation.commit(())) {
            eprintln!("carrick: FATAL: retained reuse inventory commit failed: {error}");
            std::process::abort();
        }
        owner_rollback.commit();

        match authority.mapping_is_live(
            inventory_mapping.mapping,
            inventory_mapping.frame,
            carrick_guest_mem::Gpa(new_physical_ipa),
            carrick_hal::FrameLength::from_mapping_extent(
                std::num::NonZeroU64::new(CowArmedRanges::COMPOUND_SIZE)
                    .unwrap_or_else(|| std::process::abort()),
            ),
        ) {
            Ok(true) => {}
            Ok(false) => {
                eprintln!("carrick: FATAL: retained reuse mapping absent after commit");
                std::process::abort();
            }
            Err(error) => {
                eprintln!("carrick: FATAL: authenticate retained reuse mapping: {error}");
                std::process::abort();
            }
        }

        let semantic_host = unsafe { new_host_ptr.add(physical_offset as usize) };
        let sharing = GuestMappingSharing::Private;
        register_shared_alias(AliasBacking {
            start: page_va,
            ipa: new_ipa,
            host_addr: semantic_host as usize,
            size: span_len,
            physical_ipa: new_physical_ipa,
            physical_host_addr: new_host_ptr as usize,
            physical_size: CowArmedRanges::COMPOUND_SIZE as usize,
            perms: u64::from(stage2_perms),
            guest_writable: true,
            sharing,
            ownership_scope: alias_ownership_scope(sharing, self.mm_root_slot),
            inventory_backing: backing,
            shared_key_base: 0,
            shared_key_offset: 0,
            owner_generation: global_frame_host_owner_generation(
                new_physical_ipa,
                CowArmedRanges::COMPOUND_SIZE as usize as u64,
            ),
        });
        self.mappings.push(HvfMappedRegion {
            start: page_va,
            ipa: new_ipa,
            physical_ipa: new_physical_ipa,
            end: span_end,
            host_addr: semantic_host,
            size: CowArmedRanges::COMPOUND_SIZE as usize,
            physical_size: CowArmedRanges::COMPOUND_SIZE as usize,
            perms: stage2_perms,
            memory: None,
            host_mapping: None,
            stage2_lease: None,
            is_dynamic_alias: true,
            sharing,
            guest_writable: true,
            shared_key_base: 0,
            shared_key_offset: 0,
            owner_generation: global_frame_host_owner_generation(
                new_physical_ipa,
                CowArmedRanges::COMPOUND_SIZE as usize as u64,
            ),
        });
        self.supersede_cow_receipts("retained-reuse", page_va, span_len as u64);
        let mut pending = self.cow_deferred_publications.lock();
        let mut current = page_va;
        while current < span_end {
            pending.push(PendingFrameCowPublication {
                va: current,
                len: PAGE_SIZE as usize,
                expected_ipa: new_ipa + (current - page_va),
            });
            current = current.saturating_add(PAGE_SIZE);
        }
        // This fresh frame is private to the reusing mm. A semantic arm can
        // outlive the retired physical lease (or be reintroduced by a later
        // fork from a broad arena descriptor), but carrying that arm into the
        // following `protect_range(PROT_WRITE)` would immediately force the
        // newly published leaves back to RO and fail their deferred receipt.
        self.cow_armed.lock().disarm(CowArmedSpan {
            va: page_va,
            len: span_len,
            executable: false,
            kernel_only: false,
        });
        Ok(Some(span_end))
    }

    fn live_stage1_names_writable_private_mapping(
        &self,
        fault_va: u64,
        mapping: MappingView,
    ) -> Result<bool, TrapError> {
        const VALID_PAGE: u64 = 0b11;
        const NON_GLOBAL: u64 = 1 << 11;
        const AP_MASK: u64 = 0b11 << 6;
        const AP_USER_RW: u64 = 0b01 << 6;
        const PA_MASK_4KIB: u64 = 0x0000_FFFF_FFFF_F000;
        const PAGE_SIZE: u64 = 4 * 1024;

        let page_va = align_down(fault_va, PAGE_SIZE);
        let expected_ipa = mapping
            .ipa
            .checked_add(page_va.checked_sub(mapping.start).ok_or_else(|| {
                TrapError::Hypervisor("HVPatch winner PTE precedes mapping start".to_owned())
            })?)
            .ok_or_else(|| TrapError::Hypervisor("HVPatch winner PTE IPA overflow".to_owned()))?;
        let page_table_host = self
            .mapping_for_range(
                crate::memory::LINUX_PAGE_TABLES_BASE,
                carrick_mem::memory::LINUX_PAGE_TABLES_SIZE as usize,
            )
            .map(|mapping| mapping.host_addr)
            .ok_or_else(|| {
                TrapError::Hypervisor("HVPatch winner PTE page-table backing is absent".to_owned())
            })?;
        let page_tables = self.page_tables.lock();
        let manager = page_tables.as_ref().ok_or_else(|| {
            TrapError::Hypervisor("HVPatch winner PTE manager is absent".to_owned())
        })?;
        let shadow = manager.debug_walk(page_va);
        let live = unsafe { manager.debug_walk_host(page_table_host.cast_const(), page_va) };
        if shadow != live {
            return Err(TrapError::Hypervisor(format!(
                "HVPatch winner PTE shadow/live mismatch at VA 0x{page_va:x}: shadow={shadow:x?} live={live:x?}"
            )));
        }
        let leaf = live[3];
        Ok(leaf & VALID_PAGE == VALID_PAGE
            && leaf & NON_GLOBAL != 0
            && leaf & AP_MASK == AP_USER_RW
            && leaf & PA_MASK_4KIB == expected_ipa & PA_MASK_4KIB)
    }

    fn perform_frame_cow(
        &mut self,
        fault_va: u64,
        intent: carrick_aarch64::vmm::FrameCowWriteIntent,
        trigger: FrameCowTrigger,
        flush_stage1: &mut dyn FnMut() -> Result<(), TrapError>,
    ) -> Result<bool, TrapError> {
        let identity = self.cow_identity.ok_or_else(|| {
            TrapError::Hypervisor("HVPatch frame COW has no bound mm identity".to_owned())
        })?;
        let authority = self.cow_authority.clone().ok_or_else(|| {
            TrapError::Hypervisor("HVPatch frame COW has no inventory authority".to_owned())
        })?;
        // Lock order matches every runtime page-table editor: pause sibling
        // walkers first, then serialize shared HVF stage-2/alias topology.
        let _quiesce = authority.quiesce().map_err(|error| {
            TrapError::Hypervisor(format!("quiesce HVPatch frame COW: {error}"))
        })?;
        let _topology = crate::fork_quiesce::acquire_topology_lock(
            carrick_observability::probes::HvpatchTopologyOperation::FrameCow,
            identity.linux_pid,
            identity.linux_tid,
        );

        // Another vCPU of this mm may have won while we waited for topology.
        let (span, armed) = {
            let cow_armed = self.cow_armed.lock();
            (cow_armed.span_for(fault_va), cow_armed.ranges.clone())
        };
        let Some(span) = span else {
            let mapping = self.mapping_for_range(fault_va, 1);
            let write_denied = self.protections.range_write_denied(fault_va, 1);
            let private_writable_mapping = mapping.is_some_and(|mapping| {
                mapping.guest_writable && mapping.sharing == GuestMappingSharing::Private
            });
            let live_leaf_is_writable = match mapping {
                Some(mapping) if private_writable_mapping && !write_denied => {
                    self.live_stage1_names_writable_private_mapping(fault_va, mapping)?
                }
                _ => false,
            };
            match unarmed_permission_fault_route(
                private_writable_mapping,
                write_denied,
                !armed.is_empty(),
                live_leaf_is_writable,
            ) {
                UnarmedPermissionFaultRoute::NotCow => return Ok(false),
                UnarmedPermissionFaultRoute::RetryCommittedWinner => {
                    // The exact live descriptor is already writable and names
                    // the current private mapping: a sibling won this COW while
                    // this vCPU was parking. Flush the losing vCPU's stale RO
                    // translation and retry the faulting instruction.
                    flush_stage1()?;
                    return Ok(true);
                }
                UnarmedPermissionFaultRoute::MissingArm => {
                    let mapping_shape = mapping.map(|mapping| {
                        (
                            mapping.start,
                            mapping.end,
                            mapping.ipa,
                            mapping.guest_writable,
                            mapping.sharing,
                        )
                    });
                    return Err(TrapError::Hypervisor(format!(
                        "HVPatch private writable permission fault at VA 0x{fault_va:x} has no COW arm; mapping={mapping_shape:?} write_denied={write_denied} armed={armed:?}"
                    )));
                }
            }
        };
        // COW allocation is physical at the 16 KiB host compound, but guest
        // access authority is semantic at the exact fault byte. A compound can
        // cross the current `brk`, mprotect, or partial-unmap edge; rejecting
        // the whole span incorrectly SIGSEGVs a writable byte merely because an
        // adjacent page is denied. Internal backing maintenance is distinct:
        // mmap must zero a reclaimed, currently-unmapped page BEFORE publishing
        // its fresh VMA permission. It still splits/repoints the frame, while
        // the page-table publication below deliberately preserves the denied
        // descriptor until mmap's later `protect_range` commit.
        if frame_cow_write_is_denied(self.protections.range_write_denied(fault_va, 1), intent) {
            return Ok(false);
        }
        // `span.va` can name the host-granule prefix of a semantic fragment
        // whose first live Linux leaf begins at `fault_va` (Task 1 deliberately
        // keeps semantic and physical extents separate). A guest fault proves
        // that the exact byte translated; backing maintenance may intentionally
        // start from an invalid munmap descriptor, so the mapping-metadata
        // fallback is authoritative for that pre-publication transaction.
        let old_fault_ipa = self.translate_va(fault_va).or_else(|| {
            let mapping = self.mapping_for_range(fault_va, 1)?;
            mapping
                .ipa
                .checked_add(fault_va.checked_sub(mapping.start)?)
        });
        let semantic_offset = fault_va.checked_sub(span.va).ok_or_else(|| {
            TrapError::Hypervisor("HVPatch COW fault precedes its armed span".to_owned())
        })?;
        let old_ipa = old_fault_ipa
            .and_then(|ipa| ipa.checked_sub(semantic_offset))
            .ok_or_else(|| {
                TrapError::Hypervisor(format!(
                    "HVPatch COW VA 0x{:x} (fault 0x{fault_va:x}) has no stage-1 or mapping translation",
                    span.va
                ))
            })?;
        let (old_host, old_physical_ipa) = self
            .physical_cow_source(span.va, old_ipa)
            .ok_or_else(|| {
                TrapError::Hypervisor(format!(
                    "HVPatch COW VA 0x{:x} IPA 0x{old_ipa:x} has no matching 16 KiB physical backing",
                    span.va
                ))
            })?;
        let old_offset = old_ipa.checked_sub(old_physical_ipa).ok_or_else(|| {
            TrapError::Hypervisor("HVPatch COW physical offset underflow".to_owned())
        })?;
        let retain_old_compound = {
            let page_tables = self.page_tables.lock();
            let manager = page_tables.as_ref().ok_or_else(|| {
                TrapError::Hypervisor("HVPatch COW page-table manager is absent".to_owned())
            })?;
            cow_source_has_retained_sibling(span, old_ipa, old_physical_ipa, |va| {
                manager.translate_retained_output(va)
            })
        };
        let CowInventorySplitShape {
            old_key: old_inventory_key,
            old: old_inventory_extent,
            fragments: fragment_shapes,
            retire_old_frame,
        } = {
            let inventory = self.frame_inventory.lock();
            Self::cow_inventory_split_shape(&inventory, old_physical_ipa, retain_old_compound)?
        };
        let old_frame = old_inventory_extent.frame;
        // Resolve every authority needed for stage-1 publication before the
        // first physical/staged-inventory mutation.  A fork-time response can
        // run while the engine's mapping metadata is being rebuilt; failing
        // here must leave no staged MappingId for terminal retirement to see.
        let page_table_host = self
            .mapping_for_range(
                crate::memory::LINUX_PAGE_TABLES_BASE,
                carrick_mem::memory::LINUX_PAGE_TABLES_SIZE as usize,
            )
            .map(|mapping| mapping.host_addr)
            .ok_or_else(|| {
                TrapError::Hypervisor("HVPatch COW page-table backing is absent".to_owned())
            })?;

        let receipt_va = align_down(fault_va, 4 * 1024);
        let trigger_event = carrick_observability::probes::HvpatchFrameCowTrigger::new(
            trigger.class,
            identity.linux_pid,
            identity.linux_tid,
            identity.mm,
            u32::from(identity.asid),
            receipt_va,
            trigger.syndrome,
            trigger.far,
            trigger.ttbr0,
        )
        .unwrap_or_else(|error| {
            eprintln!("carrick: FATAL: construct HVPatch frame-COW trigger: {error}");
            std::process::abort();
        });
        crate::probes::hvpatch_frame_cow_trigger(trigger_event);

        // Reserve every kernel identity/event slot before physical mutation.
        let mapping_candidates = fragment_shapes.len().saturating_add(1);
        let event_count = 1usize
            .saturating_add(mapping_candidates.saturating_mul(2))
            .saturating_add(usize::from(retire_old_frame));
        let mut reservation = authority
            .reserve(1, mapping_candidates, event_count)
            .map_err(|error| {
                TrapError::Hypervisor(format!("reserve frame COW inventory: {error}"))
            })?;
        let new_host = crate::host_mapping::OwnedHostMapping::map_shared_anon(
            CowArmedRanges::COMPOUND_SIZE as usize,
            crate::host_mapping::HostMappingKind::FrameCow,
        )
        .map_err(|error| TrapError::Hypervisor(format!("allocate frame COW backing: {error}")))?;
        let new_host_ptr = new_host.as_ptr();
        unsafe {
            std::ptr::copy_nonoverlapping(
                old_host,
                new_host_ptr,
                CowArmedRanges::COMPOUND_SIZE as usize,
            );
        }
        let source = unsafe {
            std::slice::from_raw_parts(
                old_host.cast_const(),
                CowArmedRanges::COMPOUND_SIZE as usize,
            )
        };
        let destination = unsafe {
            std::slice::from_raw_parts(
                new_host_ptr.cast_const(),
                CowArmedRanges::COMPOUND_SIZE as usize,
            )
        };
        crate::probes::hvpatch_frame_cow_copy(
            old_frame.raw(),
            old_physical_ipa,
            source,
            destination,
        );
        let mut new_lease = GlobalFrameStage2Lease::reserve(
            CowArmedRanges::COMPOUND_SIZE,
            CowArmedRanges::COMPOUND_SIZE,
        )?;
        let new_physical_ipa = new_lease.base;
        let new_ipa = new_physical_ipa
            .checked_add(old_offset)
            .ok_or_else(|| TrapError::Hypervisor("HVPatch COW semantic IPA overflow".to_owned()))?;
        let stage2_perms = applevisor::memory::MemPerms::ReadWriteExec;
        let map_result = unsafe {
            inventory_hv_vm_map(
                new_host_ptr.cast(),
                new_physical_ipa,
                CowArmedRanges::COMPOUND_SIZE as usize,
                u64::from(stage2_perms),
            )
        };
        if map_result != 0 {
            return Err(TrapError::Hypervisor(format!(
                "map frame COW IPA 0x{new_physical_ipa:x}: 0x{map_result:x}"
            )));
        }
        new_lease.mark_mapped();
        register_global_frame_host_owner(new_lease, new_host, u64::from(stage2_perms))?;

        let backing = Self::private_backing_identity();
        let split = match Self::stage_cow_inventory_split(
            &mut reservation,
            old_inventory_key,
            old_inventory_extent,
            &fragment_shapes,
            retire_old_frame,
            new_physical_ipa,
            backing,
        ) {
            Ok(split) => split,
            Err(error) => {
                let _ =
                    retire_global_frame_host_owner(new_physical_ipa, CowArmedRanges::COMPOUND_SIZE);
                return Err(error);
            }
        };
        let new_frame = split.new_extent.frame;
        let new_mapping = split.new_extent.mapping;
        const PAGE_SIZE: u64 = 4 * 1024;
        let receipt_intent = match intent {
            carrick_aarch64::vmm::FrameCowWriteIntent::GuestVisible => {
                carrick_observability::probes::HvpatchFrameCowIntent::GuestVisible
            }
            carrick_aarch64::vmm::FrameCowWriteIntent::BackingMaintenance => {
                carrick_observability::probes::HvpatchFrameCowIntent::BackingMaintenance
            }
            carrick_aarch64::vmm::FrameCowWriteIntent::PrivilegedInternal => {
                carrick_observability::probes::HvpatchFrameCowIntent::PrivilegedInternal
            }
        };
        let emit_cow = |phase| {
            let event = carrick_observability::probes::HvpatchFrameCow::new(
                phase,
                receipt_intent,
                identity.linux_pid,
                identity.linux_tid,
                identity.mm,
                u32::from(identity.asid),
                receipt_va,
                old_frame.raw(),
                new_frame.raw(),
                old_physical_ipa,
                new_physical_ipa,
            )
            .unwrap_or_else(|error| {
                eprintln!("carrick: FATAL: construct HVPatch frame-COW receipt: {error}");
                std::process::abort();
            });
            crate::probes::hvpatch_frame_cow(event);
        };
        emit_cow(carrick_observability::probes::HvpatchFrameCowPhase::Stage2Mapped);
        // Fill the recycled pre-image buffer rather than allocating a fresh
        // 1.75 MiB one per transaction (see `cow_rollback_scratch`).
        let mut rollback_scratch = self.cow_rollback_scratch.take();
        let mut rollback_page_tables = None;
        let mut preserved_denied_receipt = None;
        let page_table_result = (|| {
            const PA_MASK_4KIB: u64 = 0x0000_FFFF_FFFF_F000;
            const AP_MASK: u64 = 0b11 << 6;
            const AP_USER_RW: u64 = 0b01 << 6;
            const VALID: u64 = 1;
            const TYPE_TABLE_OR_PAGE: u64 = 0b11;
            const NON_GLOBAL: u64 = 1 << 11;
            let mut page_tables = self.page_tables.lock();
            let manager = page_tables.as_mut().ok_or_else(|| {
                TrapError::Hypervisor("HVPatch COW page-table manager is absent".to_owned())
            })?;
            // The transaction can fail after one or more descriptors were
            // written to both the manager shadow and live backing.  Preserve a
            // complete pre-edit image: a cloned manager's dirty list alone is
            // not a rollback log, because `sync_to_host` drains the NEW edits.
            rollback_page_tables = Some(Self::rollback_pre_image(&mut rollback_scratch, manager));
            Self::refresh_stage1_exclusivity(manager);
            if span.kernel_only {
                manager
                    .map_kernel_aliased(span.va, new_ipa, span.len as u64)
                    .map_err(|error| {
                        TrapError::Hypervisor(format!(
                            "publish kernel-only HVPatch COW stage-1 leaf: {error:?}"
                        ))
                    })?;
            } else {
                manager
                    .repoint_preserving_attributes(span.va, new_ipa, span.len as u64)
                    .map_err(|error| {
                        TrapError::Hypervisor(format!(
                            "repoint HVPatch COW stage-1 compound: {error:?}"
                        ))
                    })?;
                let span_end = span.va.saturating_add(span.len as u64);
                let mut page_va = span.va & !(PAGE_SIZE - 1);
                while page_va < span_end {
                    if !self.protections.range_write_denied(page_va, 1) {
                        manager
                            .set_writable_preserving_attributes(page_va, PAGE_SIZE as usize)
                            .map_err(|error| {
                                TrapError::Hypervisor(format!(
                                    "grant HVPatch COW semantic page write: {error:?}"
                                ))
                            })?;
                    }
                    page_va = page_va.saturating_add(PAGE_SIZE);
                }
            }
            unsafe { manager.sync_to_host(page_table_host) };

            // A semantic fork result is not structural proof.  Before the
            // stage-1 TLBI publishes this transaction, authenticate the exact
            // descriptors the hardware walker will consume: the manager shadow
            // and live backing must agree, every 4 KiB leaf in this 16 KiB COW
            // compound must name the new global frame IPA, and its AP bits must
            // match the EL1-only/user regime.  Fail closed while the old armed
            // range and inventory reservation are still intact.
            let expected_ap = if span.kernel_only { 0 } else { AP_USER_RW };
            let span_end = span.va.checked_add(span.len as u64).ok_or_else(|| {
                TrapError::Hypervisor("HVPatch COW stage-1 span overflow".to_owned())
            })?;
            let mut page_va = span.va;
            while page_va < span_end {
                let shadow = manager.debug_walk(page_va);
                let live =
                    unsafe { manager.debug_walk_host(page_table_host.cast_const(), page_va) };
                if shadow != live {
                    return Err(TrapError::Hypervisor(format!(
                        "HVPatch COW stage-1 shadow/live mismatch at VA 0x{page_va:x}: shadow={shadow:x?} live={live:x?}"
                    )));
                }
                let leaf = live[3];
                let expected_ipa = new_ipa
                    .checked_add(page_va.checked_sub(span.va).ok_or_else(|| {
                        TrapError::Hypervisor("HVPatch COW page offset underflow".to_owned())
                    })?)
                    .ok_or_else(|| {
                        TrapError::Hypervisor("HVPatch COW leaf IPA overflow".to_owned())
                    })?;
                let page_is_writable =
                    span.kernel_only || !self.protections.range_write_denied(page_va, 1);
                if leaf & PA_MASK_4KIB != expected_ipa & PA_MASK_4KIB
                    || (page_is_writable
                        && (leaf & VALID == 0
                            || leaf & 0b11 != TYPE_TABLE_OR_PAGE
                            || leaf & AP_MASK != expected_ap
                            || (!span.kernel_only && leaf & NON_GLOBAL == 0)))
                {
                    return Err(TrapError::Hypervisor(format!(
                        "HVPatch COW stage-1 leaf authentication failed at VA 0x{page_va:x}: leaf=0x{leaf:x} expected_ipa=0x{expected_ipa:x} expected_ap=0x{expected_ap:x}"
                    )));
                }
                if page_is_writable && page_va == receipt_va {
                    crate::probes::pt_alias_receipt(page_va, leaf, expected_ipa, expected_ap, 2);
                } else if page_va == receipt_va {
                    preserved_denied_receipt = Some((page_va, leaf, expected_ipa, leaf & AP_MASK));
                }
                // Reuse the durable descriptor-walk probe so a signed live
                // capture can bind the COW receipt to the exact published PTE.
                crate::probes::pt_alias_walk(page_va, live, 1 << 3);
                page_va = page_va.saturating_add(PAGE_SIZE);
            }
            Ok::<(), TrapError>(())
        })();
        if let Err(error) = page_table_result {
            if let Some(snapshot) = rollback_page_tables {
                {
                    let mut page_tables = self.page_tables.lock();
                    // SAFETY: the COW quiesce and topology guards remain held;
                    // no vCPU can walk or edit this mm while the complete
                    // pre-transaction image replaces its live backing.
                    unsafe { snapshot.restore_quiesced_snapshot_to_host(page_table_host) };
                    *page_tables = Some(snapshot);
                }
                if let Err(flush_error) = flush_stage1() {
                    eprintln!(
                        "carrick: FATAL: HVPatch COW rollback stage-1 TLBI failed: {flush_error}"
                    );
                    std::process::abort();
                }
            }
            let _ = retire_global_frame_host_owner(new_physical_ipa, CowArmedRanges::COMPOUND_SIZE);
            return Err(error);
        }
        // Publication succeeded: nothing needs the pre-image any more, so hand
        // its buffer back to the recycler for the next transaction.
        self.cow_rollback_scratch = rollback_page_tables.take().or(rollback_scratch);
        if let Err(error) = flush_stage1() {
            eprintln!("carrick: FATAL: HVPatch COW stage-1 TLBI failed: {error}");
            std::process::abort();
        }
        emit_cow(carrick_observability::probes::HvpatchFrameCowPhase::Stage1Published);
        if let Err(error) = authority.apply(reservation.commit(())) {
            eprintln!("carrick: FATAL: HVPatch COW inventory commit failed: {error}");
            std::process::abort();
        }
        let retire_old_stage2 = {
            let mut inventory = self.frame_inventory.lock();
            Self::commit_cow_inventory_split(&mut inventory, &split).unwrap_or_else(|error| {
                eprintln!(
                    "carrick: FATAL: commit HVPatch backend COW inventory after kernel commit: {error}"
                );
                std::process::abort();
            })
        };
        if retire_old_stage2 {
            self.retire_stage2_extent(split.old.stage2_base, split.old.stage2_length)
                .unwrap_or_else(|error| {
                    eprintln!("carrick: FATAL: retire HVPatch COW source extent: {error}");
                    std::process::abort();
                });
            forget_replay_extent(
                split.old.stage2_base,
                usize::try_from(split.old.stage2_length).unwrap_or_default(),
            );
            mutate_external_alias_state(|_, registry| {
                registry.retain(|alias| {
                    (alias.physical_ipa, alias.physical_size as u64)
                        != (split.old.stage2_base, split.old.stage2_length)
                });
            });
            self.mappings.retain(|mapping| {
                (mapping.physical_ipa, mapping.physical_size as u64)
                    != (split.old.stage2_base, split.old.stage2_length)
            });
        }
        let Some(cow_extent) = std::num::NonZeroU64::new(CowArmedRanges::COMPOUND_SIZE) else {
            eprintln!("carrick: FATAL: HVPatch COW compound extent is zero");
            std::process::abort();
        };
        let cow_length = carrick_hal::FrameLength::from_mapping_extent(cow_extent);
        match authority.mapping_is_live(
            new_mapping,
            new_frame,
            carrick_guest_mem::Gpa(new_physical_ipa),
            cow_length,
        ) {
            Ok(true) => {}
            Ok(false) => {
                eprintln!(
                    "carrick: FATAL: authenticated HVPatch COW mapping {new_mapping:?} \
                     was absent immediately after commit"
                );
                std::process::abort();
            }
            Err(error) => {
                eprintln!(
                    "carrick: FATAL: authenticate HVPatch COW mapping {new_mapping:?}: {error}"
                );
                std::process::abort();
            }
        }
        emit_cow(carrick_observability::probes::HvpatchFrameCowPhase::Committed);
        // The repoint above replaced this span's stage-1 output. Any receipt
        // still naming the PREVIOUS owner for these VAs — typically the
        // sparse-mmap extent published moments earlier in the very same guest
        // `mmap`, whose leaves are deliberately invalid until the protection
        // commit — is now a false promise, and would fail the authentication
        // that completes this mapping.
        self.supersede_cow_receipts("frame-cow", span.va, span.len as u64);
        if let Some((va, leaf, expected_ipa, expected_ap)) = preserved_denied_receipt {
            crate::probes::pt_alias_receipt(va, leaf, expected_ipa, expected_ap, 3);
            if intent == carrick_aarch64::vmm::FrameCowWriteIntent::BackingMaintenance {
                self.cow_deferred_publications
                    .lock()
                    .push(PendingFrameCowPublication {
                        va,
                        len: PAGE_SIZE as usize,
                        expected_ipa,
                    });
            }
        }

        let semantic_host = unsafe { new_host_ptr.add(old_offset as usize) };
        let alias = AliasBacking {
            start: span.va,
            ipa: new_ipa,
            host_addr: semantic_host as usize,
            size: span.len,
            physical_ipa: new_physical_ipa,
            physical_host_addr: new_host_ptr as usize,
            physical_size: CowArmedRanges::COMPOUND_SIZE as usize,
            perms: u64::from(stage2_perms),
            guest_writable: true,
            sharing: GuestMappingSharing::Private,
            ownership_scope: alias_ownership_scope(GuestMappingSharing::Private, self.mm_root_slot),
            inventory_backing: backing,
            shared_key_base: 0,
            shared_key_offset: 0,
            owner_generation: global_frame_host_owner_generation(
                new_physical_ipa,
                CowArmedRanges::COMPOUND_SIZE as usize as u64,
            ),
        };
        register_shared_alias(alias);
        self.mappings.push(HvfMappedRegion {
            start: span.va,
            ipa: new_ipa,
            physical_ipa: new_physical_ipa,
            end: span.va.saturating_add(span.len as u64),
            host_addr: semantic_host,
            size: CowArmedRanges::COMPOUND_SIZE as usize,
            physical_size: CowArmedRanges::COMPOUND_SIZE as usize,
            perms: stage2_perms,
            memory: None,
            host_mapping: None,
            stage2_lease: None,
            is_dynamic_alias: true,
            sharing: GuestMappingSharing::Private,
            guest_writable: true,
            shared_key_base: 0,
            shared_key_offset: 0,
            owner_generation: global_frame_host_owner_generation(
                new_physical_ipa,
                CowArmedRanges::COMPOUND_SIZE as usize as u64,
            ),
        });
        self.cow_armed.lock().disarm(span);
        Ok(true)
    }

    pub(crate) fn resolve_frame_cow_fault(
        &mut self,
        syndrome: u64,
        far: u64,
        ttbr0: u64,
        flush_stage1: &mut dyn FnMut() -> Result<(), TrapError>,
    ) -> Result<bool, TrapError> {
        if !is_stage1_cow_write_fault(syndrome) {
            return Ok(false);
        }
        let fault_va = strip_pointer_tag(far);
        self.perform_frame_cow(
            fault_va,
            carrick_aarch64::vmm::FrameCowWriteIntent::GuestVisible,
            FrameCowTrigger {
                class: carrick_observability::probes::HvpatchFrameCowTriggerClass::Stage1PermissionFault,
                syndrome,
                far: fault_va,
                ttbr0,
            },
            flush_stage1,
        )
    }

    pub(crate) fn ensure_frame_cow_write(
        &mut self,
        va: u64,
        len: usize,
        intent: carrick_aarch64::vmm::FrameCowWriteIntent,
        flush_stage1: &mut dyn FnMut() -> Result<(), TrapError>,
    ) -> Result<(), TrapError> {
        if len == 0 {
            return Ok(());
        }
        let start = strip_pointer_tag(va);
        let end = start
            .checked_add(len as u64)
            .ok_or_else(|| TrapError::Hypervisor("HVPatch COW write range overflow".to_owned()))?;
        let mut current = start;
        while current < end {
            let armed = self.cow_armed.lock().span_for(current).is_some();
            let (retained_output_has_no_physical_source, retained_output_source_is_shared) =
                if intent == carrick_aarch64::vmm::FrameCowWriteIntent::BackingMaintenance
                    && self.persistent_vm_lifecycle
                {
                    match self
                        .page_tables
                        .lock()
                        .as_ref()
                        .and_then(|manager| manager.translate_retained_output(current))
                    {
                        Some(ipa) => {
                            // The retired-reuse materializer serves UNMAPPED
                            // VAs whose leaf retained a dead output. A LIVE VA
                            // in that state (a brk-heap page whose fork-COW
                            // lease retired underneath it) is not its case —
                            // the materializer refuses it by design, and
                            // routing it there turned every brk SHRINK over
                            // such a page into a refusal (ltp-brk02). A live
                            // VA's scrub resolves through its live backing.
                            let unmapped = self.protections.range_unmapped(current, 1);
                            let no_source =
                                unmapped && self.physical_cow_source(current, ipa).is_none();
                            let shared = unmapped
                                && !no_source
                                && self.retained_output_lacks_exclusive_claim(ipa);
                            (no_source, shared)
                        }
                        None => (false, false),
                    }
                } else {
                    (false, false)
                };
            let route = frame_cow_write_route(
                intent,
                armed,
                retained_output_has_no_physical_source,
                retained_output_source_is_shared,
            );
            if let Some(debug_va) = std::env::var("CARRICK_FORK_DEBUG_VA")
                .ok()
                .and_then(|raw| u64::from_str_radix(raw.trim_start_matches("0x"), 16).ok())
                && current <= debug_va
                && debug_va < end.min(current.saturating_add(CowArmedRanges::COMPOUND_SIZE))
            {
                eprintln!(
                    "[ROUTEDBG pid={:?}] va={current:#x} intent={intent:?} armed={armed} \
                     no_source={retained_output_has_no_physical_source} \
                     shared={retained_output_source_is_shared} route={route:?}",
                    self.cow_identity.map(|identity| identity.linux_pid),
                );
            }
            match route {
                FrameCowWriteRoute::MaterializeRetired => {
                    if let Some(materialized_end) =
                        self.materialize_retired_reuse(current, end, flush_stage1)?
                    {
                        current = materialized_end;
                    }
                    // The materializer rechecks after acquiring quiesce. If a
                    // sibling repaired the leaf first, restart this chunk and
                    // route against the now-current stage-1/physical state.
                    continue;
                }
                FrameCowWriteRoute::CopyOnWrite => {
                    let class = match intent {
                        carrick_aarch64::vmm::FrameCowWriteIntent::GuestVisible => {
                            carrick_observability::probes::HvpatchFrameCowTriggerClass::SyscallGuestWrite
                        }
                        carrick_aarch64::vmm::FrameCowWriteIntent::BackingMaintenance => {
                            carrick_observability::probes::HvpatchFrameCowTriggerClass::BackingMaintenance
                        }
                        carrick_aarch64::vmm::FrameCowWriteIntent::PrivilegedInternal => {
                            carrick_observability::probes::HvpatchFrameCowTriggerClass::PrivilegedInternal
                        }
                    };
                    if !self.perform_frame_cow(
                        current,
                        intent,
                        FrameCowTrigger {
                            class,
                            syndrome: 0,
                            far: current,
                            ttbr0: 0,
                        },
                        flush_stage1,
                    )? {
                        return Err(TrapError::Hypervisor(format!(
                            "HVPatch COW write at 0x{current:x} remained armed"
                        )));
                    }
                }
                FrameCowWriteRoute::Direct => {}
            }
            let next = align_down(current, CowArmedRanges::COMPOUND_SIZE)
                .saturating_add(CowArmedRanges::COMPOUND_SIZE);
            current = next.min(end);
        }
        Ok(())
    }

    pub(crate) fn observe_frame_cow_protection(
        &mut self,
        va: u64,
        len: usize,
        prot: u64,
    ) -> Result<(), TrapError> {
        const PAGE_SIZE: u64 = 4 * 1024;
        const VALID: u64 = 1;
        const AP_MASK: u64 = 0b11 << 6;
        const AP_USER_RW: u64 = 0b01 << 6;
        const AP_USER_RO: u64 = 0b11 << 6;
        const NON_GLOBAL: u64 = 1 << 11;

        if len == 0 {
            return Ok(());
        }
        let end = va.checked_add(len as u64).ok_or_else(|| {
            TrapError::Hypervisor("deferred COW protection range overflow".to_owned())
        })?;
        let pending: Vec<_> = self
            .cow_deferred_publications
            .lock()
            .iter()
            .copied()
            .filter(|receipt| {
                receipt
                    .va
                    .checked_add(receipt.len as u64)
                    .is_some_and(|receipt_end| receipt.va < end && receipt_end > va)
            })
            .collect();
        if pending.is_empty() {
            return Ok(());
        }

        let page_table_host = self
            .mapping_for_range(
                crate::memory::LINUX_PAGE_TABLES_BASE,
                carrick_mem::memory::LINUX_PAGE_TABLES_SIZE as usize,
            )
            .map(|mapping| mapping.host_addr)
            .ok_or_else(|| {
                TrapError::Hypervisor(
                    "deferred COW protection has no page-table backing".to_owned(),
                )
            })?;
        let prot_flags = carrick_abi::LinuxProtFlags::from_bits_truncate(prot);
        let (expected_ap, phase, must_be_valid) =
            if prot_flags.contains(carrick_abi::LinuxProtFlags::WRITE) {
                (AP_USER_RW, 4, true)
            } else if prot_flags
                .intersects(carrick_abi::LinuxProtFlags::READ | carrick_abi::LinuxProtFlags::EXEC)
            {
                (AP_USER_RO, 5, true)
            } else {
                (AP_USER_RO, 6, false)
            };

        let page_tables = self.page_tables.lock();
        let manager = page_tables.as_ref().ok_or_else(|| {
            TrapError::Hypervisor("deferred COW protection has no page-table manager".to_owned())
        })?;
        let mut authenticated = Vec::with_capacity(pending.len());
        for receipt in pending {
            let receipt_end = receipt.va.checked_add(receipt.len as u64).ok_or_else(|| {
                TrapError::Hypervisor("deferred COW receipt range overflow".to_owned())
            })?;
            let overlap_start = receipt.va.max(va);
            let overlap_end = receipt_end.min(end);
            if !overlap_start.is_multiple_of(PAGE_SIZE) || !overlap_end.is_multiple_of(PAGE_SIZE) {
                return Err(TrapError::Hypervisor(format!(
                    "deferred COW receipt/protection is not page aligned: receipt=0x{:x}..0x{receipt_end:x} protection=0x{va:x}..0x{end:x}",
                    receipt.va
                )));
            }
            let mut page = overlap_start;
            let mut first_leaf = None;
            while page < overlap_end {
                let expected_ipa = receipt
                    .expected_ipa
                    .checked_add(page - receipt.va)
                    .ok_or_else(|| {
                        TrapError::Hypervisor("deferred COW receipt IPA range overflow".to_owned())
                    })?;
                let shadow = manager.debug_walk(page);
                let live = unsafe { manager.debug_walk_host(page_table_host.cast_const(), page) };
                let leaf = carrick_mem::page_table::terminal_descriptor(live);
                let access_is_valid = leaf & VALID != 0;
                let translated = if must_be_valid {
                    manager.translate(page)
                } else {
                    manager.translate_retained_output(page)
                };
                if shadow != live
                    || translated != Some(expected_ipa)
                    || leaf & NON_GLOBAL == 0
                    || leaf & AP_MASK != expected_ap
                    || access_is_valid != must_be_valid
                {
                    return Err(TrapError::Hypervisor(format!(
                        "deferred COW protection authentication failed at VA 0x{page:x}: leaf=0x{leaf:x} translated={translated:x?} expected_ipa=0x{expected_ipa:x} expected_ap=0x{expected_ap:x} valid={must_be_valid} receipt=0x{:x}+0x{:x}",
                        receipt.va, receipt.len
                    )));
                }
                first_leaf.get_or_insert((page, leaf, expected_ipa));
                page = page.saturating_add(PAGE_SIZE);
            }
            if let Some((page, leaf, expected_ipa)) = first_leaf {
                crate::probes::pt_alias_receipt(page, leaf, expected_ipa, expected_ap, phase);
            }
            authenticated.push(receipt);
        }
        drop(page_tables);

        let mut receipts = self.cow_deferred_publications.lock();
        let mut remaining = Vec::with_capacity(receipts.len());
        for receipt in receipts.drain(..) {
            if !authenticated.contains(&receipt) {
                remaining.push(receipt);
                continue;
            }
            let receipt_end = receipt.va.saturating_add(receipt.len as u64);
            let overlap_start = receipt.va.max(va);
            let overlap_end = receipt_end.min(end);
            if receipt.va < overlap_start {
                remaining.push(PendingFrameCowPublication {
                    va: receipt.va,
                    len: usize::try_from(overlap_start - receipt.va)
                        .unwrap_or_else(|_| std::process::abort()),
                    expected_ipa: receipt.expected_ipa,
                });
            }
            if overlap_end < receipt_end {
                remaining.push(PendingFrameCowPublication {
                    va: overlap_end,
                    len: usize::try_from(receipt_end - overlap_end)
                        .unwrap_or_else(|_| std::process::abort()),
                    expected_ipa: receipt
                        .expected_ipa
                        .checked_add(overlap_end - receipt.va)
                        .unwrap_or_else(|| std::process::abort()),
                });
            }
        }
        *receipts = remaining;
        Ok(())
    }

    /// Create a fresh vCPU bound to this VM (the boot/clone/fork/reclaim
    /// vcpu_create; admission is the bounded scheduler's job, NOT this path).
    pub(crate) fn add_vcpu(
        &mut self,
    ) -> Result<(applevisor::vcpu::Vcpu, MailboxBinding), TrapError> {
        let vcpu = create_vcpu(&self._vm)?;
        enable_el0_counter_access(vcpu.id());
        self.vcpu_id = vcpu.id();
        self.vcpu_handle = vcpu.get_handle();
        let mailbox = self.allocate_mailbox_for_vcpu(&vcpu)?;
        Ok((vcpu, mailbox))
    }

    fn mailbox_host_pointer(
        &self,
        slot: MailboxSlotId,
    ) -> Result<std::ptr::NonNull<carrick_aarch64::mailbox::Aarch64SyscallMailbox>, TrapError> {
        let address = slot.guest_address();
        let size = carrick_aarch64::mailbox::AARCH64_SYSCALL_MAILBOX_SIZE as usize;
        let pointer = self
            .translate_va(address)
            .and_then(|ipa| {
                Self::mailbox_mapping_for_range(&self.mappings, address, ipa, size).map(|mapping| {
                    let offset =
                        usize::try_from(address.saturating_sub(mapping.start)).unwrap_or_default();
                    unsafe { mapping.host_addr.add(offset) }
                })
            })
            // A persistent-VM exec deliberately drops the software page-table
            // manager until the first real edit. The mailbox lives in a static
            // boot mapping whose guest-VA extent is unambiguous, so resolve that
            // mapping directly instead of paying a 1.8 MiB table clone solely to
            // recover the root-slot/global-frame IPA during publication.
            .or_else(|| {
                let mapping = self.mapping_for_range(address, size)?;
                let offset = usize::try_from(address.checked_sub(mapping.start)?).ok()?;
                Some(unsafe { mapping.host_addr.add(offset) })
            })
            .or_else(|| {
                self.carrier_mappings
                    .as_ref()?
                    .host_pointer(address, size)
                    .map(std::ptr::NonNull::as_ptr)
            })
            .ok_or_else(|| {
                TrapError::Hypervisor(format!(
                    "AArch64 syscall mailbox slot {} at {address:#x} is not mapped",
                    slot.raw()
                ))
            })?;
        std::ptr::NonNull::new(pointer.cast()).ok_or_else(|| {
            TrapError::Hypervisor(format!(
                "AArch64 syscall mailbox slot {} resolved to a null host pointer",
                slot.raw()
            ))
        })
    }

    fn allocate_mailbox_for_vcpu(
        &self,
        vcpu: &applevisor::vcpu::Vcpu,
    ) -> Result<MailboxBinding, TrapError> {
        use applevisor::prelude::SysReg;

        let lease = self
            .mailbox_slots
            .allocate()
            .map_err(|error| TrapError::Hypervisor(error.to_string()))?;
        let address = lease.id().guest_address();
        let pointer = self.mailbox_host_pointer(lease.id())?;
        // SAFETY: `mailbox_host_pointer` resolved the complete fixed slot from
        // this VM's process-lifetime mapping, and the lease uniquely owns it.
        let binding = unsafe { MailboxBinding::new(lease, pointer, self.syscall_transport) };
        vcpu.set_sys_reg(SysReg::SP_EL1, address)
            .map_err(hvf_error)?;
        Ok(binding)
    }

    fn rebind_mailbox_after_vcpu_create(
        &self,
        vcpu: &applevisor::vcpu::Vcpu,
        binding: &mut MailboxBinding,
        preserve_outstanding: bool,
    ) -> Result<(), TrapError> {
        use applevisor::prelude::SysReg;

        let pointer = self.mailbox_host_pointer(binding.slot())?;
        // SAFETY: the refreshed pointer covers the same uniquely leased slot in
        // the rebuilt VM mapping and remains live until another rebuild/drop.
        unsafe { binding.rebind(pointer, preserve_outstanding) };
        vcpu.set_sys_reg(SysReg::SP_EL1, binding.slot().guest_address())
            .map_err(hvf_error)
    }

    pub(crate) fn relocate_mailbox_after_cow(
        &self,
        binding: &mut MailboxBinding,
    ) -> Result<(), TrapError> {
        let pointer = self.mailbox_host_pointer(binding.slot())?;
        // SAFETY: the live stage-1 walk resolves the complete replacement
        // backing for this binding's uniquely leased slot. The COW copied the
        // prior header before the guest published its request into that backing,
        // so relocation must not reset or regenerate any protocol field.
        unsafe { binding.relocate_after_cow(pointer) };
        let diagnostics = binding.diagnostics();
        if diagnostics.generation != binding.generation() {
            return Err(TrapError::Hypervisor(format!(
                "AArch64 mailbox COW relocation changed generation: binding={} backing={}",
                binding.generation(),
                diagnostics.generation
            )));
        }
        Ok(())
    }

    pub(crate) fn enrich_mailbox_run_error(
        &self,
        binding: &MailboxBinding,
        error: TrapError,
    ) -> TrapError {
        let TrapError::Hypervisor(message) = error else {
            return error;
        };
        if !message.contains("without a published mailbox request") {
            return TrapError::Hypervisor(message);
        }
        let slot = binding.slot();
        let address = slot.guest_address();
        let translated_ipa = self.translate_va(address);
        let live = self.mailbox_host_pointer(slot).ok();
        let live_diagnostics = live.map(|pointer| {
            // SAFETY: `mailbox_host_pointer` authenticated a complete live slot,
            // and the vCPU is stopped at the HVC that produced `error`.
            unsafe { MailboxBinding::diagnostics_at(pointer) }
        });
        TrapError::Hypervisor(format!(
            "{message}; mailbox_route={{slot={}, va={address:#x}, translated_ipa={translated_ipa:?}, binding_host={:#x}, live_host={:?}, live={live_diagnostics:?}}}",
            slot.raw(),
            binding.host_address(),
            live.map(|pointer| pointer.as_ptr() as usize),
        ))
    }

    fn release_mailbox_for_reclaim(&self, binding: &mut MailboxBinding) -> Result<(), TrapError> {
        binding.release_for_reclaim().map_err(|error| {
            TrapError::Hypervisor(format!("park AArch64 syscall mailbox: {error}"))
        })
    }

    fn reacquire_mailbox_after_vcpu_create(
        &self,
        vcpu: &applevisor::vcpu::Vcpu,
        binding: &mut MailboxBinding,
        continuation: Option<carrick_hal::threaded::Aarch64SyscallContinuationV1>,
    ) -> Result<(), TrapError> {
        use applevisor::prelude::SysReg;

        let lease = self
            .mailbox_slots
            .allocate()
            .map_err(|error| TrapError::Hypervisor(error.to_string()))?;
        let address = lease.id().guest_address();
        let pointer = self.mailbox_host_pointer(lease.id())?;
        // SAFETY: the allocator lease uniquely owns the complete fixed slot.
        unsafe { binding.reacquire_after_reclaim(lease, pointer, continuation) }.map_err(
            |error| TrapError::Hypervisor(format!("resume AArch64 syscall mailbox: {error}")),
        )?;
        vcpu.set_sys_reg(SysReg::SP_EL1, address).map_err(hvf_error)
    }

    /// Host pointer backing `[gpa, gpa+len)`, or `None` if unmapped. The
    /// engine's `GuestMemory` copies through this; HVF resolves it via the same
    /// per-thread mapping walk (with the stage-1-IPA disambiguation) the
    /// syscall path uses.
    pub(crate) fn host_ptr(&self, gpa: u64, len: usize) -> Option<*mut u8> {
        if let Some(mapping) = Self::mapping_for_ipa_range(&self.mappings, gpa, len.max(1)) {
            let offset = (gpa.wrapping_sub(mapping.ipa)) as usize;
            return Some(unsafe { mapping.host_addr.add(offset) });
        }
        self.carrier_mappings
            .as_ref()?
            .host_pointer_for_ipa(gpa, len)
    }

    /// Copy `bytes` into guest physical memory at `gpa` (raw GPA, no PROT_NONE
    /// gate, no permission check — the engine's run-elf / page-table seed path).
    pub(crate) fn write_gpa(&self, gpa: u64, bytes: &[u8]) -> Result<(), MemoryError> {
        let Some(host) = self.host_ptr(gpa, bytes.len()) else {
            return Err(MemoryError::OutOfBounds {
                address: gpa,
                length: bytes.len(),
            });
        };
        unsafe {
            volatile_copy_to_guest(bytes.as_ptr(), host, bytes.len());
        }
        Ok(())
    }

    /// Read `len` bytes of live guest memory at guest-physical `gpa` (no VA
    /// translation, no PROT_NONE gate).
    pub(crate) fn read_gpa(&self, gpa: u64, len: usize) -> Result<Vec<u8>, MemoryError> {
        let Some(host) = self.host_ptr(gpa, len) else {
            return Err(MemoryError::OutOfBounds {
                address: gpa,
                length: len,
            });
        };
        let mut out = vec![0u8; len];
        unsafe {
            volatile_copy_from_guest(host, out.as_mut_ptr(), len);
        }
        Ok(out)
    }

    /// Map host memory at a stage-2 IPA (`hv_vm_map`). The STAGE-1 path stays in
    /// the engine; this is the backend stage-2 op only.
    pub(crate) fn map_stage2(
        &mut self,
        ipa: u64,
        host: *mut u8,
        len: u64,
        perms: carrick_hal::MemPerms,
    ) -> Result<(), TrapError> {
        let perms_raw: u64 = u64::from(hvf_mem_perms(perms));
        let r = unsafe {
            inventory_hv_vm_map(host as *mut std::ffi::c_void, ipa, len as usize, perms_raw)
        };
        if r != 0 {
            return Err(TrapError::Hypervisor(format!(
                "hv_vm_map(ipa=0x{ipa:x}, size={len}) failed: 0x{r:x}"
            )));
        }
        Ok(())
    }

    /// The HVF-only lazy high-VA alias re-map: a forked child rebuilt its VM
    /// from only the forking thread's mappings, dropping a global-shared alias a
    /// sibling thread mapped; re-`hv_vm_map` the registered host backing into
    /// THIS VM so the faulting instruction re-executes cleanly. Returns true iff
    /// it remapped. (The engine's `next_syscall` already runs the bounded in-loop
    /// remap; this is the `handle_memory_exit` hook surface — kept for the trait,
    /// driven on the rare path the in-loop remap doesn't cover.)
    pub(crate) fn try_lazy_alias_remap(&mut self, gpa: u64, va: u64) -> bool {
        let backing = if gpa != 0 {
            lookup_shared_alias(gpa)
        } else {
            lookup_shared_alias_by_va(va, 1, self.mm_root_slot)
        };
        let Some(b) = backing else {
            return false;
        };
        // SAFETY: `host_addr` is a live MAP_SHARED mmap registered by
        // `add_alias`. Replay succeeds only when HVF confirms the installation;
        // an arbitrary nonzero result is never evidence that a racing mapper won.
        let rc = unsafe { inventory_hv_vm_map_replay(b) };
        crate::probes::hv_vm_map_alias(
            va,
            b.physical_ipa,
            b.physical_size as u64,
            rc as i32,
            self.forked_no_exec as i32,
        );
        rc == 0
    }

    /// Back a dynamic high-VA `mmap` (`DispatchOutcome::MapHostAlias`): allocate
    /// the low alias IPA, `hv_vm_map` the host file/anon backing there, register
    /// the alias process-globally, and add the per-thread region — returning the
    /// `(gpa = ipa, writable)` the engine then threads into the SHARED stage-1
    /// `map_aliased`. RWX so a JIT (Rosetta) can write+execute it; the guest may
    /// `mprotect` afterwards.
    ///
    /// Mirrors the old `map_host_alias`, with the IPA derived HERE (the dispatcher
    /// no longer supplies it through the shared `map_host_alias` seam): the same
    /// `crate::memory::alloc_alias_ipa` the dispatcher used.
    pub(crate) fn add_alias(
        &mut self,
        va: u64,
        ipa: u64,
        len: u64,
        payload: &[u8],
        file: Option<(libc::c_int, libc::off_t, libc::c_int)>,
    ) -> Result<(u64, bool), TrapError> {
        self.add_alias_with_sharing(va, ipa, len, payload, file, false)
    }

    /// Back a high-VA alias with the anonymous sharing mode carried by the
    /// original VMA. A deferred `mprotect` commit must preserve MAP_SHARED
    /// across host fork rather than silently substituting private COW backing.
    pub(crate) fn add_alias_with_sharing(
        &mut self,
        va: u64,
        ipa: u64,
        len: u64,
        payload: &[u8],
        file: Option<(libc::c_int, libc::off_t, libc::c_int)>,
        shared: bool,
    ) -> Result<(u64, bool), TrapError> {
        let file = file.map(|(fd, offset, prot)| {
            // SAFETY: dispatcher-to-backend alias setup transfers this dup.
            (unsafe { OwnedFd::from_raw_fd(fd) }, offset, prot)
        });
        let sharing = match (file.as_ref(), shared) {
            (Some(_), _) => GuestMappingSharing::GlobalShared,
            (None, true) => GuestMappingSharing::ForkSharedAnonymous,
            (None, false) => GuestMappingSharing::Private,
        };
        let inventory_backing = match file.as_ref() {
            Some((fd, offset, _)) => {
                let mut stat: libc::stat = unsafe { std::mem::zeroed() };
                if unsafe { libc::fstat(fd.as_raw_fd(), &mut stat) } != 0 {
                    return Err(TrapError::Hypervisor(format!(
                        "identify HVPatch shared-file frame: {}",
                        std::io::Error::last_os_error()
                    )));
                }
                let offset = u64::try_from(*offset).map_err(|_| {
                    TrapError::Hypervisor(
                        "HVPatch shared-file frame has negative offset".to_owned(),
                    )
                })?;
                InventoryBackingIdentity::SharedFile {
                    device: stat.st_dev as u64,
                    inode: stat.st_ino as u64,
                    offset,
                    length: len,
                }
            }
            None if sharing == GuestMappingSharing::ForkSharedAnonymous => {
                Self::shared_anon_backing_identity()
            }
            None => Self::private_backing_identity(),
        };
        // Mature VMM/root uses the IPA the dispatcher allocated from the global
        // alias arena. An in-process hvpatch mm relocates non-global aliases into
        // its mm scope; the returned GPA is authoritative for stage-1, while
        // dispatcher VMA metadata remains keyed by VA and needs no IPA.
        // hv_vm_map requires a 16 KiB-granular size; round the HOST mapping up
        // to the HVF granule. The stage-1 `map_aliased` (the engine, on the exact
        // `len`) below still maps only the guest's page-aligned request, so a
        // sub-16 KiB mmap never maps extra 4 KiB guest pages into a neighbouring
        // region's page-table entries (which would redirect that region's
        // fetches/reads to the wrong IPA — the amd64 Rosetta JIT undefined-
        // instruction bug).
        let hvf_len = align_up(len, HVF_PAGE_SIZE)?;
        let guest_size = usize::try_from(len).map_err(|_| TrapError::MappingTooLarge(len))?;
        let requested_physical_size =
            usize::try_from(hvf_len).map_err(|_| TrapError::MappingTooLarge(len))?;
        let guest_end = va.checked_add(len).ok_or(TrapError::MappingOverflow {
            guest_start: va,
            mapped_size: len,
        })?;
        // The host page is mapped at the guest's actual prot (map_shared_file),
        // so a PROT_READ file alias has a read-only host backing. Track the
        // guest-intended writability so the syscall write-path returns EFAULT
        // instead of SIGBUS-ing the host. Anon aliases are RW-backed.
        let alias_guest_writable = match file.as_ref() {
            Some((_, _, prot)) => *prot & libc::PROT_WRITE != 0,
            None => true,
        };
        let (shared_key_base, shared_key_offset) = match file.as_ref() {
            Some((fd, offset, _)) => (
                shared_file_key_base(fd.as_raw_fd()),
                u64::try_from(*offset).unwrap_or_default(),
            ),
            None => (0, 0),
        };
        let host_mapping = match file.as_ref() {
            // Live MAP_SHARED file: back the guest region with the file's page
            // cache directly, so writes are coherent with other openers and
            // survive fork. The dispatcher handed us a dup'd fd it owns; mmap
            // takes its own reference, so close the dup once mapped.
            Some((fd, offset, prot)) => crate::host_mapping::OwnedHostMapping::map_shared_file(
                fd.as_raw_fd(),
                *offset,
                requested_physical_size,
                *prot,
            )
            .map_err(|e| {
                TrapError::Hypervisor(format!(
                    "alias MAP_SHARED file (fd={} off={offset} size={requested_physical_size} prot={prot}) failed: {e}",
                    fd.as_raw_fd()
                ))
            })?,
            None => crate::host_mapping::OwnedHostMapping::map_shared_anon(
                requested_physical_size,
                if sharing.shares_across_fork() {
                    crate::host_mapping::HostMappingKind::SharedAnon
                } else {
                    crate::host_mapping::HostMappingKind::PrivateAnon
                },
            )
            .map_err(|e| {
                TrapError::Hypervisor(format!(
                    "alias mmap (size={requested_physical_size}) failed: {e}"
                ))
            })?,
        };
        let host = host_mapping.as_ptr();
        let physical_size = host_mapping.len();
        // Seed the file content (empty for anon — the anon mapping is zeroed; a
        // live MAP_SHARED file mapping is already backed by the page cache).
        if file.is_none() && !payload.is_empty() {
            let n = payload.len().min(guest_size);
            unsafe { std::ptr::copy_nonoverlapping(payload.as_ptr(), host, n) };
        }
        // Alias mappings keep permissive stage-2 rights; guest-visible
        // protections are enforced in stage-1 and adjusted by mprotect.
        let perms = hvf_perms(SegmentPerms {
            read: true,
            write: true,
            execute: true,
        });
        // Reserve the global-frame lease on a 2 MiB boundary, NOT the 16 KiB
        // COW compound granule. The dispatcher hands this path a 2 MiB-aligned
        // alias VA, so a 2 MiB-aligned output keeps VA and IPA congruent and
        // lets the stage-1 editor express the mapping as 1 GiB/2 MiB block
        // leaves. A 16 KiB-aligned base breaks that congruence, and since no
        // block leaf can then be expressed ANYWHERE the whole alias falls to
        // 4 KiB pages — one fresh L3 table per 2 MiB, which exhausts the
        // 440-page spare pool at ~850 MiB and fails the build (CPython's
        // `test_mmap` LargeMmapTests hung there). The sparse-arena sibling
        // reserves on `TWO_MIB` for exactly this reason.
        const TWO_MIB: u64 = 2 * 1024 * 1024;
        let mut global_lease = if self.persistent_vm_lifecycle {
            Some(GlobalFrameStage2Lease::reserve(hvf_len, TWO_MIB)?)
        } else {
            None
        };
        let ipa = global_lease.as_ref().map_or(ipa, |lease| lease.base);
        let r = unsafe { inventory_hv_vm_map(host.cast(), ipa, physical_size, u64::from(perms)) };
        crate::probes::hv_vm_map_alias(
            va,
            ipa,
            physical_size as u64,
            r as i32,
            self.forked_no_exec as i32,
        );
        if r != 0 {
            return Err(TrapError::Hypervisor(format!(
                "hv_vm_map alias va=0x{va:x} ipa=0x{ipa:x} size={physical_size} failed: 0x{r:x}"
            )));
        }
        if let Some(lease) = global_lease.as_mut() {
            lease.mark_mapped();
        }
        let host_mapping = if self.persistent_vm_lifecycle {
            register_global_frame_host_owner(
                global_lease.take().ok_or_else(|| {
                    TrapError::Hypervisor("HVPatch alias lost its global IPA lease".to_owned())
                })?,
                host_mapping,
                u64::from(perms),
            )?;
            None
        } else {
            Some(host_mapping)
        };
        // Register EVERY alias (MAP_SHARED file AND private anon — Go's high-VA
        // heap arenas) process-globally in `alias_registry`. Two consumers: the
        // stage-2 lazy on-fault re-map (a forked VM that lost the alias), and the
        // SYSCALL-PATH cross-thread fallback in `mapping_for_range` (a sibling
        // thread whose per-thread `mappings` never saw this alias — the
        // "read/wait: bad address" EFAULT). The index is non-owning (raw
        // host_addr) and removed on munmap. guest_writable is carried so a
        // PROT_READ file alias still EFAULTs a syscall write via the fallback
        // instead of SIGBUS-ing the host.
        register_shared_alias(AliasBacking {
            start: va,
            ipa,
            host_addr: host as usize,
            size: guest_size,
            physical_ipa: ipa,
            physical_host_addr: host as usize,
            physical_size,
            perms: u64::from(perms),
            guest_writable: alias_guest_writable,
            sharing,
            ownership_scope: alias_ownership_scope(sharing, self.mm_root_slot),
            inventory_backing,
            shared_key_base,
            shared_key_offset,
            owner_generation: global_frame_host_owner_generation(ipa, physical_size as u64),
        });
        self.mappings.push(HvfMappedRegion {
            start: va,
            ipa,
            physical_ipa: ipa,
            end: guest_end,
            host_addr: host,
            size: physical_size,
            physical_size,
            perms,
            memory: None,
            host_mapping,
            stage2_lease: None,
            is_dynamic_alias: true,
            sharing,
            guest_writable: alias_guest_writable,
            shared_key_base,
            shared_key_offset,
            owner_generation: global_frame_host_owner_generation(ipa, physical_size as u64),
        });
        if self.persistent_vm_lifecycle {
            let mut inventory = self.frame_inventory.lock();
            let mut reservation = inventory.alias_reservation.take().unwrap_or_else(|| {
                eprintln!(
                    "carrick: FATAL: HVPatch alias mapped without frame inventory reservation"
                );
                std::process::abort();
            });
            match Self::stage_mapping(
                &mut inventory,
                &mut reservation,
                InventoryMappingStage {
                    gpa: ipa,
                    length: physical_size as u64,
                    permissions: carrick_hal::MemPerms {
                        read: true,
                        write: true,
                        exec: true,
                    },
                    backing: inventory_backing,
                    inherited_frame: None,
                    stage2_lease: None,
                },
            ) {
                Ok(extent) => {
                    tracing::trace!(
                        mapping = ?extent.mapping,
                        frame = ?extent.frame,
                        gpa = format_args!("{ipa:#x}"),
                        "hvpatch alias stage"
                    );
                    inventory
                        .alias_staged
                        .push(((ipa, physical_size as u64), extent));
                }
                Err(error) => {
                    eprintln!("carrick: FATAL: stage inventory after HVPatch alias map: {error}");
                    std::process::abort();
                }
            }
            inventory.alias_commit = Some(reservation.commit(()));
        }
        Ok((ipa, alias_guest_writable))
    }

    fn emulate_el0_sys64_read_inner(
        vcpu: &mut applevisor::vcpu::Vcpu,
        esr: u64,
    ) -> Result<bool, TrapError> {
        use applevisor::prelude::*;

        // EL0 read of a feature-ID register (the CRn==0, Op0==3, Op1==0 space).
        // The Linux kernel emulates these for userspace; Apple Rosetta reads
        // ID_AA64MMFR1_EL1 (and friends) at startup, and without this the MRS
        // takes a fatal undef. Return the real vCPU value. (The Op1==3 timer /
        // CTR_EL0 / DCZID_EL0 reads handled below are a separate space.)
        let op0 = (esr >> 20) & 0x3;
        let op1 = (esr >> 14) & 0x7;
        let crn = (esr >> 10) & 0xf;
        let crm = (esr >> 1) & 0xf;
        let op2 = (esr >> 17) & 0x7;
        let direction_read = esr & 1 == 1;
        if direction_read && op0 == 3 && op1 == 0 && crn == 0 {
            let rt_id = ((esr >> 5) & 0x1f) as usize;
            let enc = (op0 << 14) | (op1 << 11) | (crn << 7) | (crm << 3) | op2;
            let id_reg = match enc {
                0xc000 => Some(SysReg::MIDR_EL1),
                0xc020 => Some(SysReg::ID_AA64PFR0_EL1),
                0xc021 => Some(SysReg::ID_AA64PFR1_EL1),
                0xc028 => Some(SysReg::ID_AA64DFR0_EL1),
                0xc029 => Some(SysReg::ID_AA64DFR1_EL1),
                0xc030 => Some(SysReg::ID_AA64ISAR0_EL1),
                0xc031 => Some(SysReg::ID_AA64ISAR1_EL1),
                0xc038 => Some(SysReg::ID_AA64MMFR0_EL1),
                0xc039 => Some(SysReg::ID_AA64MMFR1_EL1),
                0xc03a => Some(SysReg::ID_AA64MMFR2_EL1),
                // Any other CRn==0/Op0==3/Op1==0 slot reads-as-zero (RES0),
                // matching the architectural default for unallocated ID regs.
                _ => None,
            };
            let value = match id_reg {
                Some(reg) => vcpu.get_sys_reg(reg).map_err(hvf_error)?,
                None => 0,
            };
            if let Some(target) = GPR_TABLE.get(rt_id) {
                vcpu.set_reg(*target, value).map_err(hvf_error)?;
            }
            let elr = vcpu.get_sys_reg(SysReg::ELR_EL1).map_err(hvf_error)?;
            vcpu.set_sys_reg(SysReg::ELR_EL1, elr.wrapping_add(4))
                .map_err(hvf_error)?;
            return Ok(true);
        }

        let Some((rt, reg)) = decode_el0_sys64_read(esr) else {
            return Ok(false);
        };
        let value = match reg {
            El0SysRegRead::CntfrqEl0 => AARCH64_GUEST_COUNTER_HZ,
            El0SysRegRead::CntvctEl0 => guest_counter_ticks(),
            // Fallback if a guest's CTR_EL0/DCZID_EL0 read still traps despite
            // SCTLR_EL1.UCT/DZE (e.g. a forked child before its sysregs are
            // re-applied). Return the real host cache geometry.
            El0SysRegRead::CtrEl0 => host_ctr_dczid().0,
            El0SysRegRead::DczidEl0 => host_ctr_dczid().1,
        };
        if let Some(target) = GPR_TABLE.get(rt as usize) {
            vcpu.set_reg(*target, value).map_err(hvf_error)?;
        }
        let elr = vcpu.get_sys_reg(SysReg::ELR_EL1).map_err(hvf_error)?;
        vcpu.set_sys_reg(SysReg::ELR_EL1, elr.wrapping_add(4))
            .map_err(hvf_error)?;
        Ok(true)
    }

    /// True if `[address, address+length)` overlaps any PROT_NONE range. Used
    /// to fault syscall-path accesses to a guest PROT_NONE buffer (EFAULT).
    fn range_no_access(&self, address: u64, length: usize) -> bool {
        self.protections.range_no_access(address, length)
    }

    pub(crate) fn read_guest_bytes(
        &self,
        address: u64,
        length: usize,
    ) -> Result<Vec<u8>, MemoryError> {
        let mut bytes = vec![0u8; length];
        self.read_guest_bytes_into(address, &mut bytes)?;
        Ok(bytes)
    }

    /// No-alloc core of [`Self::read_guest_bytes`]: `volatile`-copy `dst.len()` bytes
    /// of guest memory at `address` straight into `dst`. Same checks, chunked
    /// mapping walk, and trace probes as the allocating form.
    pub(crate) fn read_guest_bytes_into(
        &self,
        address: u64,
        dst: &mut [u8],
    ) -> Result<(), MemoryError> {
        let length = dst.len();
        // PROT_NONE gated once in the default `GuestMemory::read_bytes`/`read_into`.
        let mut copied = 0usize;
        while copied < length {
            let (chunk_address, chunk_len) = Self::guest_copy_chunk(address, copied, length)?;
            // For a `repoint_private` overlay VA the region+offset are keyed on the
            // translated overlay IPA, not the VA (see `syscall_buffer_lookup_addr`).
            // Identity otherwise — no walk. PROT_NONE was already gated on the VA.
            let translated_lookup = self.syscall_buffer_lookup_addr(chunk_address, chunk_len);
            let (lookup_address, mapping_start, mapping_end, mapping_ipa, host_addr) = {
                // Private-overlay descriptors are keyed by their translated
                // IPA, while a boot brk descriptor remains keyed by Linux VA
                // even after HVPatch repoints its stage-1 leaf to a reusable
                // global frame. Keep translated-first ordering for the former,
                // but join the latter through mapping_for_range's authoritative
                // VA -> stage-1 IPA -> live global-owner path when the direct
                // IPA lookup has no descriptor.
                let resolved =
                    resolve_guest_copy_mapping(translated_lookup, chunk_address, |lookup| {
                        self.mapping_for_range(lookup, chunk_len)
                    });
                let Some((lookup_address, mapping)) = resolved else {
                    // `syscall_buffer_lookup_addr` deliberately stays identity
                    // for the common heap/stack hot path. Core capture has
                    // loaded the live software observer, so use its exact leaf
                    // output—not that shortcut—to join a descriptorless exec
                    // heap to the current global-frame owner.
                    let stage1_lookup = self
                        .translate_va(chunk_address)
                        .unwrap_or(translated_lookup);
                    let Some((mapping_start, mapping_end)) = copy_from_global_frame_owner(
                        stage1_lookup,
                        &mut dst[copied..copied + chunk_len],
                    ) else {
                        let stage1 = self.translate_va(chunk_address);
                        let semantic_mapping = self
                            .mappings
                            .iter()
                            .any(|mapping| mapping.contains_range(chunk_address, chunk_len));
                        let stage1_mapping = stage1.is_some_and(|ipa| {
                            self.mappings
                                .iter()
                                .any(|mapping| Self::region_owns_ipa(mapping, ipa))
                        });
                        let owner_count = global_frame_host_owners().lock().len();
                        return Err(MemoryError::HostMap(format!(
                            "live core read has no current backing: va=0x{chunk_address:x} len={chunk_len} hot_lookup=0x{translated_lookup:x} stage1={stage1:x?} mappings={} semantic_mapping={semantic_mapping} stage1_mapping={stage1_mapping} global_owners={owner_count} persistent={}",
                            self.mappings.len(),
                            self.persistent_vm_lifecycle
                        )));
                    };
                    self.emit_guest_mem_copy_decision(
                        crate::probes::guest_mem_dir::READ_GUEST,
                        chunk_address,
                        chunk_len,
                        mapping_start,
                        mapping_end,
                        stage1_lookup,
                    );
                    copied += chunk_len;
                    continue;
                };
                (
                    lookup_address,
                    mapping.start,
                    mapping.end,
                    mapping.ipa,
                    mapping.host_addr,
                )
            };
            self.emit_guest_mem_copy_decision(
                crate::probes::guest_mem_dir::READ_GUEST,
                chunk_address,
                chunk_len,
                mapping_start,
                mapping_end,
                mapping_ipa,
            );
            // Read directly out of the host buffer. Works for both
            // applevisor-owned mappings (the parent case) and raw mappings
            // we re-created in a forked child via hv_vm_map.
            let chunk_offset = (lookup_address - mapping_start) as usize;
            unsafe {
                volatile_copy_from_guest(
                    host_addr.add(chunk_offset),
                    dst.as_mut_ptr().add(copied),
                    chunk_len,
                );
            }
            copied += chunk_len;
        }
        crate::probes::guest_mem_bytes(
            crate::probes::guest_mem_dir::READ_GUEST,
            strip_pointer_tag(address),
            dst,
        );
        Ok(())
    }

    /// Host VA of `backing_gpa` iff it lives in a host-`MAP_SHARED` guest region
    /// (the boot-mapped shared aperture; shared across carrick processes via
    /// the inherited MAP_SHARED backing). Used to back a cross-process futex
    /// with the public `os_sync_wait_on_address` API (see `crate::ulock`).
    pub(crate) fn shared_futex_location(
        &self,
        backing_gpa: u64,
    ) -> Option<carrick_guest_mem::SharedFutexLocation> {
        // The neutral AArch64 engine has already translated the semantic guest
        // VA through stage-1 and passes the exact backing GPA here. HVPatch
        // global frames deliberately have VA != IPA, so this lookup MUST stay
        // in the raw IPA domain; treating the GPA as a second VA made every
        // fork-shared futex fall through to the process-private table.
        if let Some(location) = Self::shared_futex_mapping_for_ipa(
            &self.mappings,
            backing_gpa,
            self.persistent_vm_lifecycle,
        ) {
            return Some(location);
        }

        // A shared-file alias installed by another sibling may be absent from
        // this thread's mapping Vec. Its global IPA is nevertheless unique and
        // the live alias registry owns the same translated backing identity.
        if let Some(alias) = alias_registry().lock().iter().rev().find(|alias| {
            alias.sharing.has_shared_futex_identity()
                && backing_gpa >= alias.ipa
                && backing_gpa.saturating_add(4) <= alias.ipa.saturating_add(alias.size as u64)
                && alias_backing_is_live(alias.host_addr)
        }) {
            return MappingView::from_alias(alias).shared_futex_location_for_ipa(backing_gpa);
        }
        None
    }

    fn shared_futex_mapping_for_ipa(
        mappings: &[HvfMappedRegion],
        backing_gpa: u64,
        persistent_vm_lifecycle: bool,
    ) -> Option<carrick_guest_mem::SharedFutexLocation> {
        let end = backing_gpa.checked_add(4)?;
        mappings.iter().rev().find_map(|mapping| {
            let mapping_end = mapping.ipa.checked_add(mapping.size as u64)?;
            (mapping.sharing.has_shared_futex_identity()
                && backing_gpa >= mapping.ipa
                && end <= mapping_end
                && (!persistent_vm_lifecycle
                    || !is_reusable_global_frame_extent(
                        mapping.physical_ipa,
                        mapping.physical_size as u64,
                    )
                    || global_frame_region_owner_matches(mapping)))
            .then(|| mapping.view().shared_futex_location_for_ipa(backing_gpa))
            .flatten()
        })
    }

    pub(crate) fn write_guest_bytes(
        &mut self,
        address: u64,
        bytes: &[u8],
    ) -> Result<(), MemoryError> {
        let length = bytes.len();
        // PROT_NONE gated once in the default `GuestMemory::write_bytes`.
        self.validate_guest_write_range(address, length, false)?;
        let mut copied = 0usize;
        while copied < length {
            let (chunk_address, chunk_len) = Self::guest_copy_chunk(address, copied, length)?;
            // See `read_guest_bytes_into`: a `repoint_private` overlay VA resolves
            // its region+offset via the translated overlay IPA, so a syscall write
            // lands in the PRIVATE overlay backing the guest reads, not the shared
            // aperture. Identity otherwise; PROT_NONE already gated on the VA.
            let lookup_address = self.syscall_buffer_lookup_addr(chunk_address, chunk_len);
            let (mapping_start, mapping_end, mapping_ipa, host_addr) = {
                let Some(mapping) = self.mapping_for_range_mut(lookup_address, chunk_len) else {
                    return Err(MemoryError::OutOfBounds { address, length });
                };
                (mapping.start, mapping.end, mapping.ipa, mapping.host_addr)
            };
            self.emit_guest_mem_copy_decision(
                crate::probes::guest_mem_dir::WRITE_GUEST,
                chunk_address,
                chunk_len,
                mapping_start,
                mapping_end,
                mapping_ipa,
            );
            let chunk_offset = (lookup_address - mapping_start) as usize;
            unsafe {
                volatile_copy_to_guest(
                    bytes.as_ptr().add(copied),
                    host_addr.add(chunk_offset),
                    chunk_len,
                );
            }
            copied += chunk_len;
        }
        crate::probes::guest_mem_bytes(
            crate::probes::guest_mem_dir::WRITE_GUEST,
            strip_pointer_tag(address),
            bytes,
        );
        Ok(())
    }

    /// Resolve a zero-copy pointer only when every page-bounded fragment belongs
    /// to the same backing region and both its GPA and host pointer advance
    /// linearly. Otherwise the caller must use the already-segmented copy path.
    fn contiguous_guest_host_ptr(&self, address: u64, length: usize) -> Option<*mut u8> {
        let stripped = strip_pointer_tag(address);
        let mut checked = 0usize;
        let mut first: Option<(u64, u64, u64, usize, u64, *mut u8)> = None;
        while checked < length {
            let (chunk_va, chunk_len) = Self::guest_copy_chunk(stripped, checked, length).ok()?;
            let lookup = self.syscall_buffer_lookup_addr(chunk_va, chunk_len);
            let mapping = self.mapping_for_range(lookup, chunk_len)?;
            let mapping_offset = lookup.checked_sub(mapping.start)?;
            let physical = mapping.ipa.checked_add(mapping_offset)?;
            let host = unsafe { mapping.host_addr.add(mapping_offset as usize) };
            match first {
                None => {
                    first = Some((
                        mapping.start,
                        mapping.end,
                        mapping.ipa,
                        mapping.host_addr as usize,
                        physical,
                        host,
                    ));
                }
                Some((start, end, ipa, host_base, first_physical, first_host)) => {
                    if mapping.start != start
                        || mapping.end != end
                        || mapping.ipa != ipa
                        || mapping.host_addr as usize != host_base
                        || physical != first_physical.checked_add(checked as u64)?
                        || host as usize != (first_host as usize).checked_add(checked)?
                    {
                        return None;
                    }
                }
            }
            checked += chunk_len;
        }
        first.map(|(_, _, _, _, _, host)| host)
    }

    /// Host pointer for a contiguous guest range (zero-copy send source), or
    /// `None` if any page resolves to another physical fragment. See
    /// `GuestMemory::host_ptr_for_read`.
    pub(crate) fn host_ptr_for_read(&self, address: u64, length: usize) -> Option<*const u8> {
        if length == 0 || self.range_no_access(address, length) {
            return None;
        }
        self.contiguous_guest_host_ptr(address, length)
            .map(|ptr| ptr as *const u8)
    }

    /// Host pointer for a contiguous guest range as a zero-copy recv DESTINATION,
    /// or `None` if the range isn't one mapped region OR isn't guest-writable.
    /// The guest-writable requirement mirrors `write_guest_bytes_checked`: a
    /// guest read-only mapping must EFAULT via the checked copy path, not be
    /// written by the kernel through a raw host pointer. See
    /// `GuestMemory::host_ptr_for_write`.
    pub(crate) fn host_ptr_for_write(&mut self, address: u64, length: usize) -> Option<*mut u8> {
        if length == 0 || self.range_no_access(address, length) {
            return None;
        }
        let stripped = strip_pointer_tag(address);
        if self
            .validate_guest_write_range(stripped, length, true)
            .is_err()
        {
            return None;
        }
        self.contiguous_guest_host_ptr(stripped, length)
    }

    /// Zero the PHYSICAL backing of `[address, address+length)`, bypassing BOTH
    /// the `range_no_access` and the writability checks (see
    /// `GuestMemory::zero_backing`). Used to scrub a reused anon region whose
    /// stale content must never reach the guest: a region just reclaimed from
    /// `munmap` (stage-1-invalidated → `range_no_access`) or mapped `PROT_NONE`
    /// has no write permission, so `write_guest_bytes`/`_checked` deliberately
    /// fault and cannot scrub it. The arena backing is always mapped (munmap only
    /// stage-1-invalidates; arm64 HVF has no stage-2 flush), so the lookup
    /// succeeds for the reclaimed region.
    pub(crate) fn zero_guest_backing(
        &mut self,
        address: u64,
        length: usize,
    ) -> Result<(), MemoryError> {
        let address = strip_pointer_tag(address);
        // Scrub debug: CARRICK_FORK_DEBUG_VA=<hex> logs any zeroing whose range
        // covers that VA, with the caller — the instrument that named the agent
        // zeroing a live dict granule during the forkserver corruption hunt.
        if let Some(debug_va) = std::env::var("CARRICK_FORK_DEBUG_VA")
            .ok()
            .and_then(|raw| u64::from_str_radix(raw.trim_start_matches("0x"), 16).ok())
            && address <= debug_va
            && debug_va < address.saturating_add(length as u64)
        {
            eprintln!(
                "[FORKDBG pid={:?}] zero_guest_backing va={address:#x} len={length:#x}\n{}",
                self.cow_identity.map(|identity| identity.linux_pid),
                std::backtrace::Backtrace::force_capture(),
            );
        }
        let mut cleared = 0usize;
        while cleared < length {
            let (chunk_va, chunk_len) = Self::guest_copy_chunk(address, cleared, length)?;
            // munmap invalidates the leaf but intentionally preserves its PA.
            // Backing maintenance runs before the replacement VMA is made
            // guest-visible, so an ordinary hardware-valid translation cannot
            // identify a retained private-COW fragment here. Resolve that PA
            // through the typed invalid-leaf seam and scrub each page-bounded
            // physical fragment independently.
            let retained_ipa = self
                .page_tables
                .lock()
                .as_ref()
                .and_then(|manager| manager.translate_retained_output(chunk_va));
            // A partial munmap can carve this 4 KiB Linux page out of a live
            // 16 KiB private frame while preserving the invalid leaf's output
            // IPA. Reusing that page does not pass through `add_alias`, so
            // republish its semantic lifetime edge before a later sibling
            // munmap is allowed to retire the containing stage-2 lease.
            let retained_fragment = retained_ipa.and_then(|ipa| {
                retained_private_reuse_alias_fragment(
                    &alias_registry().lock(),
                    chunk_va,
                    ipa,
                    chunk_len,
                    self.mm_root_slot,
                )
            });
            // WRITE TARGETS ARE STAGE-1-AUTHENTICATED, PERIOD. This used to
            // fall back to `mapping_for_range_mut` — a VA-keyed search over
            // carrier-inherited rows with no scope filter — when the caller's
            // own translation had nothing. A fork child's engine inherits
            // Borrowed rows pointing at the ANCESTOR's host memory for
            // numerically identical VAs, and a reused range is scrubbed
            // exactly while its stage-1 is invalid, so that fallback resolved
            // another process's frame and zeroed it: one 16 KiB granule of the
            // forkserver server's live interned-strings dict, read back as
            // NULL me_keys by every worker (the CPython multiprocessing
            // SIGSEGV cluster).
            //
            // The scrub's purpose is to keep STALE BYTES from being observed
            // through THIS VA. If neither the live walk nor the retained
            // invalid-leaf output names an IPA, the guest has no translation
            // here and cannot observe anything — there is nothing to scrub,
            // and skipping is the correct amount of writing. With an IPA in
            // hand, `mapping_for_live_ipa_range` demands VA/IPA consistency
            // plus a live authenticated owner, so the write can only land in
            // this mm's own backing.
            let live_ipa = self.translate_va(chunk_va);
            let ipa = live_ipa.or(retained_ipa);
            let target = ipa
                .and_then(|ipa| {
                    self.mapping_for_live_ipa_range(chunk_va, ipa, chunk_len)
                        .and_then(|mapping| {
                            let offset = usize::try_from(ipa.checked_sub(mapping.ipa)?).ok()?;
                            Some(unsafe { mapping.host_addr.add(offset) })
                        })
                })
                .or_else(|| {
                    // VA fallback, restricted to NON-reusable backing. Boot and
                    // identity regions (the brk heap above all) are per-mm by
                    // construction and sometimes reachable only by VA here;
                    // skipping them left stale bytes where `ltp-brk02` demands
                    // zeros. Reusable global-frame results stay excluded — a
                    // VA-only join over carrier-inherited rows is exactly the
                    // cross-process write this function must never make.
                    self.mapping_for_range_mut(chunk_va, chunk_len)
                        .and_then(|mapping| {
                            // The view carries only the semantic IPA; that is
                            // sufficient here — reusable-frame mappings' semantic
                            // IPAs live inside the global-frame arena, identity
                            // and boot mappings' do not.
                            if is_reusable_global_frame_extent(mapping.ipa, 1) {
                                return None;
                            }
                            let offset =
                                usize::try_from(chunk_va.checked_sub(mapping.start)?).ok()?;
                            Some(unsafe { mapping.host_addr.add(offset) })
                        })
                });
            if let Some(debug_va) = std::env::var("CARRICK_FORK_DEBUG_VA")
                .ok()
                .and_then(|raw| u64::from_str_radix(raw.trim_start_matches("0x"), 16).ok())
                && chunk_va <= debug_va
                && debug_va < chunk_va.saturating_add(chunk_len as u64)
            {
                eprintln!(
                    "[SCRUBDBG pid={:?}] chunk va={chunk_va:#x}+{chunk_len:#x} live_ipa={live_ipa:x?} \
                     retained_ipa={retained_ipa:x?} target={target:?}",
                    self.cow_identity.map(|identity| identity.linux_pid),
                );
            }
            if let Some(target) = target {
                unsafe {
                    core::ptr::write_bytes(target, 0u8, chunk_len);
                }
                if let Some(fragment) = retained_fragment {
                    register_shared_alias(fragment);
                }
            }
            cleared += chunk_len;
        }
        Ok(())
    }

    /// Permission-respecting write used by the SYSCALL path
    /// (`GuestMemory::write_bytes`): a write into a non-writable mapping returns
    /// EFAULT (`MemoryError::OutOfBounds`) instead of either faulting the host
    /// (SIGBUS on a genuinely read-only `MAP_SHARED` file alias) or silently
    /// corrupting a carrick-owned region (the EL1 page tables / vector table are
    /// registered `write:false`). Carrick-internal writes (vdso vvar, sigframe,
    /// bootstrap) deliberately use the unchecked `write_guest_bytes`.
    /// (audit M1; probe `rosharedbus`)
    pub(crate) fn write_guest_bytes_checked(
        &mut self,
        address: u64,
        bytes: &[u8],
    ) -> Result<(), MemoryError> {
        let length = bytes.len();
        // PROT_NONE gated once in the default `GuestMemory::write_bytes`.
        self.validate_guest_write_range(address, length, true)?;
        let mut copied = 0usize;
        while copied < length {
            let (chunk_address, chunk_len) = Self::guest_copy_chunk(address, copied, length)?;
            // `repoint_private` overlay VAs resolve region+offset via the translated
            // overlay IPA (see `syscall_buffer_lookup_addr`); identity otherwise.
            let lookup_address = self.syscall_buffer_lookup_addr(chunk_address, chunk_len);
            let (mapping_start, mapping_end, mapping_ipa, host_addr) = {
                let Some(mapping) = self.mapping_for_range_mut(lookup_address, chunk_len) else {
                    return Err(MemoryError::OutOfBounds { address, length });
                };
                (mapping.start, mapping.end, mapping.ipa, mapping.host_addr)
            };
            self.emit_guest_mem_copy_decision(
                crate::probes::guest_mem_dir::WRITE_GUEST_CHECKED,
                chunk_address,
                chunk_len,
                mapping_start,
                mapping_end,
                mapping_ipa,
            );
            let chunk_offset = (lookup_address - mapping_start) as usize;
            unsafe {
                volatile_copy_to_guest(
                    bytes.as_ptr().add(copied),
                    host_addr.add(chunk_offset),
                    chunk_len,
                );
            }
            copied += chunk_len;
        }
        crate::probes::guest_mem_bytes(
            crate::probes::guest_mem_dir::WRITE_GUEST_CHECKED,
            strip_pointer_tag(address),
            bytes,
        );
        Ok(())
    }

    fn validate_guest_write_range(
        &self,
        address: u64,
        length: usize,
        require_guest_writable: bool,
    ) -> Result<(), MemoryError> {
        let mut checked = 0usize;
        while checked < length {
            let (chunk_address, chunk_len) = Self::guest_copy_chunk(address, checked, length)?;
            // The writability check follows the same region a `repoint_private`
            // overlay VA's copy will hit (the translated overlay IPA), so the
            // overlay's guest_writable flag — not the stale shared region's — gates.
            let lookup_address = self.syscall_buffer_lookup_addr(chunk_address, chunk_len);
            let Some(mapping) = self.mapping_for_range(lookup_address, chunk_len) else {
                return Err(MemoryError::OutOfBounds { address, length });
            };
            if require_guest_writable
                && (!mapping.guest_writable
                    || self
                        .protections
                        .range_write_denied(chunk_address, chunk_len))
            {
                return Err(MemoryError::OutOfBounds { address, length });
            }
            checked += chunk_len;
        }
        Ok(())
    }

    pub(crate) fn guest_copy_chunk(
        address: u64,
        offset: usize,
        total_length: usize,
    ) -> Result<(u64, usize), MemoryError> {
        let offset_u64 = u64::try_from(offset).map_err(|_| MemoryError::OutOfBounds {
            address,
            length: total_length,
        })?;
        let raw_chunk_address =
            address
                .checked_add(offset_u64)
                .ok_or(MemoryError::OutOfBounds {
                    address,
                    length: total_length,
                })?;
        let chunk_address = strip_pointer_tag(raw_chunk_address);
        let remaining = total_length - offset;
        let page_remaining =
            (GUEST_STAGE1_PAGE_SIZE - (chunk_address & (GUEST_STAGE1_PAGE_SIZE - 1))) as usize;
        Ok((chunk_address, remaining.min(page_remaining)))
    }

    fn emit_guest_mem_copy_decision(
        &self,
        direction: u32,
        address: u64,
        length: usize,
        mapping_start: u64,
        mapping_end: u64,
        mapping_ipa: u64,
    ) {
        let stage1_ipa = crate::memory::is_high_va(address)
            .then(|| self.translate_va(address))
            .flatten();
        crate::probes::guest_mem_copy(
            direction,
            address,
            length,
            stage1_ipa,
            mapping_start,
            mapping_end,
            mapping_ipa,
        );
        self.emit_guest_mem_points(direction, address, length, mapping_start, mapping_ipa);
    }

    fn emit_guest_mem_points(
        &self,
        direction: u32,
        address: u64,
        length: usize,
        mapping_start: u64,
        mapping_ipa: u64,
    ) {
        for point in crate::probes::guest_mem_probe_points(address, length)
            .into_iter()
            .flatten()
        {
            let stage1_ipa = crate::memory::is_high_va(point)
                .then(|| self.translate_va(point))
                .flatten();
            crate::probes::guest_mem_point(
                direction,
                point,
                stage1_ipa,
                mapping_start,
                mapping_ipa,
            );
        }
    }

    /// Write the vDSO vvar data page: the counter frequency and the
    /// monotonic→realtime offset, so `__kernel_clock_gettime` can convert
    /// CNTVCT_EL0 to a timespec entirely in userspace. The guest reads the same
    /// counter we calibrate against (CNTKCTL_EL1.EL0VCTEN), so the rate is exact;
    /// monotonic durations depend only on the frequency. Best-effort: silently
    /// skips if the vvar page isn't mapped.
    ///
    /// Stamp a fresh process-local epoch into the vvar RNG generation (P2).
    /// Re-stamping each forked child ensures the generation never matches the
    /// state snapshot inherited from its parent, forcing the userspace
    /// getrandom blob to reseed rather than reuse the parent's keystream.
    fn stamp_rng_generation(&mut self) -> Result<(), MemoryError> {
        let generation = next_vdso_rng_generation();
        self.write_guest_bytes(
            crate::vdso::LINUX_VVAR_BASE + crate::vdso::VVAR_OFF_RNG_GENERATION as u64,
            &generation.to_le_bytes(),
        )
    }

    fn populate_vdso_data_page(&mut self) {
        // Independent of the clock data (getrandom needs no calibrated counter),
        // so stamp it first and unconditionally.
        let _ = self.stamp_rng_generation();
        let freq = host_counter_frequency();
        if freq == 0 {
            return;
        }
        // The vDSO computes the guest's CLOCK_REALTIME as
        //   realtime_ns = guest_CNTVCT/freq + realtime_off.
        // So `realtime_off` MUST be `unix_ns - guest_CNTVCT/freq` measured on
        // the SAME clock the guest's CNTVCT_EL0 actually exposes.
        //
        // Crucially, the guest's CNTVCT does NOT equal the raw `cntvct_el0` MRS
        // that carrick reads in `host_counter()`: the bare hardware counter
        // keeps ticking across system SUSPEND (it is BOOTTIME-like), whereas
        // HVF gives the guest a virtual counter aligned to macOS
        // CLOCK_UPTIME_RAW (which EXCLUDES suspend) — empirically the guest's
        // CNTVCT/freq matches CLOCK_UPTIME_RAW to the millisecond, while the
        // raw MRS runs HOURS ahead after a laptop has slept (hv_vcpu's
        // vtimer_offset reports 0, so the gap is invisible through that API).
        // Calibrating `mono_ns` off the raw MRS therefore skewed guest
        // CLOCK_REALTIME by the accumulated suspend time → every absolute
        // FUTEX_WAIT_BITSET|FUTEX_CLOCK_REALTIME deadline (glibc sem_timedwait /
        // pthread condvar timeouts, i.e. multiprocessing SemLock/Condition)
        // computed as already-past → instant spurious ETIMEDOUT.
        //
        // Reading CLOCK_UPTIME_RAW here matches the guest's counter base, so
        // realtime_off is exact. CLOCK_MONOTONIC is unaffected (durations
        // cancel any constant base), but its absolute value now also agrees
        // with carrick's syscall-path monotonic (`monotonic_duration`, also
        // CLOCK_UPTIME_RAW) — the vDSO and syscall fast/slow paths are coherent.
        let mono_ns = host_clock_uptime_ns();
        let unix_ns = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos() as u64)
            .unwrap_or(0);
        let realtime_off = unix_ns.wrapping_sub(mono_ns);
        // Publish the SAME offset to the shared store so the trapping
        // clock_gettime(CLOCK_REALTIME) syscall computes uptime + realtime_off
        // identically to the vDSO fast path (which adds VVAR_OFF_REALTIME_OFF_NS
        // to the guest CNTVCT) — keeping the two paths coherent (clock_gettime04).
        crate::vdso::set_realtime_off_ns(realtime_off);

        let base = crate::vdso::LINUX_VVAR_BASE;
        let _ = self.write_guest_bytes(
            base + crate::vdso::VVAR_OFF_FREQ as u64,
            &freq.to_le_bytes(),
        );
        let _ = self.write_guest_bytes(
            base + crate::vdso::VVAR_OFF_REALTIME_OFF_NS as u64,
            &realtime_off.to_le_bytes(),
        );
        // seq stays 0 (even = stable); these aren't updated after boot.
    }

    /// Mark `[address, address+len)` PROT_NONE (`no_access=true`) or clear it.
    /// Clearing performs interval subtraction so an mprotect/mmap that re-enables
    /// part of a PROT_NONE region leaves only the still-protected remainder.
    pub(crate) fn set_no_access(&mut self, address: u64, len: usize, no_access: bool) {
        self.protections.set_no_access(address, len, no_access);
    }

    /// Mirror a partial `munmap`'s registry split onto this engine's LOCAL
    /// mapping rows.
    ///
    /// `unregister_alias_entries` splits an overlapped registry entry into its
    /// surviving head/tail fragments, but the engine's own row kept the
    /// ORIGINAL extent. `mapping_is_current_for_process_fork_indexed` then
    /// matched that row against the registry index by exact identity
    /// `(start, ipa, host_addr, semantic size)` — and a fragment never equals
    /// the whole — so fork DROPPED the row from its COW ranges. The child's
    /// cloned stage-1 kept a WRITABLE leaf onto the parent's frame, no COW
    /// fault ever fired, and the child's frees scribbled pymalloc free-list
    /// links over the parent's live objects (`cpython-threading`'s
    /// `free(): invalid pointer`, reducer
    /// `docs/perf-results/2026-08-17-closure-post-libuv/reducers/cpython-fork-shutdown-parent-segv.py`).
    /// An identity test was standing in for a liveness question; keeping the
    /// two representations in step restores the invariant at its source
    /// instead of teaching the consumer to guess.
    ///
    /// Ownership: `HvfMappedRegion` owns its backing handles and is not
    /// `Clone`, so the surviving HEAD keeps them and a tail fragment carries
    /// `None`. Both fragments retain the same `physical_ipa`/`physical_size`,
    /// which is what stage-2 retirement keys on, so they are still retired
    /// together. A row the unmap covers ENTIRELY is left untouched: the
    /// registry drops such an entry outright, and excluding a dead row from
    /// fork is correct.
    fn split_local_rows_for_unmap(&mut self, va: u64, len: usize) {
        let Some(end) = va.checked_add(len as u64) else {
            return;
        };
        let mut tails: Vec<HvfMappedRegion> = Vec::new();
        for row in &mut self.mappings {
            if !row.is_dynamic_alias {
                continue;
            }
            let row_size = semantic_extent_size(row.start, row.end);
            let Some(row_end) = row.start.checked_add(row_size as u64) else {
                continue;
            };
            if row_end <= va || row.start >= end {
                continue;
            }
            let head_survives = row.start < va;
            let tail_survives = row_end > end;
            if !head_survives && !tail_survives {
                continue;
            }
            if tail_survives {
                let delta = end.saturating_sub(row.start);
                tails.push(HvfMappedRegion {
                    start: end,
                    end: row.end,
                    ipa: row.ipa.saturating_add(delta),
                    physical_ipa: row.physical_ipa,
                    physical_size: row.physical_size,
                    host_addr: row.host_addr.wrapping_add(delta as usize),
                    size: usize::try_from(row_end.saturating_sub(end)).unwrap_or_default(),
                    perms: row.perms,
                    memory: None,
                    host_mapping: None,
                    stage2_lease: None,
                    is_dynamic_alias: true,
                    sharing: row.sharing,
                    guest_writable: row.guest_writable,
                    shared_key_base: row.shared_key_base,
                    shared_key_offset: row.shared_key_offset.saturating_add(delta),
                    owner_generation: global_frame_host_owner_generation(
                        row.physical_ipa,
                        row.physical_size as u64,
                    ),
                });
            }
            if head_survives {
                row.end = va;
                row.size = usize::try_from(va.saturating_sub(row.start)).unwrap_or_default();
            } else {
                // Only the tail survives: advance this row onto it and let the
                // pushed fragment be dropped below.
                let delta = end.saturating_sub(row.start);
                row.ipa = row.ipa.saturating_add(delta);
                row.host_addr = row.host_addr.wrapping_add(delta as usize);
                row.shared_key_offset = row.shared_key_offset.saturating_add(delta);
                row.start = end;
                row.size = usize::try_from(row_end.saturating_sub(end)).unwrap_or_default();
                tails.pop();
            }
        }
        self.mappings.append(&mut tails);
    }

    pub(crate) fn unregister_process_alias(
        &mut self,
        va: u64,
        len: usize,
    ) -> Result<(), TrapError> {
        if !self.persistent_vm_lifecycle {
            self.cow_armed.lock().disarm(CowArmedSpan {
                va,
                len,
                executable: false,
                kernel_only: false,
            });
            let _ = unregister_alias(va, len, self.mm_root_slot);
            self.split_local_rows_for_unmap(va, len);
            return Ok(());
        }
        let authority = self.cow_authority.as_ref().ok_or_else(|| {
            TrapError::Hypervisor("HVPatch alias retirement has no inventory authority".to_owned())
        })?;
        let identity = self.cow_identity.ok_or_else(|| {
            TrapError::Hypervisor("HVPatch alias retirement has no mm identity".to_owned())
        })?;
        // `GuestMemory::unmap_range` is reached only from the mmap-family
        // syscall set, whose runtime dispatch already owns the process-wide
        // page-table pause across invalidate + TLBI + this backend retirement.
        // Acquiring the same non-reentrant pause here deadlocks the coordinator
        // against itself as soon as the mm has a sibling vCPU.
        let _topology = crate::fork_quiesce::acquire_topology_lock(
            carrick_observability::probes::HvpatchTopologyOperation::AliasUnmap,
            identity.linux_pid,
            identity.linux_tid,
        );

        // Plan against a private copy before mutating the process-wide alias
        // index. Reservation failure therefore leaves the exact pre-munmap
        // lifetime graph intact; the checked stage-1 invalidation has already
        // made the guest range inaccessible.
        let registry_before = alias_registry().lock().clone();
        let planned_leases = {
            let mut planned = registry_before.clone();
            unregister_alias_entries(&mut planned, va, len, self.mm_root_slot)
        };
        let disarm_spans = retired_alias_disarm_spans(
            &registry_before,
            va,
            len,
            self.mm_root_slot,
            &planned_leases,
        );
        if planned_leases.is_empty() {
            let actual = unregister_alias(va, len, self.mm_root_slot);
            debug_assert!(actual.is_empty());
            // Keep this engine's rows in step with the split the registry just
            // took (see `split_local_rows_for_unmap`).
            self.split_local_rows_for_unmap(va, len);
            // A partial Linux unmap can remove the last semantic projection of
            // one 4 KiB page while another fragment still retains the same
            // 16 KiB HVPatch frame. Keep the compound armed: low-arena mmap
            // reuses the invalid stage-1 output and zero_backing must split the
            // still-fork-shared physical frame before scrubbing it. Disarming
            // here made the next fork omit the reactivated page from its exact
            // alias-derived COW ranges (mtforkcorrupt).
            return Ok(());
        }
        let retirement = {
            let inventory = self.frame_inventory.lock();
            Self::inventory_lease_retirement_shape(&inventory, &planned_leases, &|frame| {
                authority.frame_mapping_count(frame).ok().flatten()
            })?
        };
        if retirement.mappings.is_empty() {
            let actual = unregister_alias(va, len, self.mm_root_slot);
            debug_assert_eq!(actual, planned_leases);
            let mut armed = self.cow_armed.lock();
            for span in disarm_spans {
                armed.disarm(span);
            }
            return Ok(());
        }
        let event_count = retirement
            .mappings
            .len()
            .saturating_add(retirement.frames.len());
        let mut reservation = authority.reserve(0, 0, event_count).map_err(|error| {
            TrapError::Hypervisor(format!(
                "reserve HVPatch alias retirement inventory: {error}"
            ))
        })?;
        Self::stage_inventory_lease_retirement(&mut reservation, &retirement)?;
        let actual_leases = unregister_alias(va, len, self.mm_root_slot);
        if actual_leases != planned_leases {
            eprintln!(
                "carrick: FATAL: HVPatch alias registry changed under topology lock: planned={planned_leases:?} actual={actual_leases:?}"
            );
            std::process::abort();
        }
        if let Err(error) = authority.apply(reservation.commit(())) {
            // Name the retirement, not just the id that failed. This abort used
            // to print one MappingId and nothing else, which cannot distinguish
            // a double-retire from a mapping the authority never saw, and gives
            // no way to tell WHICH extent named it — `inventory.extents` is
            // keyed by `(gpa, length)`, so an extent has no lifetime tie to the
            // mapping it names and an orphan is invisible from the id alone.
            let inventory = self.frame_inventory.lock();
            let retiring: std::collections::BTreeSet<_> = retirement
                .mappings
                .iter()
                .map(|(_, extent)| extent.mapping)
                .collect();
            let naming: Vec<_> = inventory
                .extents
                .iter()
                .filter(|(_, extent)| retiring.contains(&extent.mapping))
                .map(|(&key, extent)| (key, extent.mapping, extent.frame, extent.backing))
                .collect();
            eprintln!(
                "carrick: FATAL: apply HVPatch alias retirement inventory: {error}\n  \
                 va={va:#x} len={len:#x} retiring={:?}\n  frames={:?} leases={:?}\n  \
                 every extent naming those mappings: {naming:?}\n  \
                 live extents={} planned_leases={planned_leases:?}",
                retirement.mappings,
                retirement.frames,
                retirement.stage2_leases,
                inventory.extents.len(),
            );
            std::process::abort();
        }
        {
            let mut inventory = self.frame_inventory.lock();
            Self::commit_inventory_lease_retirement(&mut inventory, &retirement).unwrap_or_else(
                |error| {
                    eprintln!(
                        "carrick: FATAL: commit HVPatch alias retirement backend ledger: {error}"
                    );
                    std::process::abort();
                },
            );
        }
        for &(ipa, length) in &retirement.stage2_leases {
            let size = usize::try_from(length).map_err(|_| TrapError::MappingTooLarge(length))?;
            self.retire_stage2_extent(ipa, length)?;
            forget_replay_extent(ipa, size);
            self.mappings.retain(|mapping| {
                (mapping.physical_ipa, mapping.physical_size as u64) != (ipa, length)
            });
        }
        let mut armed = self.cow_armed.lock();
        for span in disarm_spans {
            armed.disarm(span);
        }
        Ok(())
    }

    /// Resolve a guest VA range to a [`MappingView`] (host pointer + bounds +
    /// writability). THE single chokepoint every syscall-path memory accessor
    /// (read/write_guest_bytes, host_ptr_for_read/write, validate_guest_write_range,
    /// zero_guest_backing) routes through.
    ///
    /// Fast path: THIS thread's per-thread `mappings`. Cross-thread FALLBACK: when
    /// that misses for a high-VA address, the VA→IPA half is already process-shared
    /// (`translate_va` walks the Arc-shared page tables, which `map_aliased` edits
    /// for EVERY thread's alias), so resolve IPA→host from the process-shared
    /// `alias_registry` — fixing a syscall buffer that lives in a high-VA alias
    /// (Go heap arena) ANOTHER goroutine mmap'd, invisible to this thread's list
    /// (the "read/wait: bad address" EFAULT). Both `_range` and `_range_mut`
    /// resolve identically — no accessor mutates the region itself.
    fn mapping_for_range(&self, address: u64, length: usize) -> Option<MappingView> {
        let address = strip_pointer_tag(address);
        let stage1_ipa = self.translate_va(address);
        let region_is_live = |mapping: &HvfMappedRegion| {
            !self.persistent_vm_lifecycle
                || !is_reusable_global_frame_extent(
                    mapping.physical_ipa,
                    mapping.physical_size as u64,
                )
                || global_frame_region_owner_matches(mapping)
        };
        let alias_is_live = |alias: &AliasBacking| {
            !self.persistent_vm_lifecycle
                || !is_reusable_global_frame_extent(alias.physical_ipa, alias.physical_size as u64)
                || global_frame_host_owner_matches(
                    alias.physical_ipa,
                    alias.physical_size as u64,
                    alias.physical_host_addr,
                    alias.owner_generation,
                )
        };
        // First honor the exact output address in the authoritative stage-1
        // graph. This is required for low-VA fork-COW overlays as well as the
        // historical high-VA aliases: a sibling vCPU may not carry the overlay
        // in its local metadata Vec even though it shares this mm's tables.
        if let Some(ipa) = stage1_ipa {
            if let Some((_, mapping)) =
                self.mappings.iter().enumerate().rev().find(|(_, mapping)| {
                    Self::region_owns_ipa(mapping, ipa)
                        && mapping.contains_range(address, length)
                        && region_is_live(mapping)
                })
            {
                return Some(mapping.view());
            }
            if let Some(b) = alias_registry()
                .lock()
                .iter()
                .rev()
                .find(|alias| {
                    ipa >= alias.ipa
                        && ipa < alias.ipa.saturating_add(alias.size as u64)
                        && alias_is_live(alias)
                })
                .copied()
            {
                return Some(MappingView::from_alias(&b));
            }
        }
        if let Some(mapping) = self
            .mappings
            .iter()
            .rev()
            .find(|mapping| mapping.contains_range(address, length) && region_is_live(mapping))
        {
            return Some(mapping.view());
        }
        // VA-keyed fallback for when the IPA key is unavailable. `translate_va`
        // reads THIS thread's software stage-1 model, which can lack a high-VA
        // arena page a sibling vCPU freshly MAP_FIXED-committed (Go reserves its
        // heap arena PROT_NONE, then MAP_FIXEDs RW sub-regions; a goroutine on
        // another vCPU then reads/writes a buffer there). `add_alias` already
        // registered that backing keyed by guest VA, so resolve it by VA. Gate on
        // `!range_no_access` so a still-PROT_NONE reservation page EFAULTs as it
        // must; `lookup_shared_alias_by_va` requires the whole range in one entry
        // and picks newest-first, so it never resolves a partial or stale backing.
        // This closes the intermittent Go "read/write: bad address" EFAULT.
        if !self.range_no_access(address, length) {
            let end = address.saturating_add(length as u64);
            if let Some(b) = alias_registry()
                .lock()
                .iter()
                .rev()
                .find(|alias| {
                    alias_matches_process_scope(alias.ownership_scope, self.mm_root_slot)
                        && address >= alias.start
                        && end <= alias.start.saturating_add(alias.size as u64)
                        && alias_is_live(alias)
                })
                .copied()
            {
                return Some(MappingView::from_alias(&b));
            }
        }
        None
    }

    fn mapping_for_range_mut(&mut self, address: u64, length: usize) -> Option<MappingView> {
        self.mapping_for_range(address, length)
    }

    /// The address the per-chunk region lookup + offset should use for a syscall
    /// buffer at guest VA `chunk_va`. Identity for everything but a
    /// `repoint_private` overlay: a MAP_FIXED|MAP_PRIVATE carved over a
    /// shared-aperture VA repoints the stage-1 leaf to a per-process overlay IPA
    /// (608 GiB), but registers NO region keyed at the original VA — the only
    /// region with the overlay backing is keyed at the overlay IPA. So a syscall
    /// copy must look up (and offset) by that translated IPA, or it resolves to
    /// the STALE shared-aperture region the VA still covers (the repoint_private
    /// syscall-buffer bug). High-VA aliases are NOT redirected here: their region
    /// is keyed at the VA and `mapping_for_range` already disambiguates
    /// overlapping aliases via `translate_va` internally (VA-relative offset). For
    /// every other (identity) VA this returns `chunk_va` unchanged — no walk.
    fn syscall_buffer_lookup_addr(&self, chunk_va: u64, chunk_len: usize) -> u64 {
        if !crate::memory::needs_stage1_translation(chunk_va, chunk_len as u64) {
            return chunk_va;
        }
        self.translate_va(chunk_va).unwrap_or(chunk_va)
    }

    /// True if `ipa` falls in `region`'s `hv_vm_map`'d IPA window.
    fn region_owns_ipa(region: &HvfMappedRegion, ipa: u64) -> bool {
        ipa >= region.ipa && ipa < region.ipa + region.size as u64
    }

    #[cfg(test)]
    pub(crate) fn mapping_index_for_range(
        mappings: &[HvfMappedRegion],
        address: u64,
        length: usize,
        stage1_ipa: Option<u64>,
    ) -> Option<usize> {
        // Prefer the region selected by the authoritative stage-1 output when
        // overlapping semantic descriptors exist, then fall back newest-first
        // for test fixtures without a live page-table walk.
        if let Some(ipa) = stage1_ipa
            && let Some((idx, _)) = mappings.iter().enumerate().rev().find(|(_, mapping)| {
                Self::region_owns_ipa(mapping, ipa) && mapping.contains_range(address, length)
            })
        {
            return Some(idx);
        }
        mappings
            .iter()
            .enumerate()
            .rev()
            .find(|(_, mapping)| mapping.contains_range(address, length))
            .map(|(idx, _)| idx)
    }

    /// Resolve a raw stage-2 IPA without treating it as a guest virtual
    /// address. Global-frame aliases deliberately have `start != ipa`; using
    /// the VA lookup here could select no mapping (or an unrelated mapping at
    /// the same VA) when editing a non-identity backing.
    fn mapping_for_ipa_range(
        mappings: &[HvfMappedRegion],
        ipa: u64,
        length: usize,
    ) -> Option<MappingView> {
        let length = u64::try_from(length).ok()?;
        let end = ipa.checked_add(length)?;
        mappings
            .iter()
            .rev()
            .find(|mapping| {
                let mapping_end = mapping.ipa.checked_add(mapping.size as u64);
                ipa >= mapping.ipa && mapping_end.is_some_and(|limit| end <= limit)
            })
            .map(HvfMappedRegion::view)
    }

    /// Resolve one mailbox route without losing its semantic VA identity.
    ///
    /// A raw IPA is not a sufficient key in the persistent VM: the reusable
    /// allocator can give a retired dynamic row's physical IPA to a later
    /// process-local kernel-state mapping while that stale row remains in one
    /// vCPU's metadata solely to retain its host owner. Require the same row to
    /// cover the mailbox VA *and* express the live VA-to-IPA translation.
    fn mailbox_mapping_for_range(
        mappings: &[HvfMappedRegion],
        semantic_va: u64,
        ipa: u64,
        length: usize,
    ) -> Option<MappingView> {
        let semantic_end = semantic_va.checked_add(u64::try_from(length).ok()?)?;
        mappings
            .iter()
            .rev()
            .find(|mapping| {
                semantic_va >= mapping.start
                    && semantic_end <= mapping.end
                    && mapping
                        .ipa
                        .checked_add(semantic_va.saturating_sub(mapping.start))
                        == Some(ipa)
            })
            .map(HvfMappedRegion::view)
    }

    /// Resolve a raw IPA only through the exact currently-owned generation.
    /// A retired dynamic row can keep the same IPA and raw host pointer after
    /// the reusable allocator hands that IPA to another frame; mapped-address
    /// liveness or IPA equality alone would then select stale memory.
    fn mapping_for_live_ipa_range(
        &self,
        semantic_va: u64,
        ipa: u64,
        length: usize,
    ) -> Option<MappingView> {
        let length = u64::try_from(length).ok()?;
        let end = ipa.checked_add(length)?;
        let semantic_end = semantic_va.checked_add(length)?;
        if let Some(mapping) = self.mappings.iter().rev().find(|mapping| {
            let mapping_end = mapping.ipa.checked_add(mapping.size as u64);
            semantic_va >= mapping.start
                && semantic_end <= mapping.end
                && mapping
                    .ipa
                    .checked_add(semantic_va.saturating_sub(mapping.start))
                    == Some(ipa)
                && ipa >= mapping.ipa
                && mapping_end.is_some_and(|limit| end <= limit)
                && (!self.persistent_vm_lifecycle
                    || !is_reusable_global_frame_extent(
                        mapping.physical_ipa,
                        mapping.physical_size as u64,
                    )
                    || global_frame_region_owner_matches(mapping))
        }) {
            return Some(mapping.view());
        }
        alias_registry()
            .lock()
            .iter()
            .rev()
            .find(|alias| {
                let alias_end = alias.ipa.checked_add(alias.size as u64);
                semantic_va >= alias.start
                    && semantic_end <= alias.start.saturating_add(alias.size as u64)
                    && alias
                        .ipa
                        .checked_add(semantic_va.saturating_sub(alias.start))
                        == Some(ipa)
                    && ipa >= alias.ipa
                    && alias_end.is_some_and(|limit| end <= limit)
                    && alias_matches_process_scope(alias.ownership_scope, self.mm_root_slot)
                    && (!self.persistent_vm_lifecycle
                        || !is_reusable_global_frame_extent(
                            alias.physical_ipa,
                            alias.physical_size as u64,
                        )
                        || global_frame_host_owner_matches(
                            alias.physical_ipa,
                            alias.physical_size as u64,
                            alias.physical_host_addr,
                            alias.owner_generation,
                        ))
            })
            .map(MappingView::from_alias)
    }

    /// Walk the guest's live stage-1 page tables to resolve `va`→IPA (the output
    /// address carrick `hv_vm_map`'d). `None` if unmapped. Used to disambiguate
    /// overlapping high-VA alias regions in `mapping_for_range[_mut]`.
    fn translate_va(&self, va: u64) -> Option<u64> {
        self.page_tables.lock().as_ref()?.translate(va)
    }

    pub(crate) fn guest_range_is_writable(&self, address: u64, length: usize) -> bool {
        !self.range_no_access(address, length)
            && self
                .validate_guest_write_range(address, length, true)
                .is_ok()
    }

    /// M:N reclaim — BLOCK side. Snapshot this vCPU and DESTROY it (freeing one
    /// HVF concurrent-vCPU slot) so another guest thread can run while this one
    /// parks in the futex wait. The SAME thread recreates it via
    /// [`reclaim_resume`](Self::reclaim_resume) on wake. Unlike the fork
    /// path this does NOT publish mappings or rebuild the VM — the VM is unchanged;
    /// only the per-thread vCPU is recycled. Task state is returned through the
    /// typed engine boundary; this backend retains only executor lifecycle.
    ///
    /// WIRED via the HVF engine override `ThreadedEngine::save_guest_state`
    /// (`hvf_aarch64_engine.rs:536`), which passes the engine's separately-owned
    /// `&mut vcpu` through to this destroy-in-place reclaim; the wake side is
    /// `rebind_to_slot` (`hvf_aarch64_engine.rs:557`) → [`reclaim_resume`].
    /// This is the multi-threaded blocked-wait park (vCPU-only; the VM stays
    /// alive) that `park_vcpu_for_blocking_wait` routes to.
    pub(crate) fn reclaim_park(
        &mut self,
        vcpu: &mut applevisor::vcpu::Vcpu,
        mailbox: &mut MailboxBinding,
    ) -> Result<(), TrapError> {
        // Raw destroy — only the owning thread may, and applevisor's Drop would
        // panic on the post-destroy handle.
        let vcpu_id = vcpu.id();
        let rc = unsafe { applevisor_sys::hv_vcpu_destroy(vcpu_id) };
        if rc == 0 {
            vcpu_destroyed(vcpu_id);
        }
        if rc != 0 {
            return Err(TrapError::Hypervisor(format!(
                "reclaim_park: hv_vcpu_destroy rc={rc:#x}"
            )));
        }
        self.reclaim_authority.mark_vcpu_parked()?;
        self.release_mailbox_for_reclaim(mailbox)?;
        Ok(())
    }

    /// Owner-thread zero-instruction handoff. The initial mailbox must still be
    /// idle; validate before destroying the vCPU so an incompatible protocol
    /// state fails without partially relinquishing hardware authority.
    pub(crate) fn initial_runner_park(
        &mut self,
        vcpu: &mut applevisor::vcpu::Vcpu,
        mailbox: &mut MailboxBinding,
    ) -> Result<(), TrapError> {
        let diagnostics = mailbox.diagnostics();
        if diagnostics.state != carrick_aarch64::mailbox::MailboxState::Idle.raw() {
            return Err(TrapError::Hypervisor(format!(
                "initial runner mailbox is not idle: diagnostics={diagnostics:?}"
            )));
        }
        let vcpu_id = vcpu.id();
        let rc = unsafe { applevisor_sys::hv_vcpu_destroy(vcpu_id) };
        if rc == 0 {
            vcpu_destroyed(vcpu_id);
        }
        if rc != 0 {
            return Err(TrapError::Hypervisor(format!(
                "initial_runner_park: hv_vcpu_destroy rc={rc:#x}"
            )));
        }
        self.reclaim_authority.mark_initial_runner_parked()?;
        mailbox
            .release_idle_for_initial_handoff()
            .map_err(|error| TrapError::Hypervisor(format!("release initial mailbox: {error}")))
    }

    pub(crate) fn initial_runner_resume(
        &mut self,
        vcpu: &mut applevisor::vcpu::Vcpu,
        mailbox: &mut MailboxBinding,
    ) -> Result<(), TrapError> {
        if self.reclaim_authority != ReclaimParkAuthority::InitialRunnerParked {
            return Err(TrapError::Hypervisor(
                "initial_runner_resume: no idle initial-runner authority".to_owned(),
            ));
        }
        let new_vcpu = create_vcpu(&self._vm)?;
        enable_el0_counter_access(new_vcpu.id());
        Self::configure_executor_invariants(&new_vcpu)?;
        self.vcpu_id = new_vcpu.id();
        self.vcpu_handle = new_vcpu.get_handle();
        std::mem::forget(std::mem::replace(vcpu, new_vcpu));
        self.reacquire_mailbox_after_vcpu_create(vcpu, mailbox, None)?;
        self.reclaim_authority.mark_live_after_recreate()
    }

    /// M:N reclaim — WAKE side. Recreate this executor's vCPU in the EXISTING VM
    /// when it was locally parked. A live destination executor is retained as-is;
    /// the caller overlays only Kernel-owned typed task state. The CALLER must hold
    /// `fork_quiesce::topology_lock` so `vcpu_create` cannot race a concurrent
    /// fork's `hv_vm_destroy`/`create`. Writes the recreated vCPU back through
    /// `vcpu` via `std::mem::replace` + `forget` of the old (already-destroyed)
    /// handle (no applevisor Drop).
    ///
    /// WIRED — see [`reclaim_park`](Self::reclaim_park): reached via the HVF
    /// engine override `ThreadedEngine::rebind_to_slot`
    /// (`hvf_aarch64_engine.rs:557`), which passes the `&mut vcpu` this
    /// destroy/recreate-in-place reclaim needs.
    pub(crate) fn reclaim_resume(
        &mut self,
        vcpu: &mut applevisor::vcpu::Vcpu,
        mailbox: &mut MailboxBinding,
        continuation: Option<carrick_hal::threaded::Aarch64SyscallContinuationV1>,
    ) -> Result<(), TrapError> {
        if self.reclaim_authority.destination_vcpu_is_live().is_ok() {
            if let Some(continuation) = continuation {
                mailbox
                    .import_task_continuation(continuation)
                    .map_err(|error| {
                        TrapError::Hypervisor(format!(
                            "restore task continuation into live destination mailbox: {error}"
                        ))
                    })?;
            }
            return Ok(());
        }
        if self.reclaim_authority != ReclaimParkAuthority::VcpuParked {
            return Err(TrapError::Hypervisor(
                "reclaim_resume: executor requires whole-VM recreation".to_owned(),
            ));
        }
        let continuation = continuation.ok_or_else(|| {
            TrapError::Hypervisor(
                "reclaim_resume: parked syscall has no typed continuation authority".to_owned(),
            )
        })?;
        let new_vcpu = create_vcpu(&self._vm)?;
        enable_el0_counter_access(new_vcpu.id());
        Self::configure_executor_invariants(&new_vcpu)?;
        self.vcpu_id = new_vcpu.id();
        self.vcpu_handle = new_vcpu.get_handle();
        // Replace the destroyed handle WITHOUT running applevisor's panicky Drop on
        // the (already hv_vcpu_destroy'd) old one — mirror the fork rebuild.
        std::mem::forget(std::mem::replace(vcpu, new_vcpu));
        self.reacquire_mailbox_after_vcpu_create(vcpu, mailbox, Some(continuation))?;
        self.reclaim_authority.mark_live_after_recreate()?;
        Ok(())
    }

    /// Single-threaded process shared-futex park. Unlike `reclaim_park`, this
    /// destroys the whole VM, not just the vCPU, so a large process-fork fanout
    /// parked in `FUTEX_WAIT` does not keep one HVF VM alive per waiter.
    pub(crate) fn shared_wait_park(
        &mut self,
        vcpu: &mut applevisor::vcpu::Vcpu,
        mailbox: &mut MailboxBinding,
    ) -> Result<(), TrapError> {
        let vcpu_id = vcpu.id();
        let vcpu_rc = unsafe { applevisor_sys::hv_vcpu_destroy(vcpu_id) };
        if vcpu_rc == 0 {
            vcpu_destroyed(vcpu_id);
        }
        if vcpu_rc != 0 {
            return Err(TrapError::Hypervisor(format!(
                "shared_wait_park: hv_vcpu_destroy rc={vcpu_rc:#x}"
            )));
        }
        self.reclaim_authority.mark_vcpu_parked()?;
        self.release_mailbox_for_reclaim(mailbox)?;
        crate::probes::vm_lifecycle(2, -1);
        let vm_rc = unsafe { inventory_hv_vm_destroy() };
        if vm_rc != 0 {
            return Err(TrapError::Hypervisor(format!(
                "shared_wait_park: hv_vm_destroy rc={vm_rc:#x}"
            )));
        }
        record_vm_released();
        self.reclaim_authority.mark_vm_parked()?;
        Ok(())
    }

    /// MT whole-VM lease — VM-only release by the LAST parker of a
    /// multi-threaded process. Its own vCPU was ALREADY destroyed by
    /// [`Self::reclaim_park`] (its executor lifecycle is recorded in
    /// `reclaim_authority`), and every
    /// sibling's registry "parked" mark is set only AFTER its own
    /// `reclaim_park` destroy — so when the runtime's re-check passes, zero
    /// vCPUs are live and the bare `hv_vm_destroy` succeeds. Any nonzero rc
    /// (e.g. HV_BUSY from a vCPU in a teardown window the registry no longer
    /// tracks, like a thread mid-exit) is a clean error: the VM was NOT
    /// destroyed, and the caller must NOT set the vm-released flag — the park
    /// stays vCPU-only and the wake side stays `reclaim_resume`.
    pub(crate) fn release_vm_after_reclaim_park(&mut self) -> Result<(), TrapError> {
        if self.reclaim_authority != ReclaimParkAuthority::VcpuParked {
            return Err(TrapError::Hypervisor(
                "release_vm_after_reclaim_park: no parked vCPU authority (reclaim_park did not run)"
                    .into(),
            ));
        }
        crate::probes::vm_lifecycle(2, -1);
        let vm_rc = unsafe { inventory_hv_vm_destroy() };
        if vm_rc != 0 {
            return Err(TrapError::Hypervisor(format!(
                "release_vm_after_reclaim_park: hv_vm_destroy rc={vm_rc:#x}"
            )));
        }
        record_vm_released();
        self.reclaim_authority.mark_vm_parked()?;
        Ok(())
    }

    /// Resume a process parked by [`Self::shared_wait_park`]: create a fresh VM
    /// and vCPU, re-map this process's existing host backings, then restore the
    /// saved guest registers.
    ///
    /// `replay_alias_union` (the MT whole-VM lease first-waker rebuild): also
    /// re-map every live process-global [`alias_registry`] entry this thread's
    /// per-thread `mappings` lacks. Threads share ONE VM but `mappings` is
    /// per-thread, so a high-VA alias a STILL-PARKED sibling mapped would
    /// otherwise be missing from the rebuilt stage-2 (the same shape the fork
    /// rebuild repairs with its quiesced-sibling union). Safe because every
    /// parked sibling holds its `OwnedHostMapping`s alive while parked, and no
    /// guest thread of this process runs during the rebuild (the caller holds
    /// the topology lock; claim-false wakers rebind behind it) — so no
    /// interleaving `munmap` can invalidate an entry mid-replay. Entries are
    /// NOT pushed into `self.mappings` (ownership stays with the mapping
    /// thread; a later rebuild re-reads the registry, which reflects any
    /// munmap since). Single-threaded resumes pass `false` — their own
    /// `mappings` list is complete by construction, and a forked child must
    /// NOT re-establish inherited parent/sibling aliases the fork rebuild
    /// deliberately dropped. The bounded lazy on-fault re-map in `run_to_exit`
    /// remains the backstop either way.
    pub(crate) fn shared_wait_resume(
        &mut self,
        vcpu: &mut applevisor::vcpu::Vcpu,
        mailbox: &mut MailboxBinding,
        replay_alias_union: bool,
        continuation: Option<carrick_hal::threaded::Aarch64SyscallContinuationV1>,
    ) -> Result<(), TrapError> {
        if self.reclaim_authority != ReclaimParkAuthority::VmParked {
            return Err(TrapError::Hypervisor(
                "shared_wait_resume: no parked VM executor authority".to_owned(),
            ));
        }
        let continuation = continuation.ok_or_else(|| {
            TrapError::Hypervisor(
                "shared_wait_resume: parked syscall has no typed continuation authority".to_owned(),
            )
        })?;
        let (new_vm, permit) = create_vm_with_admission(VmCreateAdmission::SharedWaitResume)?;
        let new_vcpu = create_vcpu_with_permit(&new_vm, permit)?;
        enable_el0_counter_access(new_vcpu.id());
        Self::configure_executor_invariants(&new_vcpu)?;
        self.vcpu_id = new_vcpu.id();
        self.vcpu_handle = new_vcpu.get_handle();
        std::mem::forget(std::mem::replace(vcpu, new_vcpu));
        replace_destroyed_vm(self, new_vm);

        // Snapshot the registry's CURRENT membership before the replay: an
        // alias another thread `munmap`'d while we were parked was removed
        // from the registry (`unregister_alias`) but may still sit in this
        // thread's per-thread `mappings` list — re-REGISTERING it below would
        // resurrect a dead index entry that a later syscall/fault could
        // resolve to a freed backing. Registration is creation-complete
        // (every `add_alias` registers; removal happens only on munmap /
        // execve-clear), so absence here means "gone on purpose".
        let registered_aliases = alias_registry().lock().clone();
        let mut mapped_extents = std::collections::HashSet::new();
        for mapping in &self.mappings {
            // Skip a sibling-munmap'd stale high-VA entry ENTIRELY (absence
            // from the registry = gone on purpose, mirroring the union loop
            // below): hv_vm_map'ing it would map a freed host VA
            // (ChildMapFailed → wake fatal) or squat a dead IPA a later mmap
            // collides with.
            let live_alias = mapping
                .is_dynamic_alias
                .then(|| {
                    registered_aliases.iter().find(|alias| {
                        alias_matches_process_scope(alias.ownership_scope, self.mm_root_slot)
                            && alias.start == mapping.start
                            && alias.ipa == mapping.ipa
                            && alias.host_addr == mapping.host_addr as usize
                            && alias.size == semantic_extent_size(mapping.start, mapping.end)
                    })
                })
                .flatten();
            if mapping.is_dynamic_alias && live_alias.is_none() {
                continue;
            }
            let (host_addr, ipa, size, perms) = live_alias.map_or(
                (
                    mapping.host_addr,
                    mapping.ipa,
                    mapping.size,
                    u64::from(mapping.perms),
                ),
                |alias| {
                    (
                        alias.physical_host_addr as *mut u8,
                        alias.physical_ipa,
                        alias.physical_size,
                        alias.perms,
                    )
                },
            );
            if !mapped_extents.insert((ipa, size)) {
                continue;
            }
            let r = unsafe { inventory_hv_vm_map(host_addr.cast(), ipa, size, perms) };
            if r != 0 {
                return Err(TrapError::ChildMapFailed {
                    host_addr: host_addr as u64,
                    guest_start: ipa,
                    size,
                    code: r as u32,
                });
            }
        }

        if replay_alias_union || self.mappings.iter().any(|mapping| mapping.is_dynamic_alias) {
            // Copy the entries out so the registry mutex isn't held across the
            // hv_vm_map syscalls (`AliasBacking` is `Copy`).
            for b in registered_aliases {
                if !alias_matches_process_scope(b.ownership_scope, self.mm_root_slot)
                    || !mapped_extents.insert((b.physical_ipa, b.physical_size))
                    || !alias_backing_is_live(b.host_addr)
                {
                    continue;
                }
                let r = unsafe {
                    inventory_hv_vm_map(
                        b.physical_host_addr as *mut std::ffi::c_void,
                        b.physical_ipa,
                        b.physical_size,
                        b.perms,
                    )
                };
                if r != 0 {
                    return Err(TrapError::ChildMapFailed {
                        host_addr: b.host_addr as u64,
                        guest_start: b.physical_ipa,
                        size: b.physical_size,
                        code: r as u32,
                    });
                }
            }
        }

        self.reacquire_mailbox_after_vcpu_create(vcpu, mailbox, Some(continuation))?;
        self.reclaim_authority.mark_live_after_recreate()?;
        Ok(())
    }

    /// Multithreaded fork — sibling side, step 1. Snapshot this vCPU and destroy
    /// it (raw `hv_vcpu_destroy`; only the owning thread may) so the forking
    /// thread can `hv_vm_destroy` before `libc::fork` (which fails HV_BUSY while
    /// any vCPU is alive). The wrapper is left stale until `rebuild_vcpu_after_fork`.
    pub(crate) fn release_vcpu_for_fork(
        &mut self,
        vcpu: &mut applevisor::vcpu::Vcpu,
    ) -> Result<(), TrapError> {
        // Publish this sibling's regions so the forking thread re-maps them into
        // the rebuilt parent VM (the rebuild otherwise replays only the forker's
        // own mappings, dropping this thread's per-thread aliases). We then park
        // (caller: release_and_park_vcpu_for_fork) holding our OwnedHostMappings
        // alive, so the forker re-maps live backings.
        publish_sibling_fork_mappings(&self.mappings);
        let snap = HvfInner::snapshot_vcpu_from(vcpu)?;
        FORK_VCPU_SNAPSHOT.with(|s| *s.borrow_mut() = Some(snap));
        let vcpu_id = vcpu.id();
        let rc = unsafe { applevisor_sys::hv_vcpu_destroy(vcpu_id) };
        if rc == 0 {
            vcpu_destroyed(vcpu_id);
        }
        // phase 3: a nonzero rc means this sibling FAILED to destroy its own
        // vCPU, so it stays live and the forker's hv_vm_destroy hits HV_BUSY.
        crate::probes::fork_quiesce(3, rc as i64, vcpu.id() as i64, unsafe { libc::getpid() });
        Ok(())
    }

    /// Multithreaded fork — forking thread (parent), after rebuilding its VM.
    /// Publish a clone of the new process VM so quiesced siblings can recreate
    /// their vCPUs in it.
    pub(crate) fn publish_vm_for_siblings(&self) {
        *rebuilt_vm_cell().lock() = Some((*self._vm).clone());
    }

    /// Multithreaded fork — sibling side, step 2 (after the parent published the
    /// rebuilt VM and released the quiesce). Recreate this vCPU in the new VM
    /// and restore the pre-fork register state. Mappings are VM-global (the
    /// parent remapped them into the shared VM), so nothing to re-map here.
    pub(crate) fn rebuild_vcpu_after_fork(
        &mut self,
        vcpu: &mut applevisor::vcpu::Vcpu,
        mailbox: &mut MailboxBinding,
    ) -> Result<(), TrapError> {
        let snap = FORK_VCPU_SNAPSHOT
            .with(|s| s.borrow_mut().take())
            .ok_or_else(|| TrapError::Hypervisor("no fork vCPU snapshot for rebuild".into()))?;
        // Post-fork: recreate in the parent's rebuilt VM (published). On a
        // quiesce ABORT (timeout — no fork happened), nothing was published and
        // the existing VM is still live, so recreate the vCPU in it.
        let new_vm = rebuilt_vm_cell()
            .lock()
            .clone()
            .unwrap_or_else(|| (*self._vm).clone());
        let new_vcpu = create_vcpu(&new_vm)?;
        enable_el0_counter_access(new_vcpu.id());
        self.vcpu_id = new_vcpu.id();
        self.vcpu_handle = new_vcpu.get_handle();
        // Replace _vm and vcpu WITHOUT running applevisor's panicky Drop on the
        // old (already-destroyed) handles — mirror the fork/thread-sibling
        // leak-until-exit discipline.
        std::mem::forget(std::mem::replace(vcpu, new_vcpu));
        replace_destroyed_vm(self, new_vm);
        HvfInner::restore_vcpu_into(vcpu, &snap)?;
        self.rebind_mailbox_after_vcpu_create(vcpu, mailbox, true)?;
        self.last_exit_class = snap.last_exit_class;
        Ok(())
    }

    /// A guest thread is exiting: destroy ITS OWN vCPU (only the owning thread
    /// may) so the slot is freed in the process-global VM. Without this, the
    /// no-op `Drop` leaks the vCPU live forever, and a later fork's
    /// `hv_vm_destroy` trips over the accumulated dead-thread vCPUs (HV_BUSY).
    /// Raw `hv_vcpu_destroy`, not applevisor's panicky wrapper.
    pub(crate) fn destroy_vcpu_on_thread_exit(&mut self, vcpu: &mut applevisor::vcpu::Vcpu) {
        let vcpu_id = vcpu.id();
        let rc = unsafe { applevisor_sys::hv_vcpu_destroy(vcpu_id) };
        if rc == 0 {
            vcpu_destroyed(vcpu_id);
        }
    }

    /// Multithreaded legacy-VMM fork — PRE-`libc::fork` half (the forking
    /// thread, single process). Capture mapping descriptors, clone only the
    /// child's independently editable page-table/control backing, and tear down
    /// the HVF VM via the raw API (a live VM at fork time makes the child's
    /// `hv_vm_create` fail). Host-MAP_PRIVATE guest buffers receive ordinary
    /// fork COW. Both sides then rebuild from the stashed descriptors in
    /// `fork_rebuild`. Does NOT call `libc::fork` (the shared engine does that)
    /// and does NOT snapshot the vCPU registers (the engine snapshots separately
    /// and passes them into `fork_rebuild`).
    pub(crate) fn fork_prepare_and_teardown(&mut self) -> Result<(), TrapError> {
        let elapsed_us = |start: std::time::Instant| -> u64 {
            let micros = start.elapsed().as_micros();
            micros.min(u128::from(u64::MAX)) as u64
        };
        // Probe parity with the old monolithic fork: the engine snapshots the
        // vCPU (PC/ELR/CPSR) just before this; report the pre-fork marker. The
        // vCPU registers are no longer read here (the engine owns the snapshot),
        // so fire the marker with zeros — the engine's snapshot carries the
        // authoritative values the old `fork_pre` reported.
        crate::probes::fork_pre(0, 0, 0);

        // vfork (CLONE_VM): before libc::fork, mark each WRITABLE guest region
        // VM_INHERIT_SHARE so the fork SHARES its pages with the child (XNU
        // vm_map_fork_share — child references the SAME vm_object, no shadow/copy,
        // both is_shared; the parent is NOT made COW). This gives a CLONE_VFORK
        // child true write-visibility into the SUSPENDED parent (clone05) while
        // keeping the SAME physical pages, so the child's re-hv_vm_map binds the
        // same PAs — unlike a fresh MAP_SHARED copy (smashed the vfork-exec stack)
        // or a mach_vm_remap COW (HVF rejects). `guest_writable` is the exact
        // discriminator: it is false for every carrick-internal region (trampolines,
        // vectors, page tables, identity page, vvar, sigreturn) and read-only guest
        // text, so the share never touches the trap machinery; the page-table region
        // additionally stays a private clone (child branch below). minherit covers
        // the WHOLE region (offset 0, full len) — a sub-range would clip the map
        // entry and shadow on the first fork. The parent restores VM_INHERIT_COPY
        // after the fork (fork_rebuild) so later PLAIN forks stay cheap COW.
        let phase_start = std::time::Instant::now();
        if self.vfork_share {
            for m in &self.mappings {
                let is_pt = m.start == crate::memory::LINUX_PAGE_TABLES_BASE;
                if m.guest_writable && !m.sharing.shares_across_fork() && !is_pt {
                    set_region_fork_inheritance(m.host_addr, m.size, VM_INHERIT_SHARE);
                }
            }
        }
        crate::probes::fork_lifecycle(
            4,
            0,
            elapsed_us(phase_start),
            self.mappings.len() as i64,
            i64::from(self.vfork_share),
        );

        let phase_start = std::time::Instant::now();
        let aliases = alias_registry().lock().clone();
        let alias_index = process_alias_index(&aliases, self.mm_root_slot);
        let mapping_descs: Vec<ForkMappingDesc> = self
            .mappings
            .iter()
            .filter(|mapping| mapping_is_current_for_process_fork_indexed(mapping, &alias_index))
            .map(|m| ForkMappingDesc {
                start: m.start,
                ipa: m.ipa,
                physical_ipa: m.physical_ipa,
                end: m.end,
                host: ForkMappingHost::Borrowed(m.host_addr),
                size: m.size,
                physical_size: m.physical_size,
                perms: m.perms,
                is_dynamic_alias: m.is_dynamic_alias,
                sharing: m.sharing,
                guest_writable: m.guest_writable,
                shared_key_base: m.shared_key_base,
                shared_key_offset: m.shared_key_offset,
            })
            .collect();
        crate::probes::fork_lifecycle(4, 1, elapsed_us(phase_start), mapping_descs.len() as i64, 0);

        let share_vm = self.vfork_share;
        let mut child_descs: Vec<ForkMappingDesc> = Vec::with_capacity(mapping_descs.len());
        let phase_start = std::time::Instant::now();
        for desc in &mapping_descs {
            // vfork (CLONE_VM): the child shares the parent's address space until it
            // execs/exits, while the parent vCPU stays SUSPENDED. carrick forks a
            // real host process, and bulk guest RAM is host-MAP_PRIVATE, so the
            // child's COW view is ISOLATED — which is exactly right for the common
            // vfork-FOR-EXEC case (Go, posix_spawn, the shell): the child's pre-exec
            // trampoline writes COW away, leaving the suspended parent's stack/canary
            // intact, and execve rebuilds the child fresh. (The STRICT vfork-write
            // corner — a CLONE_VFORK child that mutates a shared global the parent
            // then reads WITHOUT exec'ing, i.e. LTP clone05 — is a known gap: making
            // those writes shared requires promoting the writable regions to
            // MAP_SHARED, which corrupts the live stack the child's exec trampoline
            // writes and regresses every vfork-exec. The isolation here is the
            // correct trade for real workloads.)
            //
            // The stage-1 page-table BACKING stays a PRIVATE clone even for vfork:
            // the child's cloned PageTableManager assumes a private backing, and a
            // COW/shared PT desyncs the guest VA->PA walk under HVF (breaks
            // cross-process futex/tst_checkpoint + clone05). Tiny region, ~free.
            let is_page_table_region = desc.start == crate::memory::LINUX_PAGE_TABLES_BASE;
            let child_host =
                if (share_vm && !is_page_table_region) || desc.sharing.shares_across_fork() {
                    ForkMappingHost::Borrowed(desc.host.ptr()) // shared mapping: child maps the SAME buffer
                } else if is_page_table_region {
                    ForkMappingHost::Owned(clone_page_tables_for_child(desc.host.ptr(), desc.size)?)
                } else {
                    // Bulk private guest RAM (data/bss/heap/stack/mmap arena) is
                    // host-MAP_PRIVATE, so libc::fork already COW-isolates it: the
                    // child re-maps its OWN COW view of the same VA, skipping the
                    // eager mincore+copy snapshot (the dominant per-fork cost — the
                    // epoll-ltp ~50x win).
                    ForkMappingHost::Borrowed(desc.host.ptr())
                };
            child_descs.push(ForkMappingDesc {
                start: desc.start,
                ipa: desc.ipa,
                physical_ipa: desc.physical_ipa,
                end: desc.end,
                host: child_host,
                size: desc.size,
                physical_size: desc.physical_size,
                perms: desc.perms,
                is_dynamic_alias: desc.is_dynamic_alias,
                sharing: desc.sharing,
                guest_writable: desc.guest_writable,
                shared_key_base: desc.shared_key_base,
                shared_key_offset: desc.shared_key_offset,
            });
        }
        crate::probes::fork_lifecycle(4, 2, elapsed_us(phase_start), child_descs.len() as i64, 0);

        // Tear down the parent's HVF context BEFORE the engine forks. macOS's
        // HVF kernel state is not fork-safe: if a VM exists in the parent at
        // fork(2) time, the child inherits a "resource is busy" state that
        // prevents `hv_vm_create` from succeeding. Both processes then rebuild a
        // fresh VM from the stashed descriptors in `fork_rebuild`. The engine's
        // `freeze_ram_for_fork` hook does NOT pass the vCPU, so we destroy by the
        // tracked `vcpu_id` (the stale `HvfAarch64Vcpu` wrapper is replaced in
        // `fork_rebuild`, which DOES hold `&mut vcpu`).
        let phase_start = std::time::Instant::now();
        let vcpu_destroy_rc = unsafe { applevisor_sys::hv_vcpu_destroy(self.vcpu_id) };
        if vcpu_destroy_rc == 0 {
            vcpu_destroyed(self.vcpu_id);
        }
        crate::probes::fork_lifecycle(
            4,
            3,
            elapsed_us(phase_start),
            vcpu_destroy_rc as i64,
            self.vcpu_id as i64,
        );
        let phase_start = std::time::Instant::now();
        crate::probes::vm_lifecycle(2, -1);
        let vm_destroy_rc = unsafe { inventory_hv_vm_destroy() };
        if vm_destroy_rc == 0 {
            record_vm_released();
        }
        // phase 2: a nonzero rc means a vCPU was still live at teardown — the
        // HV_BUSY root cause (the rebuilt VM is then corrupt and sibling
        // vcpu_create fails). Traceable via `carrick trace` fork__quiesce.
        crate::probes::fork_quiesce(
            2,
            vm_destroy_rc as i64,
            VCPU_LIVE.load(std::sync::atomic::Ordering::SeqCst),
            unsafe { libc::getpid() },
        );
        crate::probes::fork_lifecycle(
            4,
            4,
            elapsed_us(phase_start),
            vm_destroy_rc as i64,
            VCPU_LIVE.load(std::sync::atomic::Ordering::SeqCst),
        );

        let phase_start = std::time::Instant::now();
        self.fork_mapping_descs = mapping_descs;
        self.fork_child_descs = child_descs;
        crate::probes::fork_lifecycle(
            4,
            5,
            elapsed_us(phase_start),
            self.fork_mapping_descs.len() as i64,
            self.fork_child_descs.len() as i64,
        );
        Ok(())
    }

    /// Multithreaded fork — POST-`libc::fork` half. Build a fresh VM + vCPU,
    /// re-`hv_vm_map` the right buffers (the CHILD uses the private snapshots; the
    /// PARENT re-maps its own + the union of every quiesced sibling's regions),
    /// restore the engine-supplied register `snap` onto the NEW vCPU, and
    /// re-stamp the vvar RNG generation (child). `is_child` keys the parent-vs-
    /// child inheritance EXACTLY as the old monolithic `fork`.
    pub(crate) fn fork_rebuild(
        &mut self,
        vcpu: &mut applevisor::vcpu::Vcpu,
        mailbox: &mut MailboxBinding,
        snap: &VcpuSnapshot,
        is_child: bool,
    ) -> Result<(), TrapError> {
        let role = if is_child { 1 } else { 0 };
        if is_child {
            self.mailbox_slots
                .retain_only_after_fork_child(mailbox.slot());
        }
        let rebuild_start = std::time::Instant::now();
        let elapsed_us = |start: std::time::Instant| -> u64 {
            let micros = start.elapsed().as_micros();
            micros.min(u128::from(u64::MAX)) as u64
        };
        // Take the descriptors stashed in `fork_prepare_and_teardown`. The parent
        // re-maps its own buffers (`mapping_descs`); the child re-maps the private
        // snapshots / shared originals (`child_descs`). The unused set drops here.
        let mapping_descs = std::mem::take(&mut self.fork_mapping_descs);
        let child_descs = std::mem::take(&mut self.fork_child_descs);

        // Build a fresh VM + vCPU. Both processes have just had their HVF state
        // torn down (parent did it pre-fork; child inherited the now-empty state
        // via fork). Each side independently re-registers the inherited host
        // buffers via raw `hv_vm_map`.
        if is_child {
            let phase_start = std::time::Instant::now();
            reset_admission_permits_after_fork_child();
            crate::probes::fork_lifecycle(role + 4, 10, elapsed_us(phase_start), 0, 0);
        }
        let phase_start = std::time::Instant::now();
        let (new_vm, permit) = create_vm_with_admission(VmCreateAdmission::ForkRebuild {
            vfork: self.vfork_share,
        })?;
        crate::probes::fork_lifecycle(role + 4, 11, elapsed_us(phase_start), 0, 0);
        let phase_start = std::time::Instant::now();
        let new_vcpu = create_vcpu_with_permit(&new_vm, permit)?;
        crate::probes::fork_lifecycle(
            role + 4,
            12,
            elapsed_us(phase_start),
            new_vcpu.id() as i64,
            0,
        );
        let phase_start = std::time::Instant::now();
        enable_el0_counter_access(new_vcpu.id());
        self.vcpu_id = new_vcpu.id();
        self.vcpu_handle = new_vcpu.get_handle();

        // Swap the new VM + vCPU into place WITHOUT running applevisor's Drop on
        // the old (raw-destroyed) handles. `is_forked_child` is true only in the
        // child process; the parent kept its pre-fork host process identity.
        std::mem::forget(std::mem::replace(vcpu, new_vcpu));
        replace_destroyed_vm(self, new_vm);
        crate::probes::fork_lifecycle(
            role + 4,
            13,
            elapsed_us(phase_start),
            self.vcpu_id as i64,
            0,
        );

        // In the parent, keep the exact shared protection table siblings already
        // use; otherwise post-fork mmap/mprotect changes split across two Arcs and
        // one thread can see a valid Go heap futex as PROT_NONE. The child is
        // single-threaded after fork, so it gets a private copy of the parent's
        // ranges at the fork point.
        let phase_start = std::time::Instant::now();
        self.protections = if is_child {
            std::sync::Arc::new(MemoryProtections::from_snapshot(
                self.protections.snapshot_all(),
            ))
        } else {
            std::sync::Arc::clone(&self.protections)
        };
        // The stage-1 page-table manager must survive fork EXACTLY like
        // protections. The PARENT's tables and their host backing are unchanged
        // by fork, so it keeps the SAME shared manager — a fresh manager would
        // rebuild from the (live) backing with `next_free` reset to the first
        // spare, then re-hand-out table pages already in use, writing L3 entries
        // over a live L2 table (proven: the cross-test TestUserArenaNew SIGSEGV,
        // an L2 slot holding `USER_PAGE_FLAGS | <arena PA>`). The CHILD gets a
        // private backing copy, so it needs its OWN manager — but a CLONE of the
        // parent's state, not a reset, so its bump cursor matches that backing.
        self.page_tables = if is_child {
            let cloned = self.page_tables.lock().clone();
            std::sync::Arc::new(parking_lot::Mutex::new(cloned))
        } else {
            std::sync::Arc::clone(&self.page_tables)
        };
        // CRITICAL: LEAK the old mapping Vec (do NOT drop it). Each old
        // `HvfMappedRegion` owns an `OwnedHostMapping` whose Drop `munmap`s the host
        // backing — and the `mapping_descs` we re-`hv_vm_map` below carry BORROWED
        // raw pointers INTO those exact buffers. Dropping the old Vec here would
        // munmap them out from under the re-map, so `hv_vm_map` faults (HV_ERROR).
        // This matches the original monolithic `fork`, which swapped the whole
        // `HvfInner` via `ptr::write` + `mem::forget` and so never ran Drop on the
        // old mappings (the leak-until-exit / ManuallyDrop discipline; the kernel
        // reclaims the pages at process exit). The CHILD remaps its own private
        // snapshots (`child_descs`), which are MOVED into the rebuilt mappings below,
        // so the parent's borrowed originals it inherited via COW are likewise kept
        // alive by this leak.
        std::mem::forget(std::mem::replace(
            &mut self.mappings,
            Vec::with_capacity(mapping_descs.len()),
        ));
        self.reclaim_authority = ReclaimParkAuthority::Live;
        self.last_exit_class = snap.last_exit_class;
        self.last_fault_esr = 0;
        self.is_forked_child = is_child;
        self.forked_no_exec = is_child;
        self.last_syscall_nr = None;
        self.last_syscall_orig_x0 = 0;
        crate::probes::fork_lifecycle(role + 4, 14, elapsed_us(phase_start), 0, 0);

        // Re-map each region using raw hv_vm_map. The PARENT re-maps its original
        // buffers; the CHILD maps the pre-fork private snapshots for PRIVATE
        // regions and the shared originals for guest-MAP_SHARED ones.
        let descs = if is_child { child_descs } else { mapping_descs };
        let desc_count = descs.len() as u64;
        crate::probes::fork_rebuild(role, 0, desc_count, 0, 0);
        let local_map_start = std::time::Instant::now();
        let mut local_maps = 0u64;
        for desc in descs {
            let host_addr = desc.host.ptr();
            let perms_raw: u64 = u64::from(desc.perms);
            let r = unsafe {
                inventory_hv_vm_map(
                    host_addr as *mut std::ffi::c_void,
                    desc.ipa,
                    desc.size,
                    perms_raw,
                )
            };
            if r != 0 {
                return Err(TrapError::ChildMapFailed {
                    host_addr: host_addr as u64,
                    guest_start: desc.ipa,
                    size: desc.size,
                    code: r as u32,
                });
            }
            local_maps = local_maps.saturating_add(1);
            // Re-register every high-VA alias into the process-shared index with
            // THIS rebuild's host_addr. Critical for the CHILD: the index is
            // COW-inherited from the parent. A PRIVATE alias names the same host
            // VA in the child process but its host-MAP_PRIVATE fork view; this
            // overwrite rebinds the process-local registry to that view. For the
            // parent it is idempotent. Low-VA boot regions are not aliases (every
            // thread has them) and are never in the index.
            if desc.is_dynamic_alias {
                if let Some(previous) = alias_registry()
                    .lock()
                    .iter()
                    .find(|alias| alias.start == desc.start && alias.ipa == desc.ipa)
                    .copied()
                {
                    register_shared_alias(AliasBacking {
                        host_addr: host_addr as usize,
                        physical_host_addr: if previous.physical_host_addr == previous.host_addr {
                            host_addr as usize
                        } else {
                            previous.physical_host_addr
                        },
                        ownership_scope: alias_ownership_scope(desc.sharing, self.mm_root_slot),
                        ..previous
                    });
                }
            }
            self.mappings.push(HvfMappedRegion {
                start: desc.start,
                ipa: desc.ipa,
                physical_ipa: desc.physical_ipa,
                end: desc.end,
                host_addr,
                size: desc.size,
                physical_size: desc.physical_size,
                perms: desc.perms,
                guest_writable: desc.guest_writable,
                // No Memory object — the host buffer is either an inherited
                // shared mapping or a snapshot copy. Drop runs no HVF call for
                // this mapping; the engine's VM tear-down releases all stage-2
                // entries in one shot.
                memory: None,
                host_mapping: desc.host.into_owned(),
                stage2_lease: None,
                is_dynamic_alias: desc.is_dynamic_alias,
                sharing: desc.sharing,
                shared_key_base: desc.shared_key_base,
                shared_key_offset: desc.shared_key_offset,
                owner_generation: global_frame_host_owner_generation(
                    desc.physical_ipa,
                    desc.physical_size as u64,
                ),
            });
        }
        crate::probes::fork_rebuild(role, 1, desc_count, local_maps, elapsed_us(local_map_start));

        // PARENT post-vfork: restore VM_INHERIT_COPY on the regions we shared for
        // this vfork (set VM_INHERIT_SHARE in fork_prepare_and_teardown), so a LATER
        // plain fork of this parent gets cheap COW isolation again rather than
        // silently sharing its address space. The vfork child execs/exits, so it
        // keeps the inherited SHARE attribute harmlessly (a no-op once it detaches).
        if !is_child && self.vfork_share {
            let phase_start = std::time::Instant::now();
            for m in &self.mappings {
                let is_pt = m.start == crate::memory::LINUX_PAGE_TABLES_BASE;
                if m.guest_writable && !m.sharing.shares_across_fork() && !is_pt {
                    set_region_fork_inheritance(m.host_addr, m.size, VM_INHERIT_COPY);
                }
            }
            crate::probes::fork_lifecycle(
                role + 4,
                15,
                elapsed_us(phase_start),
                self.mappings.len() as i64,
                0,
            );
        }

        // PARENT only: re-map the UNION of all quiesced siblings' regions that
        // the forking thread's `mapping_descs` lacked. Threads share one VM but
        // this rebuild replays only the forker's mappings, so a per-thread alias
        // a SIBLING established (e.g. a Go heap-arena chunk at high-VA) is missing
        // from the rebuilt stage-2 — the parent then DC-ZVA-faults on it
        // (translation fault, mapped_here=false). The shared stage-1 page tables
        // (kept by Arc above) already carry the VA->IPA entry; only the stage-2
        // `hv_vm_map` is absent, so re-map each sibling region by IPA (deduped
        // against what we just mapped; alias IPAs are process-global + unique).
        // The backing is alive: every publisher PARKED in
        // release_and_park_vcpu_for_fork after publishing and stays parked until
        // we end the quiesce, holding its OwnedHostMapping. The region is UNOWNED
        // here (memory/host_mapping = None) so the parent never frees a buffer the
        // sibling owns. The CHILD is single-threaded post-fork (uses child_descs),
        // so it must NOT inherit sibling aliases — hence parent only.
        let mut sibling_maps = 0u64;
        if !is_child {
            let mut mapped_ipas: std::collections::HashSet<u64> =
                self.mappings.iter().map(|m| m.ipa).collect();
            let siblings = sibling_fork_mappings().lock().clone();
            let aliases = alias_registry().lock().clone();
            let sibling_count = siblings.len() as u64;
            let sibling_map_start = std::time::Instant::now();
            for sm in siblings {
                if sm.is_dynamic_alias
                    && !aliases.iter().any(|alias| {
                        alias_matches_process_scope(alias.ownership_scope, self.mm_root_slot)
                            && alias.start == sm.start
                            && alias.ipa == sm.ipa
                            && alias.host_addr == sm.host_addr
                            && alias.size == semantic_extent_size(sm.start, sm.end)
                    })
                {
                    continue;
                }
                if !mapped_ipas.insert(sm.ipa) {
                    continue;
                }
                let r = unsafe {
                    inventory_hv_vm_map(
                        sm.host_addr as *mut std::ffi::c_void,
                        sm.ipa,
                        sm.size,
                        sm.perms,
                    )
                };
                if r != 0 {
                    return Err(TrapError::ChildMapFailed {
                        host_addr: sm.host_addr as u64,
                        guest_start: sm.ipa,
                        size: sm.size,
                        code: r as u32,
                    });
                }
                sibling_maps = sibling_maps.saturating_add(1);
                self.mappings.push(HvfMappedRegion {
                    start: sm.start,
                    ipa: sm.ipa,
                    physical_ipa: sm.physical_ipa,
                    end: sm.end,
                    host_addr: sm.host_addr as *mut u8,
                    size: sm.size,
                    physical_size: sm.physical_size,
                    perms: applevisor::memory::MemPerms::from(sm.perms),
                    guest_writable: sm.guest_writable,
                    memory: None,
                    host_mapping: None,
                    stage2_lease: None,
                    is_dynamic_alias: sm.is_dynamic_alias,
                    sharing: sm.sharing,
                    shared_key_base: sm.shared_key_base,
                    shared_key_offset: sm.shared_key_offset,
                    owner_generation: global_frame_host_owner_generation(
                        sm.physical_ipa,
                        sm.physical_size as u64,
                    ),
                });
            }
            crate::probes::fork_rebuild(
                role,
                2,
                sibling_count,
                sibling_maps,
                elapsed_us(sibling_map_start),
            );
        }

        // Restore vCPU register state from the engine's pre-fork snapshot. Both
        // parent and child resume inside the same `clone` syscall site; the
        // dispatcher then writes the appropriate retval into X0 (child pid for
        // parent, 0 for child).
        let phase_start = std::time::Instant::now();
        HvfInner::restore_vcpu_into(vcpu, snap)?;
        self.rebind_mailbox_after_vcpu_create(vcpu, mailbox, true)?;
        self.last_exit_class = snap.last_exit_class;
        crate::probes::fork_lifecycle(role + 4, 16, elapsed_us(phase_start), 0, 0);
        crate::probes::fork_rebuild(role, 3, desc_count, local_maps, elapsed_us(rebuild_start));
        let post_pid = if is_child {
            0
        } else {
            unsafe { libc::getpid() }
        };
        crate::probes::fork_post(post_pid, snap.core.pc, snap.core.elr_el1);
        if is_child {
            // The child has a new pid, but its inherited USDT DOF is registered
            // with the kernel under the PARENT's pid. Re-register so DTrace's
            // `carrick*` provider matches this child too — otherwise forked guest
            // processes (apt's http method, dpkg-deb's tar subprocess) are
            // invisible to `carrick trace`.
            let phase_start = std::time::Instant::now();
            let _ = crate::probes::register_dtrace_probes();
            crate::probes::fork_lifecycle(role + 4, 17, elapsed_us(phase_start), 0, 0);
            // P2 getrandom fork-safety: re-stamp the vvar RNG generation with a
            // fresh epoch. `self` is now the child's rebuilt engine — its vvar
            // mapping points at the child's freshly re-mapped snapshot buffer, and
            // the vCPU was just recreated (clean stage-2 TLB) — so this write IS
            // visible to the child's guest reads. The child's distinct generation
            // forces the userspace getrandom blob to reseed instead of reusing the
            // parent's keystream (gated by conformance-probes/getrandomvdsofork).
            let phase_start = std::time::Instant::now();
            let _ = self.stamp_rng_generation();
            crate::probes::fork_lifecycle(role + 4, 18, elapsed_us(phase_start), 0, 0);
        }
        Ok(())
    }

    pub(crate) fn take_persistent_executor_spec(
        &mut self,
    ) -> Result<PersistentExecutorSpec, TrapError> {
        if self.carrier_mappings.is_some() {
            return Err(TrapError::Hypervisor(
                "persistent executor carrier authority was already extracted".to_owned(),
            ));
        }
        let carrier_mappings =
            std::sync::Arc::new(PersistentCarrierMappings::extract(&mut self.mappings)?);
        Ok(PersistentExecutorSpec {
            vm: (*self._vm).clone(),
            carrier_mappings,
            mailbox_slots: std::sync::Arc::clone(&self.mailbox_slots),
            syscall_transport: self.syscall_transport,
        })
    }

    fn allocate_persistent_mailbox_for_vcpu(
        spec: &PersistentExecutorSpec,
        vcpu: &applevisor::vcpu::Vcpu,
    ) -> Result<MailboxBinding, TrapError> {
        use applevisor::prelude::SysReg;

        let lease = spec
            .mailbox_slots
            .allocate()
            .map_err(|error| TrapError::Hypervisor(error.to_string()))?;
        let address = lease.id().guest_address();
        let pointer = spec
            .carrier_mappings
            .host_pointer(
                address,
                carrick_aarch64::mailbox::AARCH64_SYSCALL_MAILBOX_SIZE as usize,
            )
            .ok_or_else(|| {
                TrapError::Hypervisor(format!(
                    "persistent executor syscall mailbox slot {} at {address:#x} is not mapped",
                    lease.id().raw()
                ))
            })?
            .cast::<carrick_aarch64::mailbox::Aarch64SyscallMailbox>();
        // SAFETY: the carrier projection was validated to contain the complete
        // fixed mailbox arena, and the lease uniquely owns this slot.
        let binding = unsafe { MailboxBinding::new(lease, pointer, spec.syscall_transport) };
        vcpu.set_sys_reg(SysReg::SP_EL1, address)
            .map_err(hvf_error)?;
        Ok(binding)
    }

    pub(crate) fn from_persistent_executor_spec(
        spec: &PersistentExecutorSpec,
    ) -> Result<(HvfVmState, applevisor::vcpu::Vcpu, MailboxBinding), TrapError> {
        spec.carrier_mappings.audit()?;
        let vm = rebuilt_vm_cell()
            .lock()
            .clone()
            .unwrap_or_else(|| spec.vm.clone());
        let vcpu = create_vcpu(&vm)?;
        enable_el0_counter_access(vcpu.id());
        let state = HvfVmState {
            _vm: std::mem::ManuallyDrop::new(vm),
            task: HvfTaskState::neutral(),
            carrier_mappings: Some(std::sync::Arc::clone(&spec.carrier_mappings)),
            reclaim_authority: ReclaimParkAuthority::Live,
            mailbox_slots: std::sync::Arc::clone(&spec.mailbox_slots),
            syscall_transport: spec.syscall_transport,
            vcpu_id: vcpu.id(),
            vcpu_handle: vcpu.get_handle(),
        };
        Self::configure_executor_invariants(&vcpu)?;
        let mailbox = Self::allocate_persistent_mailbox_for_vcpu(spec, &vcpu)?;
        Self::audit_executor_invariants(&vcpu, mailbox.slot().guest_address())?;
        state.task.audit_neutral()?;
        Ok((state, vcpu, mailbox))
    }

    pub(crate) fn audit_persistent_executor_idle(&self) -> Result<(), TrapError> {
        self.task.audit_neutral()?;
        self.carrier_mappings
            .as_ref()
            .ok_or_else(|| {
                TrapError::Hypervisor(
                    "persistent executor lost carrier mapping authority".to_owned(),
                )
            })?
            .audit()
    }

    pub(crate) fn audit_persistent_worker_vcpu_boundary(
        &self,
        vcpu: &applevisor::vcpu::Vcpu,
        mailbox: &MailboxBinding,
    ) -> Result<(), TrapError> {
        self.audit_persistent_executor_idle()?;
        if !fork_vcpu_snapshot_is_empty_for_executor_boundary() {
            return Err(TrapError::Hypervisor(
                "persistent worker retained a legacy fork vCPU snapshot".to_owned(),
            ));
        }
        if self.reclaim_authority != ReclaimParkAuthority::Live {
            return Err(TrapError::Hypervisor(
                "persistent worker lost its live owner-thread vCPU authority".to_owned(),
            ));
        }
        if mailbox.is_released_for_executor_boundary() {
            return Err(TrapError::Hypervisor(
                "persistent worker released its executor-local mailbox".to_owned(),
            ));
        }
        if mailbox
            .export_task_continuation()
            .map_err(|error| {
                TrapError::Hypervisor(format!("audit persistent worker mailbox boundary: {error}"))
            })?
            .is_some()
        {
            return Err(TrapError::Hypervisor(
                "persistent worker retained a task syscall continuation".to_owned(),
            ));
        }
        use applevisor::prelude::SysReg;
        let sp_el1 = vcpu.get_sys_reg(SysReg::SP_EL1).map_err(hvf_error)?;
        if sp_el1 != mailbox.slot().guest_address() {
            return Err(TrapError::Hypervisor(format!(
                "persistent worker mailbox SP_EL1 drifted: {sp_el1:#x}/{:#x}",
                mailbox.slot().guest_address()
            )));
        }
        Ok(())
    }

    pub(crate) fn restore_persistent_worker_vcpu_boundary(
        &self,
        vcpu: &applevisor::vcpu::Vcpu,
        mailbox: &MailboxBinding,
    ) -> Result<(), TrapError> {
        use applevisor::prelude::SysReg;

        restore_persistent_executor_invariant_registers(
            |register, value| {
                let register = match register {
                    PersistentExecutorInvariantRegister::VbarEl1 => SysReg::VBAR_EL1,
                    PersistentExecutorInvariantRegister::SctlrEl1 => SysReg::SCTLR_EL1,
                    PersistentExecutorInvariantRegister::MairEl1 => SysReg::MAIR_EL1,
                    PersistentExecutorInvariantRegister::CpacrEl1 => SysReg::CPACR_EL1,
                    PersistentExecutorInvariantRegister::CntkctlEl1 => SysReg::CNTKCTL_EL1,
                    PersistentExecutorInvariantRegister::TpidrEl1 => SysReg::TPIDR_EL1,
                    PersistentExecutorInvariantRegister::SpEl1 => SysReg::SP_EL1,
                };
                vcpu.set_sys_reg(register, value).map_err(hvf_error)
            },
            mailbox.slot().guest_address(),
        )?;
        Self::audit_executor_invariants(vcpu, mailbox.slot().guest_address())
    }

    /// Build a [`ThreadSpec`] for a thread-creating `clone(CLONE_THREAD)`: clone the
    /// SHARED VM handle (Arc-refcounted, so the new thread can `vcpu_create` against
    /// it) + the SHARED protections/page-table Arcs + a COPY of the mapping
    /// descriptors (the new thread's vCPU sees the same guest memory; the stage-2
    /// entries are VM-global). Does NOT snapshot the vCPU — the engine carries the
    /// seeded register snapshot in its own `Aarch64SiblingSpec` and restores it onto
    /// the sibling vCPU via `restore_thread_start` after `from_thread_spec`.
    pub(crate) fn build_thread_spec(&self) -> Result<ThreadSpec, TrapError> {
        let mappings: Vec<ThreadMappingDesc> = self
            .mappings
            .iter()
            .map(ThreadMappingDesc::from_region)
            .collect();
        Ok(ThreadSpec {
            vm: (*self._vm).clone(),
            mappings,
            protections: std::sync::Arc::clone(&self.protections),
            page_tables: std::sync::Arc::clone(&self.page_tables),
            mailbox_slots: std::sync::Arc::clone(&self.mailbox_slots),
            syscall_transport: self.syscall_transport,
            persistent_vm_lifecycle: self.persistent_vm_lifecycle,
            mm_root_slot: self.mm_root_slot,
            frame_inventory: self.frame_inventory.shared_ledger(),
            cow_authority: self.cow_authority.clone(),
            cow_identity: self.cow_identity,
            cow_armed: std::sync::Arc::clone(&self.cow_armed),
            cow_deferred_publications: std::sync::Arc::clone(&self.cow_deferred_publications),
        })
    }

    /// Stand up a thread sibling on the current host thread from a [`ThreadSpec`]:
    /// create a new vCPU in the shared VM and mirror the inherited (UNOWNED)
    /// mapping metadata. Returns the `(state, vcpu)` pair; the engine restores the
    /// seeded register snapshot. MUST be called on the host thread that will own
    /// the vCPU (HVF requires vCPU create+run+destroy on one thread).
    pub(crate) fn from_thread_spec(
        spec: ThreadSpec,
    ) -> Result<(HvfVmState, applevisor::vcpu::Vcpu, MailboxBinding), TrapError> {
        let ThreadSpec {
            vm,
            mappings,
            protections,
            page_tables,
            mailbox_slots,
            syscall_transport,
            persistent_vm_lifecycle,
            mm_root_slot,
            frame_inventory,
            cow_authority,
            cow_identity,
            cow_armed,
            cow_deferred_publications,
        } = spec;

        // The spec captured `vm` at clone time. If a fork rebuilt the VM since
        // then (the spec's `vm` was destroyed), create the vCPU in the CURRENT
        // VM that the fork published instead — otherwise vcpu_create hits
        // HV_BUSY on a torn-down VM. Between forks the published cell holds the
        // live VM; with no fork yet it's empty and the spec's `vm` is current.
        // The caller holds `fork_quiesce::topology_lock()`, so this read can't
        // race a fork's republish.
        let vm = rebuilt_vm_cell().lock().clone().unwrap_or(vm);
        let vcpu = create_vcpu(&vm)?;
        enable_el0_counter_access(vcpu.id());

        let mut state = HvfVmState {
            _vm: std::mem::ManuallyDrop::new(vm),
            task: HvfTaskState {
                mappings: Vec::with_capacity(mappings.len()),
                mm_root_slot,
                pending_exec_mm_root_slot: None,
                pending_exec_asid: None,
                pending_exec_stage2_cleanup: None,
                shared_process_mm: false,
                last_exit_class: 0,
                last_fault_esr: 0,
                is_forked_child: false,
                forked_no_exec: false,
                protections,
                page_tables,
                last_syscall_nr: None,
                last_syscall_orig_x0: 0,
                vfork_share: false,
                fork_mapping_descs: Vec::new(),
                fork_child_descs: Vec::new(),
                persistent_vm_lifecycle,
                frame_inventory: HvpatchFrameInventoryState::new(frame_inventory),
                cow_authority,
                cow_identity,
                cow_armed,
                cow_deferred_publications,
                pending_fork_frame_receipts: Vec::new(),
                pending_process_aliases: Vec::new(),
                cow_rollback_scratch: None,
            },
            carrier_mappings: None,
            reclaim_authority: ReclaimParkAuthority::Live,
            mailbox_slots,
            syscall_transport,
            vcpu_id: vcpu.id(),
            vcpu_handle: vcpu.get_handle(),
        };

        for mapping in mappings {
            // `hv_vm_map` is VM-global on Hypervisor.framework. The new vCPU is
            // created in the parent's VM clone, so the parent mappings are
            // already visible here; reissuing them for every sibling is at best
            // an already-mapped no-op and at worst map-table churn while other
            // vCPUs are running. Keep only local metadata used by syscall-path
            // guest-memory accessors.
            state.mappings.push(mapping.into_unowned_region());
        }

        let mailbox = state.allocate_mailbox_for_vcpu(&vcpu)?;
        Ok((state, vcpu, mailbox))
    }

    pub(crate) fn build_process_spec(
        &self,
        request: carrick_hal::ProcessForkRequest,
        page_tables: &mut crate::page_table::PageTableManager,
        cow_ranges: &[carrick_aarch64::vmm::ForkCowRange],
    ) -> Result<ProcessSpec, TrapError> {
        use carrick_observability::probes::{
            HvpatchForkProcessSpecStage, HvpatchForkProcessSpecStagePhase,
        };

        let emit_stage =
            |phase: HvpatchForkProcessSpecStagePhase, started: std::time::Instant, units: u64| {
                let elapsed_ns = started.elapsed().as_nanos().min(u128::from(u64::MAX)) as u64;
                crate::probes::hvpatch_fork_process_spec_stage(HvpatchForkProcessSpecStage::new(
                    phase,
                    request.child_tid.raw(),
                    request.forking_tid.raw(),
                    elapsed_ns,
                    units,
                ));
            };

        crate::probes::hvpatch_fork_snapshot_begin(
            request.child_tid.raw(),
            request.forking_tid.raw(),
        );
        let stage_started = std::time::Instant::now();
        const STAGE2_PAGE: u64 = 16 * 1024;
        let root_slot_end = request
            .root_slot_base
            .checked_add(request.root_slot_size)
            .ok_or_else(|| {
                TrapError::Hypervisor("hvpatch child stage-1 root slot overflow".to_owned())
            })?;
        let mut cursor = request.root_slot_base;
        let aliases = alias_registry().lock().clone();
        let alias_index = process_alias_index(&aliases, self.mm_root_slot);
        let mut source_mappings: Vec<ThreadMappingDesc> = self
            .mappings
            .iter()
            .filter_map(|mapping| {
                if !mapping.is_dynamic_alias {
                    return Some(ThreadMappingDesc::from_region(mapping));
                }
                alias_index
                    .get(&(
                        mapping.start,
                        mapping.ipa,
                        mapping.host_addr as usize,
                        semantic_extent_size(mapping.start, mapping.end),
                    ))
                    .copied()
                    .and_then(ThreadMappingDesc::from_alias)
            })
            .collect();
        // Fork-union audit: `CARRICK_FORK_DEBUG_VA=<hex guest VA>` reports every
        // LOCAL mapping row covering that VA and whether the alias index kept
        // it. The `[FORKDBG] mapping` block further down only prints rows that
        // already SURVIVED this filter, so a row dropped here — the child then
        // inherits a writable stage-1 leaf onto the parent's frame with nothing
        // arming COW — was previously invisible.
        if let Some(debug_va) = std::env::var("CARRICK_FORK_DEBUG_VA")
            .ok()
            .and_then(|raw| u64::from_str_radix(raw.trim_start_matches("0x"), 16).ok())
        {
            let window_lo = debug_va.saturating_sub(0x20_0000);
            let window_hi = debug_va.saturating_add(0x20_0000);
            for alias in aliases.iter().filter(|alias| {
                alias.start < window_hi && alias.start.saturating_add(alias.size as u64) > window_lo
            }) {
                eprintln!(
                    "[UNIONDBG pid={:?}] alias [{:#x}+{:#x}) ipa={:#x} host={:#x} \
                     phys=({:#x}+{:#x}) scope={:?} in_scope={} sharing={:?} writable={} \
                     covers_va={}",
                    self.cow_identity.map(|identity| identity.linux_pid),
                    alias.start,
                    alias.size,
                    alias.ipa,
                    alias.host_addr,
                    alias.physical_ipa,
                    alias.physical_size,
                    alias.ownership_scope,
                    alias_matches_process_scope(alias.ownership_scope, self.mm_root_slot),
                    alias.sharing,
                    alias.guest_writable,
                    alias.start <= debug_va
                        && debug_va < alias.start.saturating_add(alias.size as u64),
                );
            }
            for mapping in self
                .mappings
                .iter()
                .filter(|mapping| mapping.start < window_hi && mapping.end > window_lo)
            {
                let kept = mapping_is_current_for_process_fork_indexed(mapping, &alias_index);
                eprintln!(
                    "[UNIONDBG pid={:?}] local row [{:#x},{:#x}) ipa={:#x} host={:p} \
                     size={:#x} sem={:#x} dyn={} sharing={:?} guest_writable={} kept={} \
                     covers_va={}",
                    self.cow_identity.map(|identity| identity.linux_pid),
                    mapping.start,
                    mapping.end,
                    mapping.ipa,
                    mapping.host_addr,
                    mapping.size,
                    semantic_extent_size(mapping.start, mapping.end),
                    mapping.is_dynamic_alias,
                    mapping.sharing,
                    mapping.guest_writable,
                    kept,
                    mapping.start <= debug_va && debug_va < mapping.end,
                );
            }
            let armed = self.fork_cow_ranges();
            let covering: Vec<_> = armed
                .iter()
                .filter(|range| {
                    range.va <= debug_va && debug_va < range.va.saturating_add(range.len as u64)
                })
                .map(|range| (range.va, range.len))
                .collect();
            eprintln!(
                "[UNIONDBG pid={:?}] fork_cow_ranges covering {debug_va:#x}: {covering:x?} \
                 (total {} ranges)",
                self.cow_identity.map(|identity| identity.linux_pid),
                armed.len(),
            );
        }
        let local_regions = source_mappings.len() as u64;
        // A structural boot mapping can physically contain a narrower semantic
        // alias at the same IPA (the private-overlay aperture is the canonical
        // case). Only an exact dynamic publication suppresses a registry row;
        // keying every local descriptor by IPA hid MAP_FIXED private ownership
        // from fork even though stage-1 already selected it.
        let local_ipas: std::collections::HashSet<u64> = source_mappings
            .iter()
            .filter(|mapping| mapping.is_dynamic_alias)
            .map(|mapping| mapping.ipa)
            .collect();
        let missing = missing_process_aliases(&local_ipas, &aliases, self.mm_root_slot);
        let candidate_regions = missing.len() as u64;
        let mut added_regions = 0_u64;
        let mut added_bytes = 0_u64;
        let mut private_added_regions = 0_u64;
        let mut shared_added_regions = 0_u64;
        let mut largest_added_bytes = 0_u64;
        for alias in missing {
            // The registry is the authoritative live-alias inventory. Scope by
            // mm root-slot scope above and require its retained host owner to be live, but
            // do not require a valid stage-1 leaf: a live PROT_NONE alias is
            // intentionally invalid in stage-1 and still must survive fork.
            if alias_backing_is_live(alias.host_addr)
                && let Some(mapping) = ThreadMappingDesc::from_alias(alias)
            {
                added_regions = added_regions.saturating_add(1);
                added_bytes = added_bytes.saturating_add(mapping.size as u64);
                largest_added_bytes = largest_added_bytes.max(mapping.size as u64);
                if mapping.sharing.shares_across_fork() {
                    shared_added_regions = shared_added_regions.saturating_add(1);
                } else {
                    private_added_regions = private_added_regions.saturating_add(1);
                }
                source_mappings.push(mapping);
            }
        }
        emit_stage(
            HvpatchForkProcessSpecStagePhase::AliasUnion,
            stage_started,
            source_mappings.len() as u64,
        );

        let stage_started = std::time::Instant::now();
        let mut mappings = Vec::with_capacity(source_mappings.len());
        let parent_inventory = self.frame_inventory.lock().extents.clone();
        let mut inventory_mappings = Vec::with_capacity(parent_inventory.len());
        let mut inherited_inventory_ids = std::collections::BTreeSet::new();

        // Put the stage-1 backing at the root slot promised by TTBR. Guest
        // frames retain their stable global IPAs and never enter this slot.
        let mut order: Vec<usize> = (0..source_mappings.len()).collect();
        order.sort_by_key(|&index| {
            u8::from(source_mappings[index].start != crate::memory::LINUX_PAGE_TABLES_BASE)
        });
        for index in order {
            let mapping = &source_mappings[index];
            let disposition = fork_mapping_disposition(mapping, request.shares_mm);
            if matches!(
                disposition,
                ForkMappingDisposition::SharedFrameWritable
                    | ForkMappingDisposition::SharedFrameReadOnly
            ) {
                let inherited = inherited_fork_inventory_extents(mapping, &parent_inventory);
                // Fork lineage debug: CARRICK_FORK_DEBUG_VA=<hex guest VA>
                // prints, for the mapping covering that VA, every inherited
                // extent and — crucially — a mapping DROPPED for having none.
                // Added while hunting a deterministic zeroed 16 KiB granule in
                // a forkserver worker; the drop below is silent by design and
                // was otherwise unobservable.
                if let Some(debug_va) = std::env::var("CARRICK_FORK_DEBUG_VA")
                    .ok()
                    .and_then(|raw| u64::from_str_radix(raw.trim_start_matches("0x"), 16).ok())
                    && mapping.start <= debug_va
                    && debug_va < mapping.end
                {
                    eprintln!(
                        "[FORKDBG] mapping [{:#x},{:#x}) ipa={:#x} phys_ipa={:#x} size={:#x} \
                         sharing={:?} dyn={} extents={} phys_host={:p}",
                        mapping.start,
                        mapping.end,
                        mapping.ipa,
                        mapping.physical_ipa,
                        mapping.size,
                        mapping.sharing,
                        mapping.is_dynamic_alias,
                        inherited.len(),
                        mapping.physical_host_addr,
                    );
                    for ((gpa, length), extent) in &inherited {
                        eprintln!(
                            "[FORKDBG]   extent gpa={gpa:#x}+{length:#x} mapping={:?} frame={:?} \
                             backing={:?} lease=({:#x},{:#x})",
                            extent.mapping,
                            extent.frame,
                            extent.backing,
                            extent.stage2_base,
                            extent.stage2_length,
                        );
                    }
                    if inherited.is_empty() {
                        eprintln!(
                            "[FORKDBG]   DROPPED: no inventory extents; child will have NO backing here"
                        );
                    }
                    // Peek the PARENT frame's bytes for the debug granule: if
                    // they are already zero here, the parent reads its data
                    // through some OTHER backing than the frame the child will
                    // inherit — the divergence predates the fork.
                    let frame_offset =
                        (debug_va - mapping.start) + (mapping.ipa - mapping.physical_ipa);
                    let peek = mapping
                        .physical_host_addr
                        .wrapping_add(frame_offset as usize);
                    // SAFETY: debug-only read inside the mapping's live host
                    // backing, bounds-checked against physical_size just below.
                    if (frame_offset as usize) + 16 <= mapping.physical_size {
                        let bytes = unsafe { std::slice::from_raw_parts(peek.cast_const(), 16) };
                        eprintln!(
                            "[FORKDBG]   parent frame bytes @host+{frame_offset:#x}: {bytes:02x?}"
                        );
                    }
                    // The decisive comparison: where does the PARENT's live
                    // stage-1 actually point for this VA, versus where the
                    // inventory says the frame is? A mismatch proves the
                    // divergence the child will inherit.
                    let expected_ipa = mapping.physical_ipa + frame_offset;
                    let walk = self
                        .page_tables
                        .lock()
                        .as_ref()
                        .map(|manager| manager.debug_walk(debug_va));
                    if let Some(w) = walk {
                        let leaf_pa = w[3] & 0x0000_FFFF_FFFF_F000;
                        eprintln!(
                            "[FORKDBG]   parent stage-1 leaf for {debug_va:#x}: {:#x} -> pa {leaf_pa:#x} \
                             (inventory expects {expected_ipa:#x}) {}",
                            w[3],
                            if leaf_pa == expected_ipa & !0xfff {
                                "AGREES"
                            } else {
                                "DIVERGED"
                            },
                        );
                    }
                }
                // A coarse per-vCPU host-owner row may outlive its exact
                // per-mm mapping coverage after every compound in that stage-2
                // lease was repointed. It is no longer a fork source.
                let Some((_, parent_extent)) = inherited.first().copied() else {
                    continue;
                };
                let raw = u64::from(mapping.perms);
                for ((gpa, length), extent) in &inherited {
                    if inherited_inventory_ids.insert(extent.mapping) {
                        inventory_mappings.push(ProcessInventoryDesc {
                            gpa: *gpa,
                            length: *length,
                            permissions: carrick_hal::MemPerms {
                                read: raw & 1 != 0,
                                write: raw & 2 != 0,
                                exec: raw & 4 != 0,
                            },
                            inherited_frame: Some(extent.frame),
                            inherited_mapping: Some(extent.mapping),
                            backing: extent.backing,
                            stage2_lease: (extent.stage2_base, extent.stage2_length),
                            sharing: mapping.sharing,
                            guest_writable: mapping.guest_writable,
                            shared_mm: request.shares_mm,
                        });
                    }
                }
                mappings.push(ProcessMappingDesc {
                    start: mapping.start,
                    ipa: mapping.ipa,
                    end: mapping.end,
                    host: ForkMappingHost::Borrowed(mapping.physical_host_addr),
                    size: mapping.size,
                    physical_ipa: mapping.physical_ipa,
                    physical_host_addr: mapping.physical_host_addr,
                    physical_size: mapping.physical_size,
                    inventory_backing: parent_extent.backing,
                    perms: mapping.perms,
                    is_dynamic_alias: mapping.is_dynamic_alias,
                    sharing: mapping.sharing,
                    guest_writable: mapping.guest_writable,
                    shared_key_base: mapping.shared_key_base,
                    shared_key_offset: mapping.shared_key_offset,
                    inherited_frame: Some(parent_extent.frame),
                    stage2_lease: None,
                });
                continue;
            }

            const TWO_MIB: u64 = 2 * 1024 * 1024;
            let (physical_ipa, stage2_lease) = match disposition {
                ForkMappingDisposition::IndependentPageTables => {
                    let packing_alignment = if mapping.start.is_multiple_of(TWO_MIB)
                        && (mapping.physical_size as u64) >= TWO_MIB
                    {
                        TWO_MIB
                    } else {
                        STAGE2_PAGE
                    };
                    cursor = align_up(cursor, packing_alignment)?;
                    let physical_ipa = cursor;
                    cursor = cursor
                        .checked_add(mapping.physical_size as u64)
                        .ok_or_else(|| {
                            TrapError::Hypervisor(
                                "hvpatch child page-table root overflow".to_owned(),
                            )
                        })?;
                    if cursor > root_slot_end {
                        return Err(TrapError::Hypervisor(format!(
                            "hvpatch child page tables need more than {}-byte root slot",
                            request.root_slot_size
                        )));
                    }
                    (
                        physical_ipa,
                        Some(GlobalFrameStage2Lease::fixed(
                            physical_ipa,
                            mapping.physical_size as u64,
                        )),
                    )
                }
                ForkMappingDisposition::IndependentKernelState => {
                    let lease = GlobalFrameStage2Lease::reserve(
                        mapping.physical_size as u64,
                        CowArmedRanges::COMPOUND_SIZE,
                    )?;
                    let physical_ipa = lease.base;
                    (physical_ipa, Some(lease))
                }
                ForkMappingDisposition::SharedFrameWritable
                | ForkMappingDisposition::SharedFrameReadOnly => {
                    return Err(TrapError::Hypervisor(
                        "shared fork mapping escaped inherited-frame branch".to_owned(),
                    ));
                }
            };
            // Per-mm page tables and EL1 control state are the only fresh fork
            // frames.  Both are Carrick kernel state, not the guest-private
            // mappings governed by permission-fault COW.
            let host_kind = match disposition {
                ForkMappingDisposition::IndependentPageTables => {
                    crate::host_mapping::HostMappingKind::PrivateAnon
                }
                ForkMappingDisposition::IndependentKernelState => {
                    crate::host_mapping::HostMappingKind::PerMmKernelState
                }
                ForkMappingDisposition::SharedFrameWritable
                | ForkMappingDisposition::SharedFrameReadOnly => {
                    return Err(TrapError::Hypervisor(
                        "shared fork mapping escaped inherited-frame branch".to_owned(),
                    ));
                }
            };
            let host = crate::host_mapping::OwnedHostMapping::map_shared_anon(
                mapping.physical_size,
                host_kind,
            )
            .map_err(|error| {
                TrapError::Hypervisor(format!(
                    "allocate HVPatch child per-mm kernel backing: {error}"
                ))
            })?;
            if disposition == ForkMappingDisposition::IndependentKernelState {
                // Preserve the fork boundary's coherent control-state image;
                // child identity/mailbox rebinding mutates this independent
                // frame before entry.  This is a bounded Carrick-kernel copy,
                // never a guest private whole-mapping snapshot.
                unsafe {
                    std::ptr::copy_nonoverlapping(
                        mapping.physical_host_addr,
                        host.as_ptr(),
                        mapping.physical_size,
                    );
                }
            }
            let semantic_physical_offset = mapping
                .ipa
                .checked_sub(mapping.physical_ipa)
                .ok_or_else(|| {
                    TrapError::Hypervisor(format!(
                        "HVPatch alias IPA 0x{:x} precedes physical IPA 0x{:x}",
                        mapping.ipa, mapping.physical_ipa
                    ))
                })?;
            let ipa = physical_ipa
                .checked_add(semantic_physical_offset)
                .ok_or_else(|| {
                    TrapError::Hypervisor("hvpatch child alias IPA overflow".to_owned())
                })?;
            let mapped = if (crate::memory::LINUX_KERNEL_REGION_BASE
                ..crate::memory::LINUX_KERNEL_REGION_BASE + TWO_MIB)
                .contains(&mapping.start)
            {
                page_tables.map_kernel_aliased(
                    mapping.start,
                    ipa,
                    mapping.end.saturating_sub(mapping.start),
                )
            } else {
                page_tables.map_aliased(
                    mapping.start,
                    ipa,
                    mapping.end.saturating_sub(mapping.start),
                    mapping.guest_writable,
                )
            };
            mapped.map_err(|error| {
                // Name the pool's own numbers, exactly as `pt_edit_locked` does
                // for the syscall path. "OutOfTables" alone cannot distinguish a
                // legitimately huge address space from a pool the child clone was
                // refused permission to sweep.
                let (in_use, free, capacity) = page_tables.pool_stats();
                let (multi_vcpu, exclusive, reclaim_pending) = page_tables.coalesce_policy();
                TrapError::Hypervisor(format!(
                    "map hvpatch child VA 0x{:x} to global/root-slot IPA 0x{ipa:x}: {error:?} \
                     (in_use={in_use} free={free} capacity={capacity} multi_vcpu={multi_vcpu} \
                     exclusive={exclusive} reclaim_pending={reclaim_pending})",
                    mapping.start
                ))
            })?;
            let physical_host_addr = host.as_ptr();
            let inventory_backing = Self::private_backing_identity();
            mappings.push(ProcessMappingDesc {
                start: mapping.start,
                ipa,
                end: mapping.end,
                host: ForkMappingHost::Owned(host),
                size: mapping.size,
                physical_ipa,
                physical_host_addr,
                physical_size: mapping.physical_size,
                inventory_backing,
                perms: mapping.perms,
                is_dynamic_alias: mapping.is_dynamic_alias,
                sharing: GuestMappingSharing::Private,
                guest_writable: mapping.guest_writable,
                shared_key_base: mapping.shared_key_base,
                shared_key_offset: mapping.shared_key_offset,
                inherited_frame: None,
                stage2_lease,
            });
            inventory_mappings.push(ProcessInventoryDesc {
                gpa: physical_ipa,
                length: mapping.physical_size as u64,
                permissions: {
                    let raw = u64::from(mapping.perms);
                    carrick_hal::MemPerms {
                        read: raw & 1 != 0,
                        write: raw & 2 != 0,
                        exec: raw & 4 != 0,
                    }
                },
                inherited_frame: None,
                inherited_mapping: None,
                backing: inventory_backing,
                stage2_lease: (physical_ipa, mapping.physical_size as u64),
                sharing: GuestMappingSharing::Private,
                guest_writable: mapping.guest_writable,
                shared_mm: false,
            });
        }
        emit_stage(
            HvpatchForkProcessSpecStagePhase::FramePlan,
            stage_started,
            cursor.saturating_sub(request.root_slot_base),
        );

        let stage_started = std::time::Instant::now();
        let mut child_pte_receipts = Vec::new();
        for (index, mapping) in mappings.iter().enumerate() {
            let Some(translated) = page_tables.translate(mapping.start) else {
                // A live PROT_NONE reservation or post-munmap physical owner
                // intentionally has no valid stage-1 translation. It still
                // belongs in the child's physical/frame inventory and COW-arm
                // registry so a later mprotect/remap cannot expose the parent's
                // frame, but there is no live PTE to authenticate at fork.
                if self.protections.range_no_access(mapping.start, 1)
                    || !fork_mapping_requires_base_translation(
                        mapping.start,
                        mapping.size,
                        mapping.is_dynamic_alias,
                    )
                {
                    continue;
                }
                return Err(TrapError::Hypervisor(format!(
                    "hvpatch child stage-1 has no translation for VA 0x{:x}",
                    mapping.start
                )));
            };
            // A completed COW is an overlay on the original physical extent:
            // the old extent must remain in the child inventory for its
            // unaffected leaves, while the newer 16 KiB descriptor owns this
            // particular VA.  Validate against the last applicable overlay,
            // matching the reverse-order syscall-memory lookup authority.
            // Thread-local descriptor vectors and the process alias registry
            // can contribute COW overlays in different orders. The shared
            // stage-1 graph is authoritative, so authenticate its translation
            // against any other exact overlay owner rather than assuming the
            // winning overlay was appended after this descriptor.
            let overlay_matches =
                fork_translation_has_overlay_owner(&mappings, index, mapping.start, translated);
            if translated != mapping.ipa && !overlay_matches {
                return Err(TrapError::Hypervisor(format!(
                    "hvpatch child stage-1 VA 0x{:x} resolves to IPA 0x{translated:x}, expected 0x{:x}",
                    mapping.start, mapping.ipa
                )));
            }
            if mapping.inherited_frame.is_some()
                && mapping.sharing == GuestMappingSharing::Private
                && !is_kernel_only_stage1_range(mapping.start, mapping.size)
                && !overlay_matches
            {
                const VALID: u64 = 1;
                const NON_GLOBAL: u64 = 1 << 11;
                const AP_MASK: u64 = 0b11 << 6;
                const AP_USER_RW: u64 = 0b01 << 6;
                const AP_USER_RO: u64 = 0b11 << 6;
                let leaf = carrick_mem::page_table::terminal_descriptor(
                    page_tables.debug_walk(mapping.start),
                );
                if leaf & VALID != 0 {
                    let expected_ap = if request.shares_mm {
                        // The descriptor can cover mixed ELF permissions; a
                        // shared-mm child keeps the exact cloned leaf rather
                        // than deriving AP from the coarse physical owner.
                        leaf & AP_MASK
                    } else if mapping.guest_writable && mapping.sharing.shares_across_fork() {
                        AP_USER_RW
                    } else {
                        AP_USER_RO
                    };
                    // CLONE_VM deliberately preserves the parent's exact
                    // user translation, including its global attribute: both
                    // ASIDs name the same frame until the child exits or execs.
                    let expected_non_global = !request.shares_mm;
                    if leaf & AP_MASK != expected_ap
                        || (expected_non_global && leaf & NON_GLOBAL == 0)
                    {
                        return Err(TrapError::Hypervisor(format!(
                            "hvpatch child inherited stage-1 AP mismatch at VA 0x{:x}: leaf=0x{leaf:x} expected_ap=0x{expected_ap:x} expected_non_global={expected_non_global}",
                            mapping.start,
                        )));
                    }
                    child_pte_receipts.push((
                        mapping.start,
                        mapping.ipa,
                        expected_ap,
                        expected_non_global,
                    ));
                }
            }
        }
        emit_stage(
            HvpatchForkProcessSpecStagePhase::Validation,
            stage_started,
            mappings.len() as u64,
        );

        let stage_started = std::time::Instant::now();
        // Borrow the table image; do NOT clone it. The region is
        // `LINUX_PAGE_TABLES_SIZE` = 1.75 MiB, and this runs once per fork, so
        // the clone was 1.75 MiB of allocation plus memcpy on top of the copy
        // into the child's backing below — roughly 238 MiB of pointless copying
        // across the 68 forks of a cold `go build`.
        let table_bytes = page_tables.as_bytes();
        let table_bytes_len = table_bytes.len() as u64;
        let table = mappings
            .iter_mut()
            .find(|mapping| mapping.start == crate::memory::LINUX_PAGE_TABLES_BASE)
            .ok_or_else(|| {
                TrapError::Hypervisor("hvpatch child page-table mapping absent".to_owned())
            })?;
        if table.ipa != request.root_slot_base || table_bytes.len() > table.size {
            return Err(TrapError::Hypervisor(
                "hvpatch child page-table root-slot layout mismatch".to_owned(),
            ));
        }
        unsafe {
            std::ptr::copy_nonoverlapping(
                table_bytes.as_ptr(),
                table.host.ptr(),
                table_bytes.len(),
            );
        }
        for (va, expected_ipa, expected_ap, expected_non_global) in child_pte_receipts {
            let shadow = page_tables.debug_walk(va);
            let live = unsafe { page_tables.debug_walk_host(table.host.ptr().cast_const(), va) };
            let live_leaf = carrick_mem::page_table::terminal_descriptor(live);
            if shadow != live
                // An unmodified CLONE_VM graph may retain an L1/L2 block: its
                // descriptor carries the block base, while `expected_ipa`
                // includes the VA's offset inside that block. `shadow == live`
                // plus the earlier software translation receipt authenticates
                // the exact address without falsely applying an L3 mask.
                || (!request.shares_mm
                    && live_leaf & 0x0000_FFFF_FFFF_F000
                        != expected_ipa & 0x0000_FFFF_FFFF_F000)
                || live_leaf & (0b11 << 6) != expected_ap
                || (expected_non_global && live_leaf & (1 << 11) == 0)
            {
                return Err(TrapError::Hypervisor(format!(
                    "hvpatch child live stage-1 receipt mismatch at VA 0x{va:x}: shadow={shadow:x?} live={live:x?} expected_ipa=0x{expected_ipa:x} expected_ap=0x{expected_ap:x} expected_non_global={expected_non_global}"
                )));
            }
            crate::probes::pt_alias_receipt(va, live_leaf, expected_ipa, expected_ap, 1);
        }
        emit_stage(
            HvpatchForkProcessSpecStagePhase::TablePublish,
            stage_started,
            table_bytes_len,
        );

        crate::probes::hvpatch_fork_snapshot_end(
            request.child_tid.raw(),
            local_regions,
            candidate_regions,
            added_regions,
            added_bytes,
        );
        crate::probes::hvpatch_fork_snapshot_shape(
            request.child_tid.raw(),
            private_added_regions,
            shared_added_regions,
            largest_added_bytes,
            cursor.saturating_sub(request.root_slot_base),
        );

        let stage_started = std::time::Instant::now();
        let protections = std::sync::Arc::new(MemoryProtections::from_snapshot(
            self.protections.snapshot_all(),
        ));
        emit_stage(
            HvpatchForkProcessSpecStagePhase::BackendProtections,
            stage_started,
            0,
        );

        let stage_started = std::time::Instant::now();
        let frame_inventory = {
            let mut parent_inventory = self.frame_inventory.lock();
            let reservation = parent_inventory.process_reservation.take().ok_or_else(|| {
                TrapError::Hypervisor(
                    "HVPatch child map began without a frame inventory reservation".to_owned(),
                )
            })?;
            let mut child =
                HvpatchFrameInventory::with_frames(std::sync::Arc::clone(&parent_inventory.frames));
            child.process_reservation = Some(reservation);
            std::sync::Arc::new(parking_lot::Mutex::new(child))
        };
        let mut child_cow_armed = self.cow_armed.lock().clone();
        child_cow_armed.arm(cow_ranges);
        let spec = ProcessSpec {
            vm: (*self._vm).clone(),
            mappings,
            inventory_mappings,
            protections,
            mailbox_slots: std::sync::Arc::clone(&self.mailbox_slots),
            syscall_transport: self.syscall_transport,
            persistent_vm_lifecycle: self.persistent_vm_lifecycle,
            mm_root_slot: (request.root_slot_base, request.root_slot_size),
            frame_inventory,
            cow_armed: std::sync::Arc::new(parking_lot::Mutex::new(child_cow_armed)),
        };
        // Zero bytes: this stage no longer copies the page-table image (see the
        // `ProcessSpec` field comment). Reporting the old
        // `LINUX_PAGE_TABLES_SIZE` here would keep claiming a copy that the
        // stage does not make.
        emit_stage(
            HvpatchForkProcessSpecStagePhase::BackendSpecFinalize,
            stage_started,
            0,
        );
        Ok(spec)
    }

    fn prepare_task_only_process_spec(
        spec: ProcessSpec,
    ) -> Result<(HvpatchCarrierTaskState, HvpatchPreparedTaskAuthority), TrapError> {
        let mut mapped = Vec::with_capacity(spec.mappings.len());
        let mut stage2_leases = Vec::with_capacity(spec.mappings.len());
        let inventory_mappings = spec.inventory_mappings;
        let mut pending_aliases = Vec::new();
        let mut pending_receipts = Vec::new();
        for mut mapping in spec.mappings {
            let semantic_physical_offset = mapping
                .ipa
                .checked_sub(mapping.physical_ipa)
                .and_then(|offset| usize::try_from(offset).ok())
                .filter(|offset| {
                    offset
                        .checked_add(mapping.size)
                        .is_some_and(|end| end <= mapping.physical_size)
                })
                .ok_or_else(|| {
                    TrapError::Hypervisor(format!(
                        "task-only child alias IPA 0x{:x} escapes physical IPA 0x{:x}",
                        mapping.ipa, mapping.physical_ipa
                    ))
                })?;
            let host_addr = mapping
                .physical_host_addr
                .wrapping_add(semantic_physical_offset);
            if process_mapping_needs_stage2_install(mapping.inherited_frame) {
                let rc = unsafe {
                    inventory_hv_vm_map(
                        mapping.physical_host_addr.cast(),
                        mapping.physical_ipa,
                        mapping.physical_size,
                        u64::from(mapping.perms),
                    )
                };
                if rc != 0 {
                    drop(mapping.stage2_lease.take());
                    drop(stage2_leases);
                    drop(mapped);
                    return Err(TrapError::ChildMapFailed {
                        host_addr: mapping.physical_host_addr as u64,
                        guest_start: mapping.physical_ipa,
                        size: mapping.physical_size,
                        code: rc as u32,
                    });
                }
                if let Some(lease) = mapping.stage2_lease.as_mut() {
                    lease.mark_mapped();
                }
            }
            if mapping.is_dynamic_alias {
                let alias = AliasBacking {
                    start: mapping.start,
                    ipa: mapping.ipa,
                    host_addr: host_addr as usize,
                    size: mapping.size,
                    physical_ipa: mapping.physical_ipa,
                    physical_host_addr: mapping.physical_host_addr as usize,
                    physical_size: mapping.physical_size,
                    perms: u64::from(mapping.perms),
                    guest_writable: mapping.guest_writable,
                    sharing: mapping.sharing,
                    ownership_scope: alias_ownership_scope(mapping.sharing, None),
                    inventory_backing: mapping.inventory_backing,
                    shared_key_base: mapping.shared_key_base,
                    shared_key_offset: mapping.shared_key_offset,
                    owner_generation: global_frame_host_owner_generation(
                        mapping.physical_ipa,
                        mapping.physical_size as u64,
                    ),
                };
                pending_aliases.push(if mapping.sharing.uses_global_ipa() {
                    alias
                } else {
                    rebind_inherited_alias_to_process(alias, spec.mm_root_slot)
                });
            }
            if let Some(stage2_lease) = mapping.stage2_lease.take() {
                stage2_leases.push(stage2_lease);
            }
            mapped.push(HvpatchTaskMappingState {
                start: mapping.start,
                ipa: mapping.ipa,
                physical_ipa: mapping.physical_ipa,
                end: mapping.end,
                host_addr,
                physical_host_addr: mapping.physical_host_addr,
                size: mapping.size,
                physical_size: mapping.physical_size,
                perms: mapping.perms,
                guest_writable: mapping.guest_writable,
                host_mapping: mapping.host.into_owned(),
                is_dynamic_alias: mapping.is_dynamic_alias,
                sharing: mapping.sharing,
                shared_key_base: mapping.shared_key_base,
                shared_key_offset: mapping.shared_key_offset,
                owner_generation: global_frame_host_owner_generation(
                    mapping.physical_ipa,
                    mapping.physical_size as u64,
                ),
            });
        }
        let mut process_reservation = spec
            .frame_inventory
            .lock()
            .process_reservation
            .take()
            .ok_or_else(|| {
                TrapError::Hypervisor(
                    "task-only child has no frame inventory reservation".to_owned(),
                )
            })?;
        let process_transaction = process_reservation.transaction();
        let mut staged_inventory_mappings = Vec::with_capacity(inventory_mappings.len());
        let process_commit;
        {
            let mut inventory = spec.frame_inventory.lock();
            for mapping in inventory_mappings {
                let staged = match Self::stage_mapping(
                    &mut inventory,
                    &mut process_reservation,
                    InventoryMappingStage {
                        gpa: mapping.gpa,
                        length: mapping.length,
                        permissions: mapping.permissions,
                        backing: mapping.backing,
                        inherited_frame: mapping.inherited_frame,
                        stage2_lease: Some(mapping.stage2_lease),
                    },
                ) {
                    Ok(staged) => staged,
                    Err(error) => {
                        Self::rollback_unpublished_mappings(
                            &mut inventory,
                            &staged_inventory_mappings,
                        )
                            .unwrap_or_else(|rollback_error| {
                                eprintln!(
                                    "carrick: FATAL: rollback task-only child inventory: {rollback_error}"
                                );
                                std::process::abort();
                        });
                        drop(inventory);
                        drop(stage2_leases);
                        drop(mapped);
                        return Err(error);
                    }
                };
                staged_inventory_mappings.push(((mapping.gpa, mapping.length), staged));
                if let (Some(parent_mapping), Some(frame)) =
                    (mapping.inherited_mapping, mapping.inherited_frame)
                    && (mapping.guest_writable || mapping.sharing.shares_across_fork())
                {
                    pending_receipts.push(PendingForkFrameReceipt {
                        transaction: process_transaction,
                        kind: if mapping.shared_mm || mapping.sharing.shares_across_fork() {
                            carrick_observability::probes::HvpatchForkFrameKind::Shared
                        } else {
                            carrick_observability::probes::HvpatchForkFrameKind::PrivateCow
                        },
                        parent_mapping,
                        child_mapping: staged.mapping,
                        frame,
                        ipa: mapping.gpa,
                        length: mapping.length,
                    });
                }
            }
            inventory.initialized = true;
            process_commit = process_reservation.commit(());
        }
        let process_challenge = process_commit.receipt_challenge();
        Ok((
            HvpatchCarrierTaskState::Process {
                vm: spec.vm,
                stage2_leases,
            },
            HvpatchPreparedTaskAuthority {
                mappings: mapped,
                mm_root_slot: Some(spec.mm_root_slot),
                inventory: HvpatchTaskInventoryAuthority::ProcessPrepared {
                    ledger: spec.frame_inventory,
                    staged: staged_inventory_mappings,
                    commit: Some(process_commit),
                    challenge: Some(process_challenge),
                },
                cow_armed: Some(spec.cow_armed),
                // A freshly materialized process has no deferred COW
                // publication yet, but it must own the slot they land in:
                // `from_process_spec` gives the live state the same fresh
                // vector, and arming without one is not a task authority.
                cow_deferred_publications: Some(std::sync::Arc::new(parking_lot::Mutex::new(
                    Vec::new(),
                ))),
                pending_receipts,
                pending_aliases,
                ..HvpatchPreparedTaskAuthority::default()
            },
        ))
    }

    pub(crate) fn from_process_spec(
        spec: ProcessSpec,
    ) -> Result<(HvfVmState, applevisor::vcpu::Vcpu, MailboxBinding), TrapError> {
        let vcpu = create_vcpu(&spec.vm)?;
        enable_el0_counter_access(vcpu.id());
        let mut mapped = Vec::with_capacity(spec.mappings.len());
        let inventory_mappings = spec.inventory_mappings;
        let mut aliases_to_publish = Vec::new();
        let mut pending_fork_frame_receipts = Vec::new();
        for mut mapping in spec.mappings {
            let semantic_physical_offset = mapping
                .ipa
                .checked_sub(mapping.physical_ipa)
                .and_then(|offset| usize::try_from(offset).ok())
                .filter(|offset| {
                    offset
                        .checked_add(mapping.size)
                        .is_some_and(|end| end <= mapping.physical_size)
                })
                .ok_or_else(|| {
                    TrapError::Hypervisor(format!(
                        "HVPatch semantic alias IPA 0x{:x} size {} escapes physical IPA 0x{:x} size {}",
                        mapping.ipa, mapping.size, mapping.physical_ipa, mapping.physical_size
                    ))
                })?;
            let host_addr = mapping
                .physical_host_addr
                .wrapping_add(semantic_physical_offset);
            if process_mapping_needs_stage2_install(mapping.inherited_frame) {
                let rc = unsafe {
                    inventory_hv_vm_map(
                        mapping.physical_host_addr.cast(),
                        mapping.physical_ipa,
                        mapping.physical_size,
                        u64::from(mapping.perms),
                    )
                };
                if rc != 0 {
                    let error = TrapError::ChildMapFailed {
                        host_addr: mapping.physical_host_addr as u64,
                        guest_start: mapping.physical_ipa,
                        size: mapping.physical_size,
                        code: rc as u32,
                    };
                    return Err(error);
                }
                if let Some(lease) = mapping.stage2_lease.as_mut() {
                    lease.mark_mapped();
                }
            }
            if mapping.is_dynamic_alias {
                let alias = AliasBacking {
                    start: mapping.start,
                    ipa: mapping.ipa,
                    host_addr: host_addr as usize,
                    size: mapping.size,
                    physical_ipa: mapping.physical_ipa,
                    physical_host_addr: mapping.physical_host_addr as usize,
                    physical_size: mapping.physical_size,
                    perms: u64::from(mapping.perms),
                    guest_writable: mapping.guest_writable,
                    sharing: mapping.sharing,
                    ownership_scope: alias_ownership_scope(mapping.sharing, None),
                    inventory_backing: mapping.inventory_backing,
                    shared_key_base: mapping.shared_key_base,
                    shared_key_offset: mapping.shared_key_offset,
                    owner_generation: global_frame_host_owner_generation(
                        mapping.physical_ipa,
                        mapping.physical_size as u64,
                    ),
                };
                aliases_to_publish.push(if mapping.sharing.uses_global_ipa() {
                    alias
                } else {
                    rebind_inherited_alias_to_process(alias, spec.mm_root_slot)
                });
            }
            mapped.push(HvfMappedRegion {
                start: mapping.start,
                ipa: mapping.ipa,
                physical_ipa: mapping.physical_ipa,
                end: mapping.end,
                host_addr,
                size: mapping.physical_size,
                physical_size: mapping.physical_size,
                perms: mapping.perms,
                guest_writable: mapping.guest_writable,
                memory: None,
                host_mapping: mapping.host.into_owned(),
                stage2_lease: mapping.stage2_lease,
                is_dynamic_alias: mapping.is_dynamic_alias,
                sharing: mapping.sharing,
                shared_key_base: mapping.shared_key_base,
                shared_key_offset: mapping.shared_key_offset,
                owner_generation: global_frame_host_owner_generation(
                    mapping.physical_ipa,
                    mapping.physical_size as u64,
                ),
            });
        }
        let mut process_reservation = spec
            .frame_inventory
            .lock()
            .process_reservation
            .take()
            .ok_or_else(|| {
                TrapError::Hypervisor(
                    "HVPatch child materialized without frame inventory reservation".to_owned(),
                )
            })?;
        let process_transaction = process_reservation.transaction();
        let mut state = HvfVmState {
            _vm: std::mem::ManuallyDrop::new(spec.vm),
            task: HvfTaskState {
                mappings: mapped,
                mm_root_slot: Some(spec.mm_root_slot),
                pending_exec_mm_root_slot: None,
                pending_exec_asid: None,
                pending_exec_stage2_cleanup: None,
                shared_process_mm: false,
                last_exit_class: 0,
                last_fault_esr: 0,
                is_forked_child: false,
                forked_no_exec: false,
                protections: spec.protections,
                // Empty until the shared engine's `bind_stage1_page_tables`
                // installs the child's real manager.
                page_tables: std::sync::Arc::new(parking_lot::Mutex::new(None)),
                last_syscall_nr: None,
                last_syscall_orig_x0: 0,
                vfork_share: false,
                fork_mapping_descs: Vec::new(),
                fork_child_descs: Vec::new(),
                persistent_vm_lifecycle: spec.persistent_vm_lifecycle,
                frame_inventory: HvpatchFrameInventoryState::new(spec.frame_inventory),
                cow_authority: None,
                cow_identity: None,
                cow_armed: spec.cow_armed,
                cow_deferred_publications: std::sync::Arc::new(parking_lot::Mutex::new(Vec::new())),
                pending_fork_frame_receipts: Vec::new(),
                pending_process_aliases: aliases_to_publish,
                cow_rollback_scratch: None,
            },
            carrier_mappings: None,
            reclaim_authority: ReclaimParkAuthority::Live,
            mailbox_slots: spec.mailbox_slots,
            syscall_transport: spec.syscall_transport,
            vcpu_id: vcpu.id(),
            vcpu_handle: vcpu.get_handle(),
        };
        let mailbox = match state.allocate_mailbox_for_vcpu(&vcpu) {
            Ok(mailbox) => mailbox,
            Err(error) => {
                // `HvfVmState::drop` intentionally leaks live process mappings.
                // Materialization has not committed, so explicitly drop the
                // fresh RAII leases and host owners instead.
                drop(std::mem::take(&mut state.mappings));
                return Err(error);
            }
        };
        {
            let mut inventory = state.frame_inventory.lock();
            let mut staged_mappings = Vec::with_capacity(inventory_mappings.len());
            for mapping in inventory_mappings {
                let staged = match Self::stage_mapping(
                    &mut inventory,
                    &mut process_reservation,
                    InventoryMappingStage {
                        gpa: mapping.gpa,
                        length: mapping.length,
                        permissions: mapping.permissions,
                        backing: mapping.backing,
                        inherited_frame: mapping.inherited_frame,
                        stage2_lease: Some(mapping.stage2_lease),
                    },
                ) {
                    Ok(staged) => staged,
                    Err(error) => {
                        Self::rollback_unpublished_mappings(
                            &mut inventory,
                            &staged_mappings,
                        )
                        .unwrap_or_else(|rollback_error| {
                            eprintln!(
                                "carrick: FATAL: rollback HVPatch child inventory staging: {rollback_error}"
                            );
                            std::process::abort();
                        });
                        drop(inventory);
                        drop(std::mem::take(&mut state.mappings));
                        return Err(error);
                    }
                };
                staged_mappings.push(((mapping.gpa, mapping.length), staged));
                if let (Some(parent_mapping), Some(frame)) =
                    (mapping.inherited_mapping, mapping.inherited_frame)
                    && (mapping.guest_writable || mapping.sharing.shares_across_fork())
                {
                    let kind = if mapping.shared_mm || mapping.sharing.shares_across_fork() {
                        carrick_observability::probes::HvpatchForkFrameKind::Shared
                    } else {
                        carrick_observability::probes::HvpatchForkFrameKind::PrivateCow
                    };
                    pending_fork_frame_receipts.push(PendingForkFrameReceipt {
                        transaction: process_transaction,
                        kind,
                        parent_mapping,
                        child_mapping: staged.mapping,
                        frame,
                        ipa: mapping.gpa,
                        length: mapping.length,
                    });
                }
            }
            inventory.initialized = true;
            inventory.process_commit = Some(process_reservation.commit(()));
        }
        state.pending_fork_frame_receipts = pending_fork_frame_receipts;
        Ok((state, vcpu, mailbox))
    }

    fn global_frame_exec_plan(&self, plan: &GuestMappingPlan) -> Result<GlobalExecPlan, TrapError> {
        prepare_global_exec_plan(plan, self.pending_exec_mm_root_slot.or(self.mm_root_slot))
    }

    /// `execve(2)` image replacement. Ordinary VMM tears down and rebuilds the
    /// VM; hvpatch retains its one process-wide VM and replaces only stage-2
    /// mappings plus vCPU architectural state. Clears the alias registry and
    /// preserves `is_forked_child`.
    pub(crate) fn execve_rebuild(
        &mut self,
        vcpu: &mut applevisor::vcpu::Vcpu,
        mailbox: &mut MailboxBinding,
        plan: &GuestMappingPlan,
    ) -> Result<(), TrapError> {
        use applevisor::prelude::*;
        let predecessor_mm_root_slot = self.mm_root_slot;
        let replacement_mm_root_slot = if self.persistent_vm_lifecycle {
            self.pending_exec_mm_root_slot.ok_or_else(|| {
                TrapError::Hypervisor(
                    "HVPatch exec began without a fresh root-slot lease".to_owned(),
                )
            })?
        } else {
            self.mm_root_slot.unwrap_or((0, 0))
        };
        let replacement_asid = if self.persistent_vm_lifecycle {
            self.pending_exec_asid.ok_or_else(|| {
                TrapError::Hypervisor("HVPatch exec began without a fresh ASID lease".to_owned())
            })?
        } else {
            0
        };
        let mut inventory_reservations = if self.persistent_vm_lifecycle {
            let mut inventory = self.frame_inventory.lock();
            // The replacement transaction is mandatory. The retirement one is
            // absent exactly when the old mm stays owned by a live sharer, so
            // its absence here is the armed contract, not a missing reservation.
            let replacement = inventory.replacement_reservation.take().ok_or_else(|| {
                TrapError::Hypervisor(
                    "HVPatch exec began without replacement-mm inventory reservation".to_owned(),
                )
            })?;
            Some((inventory.retired_reservation.take(), replacement))
        } else {
            None
        };
        let frame_plan_started = std::time::Instant::now();
        let GlobalExecPlan {
            plan: mut global_plan,
            mut stage2_leases,
        } = self.global_frame_exec_plan(plan)?;
        self.pending_exec_mm_root_slot = None;
        self.pending_exec_asid = None;
        let frame_plan_elapsed_ns = frame_plan_started
            .elapsed()
            .as_nanos()
            .min(u128::from(u64::MAX)) as u64;
        let replacement_mapping_count = global_plan
            .mappings
            .iter()
            .filter(|mapping| {
                !is_sparse_hvpatch_mmap_mapping(mapping)
                    && !is_persistent_executor_carrier_guest_mapping(mapping)
            })
            .count() as u64;
        let replacement_mapped_bytes = global_plan
            .mappings
            .iter()
            .filter(|mapping| {
                !is_sparse_hvpatch_mmap_mapping(mapping)
                    && !is_persistent_executor_carrier_guest_mapping(mapping)
            })
            .map(|mapping| mapping.mapped_size)
            .sum::<u64>();
        crate::probes::hvpatch_exec_replace_stage(
            carrick_observability::probes::HvpatchExecReplaceStage::new(
                carrick_observability::probes::HvpatchExecReplaceStagePhase::FramePlan,
                frame_plan_elapsed_ns,
                replacement_mapping_count,
                replacement_mapped_bytes,
            ),
        );
        let private_file_artifacts_started = std::time::Instant::now();
        if self.persistent_vm_lifecycle {
            attach_exec_private_file_backings(&mut global_plan)?;
        }
        let private_file_artifacts_elapsed_ns = private_file_artifacts_started
            .elapsed()
            .as_nanos()
            .min(u128::from(u64::MAX)) as u64;
        let plan = &global_plan;
        let map_backings_started = std::time::Instant::now();
        let mut prepared_exec_regions = Vec::new();
        if self.persistent_vm_lifecycle {
            for mapping in plan.mappings.iter().filter(|mapping| {
                !is_sparse_hvpatch_mmap_mapping(mapping)
                    && !is_persistent_executor_carrier_guest_mapping(mapping)
            }) {
                let key = (mapping.ipa_start, mapping.mapped_size);
                let lease = stage2_leases.remove(&key).ok_or_else(|| {
                    TrapError::Hypervisor(format!(
                        "HVPatch exec mapping IPA 0x{:x} size {} has no owning lease",
                        key.0, key.1
                    ))
                })?;
                let region = prepare_exec_region_raw(mapping)?;
                prepared_exec_regions.push((region, lease));
            }
            if !stage2_leases.is_empty() {
                return Err(TrapError::Hypervisor(format!(
                    "HVPatch exec left {} reserved stage-2 leases unmaterialized",
                    stage2_leases.len()
                )));
            }
        }
        let emit_replace_stage =
            |phase: carrick_observability::probes::HvpatchExecReplaceStagePhase,
             started: std::time::Instant| {
                let elapsed_ns = started.elapsed().as_nanos().min(u128::from(u64::MAX)) as u64;
                crate::probes::hvpatch_exec_replace_stage(
                    carrick_observability::probes::HvpatchExecReplaceStage::new(
                        phase,
                        elapsed_ns,
                        replacement_mapping_count,
                        replacement_mapped_bytes,
                    ),
                );
            };
        crate::probes::hvpatch_exec_replace_stage(
            carrick_observability::probes::HvpatchExecReplaceStage::new(
                carrick_observability::probes::HvpatchExecReplaceStagePhase::PrivateFileArtifacts,
                private_file_artifacts_elapsed_ns,
                replacement_mapping_count,
                replacement_mapped_bytes,
            ),
        );
        // Preserve `is_forked_child` across execve. A process that descended from
        // the original `carrick run` invocation should keep using the
        // `_exit`-without-JSON shutdown path even after it execve's into a
        // different image; otherwise every forked + execve'd descendant prints its
        // own JSON report to stdout (interleaved with the parent's), making the
        // user-visible output unreadable.
        let was_forked_child = self.is_forked_child;
        let address_space_teardown_started = std::time::Instant::now();
        let retired_physical_extents = if self.persistent_vm_lifecycle {
            // The vCPU is stopped at the execve syscall exit and every sibling
            // has already retired. Build the complete predecessor/replacement
            // edge sets before touching stage-2. The switch helper restores the
            // exact predecessor on every ordinary failure, so backend inventory,
            // owners and mapping rows remain unchanged until this succeeds.
            let extents = final_exec_physical_extents(&self.frame_inventory.lock())?;
            let replacement = plan
                .mappings
                .iter()
                .filter(|mapping| {
                    !is_sparse_hvpatch_mmap_mapping(mapping)
                        && !is_persistent_executor_carrier_guest_mapping(mapping)
                })
                .zip(prepared_exec_regions.iter())
                .map(|(mapping, (region, _))| exec_stage2_install(mapping, region))
                .collect::<Vec<_>>();
            let authority_before = self.exec_authority_fingerprint();
            let switch_result = switch_exec_stage2_transaction(
                &[],
                &replacement,
                exec_stage2_fail_after_maps(),
                |extent| {
                    crate::probes::hvpatch_exec_stage2(
                        carrick_observability::probes::HvpatchExecStage2::new(
                            carrick_observability::probes::HvpatchExecStage2Phase::UnmapBegin,
                            extent.ipa,
                            extent.size as u64,
                            u64::MAX,
                            0,
                        ),
                    );
                    let rc = unsafe { inventory_hv_vm_unmap(extent.ipa, extent.size) };
                    crate::probes::hvpatch_exec_stage2(
                        carrick_observability::probes::HvpatchExecStage2::new(
                            carrick_observability::probes::HvpatchExecStage2Phase::UnmapEnd,
                            extent.ipa,
                            extent.size as u64,
                            u64::MAX,
                            if rc == 0 { 0 } else { -1 },
                        ),
                    );
                    if rc == 0 {
                        Ok(())
                    } else {
                        Err(TrapError::Hypervisor(format!(
                            "unmap HVPatch exec predecessor IPA 0x{:x} size {} failed: 0x{rc:x}",
                            extent.ipa, extent.size
                        )))
                    }
                },
                |extent| {
                    crate::probes::hvpatch_exec_stage2(
                        carrick_observability::probes::HvpatchExecStage2::new(
                            carrick_observability::probes::HvpatchExecStage2Phase::MapBegin,
                            extent.ipa,
                            extent.size as u64,
                            u64::MAX,
                            0,
                        ),
                    );
                    let rc = unsafe {
                        inventory_hv_vm_map(
                            extent.host.cast(),
                            extent.ipa,
                            extent.size,
                            extent.perms,
                        )
                    };
                    if rc == 0
                        && let Some(replay_key) = extent.replay_key()
                    {
                        mutate_external_alias_state(|replay, _| {
                            replay.insert(replay_key);
                        });
                    }
                    crate::probes::hvpatch_exec_stage2(
                        carrick_observability::probes::HvpatchExecStage2::new(
                            carrick_observability::probes::HvpatchExecStage2Phase::MapEnd,
                            extent.ipa,
                            extent.size as u64,
                            u64::MAX,
                            rc as i32,
                        ),
                    );
                    if rc == 0 {
                        Ok(())
                    } else {
                        Err(TrapError::Hypervisor(format!(
                            "map HVPatch exec replacement IPA 0x{:x} size {} failed: 0x{rc:x}",
                            extent.ipa, extent.size
                        )))
                    }
                },
            );
            if let Err(error) = switch_result {
                let authority_after = self.exec_authority_fingerprint();
                if let Err(rollback_error) =
                    verify_exec_authority_rollback(&authority_before, &authority_after)
                {
                    eprintln!("carrick: FATAL: {rollback_error}");
                    std::process::abort();
                }
                return Err(error);
            }
            for (_, lease) in &mut prepared_exec_regions {
                lease.mark_mapped();
            }
            if let Some((Some(retired), _)) = inventory_reservations.as_mut() {
                let mut inventory = self.frame_inventory.lock();
                if let Err(error) = Self::stage_retirement(&mut inventory, retired) {
                    eprintln!("carrick: FATAL: stage inventory after HVPatch exec unmap: {error}");
                    std::process::abort();
                }
            }
            extents
        } else {
            // Mature VMM behavior: tear down the current HVF VM and rebuild it.
            let inherited_vcpu_id = vcpu.id();
            let vcpu_destroy_rc = unsafe { applevisor_sys::hv_vcpu_destroy(inherited_vcpu_id) };
            if vcpu_destroy_rc == 0 {
                vcpu_destroyed(inherited_vcpu_id);
            }
            crate::probes::vm_lifecycle(2, -1);
            let vm_destroy_rc = unsafe { inventory_hv_vm_destroy() };
            if vm_destroy_rc == 0 {
                record_vm_released();
            }

            let (new_vm, permit) = create_vm_with_admission(VmCreateAdmission::ExecveRebuild)?;
            let new_vcpu = create_vcpu_with_permit(&new_vm, permit)?;
            enable_el0_counter_access(new_vcpu.id());
            self.vcpu_id = new_vcpu.id();
            self.vcpu_handle = new_vcpu.get_handle();
            // Swap the new VM + vCPU into place WITHOUT running Drop on the old.
            std::mem::forget(std::mem::replace(vcpu, new_vcpu));
            replace_destroyed_vm(self, new_vm);
            std::collections::BTreeSet::new()
        };
        emit_replace_stage(
            carrick_observability::probes::HvpatchExecReplaceStagePhase::AddressSpaceTeardown,
            address_space_teardown_started,
        );
        // Retain aliases still backed by another live mm. Mature VMM destroyed
        // the whole VM; persistent HVPatch removes only physical extents whose
        // final logical references retired above.
        let alias_cleanup_started = std::time::Instant::now();
        if !self.persistent_vm_lifecycle {
            clear_alias_registry();
        }
        emit_replace_stage(
            carrick_observability::probes::HvpatchExecReplaceStagePhase::AliasCleanup,
            alias_cleanup_started,
        );
        let drop_backings_started = std::time::Instant::now();
        if self.persistent_vm_lifecycle {
            let predecessor_mappings = std::mem::take(&mut self.mappings);
            let shared_projection = self.shared_process_mm;
            if self
                .pending_exec_stage2_cleanup
                .replace(PendingExecStage2Cleanup {
                    mappings: predecessor_mappings,
                    extents: retired_physical_extents.clone(),
                    mm_root_slot: predecessor_mm_root_slot,
                    shared_projection,
                    armed: true,
                })
                .is_some()
            {
                eprintln!("carrick: FATAL: overlapping detached exec predecessor cleanup");
                std::process::abort();
            }
        } else {
            // Preserve mature VMM's historical leak-until-process-exit discipline:
            // the old VM was raw-destroyed and sibling/alias projections may still
            // carry non-owning pointers into these backings.
            std::mem::forget(std::mem::take(&mut self.mappings));
        }
        emit_replace_stage(
            carrick_observability::probes::HvpatchExecReplaceStagePhase::DropBackings,
            drop_backings_started,
        );
        let page_tables_started = std::time::Instant::now();
        self.reclaim_authority = ReclaimParkAuthority::Live;
        self.last_exit_class = 0;
        self.last_fault_esr = 0;
        self.is_forked_child = was_forked_child;
        self.forked_no_exec = false; // execve gives a fresh VM: no longer a live forked-no-exec child
        self.shared_process_mm = false;
        // execve replaces the address space; any prior PROT_NONE ranges are gone.
        self.protections = std::sync::Arc::new(MemoryProtections::default());
        self.seed_readonly_spans_from_plan(plan);
        // Exec replaces the complete address space.  Fork-COW arming belongs
        // to the retired image and can overlap unrelated VAs in the new one;
        // retaining it turns ordinary loader writes into COW transactions
        // against the replacement mm.
        self.cow_armed = std::sync::Arc::new(parking_lot::Mutex::new(CowArmedRanges::default()));
        self.cow_deferred_publications = std::sync::Arc::new(parking_lot::Mutex::new(Vec::new()));
        // The shared AArch64 engine already builds this editor lazily from the
        // live page-table backing on its first real edit. Keeping an eager
        // manager here cloned the complete 1.8 MiB root-slot table on every exec,
        // even for short-lived compiler children that never mmap/mprotect.
        // Mailbox publication resolves its static boot mapping directly; an
        // in-process fork below explicitly materializes the manager on demand.
        // The =0 hatch restores the eager clone for schedule-identical ABBA.
        if self.persistent_vm_lifecycle {
            self.mm_root_slot = Some(replacement_mm_root_slot);
        }
        let exec_page_tables = if lazy_exec_page_tables_enabled() {
            None
        } else {
            self.mm_root_slot.and_then(|_| {
                let root = plan.stage1_page_tables_base?;
                let table = plan
                    .mappings
                    .iter()
                    .find(|mapping| mapping.guest_start == crate::memory::LINUX_PAGE_TABLES_BASE)?;
                Some(crate::page_table::PageTableManager::new(
                    table.image.as_ref().clone(),
                    root,
                ))
            })
        };
        self.page_tables = std::sync::Arc::new(parking_lot::Mutex::new(exec_page_tables));
        // Mature one-process VMM exec gets a fresh VM-local allocator. A
        // persistent HVPatch worker must retain its executor-local allocator
        // on the owner pthread; `allocate_mailbox_for_vcpu` below gives the
        // replacement task a fresh slot from that same bounded arena.
        if !self.persistent_vm_lifecycle {
            self.mailbox_slots = std::sync::Arc::new(MailboxSlotAllocator::new());
        }
        self.last_syscall_nr = None;
        self.last_syscall_orig_x0 = 0;
        emit_replace_stage(
            carrick_observability::probes::HvpatchExecReplaceStagePhase::PageTables,
            page_tables_started,
        );

        // Stage-2 is already switched transactionally on HVPatch. Publish its
        // host owners only after predecessor retirement can no longer roll
        // back. Mature VMM still maps through the historical helper here.
        if self.persistent_vm_lifecycle {
            for (mut region, lease) in prepared_exec_regions.drain(..) {
                let key = lease.key();
                let host_mapping = region.host_mapping.take().unwrap_or_else(|| {
                    eprintln!(
                        "carrick: FATAL: HVPatch exec mapping IPA 0x{:x} has no host owner",
                        key.0
                    );
                    std::process::abort();
                });
                register_global_frame_host_owner(lease, host_mapping, u64::from(region.perms))
                    .unwrap_or_else(|error| {
                        eprintln!(
                            "carrick: FATAL: publish HVPatch exec global-frame owner: {error}"
                        );
                        std::process::abort();
                    });
                self.mappings.push(region);
            }
        } else {
            for mapping in &plan.mappings {
                self.mappings.push(map_region_raw(mapping, false)?);
            }
        }
        if let Some((retired, mut replacement)) = inventory_reservations.take() {
            let mut inventory = self.frame_inventory.lock();
            for region in &self.mappings {
                if let Err(error) = Self::stage_mapping(
                    &mut inventory,
                    &mut replacement,
                    InventoryMappingStage {
                        gpa: region.physical_ipa,
                        length: region.physical_size as u64,
                        permissions: Self::region_permissions(region),
                        backing: Self::private_backing_identity(),
                        inherited_frame: None,
                        stage2_lease: None,
                    },
                ) {
                    eprintln!("carrick: FATAL: stage inventory after HVPatch exec map: {error}");
                    std::process::abort();
                }
            }
            inventory.exec_commits = Some((
                retired.map(|retired| retired.commit(())),
                replacement.commit(()),
            ));
        }
        emit_replace_stage(
            carrick_observability::probes::HvpatchExecReplaceStagePhase::MapBackings,
            map_backings_started,
        );

        // Initial vCPU state — same sequence as `new_with_plan`. Zero the GPRs
        // first: Linux's execve contract says the new program starts with all
        // registers clear except for SP and PC. Without this, musl's _start in the
        // new image inherits the previous process's x8 which can decode as a bogus
        // syscall number on the first svc.
        let post_publication = (|| -> std::result::Result<MailboxBinding, TrapError> {
            let registers_started = std::time::Instant::now();
            for reg in GPR_TABLE {
                vcpu.set_reg(reg, 0).map_err(hvf_error)?;
            }

            let initial_pc = plan.el0_trampoline_entry.unwrap_or(plan.entry);
            vcpu.set_reg(Reg::PC, initial_pc).map_err(hvf_error)?;
            const AARCH64_PSTATE_EL1H_DAIF_MASKED: u64 = 0x3c5;
            vcpu.set_reg(Reg::CPSR, AARCH64_PSTATE_EL1H_DAIF_MASKED)
                .map_err(hvf_error)?;
            if let Some(_trampoline) = plan.el0_trampoline_entry {
                const AARCH64_PSTATE_EL0T_DAIF_MASKED: u64 = 0x3c0;
                vcpu.set_sys_reg(SysReg::SPSR_EL1, AARCH64_PSTATE_EL0T_DAIF_MASKED)
                    .map_err(hvf_error)?;
                vcpu.set_sys_reg(SysReg::ELR_EL1, plan.entry)
                    .map_err(hvf_error)?;
            }
            // C=1, I=1, UCI=1 (bit 26), UCT=1 (bit 15), DZE=1 (bit 14) — EL0 cache-
            // maintenance ops + CTR_EL0/DCZID_EL0 reads + DC ZVA, matching Linux.
            // See the matching comment at the initial-bringup site; glibc 2.41 reads
            // CTR_EL0 at startup, which traps to EL1 (fatal) without UCT.
            // Shared bootstrap SCTLR (via GuestArch; canonical rationale in
            // carrick_mem::arch_sysregs) carries M=1 (stage-1 on); HVF enables M
            // only when stage-1 tables exist (below), so start from the value with
            // M cleared and OR M back in there. HVF leaves SPAN(23) CLEAR and
            // forces PSTATE.PAN=1 (FEAT_PAN3) — SPAN is KVM glue, NOT part of the
            // shared value.
            use carrick_hal::GuestArch as _;
            let boot = <HvfTrapEngine as carrick_hal::ThreadedEngine>::Arch::bootstrap_sysregs();
            let mut sctlr_el1: u64 = boot.sctlr_el1 & !1;
            if let Some(pt_base) = plan.stage1_page_tables_base {
                vcpu.set_sys_reg(SysReg::MAIR_EL1, boot.mair_el1)
                    .map_err(hvf_error)?;
                // 48-bit VA, TTBR0 + TTBR1 both active sharing one root. MUST stay
                // identical to the canonical TCR comment/value in new_with_plan.
                // boot.tcr_el1 is the shared bootstrap value via GuestArch
                // (canonical rationale in carrick_mem::arch_sysregs).
                vcpu.set_sys_reg(SysReg::TCR_EL1, boot.tcr_el1)
                    .map_err(hvf_error)?;
                let ttbr = pt_base | (u64::from(replacement_asid) << 48);
                vcpu.set_sys_reg(SysReg::TTBR0_EL1, ttbr)
                    .map_err(hvf_error)?;
                // TTBR1 shares the same root (see the TCR comment above).
                vcpu.set_sys_reg(SysReg::TTBR1_EL1, ttbr)
                    .map_err(hvf_error)?;
                sctlr_el1 |= 1;
            }
            vcpu.set_sys_reg(SysReg::SCTLR_EL1, sctlr_el1)
                .map_err(hvf_error)?;
            // boot.cpacr_el1 (FPEN=0b11, no FP/SIMD trap at EL0) is shared.
            vcpu.set_sys_reg(SysReg::CPACR_EL1, boot.cpacr_el1)
                .map_err(hvf_error)?;
            if let Some(vectors_base) = plan.el1_vectors_base {
                vcpu.set_sys_reg(SysReg::VBAR_EL1, vectors_base)
                    .map_err(hvf_error)?;
            }
            if let Some(stack_pointer) = plan.initial_stack_pointer {
                vcpu.set_sys_reg(SysReg::SP_EL0, stack_pointer)
                    .map_err(hvf_error)?;
            }
            // execve resets TPIDR_EL0 — the new image's musl init will call
            // set_thread_area to initialise it.
            vcpu.set_sys_reg(SysReg::TPIDR_EL0, 0).map_err(hvf_error)?;

            // Verify post-execve sysreg state through dtrace. If stage-1 isn't on or
            // TTBR0 doesn't point at the new tables, the new process will fault on the
            // first LDAXR.
            let actual_sctlr = vcpu.get_sys_reg(SysReg::SCTLR_EL1).unwrap_or(0);
            let actual_ttbr0 = vcpu.get_sys_reg(SysReg::TTBR0_EL1).unwrap_or(0);
            let actual_mair = vcpu.get_sys_reg(SysReg::MAIR_EL1).unwrap_or(0);
            emit_replace_stage(
                carrick_observability::probes::HvpatchExecReplaceStagePhase::Registers,
                registers_started,
            );
            crate::probes::execve_sysregs(actual_sctlr, actual_ttbr0, actual_mair);
            self.populate_vdso_data_page();
            self.allocate_mailbox_for_vcpu(vcpu)
        })();
        let mailbox_started = std::time::Instant::now();
        *mailbox = post_publication.unwrap_or_else(|error| {
            // Backend inventory and non-owning mapping rows already name these
            // frames. Returning would let `owner_rollback` retire their leases
            // while leaving those authorities published, so the only sound
            // outcome after this indeterminate boundary is process fail-stop.
            eprintln!(
                "carrick: FATAL: HVPatch exec post-publication register/mailbox failure: {error}"
            );
            std::process::abort();
        });
        emit_replace_stage(
            carrick_observability::probes::HvpatchExecReplaceStagePhase::Mailbox,
            mailbox_started,
        );
        Ok(())
    }
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
impl HvfInner {
    /// Snapshot every register the trap engine ever writes, reading from the
    /// passed `vcpu`. Gated like the signal path on `fpsimd_save_enabled()`. The
    /// shared engine's `Aarch64Vcpu::snapshot` calls this; `last_exit_class` is
    /// owned by the engine, so the snapshot carries 0 for it.
    pub(crate) fn snapshot_vcpu_from(
        vcpu: &applevisor::vcpu::Vcpu,
    ) -> Result<VcpuSnapshot, TrapError> {
        use applevisor::prelude::*;
        let mut gprs = [0u64; 31];
        for (i, reg) in GPR_TABLE.iter().enumerate() {
            gprs[i] = vcpu.get_reg(*reg).map_err(hvf_error)?;
        }
        // V0-V31 + FPSR/FPCR (audit M2): preserved across fork/clone so the
        // vector file survives the vCPU rebuild. Gated like the signal path.
        let mut vregs = [0u128; 32];
        let (mut fpsr, mut fpcr) = (0u32, 0u32);
        if fpsimd_save_enabled() {
            for (i, reg) in SIMD_FP_TABLE.iter().enumerate() {
                vregs[i] = vcpu.get_simd_fp_reg(*reg).map_err(hvf_error)?;
            }
            fpsr = vcpu.get_reg(Reg::FPSR).map_err(hvf_error)? as u32;
            fpcr = vcpu.get_reg(Reg::FPCR).map_err(hvf_error)? as u32;
        }
        let sp_el0 = vcpu.get_sys_reg(SysReg::SP_EL0).map_err(hvf_error)?;
        let sp_el1 = vcpu.get_sys_reg(SysReg::SP_EL1).map_err(hvf_error)?;
        Ok(VcpuSnapshot {
            core: Aarch64VcpuSnapshot {
                gprs,
                pc: vcpu.get_reg(Reg::PC).map_err(hvf_error)?,
                pstate: vcpu.get_reg(Reg::CPSR).map_err(hvf_error)?,
                sp_el0,
                // SP_EL1 is the per-vCPU syscall-mailbox address. Rebuild paths
                // refresh it from the binding after restoring this snapshot.
                sp_el1,
                elr_el1: vcpu.get_sys_reg(SysReg::ELR_EL1).map_err(hvf_error)?,
                spsr_el1: vcpu.get_sys_reg(SysReg::SPSR_EL1).map_err(hvf_error)?,
                ttbr0: vcpu.get_sys_reg(SysReg::TTBR0_EL1).map_err(hvf_error)?,
                ttbr1: vcpu.get_sys_reg(SysReg::TTBR1_EL1).map_err(hvf_error)?,
                tcr: vcpu.get_sys_reg(SysReg::TCR_EL1).map_err(hvf_error)?,
                sctlr: vcpu.get_sys_reg(SysReg::SCTLR_EL1).map_err(hvf_error)?,
                mair: vcpu.get_sys_reg(SysReg::MAIR_EL1).map_err(hvf_error)?,
                vbar: vcpu.get_sys_reg(SysReg::VBAR_EL1).map_err(hvf_error)?,
                cpacr: vcpu.get_sys_reg(SysReg::CPACR_EL1).map_err(hvf_error)?,
                cntkctl_el1: vcpu.get_sys_reg(SysReg::CNTKCTL_EL1).map_err(hvf_error)?,
                tpidr_el0: vcpu.get_sys_reg(SysReg::TPIDR_EL0).map_err(hvf_error)?,
                tpidrro_el0: vcpu.get_sys_reg(SysReg::TPIDRRO_EL0).map_err(hvf_error)?,
                tpidr_el1: vcpu.get_sys_reg(SysReg::TPIDR_EL1).map_err(hvf_error)?,
                contextidr_el1: vcpu
                    .get_sys_reg(SysReg::CONTEXTIDR_EL1)
                    .map_err(hvf_error)?,
                actlr_el1: vcpu.get_sys_reg(SysReg::ACTLR_EL1).map_err(hvf_error)?,
                vregs,
                fpsr,
                fpcr,
            },
            // The engine owns last_exit_class; the snapshot carries 0 for it.
            last_exit_class: 0,
        })
    }

    /// Restore `snap` onto the passed `vcpu` (the fork/clone/reclaim rebuild +
    /// the engine's `Aarch64Vcpu::restore`). The old `restore_vcpu` body.
    pub(crate) fn restore_vcpu_into(
        vcpu: &mut applevisor::vcpu::Vcpu,
        snap: &VcpuSnapshot,
    ) -> Result<(), TrapError> {
        use applevisor::prelude::*;
        for (reg, value) in GPR_TABLE.iter().zip(snap.core.gprs.iter()) {
            vcpu.set_reg(*reg, *value).map_err(hvf_error)?;
        }
        vcpu.set_reg(Reg::PC, snap.core.pc).map_err(hvf_error)?;
        vcpu.set_reg(Reg::CPSR, snap.core.pstate)
            .map_err(hvf_error)?;
        vcpu.set_sys_reg(SysReg::SP_EL0, snap.core.sp_el0)
            .map_err(hvf_error)?;
        // Order matters: program TCR/MAIR/TTBR0 before flipping SCTLR.M.
        vcpu.set_sys_reg(SysReg::MAIR_EL1, snap.core.mair)
            .map_err(hvf_error)?;
        vcpu.set_sys_reg(SysReg::TCR_EL1, snap.core.tcr)
            .map_err(hvf_error)?;
        vcpu.set_sys_reg(SysReg::TTBR0_EL1, snap.core.ttbr0)
            .map_err(hvf_error)?;
        // TTBR1 (upper-half, x86-64 high half under Rosetta) and ACTLR (EnTSO)
        // are part of the guest's live state; the captured TCR enables TTBR1, so
        // restoring TTBR0 alone would leave TTBR1 walking from base 0 and lose
        // hardware TSO — both required for the post-fork/clone guest to run.
        vcpu.set_sys_reg(SysReg::TTBR1_EL1, snap.core.ttbr1)
            .map_err(hvf_error)?;
        vcpu.set_sys_reg(SysReg::ACTLR_EL1, snap.core.actlr_el1)
            .map_err(hvf_error)?;
        vcpu.set_sys_reg(SysReg::CPACR_EL1, snap.core.cpacr)
            .map_err(hvf_error)?;
        vcpu.set_sys_reg(SysReg::CNTKCTL_EL1, snap.core.cntkctl_el1)
            .map_err(hvf_error)?;
        vcpu.set_sys_reg(SysReg::VBAR_EL1, snap.core.vbar)
            .map_err(hvf_error)?;
        vcpu.set_sys_reg(SysReg::SPSR_EL1, snap.core.spsr_el1)
            .map_err(hvf_error)?;
        vcpu.set_sys_reg(SysReg::ELR_EL1, snap.core.elr_el1)
            .map_err(hvf_error)?;
        vcpu.set_sys_reg(SysReg::TPIDR_EL0, snap.core.tpidr_el0)
            .map_err(hvf_error)?;
        // TPIDRRO_EL0 (guest-readable thread ptr), TPIDR_EL1 (the shim's x16
        // scratch) and CONTEXTIDR_EL1 (carrick's fast-`gettid` tid stamp) are all
        // zeroed by hv_vcpu_create, so a rebuilt vCPU (fork/clone or a
        // destroy/recreate reclaim) must restore each. CONTEXTIDR_EL1 is the one
        // that is guest-VISIBLE through `gettid`: miss it and the EL1 handler
        // reads 0 and degrades to a host round trip for the rest of the thread's
        // life. (The tid lived in TPIDR_EL1 before it was moved here to free that
        // register as the scratch; restoring only TPIDR_EL1 preserved a value that
        // means nothing across a park and dropped the one that does.)
        vcpu.set_sys_reg(SysReg::TPIDRRO_EL0, snap.core.tpidrro_el0)
            .map_err(hvf_error)?;
        vcpu.set_sys_reg(SysReg::TPIDR_EL1, snap.core.tpidr_el1)
            .map_err(hvf_error)?;
        vcpu.set_sys_reg(SysReg::CONTEXTIDR_EL1, snap.core.contextidr_el1)
            .map_err(hvf_error)?;
        // Apply SCTLR last so the MMU enable lands with the new tables.
        vcpu.set_sys_reg(SysReg::SCTLR_EL1, snap.core.sctlr)
            .map_err(hvf_error)?;
        // Restore V0-V31 + FPSR/FPCR via the C shim (NOT applevisor's
        // set_simd_fp_reg, which zeroes via the wrong register class). (audit M2)
        if fpsimd_save_enabled() {
            let vcpu_id = vcpu.id();
            for (i, reg) in SIMD_FP_TABLE.iter().enumerate() {
                let rc = set_simd_fp_reg_v(vcpu_id, *reg, snap.core.vregs[i]);
                if rc != 0 {
                    return Err(TrapError::Hypervisor(format!(
                        "fork restore set_simd_fp_reg(q{i}) failed: rc={rc:#x}"
                    )));
                }
            }
            vcpu.set_reg(Reg::FPSR, u64::from(snap.core.fpsr))
                .map_err(hvf_error)?;
            vcpu.set_reg(Reg::FPCR, u64::from(snap.core.fpcr))
                .map_err(hvf_error)?;
        }
        Ok(())
    }

    /// Seed a BRAND-NEW sibling vCPU (a `clone(CLONE_THREAD)` thread) so it enters
    /// EL0 at the child's resume PC. Unlike [`restore_vcpu_into`] (used by fork,
    /// whose vCPU had already done the boot trampoline `eret` into EL0 and merely
    /// resumes), a freshly created vCPU has never transitioned to EL0. We therefore
    /// start it at the EL0 trampoline page (in EL1h) with `SPSR_EL1=EL0t` and
    /// `ELR_EL1=snap.core.pc`, so the trampoline's single `eret` drops the vCPU into EL0
    /// at exactly the post-clone instruction — mirroring `map_plan`'s initial-boot
    /// sequence but with thread-private PC/SP/TLS. (The engine's `restore_thread_start`
    /// routes here for HVF; `last_exit_class` is engine-owned and not restored here.)
    pub(crate) fn restore_vcpu_thread_start_into(
        vcpu: &mut applevisor::vcpu::Vcpu,
        snap: &VcpuSnapshot,
    ) -> Result<(), TrapError> {
        use applevisor::prelude::*;
        for (reg, value) in GPR_TABLE.iter().zip(snap.core.gprs.iter()) {
            vcpu.set_reg(*reg, *value).map_err(hvf_error)?;
        }
        // Start at the EL0 trampoline page in EL1h; the trampoline `eret`s into EL0t
        // at ELR_EL1 with SPSR_EL1's PSTATE.
        const AARCH64_PSTATE_EL1H_DAIF_MASKED: u64 = 0x3c5;
        const AARCH64_PSTATE_EL0T_DAIF_MASKED: u64 = 0x3c0;
        vcpu.set_reg(Reg::PC, crate::memory::LINUX_EL0_TRAMPOLINE_BASE)
            .map_err(hvf_error)?;
        vcpu.set_reg(Reg::CPSR, AARCH64_PSTATE_EL1H_DAIF_MASKED)
            .map_err(hvf_error)?;
        vcpu.set_sys_reg(SysReg::SPSR_EL1, AARCH64_PSTATE_EL0T_DAIF_MASKED)
            .map_err(hvf_error)?;
        // The child's EL0 resume PC (snap.core.pc == parent ELR_EL1 == post-svc).
        vcpu.set_sys_reg(SysReg::ELR_EL1, snap.core.pc)
            .map_err(hvf_error)?;
        vcpu.set_sys_reg(SysReg::SP_EL0, snap.core.sp_el0)
            .map_err(hvf_error)?;
        // Same translation regime as the parent (shared address space).
        vcpu.set_sys_reg(SysReg::MAIR_EL1, snap.core.mair)
            .map_err(hvf_error)?;
        vcpu.set_sys_reg(SysReg::TCR_EL1, snap.core.tcr)
            .map_err(hvf_error)?;
        vcpu.set_sys_reg(SysReg::TTBR0_EL1, snap.core.ttbr0)
            .map_err(hvf_error)?;
        // TTBR1 (upper-half, x86-64 high half under Rosetta) and ACTLR (EnTSO) are
        // part of the guest's live state; the captured TCR enables TTBR1, so restoring
        // TTBR0 alone would leave TTBR1 walking from base 0 and lose hardware TSO —
        // both required for the post-clone guest to run.
        vcpu.set_sys_reg(SysReg::TTBR1_EL1, snap.core.ttbr1)
            .map_err(hvf_error)?;
        vcpu.set_sys_reg(SysReg::ACTLR_EL1, snap.core.actlr_el1)
            .map_err(hvf_error)?;
        vcpu.set_sys_reg(SysReg::CPACR_EL1, snap.core.cpacr)
            .map_err(hvf_error)?;
        vcpu.set_sys_reg(SysReg::CNTKCTL_EL1, snap.core.cntkctl_el1)
            .map_err(hvf_error)?;
        vcpu.set_sys_reg(SysReg::VBAR_EL1, snap.core.vbar)
            .map_err(hvf_error)?;
        vcpu.set_sys_reg(SysReg::TPIDR_EL0, snap.core.tpidr_el0)
            .map_err(hvf_error)?;
        // CONTEXTIDR_EL1 is deliberately LEFT ZERO here: a new thread must not
        // inherit the parent's tid stamp. Zero is the fail-safe — the EL1
        // `gettid` handler's degrade branch traps to the host and returns the
        // correct tid — whereas a stale parent tid would be returned silently
        // and WRONG if the caller's re-stamp ever failed to run.
        // SP_EL1 was already set to this sibling's mailbox by materialization.
        // The trampoline does not touch it before `eret` enters EL0.
        // Enable the MMU last, identically to the parent.
        vcpu.set_sys_reg(SysReg::SCTLR_EL1, snap.core.sctlr)
            .map_err(hvf_error)?;
        // A new fork/clone vCPU starts with zeroed SIMD/FP state. Preserve the
        // captured V0-V31 + FPSR/FPCR just as the ordinary restore path does;
        // otherwise a raw clone loses live vector state in the child.
        if fpsimd_save_enabled() {
            let vcpu_id = vcpu.id();
            for (i, reg) in SIMD_FP_TABLE.iter().enumerate() {
                let rc = set_simd_fp_reg_v(vcpu_id, *reg, snap.core.vregs[i]);
                if rc != 0 {
                    return Err(TrapError::Hypervisor(format!(
                        "thread-start restore set_simd_fp_reg(q{i}) failed: rc={rc:#x}"
                    )));
                }
            }
            vcpu.set_reg(Reg::FPSR, u64::from(snap.core.fpsr))
                .map_err(hvf_error)?;
            vcpu.set_reg(Reg::FPCR, u64::from(snap.core.fpcr))
                .map_err(hvf_error)?;
        }
        Ok(())
    }

    /// Run the passed `vcpu` to its next exit, decoding HVF's native trap surface
    /// into the neutral [`carrick_aarch64::Aarch64Exit`]. The old
    /// `run_until_syscall` exit decode, returning `Aarch64Exit` instead of an
    /// `Option<Aarch64SyscallFrame>` — the shared engine owns the
    /// pending-syscall/SA_RESTART state, the guest-CPU accounting and the
    /// EL1-maintenance loop, so this surfaces
    /// `Syscall`/`EL0Fault`/`MaintenanceDone`/`Kicked`, keeps the internal
    /// kick-swallow + the bounded in-loop lazy alias re-map, and services the
    /// sys64 MRS read inline (a loop `continue`).
    pub(crate) fn run_to_exit(
        vcpu: &mut applevisor::vcpu::Vcpu,
        mailbox: &mut MailboxBinding,
    ) -> Result<carrick_aarch64::Aarch64Exit, TrapError> {
        use applevisor::prelude::*;
        use carrick_aarch64::Aarch64Exit;

        // Lifecycle marker: the first entry here is the moment the guest first
        // runs — i.e. INITIAL boot/setup is done. Fired once per process; since
        // carrick forks via no-exec `libc::fork`, a forked child inherits the
        // parent's already-completed Once and does NOT re-fire this.
        static FIRST_RUN: std::sync::Once = std::sync::Once::new();
        FIRST_RUN.call_once(|| crate::probes::lifecycle(crate::probes::phase::FIRST_VCPU_RUN));

        // Bounds lazy re-mapping of dropped aliases so a
        // genuinely-unmappable backing still terminates instead of spinning.
        let mut alias_remap_limiter = AliasRemapLimiter::default();
        loop {
            // The engine accounts the guest CPU time via `guest_cpu::timed_run`
            // around its `vcpu.run()` call, so do NOT double-account here.
            vcpu.run().map_err(hvf_error)?;
            let exit = vcpu.get_exit_info();
            if exit.reason == ExitReason::CANCELED {
                // A cross-thread `hv_vcpus_exit` (crate::vcpu_kick) forced this
                // vCPU out of the guest so a pending signal can be delivered.
                //
                // But the kick can land while the vCPU is still inside carrick's
                // EL1 trap trampoline — a guest EL0 `svc`/fault is mid-flight,
                // between the vector entry (VBAR_EL1 = vectors_base, e.g. the
                // sync-from-EL0 entry at +0x400) and the HVC that traps out to
                // the host. PC there is an EL1 trampoline address, NOT a guest
                // userspace PC. Reporting that as a deliverable kick overwrites
                // the in-flight exception and wedges the thread — reproduced as a
                // SIGURG storm corrupting a futex waiter (pc=vectors_base+0x404).
                //
                // Resume until the guest is back at EL0 so the trampoline
                // completes its HVC and the real syscall is serviced; the
                // pending signal is then delivered at that clean EL0 boundary.
                let cpsr = vcpu.get_reg(Reg::CPSR).map_err(hvf_error)?;
                if !ExecLevel::from_pstate(cpsr).is_guest() {
                    EL1_KICK_RESUMED.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    crate::probes::kick_in_kernel(
                        vcpu.get_reg(Reg::PC).unwrap_or(0),
                        ((cpsr >> 2) & 0b11) as u32,
                    );
                    continue;
                }
                return Ok(Aarch64Exit::Kicked);
            }
            // A direct EL0 abort on a high-VA alias address that THIS vCPU's
            // shared VM is missing: a `fork()` rebuilt the shared VM from only the
            // forking thread's mappings, dropping an alias mapped by
            // a sibling thread (the go-build telemetry counter). arm64 HVF has no
            // stage-2 TLB shootdown, so re-running alone never fixes it — but the
            // host backing is a MAP_SHARED mmap still live at the registered host
            // address, so re-`hv_vm_map`'ing it into THIS (shared) VM restores the
            // stage-2 entry for every thread, and the instruction re-executes
            // cleanly. Only registered aliases are touched, so a genuine bad
            // access to unregistered memory still faults. Bounded as a backstop.
            // (Kept INSIDE run_to_exit, NOT surfaced as Aarch64Exit::Memory — the
            // in-loop remap is the safe, behavior-identical choice.)
            if exit.reason == ExitReason::EXCEPTION
                && is_aarch64_el0_abort_exception(exit.exception.syndrome)
                && crate::memory::is_high_va(exit.exception.virtual_address)
            {
                let backing = if exit.exception.physical_address != 0 {
                    lookup_shared_alias(exit.exception.physical_address)
                } else {
                    lookup_live_alias_by_va_any_scope(exit.exception.virtual_address, 1)
                };
                if let Some(b) = backing
                    && alias_remap_limiter.allow(b.physical_ipa)
                {
                    // SAFETY: `host_addr` is a live MAP_SHARED mmap registered
                    // by add_alias. Only rc=0 proves replay installation.
                    let rc = unsafe { inventory_hv_vm_map_replay(b) };
                    crate::probes::hv_vm_map_alias(
                        exit.exception.virtual_address,
                        b.physical_ipa,
                        b.physical_size as u64,
                        rc as i32,
                        0,
                    );
                    if rc != 0 {
                        return Err(TrapError::Hypervisor(format!(
                            "lazy alias replay hv_vm_map(ipa=0x{:x}, size={}) failed: 0x{rc:x}",
                            b.physical_ipa, b.physical_size
                        )));
                    }
                    // Diagnostic-only alias-remap counter+dump, gated behind
                    // `debug-stats` (no other consumer reads the counter).
                    #[cfg(feature = "debug-stats")]
                    {
                        let n =
                            ALIAS_REMAP_COUNT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                        if n.is_multiple_of(256) {
                            eprintln!("ALIAS_REMAP n={n} ipa=0x{:x}", b.physical_ipa);
                        }
                    }
                    continue;
                }
            }
            if exit.reason != ExitReason::EXCEPTION {
                // WFI/halt or any non-EXCEPTION non-CANCELED exit that today
                // errored: keep erroring.
                return Err(TrapError::UnexpectedExit {
                    reason: format!("{:?}", exit.reason),
                });
            }

            let exception = exit.exception;
            // A guest EL0 memory abort HVF couldn't satisfy (e.g. a stack overflow
            // that ran SP off the mapped stack) surfaces DIRECTLY as an EXCEPTION
            // exit with EC=0x20/0x24, NOT through our EL1 vector's HVC. Surface it
            // as a DIRECT EL0Fault so the runtime delivers the right Linux signal
            // (SIGSEGV) instead of fataling. ELR_EL1/FAR_EL1 are STALE here (the
            // guest's EL1 vector never ran), so build the fault from HVF's
            // authoritative PC (Reg::PC) + VA (exception.virtual_address).
            if is_aarch64_el0_abort_exception(exception.syndrome) {
                let true_pc = vcpu.get_reg(Reg::PC).unwrap_or(0);
                let far = exception.virtual_address;
                let x16 = vcpu.get_reg(Reg::X16).unwrap_or(0);
                let x17 = vcpu.get_reg(Reg::X17).unwrap_or(0);
                let x29 = vcpu.get_reg(Reg::X29).unwrap_or(0);
                let x30 = vcpu.get_reg(Reg::LR).unwrap_or(0);
                let sp = vcpu.get_sys_reg(SysReg::SP_EL0).unwrap_or(0);
                crate::probes::vcpu_fault(exception.syndrome, true_pc, far, x30, sp, unsafe {
                    libc::getpid()
                });
                return Ok(Aarch64Exit::EL0Fault {
                    syndrome: exception.syndrome,
                    elr: true_pc,
                    far,
                    x16,
                    x17,
                    x29,
                    x30,
                    sp,
                    from_el0_direct: true,
                });
            }
            // Fail loud on the EL1 vector's `hvc #3` (current-EL synchronous slot):
            // carrick's guest took a synchronous exception WHILE AT EL1, which only
            // happens when a guest resume left PSTATE at EL1 (e.g. a signal handler
            // entered with SPSR_EL1=EL1h, whose PXN instruction fetch aborts). The
            // bare-`eret` vectors used to spin on this forever at 100 % CPU with no
            // host exit; the `hvc #3` trap surfaces it here. ESR_EL1/ELR_EL1/FAR_EL1
            // still hold the ORIGINAL EL1 fault (the `hvc` left them untouched), so
            // report them verbatim. This is a carrick bug, not a guest fault — do
            // not deliver it to the guest as a signal; terminate loudly.
            if is_aarch64_hvc_fault(exception.syndrome) {
                let esr_el1 = vcpu.get_sys_reg(SysReg::ESR_EL1).unwrap_or(0);
                let elr_el1 = vcpu.get_sys_reg(SysReg::ELR_EL1).unwrap_or(0);
                let far_el1 = vcpu.get_sys_reg(SysReg::FAR_EL1).unwrap_or(0);
                let spsr_el1 = vcpu.get_sys_reg(SysReg::SPSR_EL1).unwrap_or(0);
                if is_stage1_cow_write_fault(esr_el1) {
                    vcpu.set_reg(Reg::PC, elr_el1).map_err(hvf_error)?;
                    vcpu.set_reg(Reg::CPSR, spsr_el1).map_err(hvf_error)?;
                    return Ok(Aarch64Exit::Stage1CowFault {
                        syndrome: esr_el1,
                        far: far_el1,
                    });
                }
                let ec = (esr_el1 >> 26) & 0x3f;
                let mailbox_diagnostics = mailbox.diagnostics();
                eprintln!(
                    "FAIL-LOUD pid={pid}: guest executed at EL1 and faulted \
                     (current-EL sync vector) — carrick state corruption (a guest \
                     resume left PSTATE at EL1, commonly a signal handler entered \
                     with SPSR_EL1=EL1h). Was a silent 100% CPU spin before the \
                     hvc #3 vector trap. esr_el1={esr_el1:#x} ec={ec:#x} \
                     elr_el1={elr_el1:#x} far_el1={far_el1:#x} spsr_el1={spsr_el1:#x} \
                     mailbox={mailbox_diagnostics:?}",
                    pid = unsafe { libc::getpid() },
                );
                return Err(TrapError::GuestAtEl1 {
                    esr_el1,
                    elr_el1,
                    far_el1,
                    spsr_el1,
                });
            }
            if !is_aarch64_syscall_exception(exception.syndrome) {
                return Err(TrapError::UnexpectedException {
                    syndrome: exception.syndrome,
                    virtual_address: exception.virtual_address,
                    physical_address: exception.physical_address,
                });
            }
            // EC=0x16 (HVC) only means our EL1 vector trampoline fired — it catches
            // ALL lower-EL synchronous exceptions, not just SVCs. Look at ESR_EL1
            // to see what actually trapped to EL1; if it's not an SVC, either
            // emulate it (sys64 MRS read → re-run) or surface it as an EL0Fault.
            if is_aarch64_hvc_exception(exception.syndrome) {
                // The maintenance HVC (`hvc #1`) is consumed by the engine's
                // EL1-maintenance loop; if it ever reaches here, report it so the
                // engine's loop can match on it.
                if is_aarch64_hvc_maintenance(exception.syndrome) {
                    return Ok(Aarch64Exit::MaintenanceDone);
                }
                let underlying = vcpu.get_sys_reg(SysReg::ESR_EL1).map_err(hvf_error)?;
                if !is_aarch64_svc_exception(underlying) {
                    if HvfVmState::emulate_el0_sys64_read_inner(vcpu, underlying)? {
                        // Serviced (ELR_EL1 advanced, target GPR written) — re-run.
                        continue;
                    }
                    let elr = vcpu.get_sys_reg(SysReg::ELR_EL1).unwrap_or(0);
                    let far = vcpu.get_sys_reg(SysReg::FAR_EL1).unwrap_or(0);
                    let x16 = vcpu.get_reg(Reg::X16).unwrap_or(0);
                    let x17 = vcpu.get_reg(Reg::X17).unwrap_or(0);
                    let x29 = vcpu.get_reg(Reg::X29).unwrap_or(0);
                    let x30 = vcpu.get_reg(Reg::LR).unwrap_or(0);
                    let sp = vcpu.get_sys_reg(SysReg::SP_EL0).unwrap_or(0);
                    crate::probes::vcpu_fault(underlying, elr, far, x30, sp, unsafe {
                        libc::getpid()
                    });
                    // HVC-trampoline path: the guest EL1 vector latched
                    // ELR_EL1/FAR_EL1, so they are authoritative.
                    return Ok(Aarch64Exit::EL0Fault {
                        syndrome: underlying,
                        elr,
                        far,
                        x16,
                        x17,
                        x29,
                        x30,
                        sp,
                        from_el0_direct: false,
                    });
                }
            }
            // A genuine guest EL0 `svc`. HVC2 from the mailbox vector consumes
            // the release-published frame without any register/sysreg API reads.
            // The diagnostic legacy mode still validates that publication, then
            // deliberately reads the live registers for an apples-to-apples
            // transport comparison. A direct SVC exit (no EL1 HVC vehicle) keeps
            // the historical register decode as a defensive compatibility path.
            let mut register_reads = 0u32;
            let mut sysreg_reads = 0u32;
            let mut legacy_decode = || {
                sysreg_reads += 1;
                let resume_pc = vcpu.get_sys_reg(SysReg::ELR_EL1).map_err(|error| {
                    crate::syscall_mailbox::MailboxConsumeError::Legacy(error.to_string())
                })?;
                let frame = carrick_hal::read_aarch64_syscall_frame(|r| {
                    register_reads += 1;
                    hvf_get_reg(vcpu, r)
                })
                .map_err(|error| {
                    crate::syscall_mailbox::MailboxConsumeError::Legacy(error.to_string())
                })?;
                sysreg_reads += 1;
                let spsr = vcpu.get_sys_reg(SysReg::SPSR_EL1).unwrap_or(0);
                register_reads += 1;
                let fp = vcpu.get_reg(Reg::X29).unwrap_or(0);
                register_reads += 1;
                let lr = vcpu.get_reg(Reg::LR).unwrap_or(0);
                sysreg_reads += 1;
                let sp = vcpu.get_sys_reg(SysReg::SP_EL0).unwrap_or(0);
                sysreg_reads += 1;
                let esr = vcpu.get_sys_reg(SysReg::ESR_EL1).unwrap_or(0);
                Ok(crate::syscall_mailbox::MailboxRequest {
                    native_nr: frame.x8,
                    frame,
                    resume_pc,
                    spsr,
                    fp,
                    lr,
                    sp,
                    esr,
                })
            };
            let request = if is_aarch64_hvc_exception(exception.syndrome) {
                mailbox.decode_request(legacy_decode)
            } else {
                legacy_decode()
            }
            .map_err(|error| {
                let pc = vcpu.get_reg(Reg::PC).unwrap_or(0);
                let sp_el1 = vcpu.get_sys_reg(SysReg::SP_EL1).unwrap_or(0);
                let binding_address = mailbox.slot().guest_address();
                let diagnostics = mailbox.diagnostics();
                TrapError::Hypervisor(format!(
                    "{error}; vcpu_pc={pc:#x}; sp_el1={sp_el1:#x}; binding_address={binding_address:#x}; mailbox={diagnostics:?}"
                ))
            })?;
            crate::probes::hvf_syscall_transport(
                mailbox.transport().raw(),
                0,
                register_reads,
                sysreg_reads,
                0,
            );
            let frame = request.frame;
            let resume_pc = request.resume_pc;
            // vcpu_trap probe parity: guest PC at the trap (= ELR_EL1) + the live
            // FP/SP/LR so a DTrace consumer can walk the guest call chain. The
            // stack-region bases require the per-thread mapping list (on
            // HvfVmState, not reachable here), so report zero bases.
            crate::probes::vcpu_trap(&crate::compat::GuestRegs {
                pc: resume_pc,
                sp: request.sp,
                fp: request.fp,
                lr: request.lr,
                x8: frame.x8,
                x0: frame.x0,
                stack_guest_base: 0,
                stack_host_base: 0,
                stack_guest_end: 0,
            });
            return Ok(Aarch64Exit::Syscall { frame, resume_pc });
        }
    }
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
impl HvfMappedRegion {
    /// Whether `[address, address+length)` lies wholly within this region's
    /// VA span `[start, end)`. Delegates the whole-range containment+bounds math
    /// to the neutral [`carrick_guest_mem::region::GuestMemoryRegion::contains_range`]
    /// so the bounds test can't drift across backends. HVF keeps its RICHER
    /// region SELECTION (newest-first + stage-1-IPA preference, chunked per page,
    /// `translate_va` for high-VA aliases — see `mapping_index_for_range`) as its
    /// own glue; only this per-region bounds primitive is shared. The projected
    /// region keys on `start`/`end` (NOT `size`: a 16 KiB host-rounded `end` can
    /// over-claim, and the copy loops compute `host_addr + (addr - start)`).
    fn contains_range(&self, address: u64, length: usize) -> bool {
        carrick_guest_mem::region::GuestMemoryRegion {
            base: self.start,
            len: (self.end - self.start) as usize,
            host_addr: self.host_addr,
        }
        .contains_range(address, length)
    }

    fn view(&self) -> MappingView {
        MappingView {
            start: self.start,
            end: self.end,
            ipa: self.ipa,
            host_addr: self.host_addr,
            guest_writable: self.guest_writable,
            sharing: self.sharing,
            shared_key_base: self.shared_key_base,
            shared_key_offset: self.shared_key_offset,
        }
    }
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
impl MappingView {
    /// Synthesize a view from a process-shared `alias_registry` entry (the
    /// cross-thread fallback). The alias is a contiguous VA→IPA→host window, so
    /// the VA base + backing base reproduce the same `host_addr + (addr - start)`
    /// offset math a real region uses.
    fn from_alias(b: &AliasBacking) -> Self {
        MappingView {
            start: b.start,
            end: b.start.saturating_add(b.size as u64),
            ipa: b.ipa,
            host_addr: b.host_addr as *mut u8,
            guest_writable: b.guest_writable,
            sharing: b.sharing,
            shared_key_base: b.shared_key_base,
            shared_key_offset: b.shared_key_offset,
        }
    }

    fn shared_futex_location_for_ipa(
        &self,
        backing_gpa: u64,
    ) -> Option<carrick_guest_mem::SharedFutexLocation> {
        if !self.sharing.has_shared_futex_identity() {
            return None;
        }
        let offset = usize::try_from(backing_gpa.checked_sub(self.ipa)?).ok()?;
        if offset.checked_add(std::mem::size_of::<u32>())?
            > self.end.checked_sub(self.start)? as usize
        {
            return None;
        }
        let word = carrick_guest_mem::HostVa(unsafe { self.host_addr.add(offset) } as usize);
        let waiter_key = if self.shared_key_base == 0 {
            word.raw()
        } else {
            let file_offset = self.shared_key_offset.saturating_add(offset as u64);
            shared_futex_waiter_key(self.shared_key_base, file_offset)
        };
        Some(carrick_guest_mem::SharedFutexLocation::Direct { word, waiter_key })
    }
}

/// True for a memory abort taken from a LOWER exception level (EL0 guest code):
/// instruction abort (`EC = 0x20`) or data abort (`EC = 0x24`). HVF normally
/// funnels guest EL0 faults through our EL1 vector trampoline (an HVC), but a
/// fault HVF itself can't satisfy (e.g. a stack overflow whose SP ran off the
/// mapped guest stack) surfaces DIRECTLY as an EXCEPTION exit with this EC. It
/// must be delivered to the guest as SIGSEGV (faulthandler._stack_overflow,
/// Go's sigpanic), not treated as a fatal "unexpected exception".
pub fn is_aarch64_el0_abort_exception(syndrome: u64) -> bool {
    matches!(aarch64_exception_class(syndrome), 0x20 | 0x24)
}

fn align_down(value: u64, alignment: u64) -> u64 {
    value / alignment * alignment
}

fn align_up(value: u64, alignment: u64) -> Result<u64, TrapError> {
    if alignment == 0 {
        return Err(TrapError::Hypervisor(
            "cannot align a guest mapping to zero bytes".to_owned(),
        ));
    }
    let remainder = value % alignment;
    if remainder == 0 {
        Ok(value)
    } else {
        value
            .checked_add(alignment - remainder)
            .ok_or(TrapError::MappingOverflow {
                guest_start: value,
                mapped_size: alignment,
            })
    }
}

/// Sole raw Hypervisor.framework stage-2 map boundary. Inventory-aware callers
/// own logical publication; VM/vCPU replay calls this only to reinstall the
/// same physical extent and must still treat every nonzero result as failure.
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
unsafe fn inventory_hv_vm_map(
    host: *mut std::ffi::c_void,
    ipa: u64,
    size: usize,
    permissions: u64,
) -> applevisor_sys::hv_return_t {
    let result = unsafe { applevisor_sys::hv_vm_map(host, ipa, size, permissions) };
    if result == 0 {
        emit_global_frame_stage2(
            carrick_observability::probes::HvpatchGlobalFrameStage2Phase::Mapped,
            ipa,
            size,
            host as u64,
            permissions,
        );
    }
    result
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
fn emit_global_frame_stage2(
    phase: carrick_observability::probes::HvpatchGlobalFrameStage2Phase,
    ipa: u64,
    size: usize,
    host_addr: u64,
    permissions: u64,
) {
    let event = carrick_observability::probes::HvpatchGlobalFrameStage2::new(
        phase,
        ipa,
        size as u64,
        host_addr,
        permissions,
    )
    .unwrap_or_else(|error| {
        eprintln!("carrick: FATAL: construct global-frame stage-2 receipt: {error}");
        std::process::abort();
    });
    crate::probes::hvpatch_global_frame_stage2(event);
}

/// Serialize lazy replay and make a sibling that lost the race observe the
/// exact already-installed extent as success without accepting arbitrary HVF
/// errors. The marker is cleared on unmap and every VM destruction.
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
unsafe fn inventory_hv_vm_map_replay(backing: AliasBacking) -> applevisor_sys::hv_return_t {
    let key = replay_mapping_key(backing);
    mutate_external_alias_state(|installed, _| {
        if installed.contains(&key) {
            return 0;
        }
        let result = unsafe {
            inventory_hv_vm_map(
                backing.physical_host_addr as *mut std::ffi::c_void,
                backing.physical_ipa,
                backing.physical_size,
                backing.perms,
            )
        };
        if result == 0 {
            installed.insert(key);
        }
        result
    })
}

/// Sole raw Hypervisor.framework stage-2 unmap boundary.
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
unsafe fn inventory_hv_vm_unmap(ipa: u64, size: usize) -> applevisor_sys::hv_return_t {
    let result = unsafe { applevisor_sys::hv_vm_unmap(ipa, size) };
    if result == 0 {
        forget_replay_extent(ipa, size);
        emit_global_frame_stage2(
            carrick_observability::probes::HvpatchGlobalFrameStage2Phase::Unmapped,
            ipa,
            size,
            0,
            0,
        );
    }
    result
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
unsafe fn inventory_hv_vm_destroy() -> applevisor_sys::hv_return_t {
    let result = unsafe { applevisor_sys::hv_vm_destroy() };
    if result == 0 {
        clear_replay_mappings();
    }
    result
}

#[cfg(test)]
#[test]
fn raw_hvf_stage2_calls_are_inventory_gated() {
    let source = include_str!("trap.rs");
    assert_eq!(
        source
            .matches(concat!("applevisor_sys::hv_vm_", "map("))
            .count(),
        1,
        "raw hv_vm_map must appear only in inventory_hv_vm_map"
    );
    assert_eq!(
        source
            .matches(concat!("applevisor_sys::hv_vm_", "unmap("))
            .count(),
        1,
        "raw hv_vm_unmap must appear only in inventory_hv_vm_unmap"
    );
    assert_eq!(
        source
            .matches(concat!("inventory_hv_vm_map_replay", "(b)"))
            .count(),
        2,
        "both lazy replay paths must use exact serialized replay"
    );
}

#[cfg(test)]
#[test]
fn reclaim_park_authority_contains_no_task_snapshot() {
    let mut authority = ReclaimParkAuthority::Live;
    authority.mark_vcpu_parked().unwrap();
    assert_eq!(authority, ReclaimParkAuthority::VcpuParked);
    assert!(authority.destination_vcpu_is_live().is_err());
    authority.mark_live_after_recreate().unwrap();
    assert_eq!(authority, ReclaimParkAuthority::Live);
    assert!(authority.destination_vcpu_is_live().is_ok());
}

/// Back one guest region with a raw `mmap(MAP_ANON)` buffer + `hv_vm_map`,
/// returning an UNOWNED [`HvfMappedRegion`] (`memory: None`).
///
/// We deliberately do NOT use applevisor's `Memory` (`vm.memory_create`), whose
/// `alloc_zeroed(Layout::from_size_align(size, 16 KiB))` produces a VM mapping
/// that macOS `fork(2)` is ~8x more expensive to COW than a clean anonymous
/// `mmap` — even though neither is resident (both ~6 MiB RSS). For carrick's
/// ~640 MiB of guest windows this was the dominant per-fork cost: 640 MiB
/// fork+wait measured 9.6 ms (applevisor) vs 1.1 ms (raw mmap). See
/// `examples/fork_alloc_bench.rs`. The host pages leak only at process exit,
/// matching the existing `ManuallyDrop<HvfInner>` discipline (applevisor
/// `Memory` Drop never ran either) and the `map_shared_file` raw path.
/// Allocate a fresh `MAP_SHARED` anon buffer and copy `src`'s RESIDENT pages
/// into it. Used by `HvfInner::fork` to take a private snapshot of guest-
/// PRIVATE memory: guest RAM is host-`MAP_SHARED` for HVF coherence (see
/// `map_region_raw`), so `fork(2)` does NOT COW-isolate it — without an
/// explicit copy a forked child and its parent would share, and corrupt, the
/// macOS `vm_inherit.h`: parent + child share the SAME pages across `fork(2)`.
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
const VM_INHERIT_SHARE: libc::c_int = 0;
/// macOS `vm_inherit.h`: child gets a COW copy across `fork(2)` (the default).
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
const VM_INHERIT_COPY: libc::c_int = 1;

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
const FORK_FOOTPRINT_CLASS_PRIVATE_MMAP_ARENA: i32 = 1;
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
const FORK_FOOTPRINT_CLASS_PRIVATE_HEAP: i32 = 2;
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
const FORK_FOOTPRINT_CLASS_PRIVATE_OVERLAY: i32 = 3;
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
const FORK_FOOTPRINT_CLASS_PRIVATE_HIGH_ALIAS: i32 = 4;
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
const FORK_FOOTPRINT_CLASS_PRIVATE_WRITABLE_OTHER: i32 = 5;
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
const FORK_FOOTPRINT_CLASS_PRIVATE_RO_OR_INTERNAL: i32 = 6;
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
const FORK_FOOTPRINT_CLASS_SHARED_APERTURE: i32 = 7;
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
const FORK_FOOTPRINT_CLASS_SHARED_OTHER: i32 = 8;
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
const FORK_FOOTPRINT_CLASS_PRIVATE_PAGE_TABLES: i32 = 9;

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
const FORK_FOOTPRINT_FLAG_CHILD_OBSERVES: u64 = 1 << 0;
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
const FORK_FOOTPRINT_FLAG_PARENT_SHARED: u64 = 1 << 1;
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
const FORK_FOOTPRINT_FLAG_COW_COPY: u64 = 1 << 2;
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
const FORK_FOOTPRINT_FLAG_GUEST_WRITABLE: u64 = 1 << 3;
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
const FORK_FOOTPRINT_FLAG_INDEPENDENT_STAGE1: u64 = 1 << 4;

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
#[derive(Clone, Copy, Default)]
struct ForkFootprintClassSample {
    region_count: u64,
    scan_bytes: u64,
    resident_bytes: u64,
    flags: u64,
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
fn fork_footprint_class_id(start: u64, fork_shared: bool, guest_writable: bool) -> i32 {
    if fork_shared {
        if start == crate::memory::LINUX_SHARED_FILE_BASE {
            return FORK_FOOTPRINT_CLASS_SHARED_APERTURE;
        }
        return FORK_FOOTPRINT_CLASS_SHARED_OTHER;
    }
    if start == crate::memory::LINUX_MMAP_BASE {
        return FORK_FOOTPRINT_CLASS_PRIVATE_MMAP_ARENA;
    }
    if start == crate::memory::LINUX_HEAP_BASE {
        return FORK_FOOTPRINT_CLASS_PRIVATE_HEAP;
    }
    if start == crate::memory::LINUX_PRIVATE_OVERLAY_BASE {
        return FORK_FOOTPRINT_CLASS_PRIVATE_OVERLAY;
    }
    if start == crate::memory::LINUX_PAGE_TABLES_BASE {
        return FORK_FOOTPRINT_CLASS_PRIVATE_PAGE_TABLES;
    }
    if crate::memory::is_high_va(start) {
        return FORK_FOOTPRINT_CLASS_PRIVATE_HIGH_ALIAS;
    }
    if guest_writable {
        FORK_FOOTPRINT_CLASS_PRIVATE_WRITABLE_OTHER
    } else {
        FORK_FOOTPRINT_CLASS_PRIVATE_RO_OR_INTERNAL
    }
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
fn fork_footprint_flags(m: &HvfMappedRegion) -> u64 {
    let mut flags = FORK_FOOTPRINT_FLAG_CHILD_OBSERVES;
    if m.sharing.shares_across_fork() {
        flags |= FORK_FOOTPRINT_FLAG_PARENT_SHARED;
    } else if m.start == crate::memory::LINUX_PAGE_TABLES_BASE {
        flags |= FORK_FOOTPRINT_FLAG_INDEPENDENT_STAGE1;
    } else {
        flags |= FORK_FOOTPRINT_FLAG_COW_COPY;
    }
    if m.guest_writable {
        flags |= FORK_FOOTPRINT_FLAG_GUEST_WRITABLE;
    }
    flags
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
fn fork_footprint_scan_len(m: &HvfMappedRegion, class_id: i32, arena_high_water: u64) -> usize {
    if class_id == FORK_FOOTPRINT_CLASS_PRIVATE_MMAP_ARENA {
        arena_high_water
            .saturating_sub(crate::memory::LINUX_MMAP_BASE)
            .try_into()
            .unwrap_or(m.size)
            .min(m.size)
    } else {
        m.size
    }
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
fn resident_bytes_for_host_range(host_addr: *mut u8, len: usize) -> u64 {
    if host_addr.is_null() || len == 0 {
        return 0;
    }
    let page = {
        let p = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
        if p <= 0 { 16 * 1024 } else { p as usize }
    };
    let pages = len.div_ceil(page);
    let mut resident = vec![0u8; pages];
    let rc = unsafe {
        libc::mincore(
            host_addr.cast::<libc::c_void>(),
            len,
            resident.as_mut_ptr().cast::<libc::c_char>(),
        )
    };
    if rc != 0 {
        return 0;
    }
    resident
        .iter()
        .filter(|flag| **flag & 1 != 0)
        .count()
        .saturating_mul(page) as u64
}

/// Set a guest region's per-process `fork(2)` inheritance via macOS `minherit(2)`.
///
/// `VM_INHERIT_SHARE` makes the WHOLE region's pages SHARED across a later
/// `libc::fork` (XNU `vm_map_fork_share`: the child references the SAME
/// `vm_object` — no shadow, no copy — and both entries are `is_shared`; the
/// parent is NOT converted to copy-on-write, unlike FreeBSD/NetBSD UVM). This is
/// how a vfork/CLONE_VM child gets true write-visibility into the SUSPENDED
/// parent (LTP clone05) while keeping the same physical pages, so the child's
/// re-`hv_vm_map` binds the same PAs. `VM_INHERIT_COPY` restores cheap COW
/// isolation for subsequent plain forks.
///
/// MUST be applied to a WHOLE mmap region (offset 0, full len): `minherit` on a
/// sub-range clips the `vm_map_entry`, so the first fork shadows the sub-entry
/// (`vo_size > entry_size`) instead of sharing. carrick's per-region mmaps make
/// the whole-region call natural. Best-effort: a failure degrades to COW (the
/// vfork child just won't see the parent's writes), never a crash.
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
fn set_region_fork_inheritance(host_addr: *mut u8, size: usize, inherit: libc::c_int) {
    unsafe extern "C" {
        fn minherit(
            addr: *mut libc::c_void,
            len: libc::size_t,
            inherit: libc::c_int,
        ) -> libc::c_int;
    }
    let rc = unsafe { minherit(host_addr.cast(), size, inherit) };
    let _ = rc;
}

/// Create the independent stage-1 table backing required by a legacy VMM fork.
/// Called pre-fork while the guest vCPU is suspended (atomic, no race). This is
/// page-table/control state, never an alternate private guest-frame snapshot
/// authority.
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
fn clone_page_tables_for_child(
    src: *mut u8,
    size: usize,
) -> Result<crate::host_mapping::OwnedHostMapping, TrapError> {
    let dst = crate::host_mapping::OwnedHostMapping::map_shared_anon(
        size,
        crate::host_mapping::HostMappingKind::PerMmKernelState,
    )
    .map_err(|error| {
        TrapError::Hypervisor(format!(
            "fork child-snapshot mmap (size={size}) failed: {error}"
        ))
    })?;
    let dst_ptr = dst.as_ptr();
    unsafe { std::ptr::copy_nonoverlapping(src, dst_ptr, size) };
    Ok(dst)
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
fn prepare_exec_region_raw(mapping: &GuestMapping) -> Result<HvfMappedRegion, TrapError> {
    let requested_size = usize::try_from(mapping.mapped_size)
        .map_err(|_| TrapError::MappingTooLarge(mapping.mapped_size))?;
    let backing_started = std::time::Instant::now();
    let (host, size, host_mapping) = map_exclusive_region(mapping, requested_size)?;
    let elapsed_ns = backing_started
        .elapsed()
        .as_nanos()
        .min(u128::from(u64::MAX)) as u64;
    crate::probes::hvpatch_exec_backing(carrick_observability::probes::HvpatchExecBacking::new(
        if mapping.private_file_backing.is_some() {
            carrick_observability::probes::HvpatchExecBackingPhase::PrivateFileMapped
        } else {
            carrick_observability::probes::HvpatchExecBackingPhase::Materialized
        },
        mapping.guest_start,
        mapping.ipa_start,
        mapping.mapped_size,
        elapsed_ns,
    ));
    let end =
        mapping
            .guest_start
            .checked_add(mapping.mapped_size)
            .ok_or(TrapError::MappingOverflow {
                guest_start: mapping.guest_start,
                mapped_size: mapping.mapped_size,
            })?;
    Ok(HvfMappedRegion {
        start: mapping.guest_start,
        ipa: mapping.ipa_start,
        physical_ipa: mapping.ipa_start,
        end,
        host_addr: host,
        size,
        physical_size: size,
        perms: hvf_perms(mapping.perms),
        memory: None,
        host_mapping: Some(host_mapping),
        stage2_lease: None,
        is_dynamic_alias: false,
        sharing: if mapping.shared {
            GuestMappingSharing::GlobalShared
        } else {
            GuestMappingSharing::Private
        },
        guest_writable: mapping.perms.write,
        shared_key_base: 0,
        shared_key_offset: 0,
        owner_generation: global_frame_host_owner_generation(mapping.ipa_start, size as u64),
    })
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
fn exec_stage2_install(mapping: &GuestMapping, region: &HvfMappedRegion) -> ExecStage2Install {
    ExecStage2Install {
        ipa: mapping.ipa_start,
        size: region.physical_size,
        host: region.host_addr,
        perms: u64::from(region.perms),
        replay_registered: false,
    }
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
fn map_region_raw(
    mapping: &GuestMapping,
    emit_exec_backing_census: bool,
) -> Result<HvfMappedRegion, TrapError> {
    let size = usize::try_from(mapping.mapped_size)
        .map_err(|_| TrapError::MappingTooLarge(mapping.mapped_size))?;
    // MAP_SHARED, not MAP_PRIVATE: a MAP_PRIVATE anon page mapped into the
    // guest via hv_vm_map desyncs from the host buffer — the guest's own store
    // and a later guest load observe different memory (the "PROT_REA" wild-PC
    // crash: a dynamic binary's GOT slot that ld.so resolved reads back stale).
    // MAP_SHARED anon is HVF-coherent (same as `map_shared_file`). The cost:
    // fork(2) no longer COW-isolates these pages. HVPatch isolates them with
    // per-mm stage-1 COW; the legacy VMM fork path separately clones only its
    // page-table/control backing (`clone_page_tables_for_child`).
    // The aperture region is host-MAP_SHARED so it stays shared across fork(2)
    // (never snapshotted); all other regions are private guest RAM.
    let backing_started = std::time::Instant::now();
    let (host, size, host_mapping) = map_exclusive_region(mapping, size)?;
    if emit_exec_backing_census {
        let elapsed_ns = backing_started
            .elapsed()
            .as_nanos()
            .min(u128::from(u64::MAX)) as u64;
        crate::probes::hvpatch_exec_backing(
            carrick_observability::probes::HvpatchExecBacking::new(
                if mapping.private_file_backing.is_some() {
                    carrick_observability::probes::HvpatchExecBackingPhase::PrivateFileMapped
                } else {
                    carrick_observability::probes::HvpatchExecBackingPhase::Materialized
                },
                mapping.guest_start,
                mapping.ipa_start,
                mapping.mapped_size,
                elapsed_ns,
            ),
        );
    }
    let perms = hvf_perms(mapping.perms);
    let perms_raw: u64 = u64::from(perms);
    // Map at the IPA (identity for all but the Rosetta alias); the guest's
    // stage-1 page tables translate the VIRTUAL `guest_start` to this IPA.
    if emit_exec_backing_census {
        crate::probes::hvpatch_exec_stage2(carrick_observability::probes::HvpatchExecStage2::new(
            carrick_observability::probes::HvpatchExecStage2Phase::MapBegin,
            mapping.ipa_start,
            size as u64,
            mapping.guest_start,
            0,
        ));
    }
    let r = unsafe {
        inventory_hv_vm_map(
            host.cast::<std::ffi::c_void>(),
            mapping.ipa_start,
            size,
            perms_raw,
        )
    };
    if emit_exec_backing_census {
        crate::probes::hvpatch_exec_stage2(carrick_observability::probes::HvpatchExecStage2::new(
            carrick_observability::probes::HvpatchExecStage2Phase::MapEnd,
            mapping.ipa_start,
            size as u64,
            mapping.guest_start,
            r as i32,
        ));
    }
    if r != 0 {
        return Err(TrapError::Hypervisor(format!(
            "hv_vm_map(ipa=0x{:x}, va=0x{:x}, size={size}) failed: 0x{r:x}",
            mapping.ipa_start, mapping.guest_start
        )));
    }
    let end =
        mapping
            .guest_start
            .checked_add(mapping.mapped_size)
            .ok_or(TrapError::MappingOverflow {
                guest_start: mapping.guest_start,
                mapped_size: mapping.mapped_size,
            })?;
    let sharing = if mapping.shared {
        GuestMappingSharing::GlobalShared
    } else {
        GuestMappingSharing::Private
    };
    Ok(HvfMappedRegion {
        start: mapping.guest_start,
        ipa: mapping.ipa_start,
        physical_ipa: mapping.ipa_start,
        end,
        host_addr: host,
        size,
        physical_size: size,
        perms,
        memory: None,
        host_mapping: Some(host_mapping),
        stage2_lease: None,
        is_dynamic_alias: false,
        // Private guest RAM (data/bss/heap/stack/MAP_PRIVATE): HVPatch fork
        // shares the global frame read-only until the writer COWs it.
        sharing,
        // Boot regions carry their true guest write-intent (image=RX, page
        // tables=RO -> not writable; heap/stack/data=RW -> writable).
        guest_writable: mapping.perms.write,
        shared_key_base: 0,
        shared_key_offset: 0,
        owner_generation: global_frame_host_owner_generation(mapping.ipa_start, size as u64),
    })
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
fn map_exclusive_region(
    mapping: &GuestMapping,
    size: usize,
) -> Result<(*mut u8, usize, crate::host_mapping::OwnedHostMapping), TrapError> {
    if let Some(backing) = &mapping.private_file_backing {
        let host_mapping = crate::host_mapping::OwnedHostMapping::map_private_file(
            backing.file.as_raw_fd(),
            0,
            size,
        )
        .map_err(|error| {
            TrapError::Hypervisor(format!(
                "mmap private executable artifact (size={size}) failed: {error}"
            ))
        })?;
        return Ok((host_mapping.as_ptr(), host_mapping.len(), host_mapping));
    }
    let kind = if mapping.shared {
        crate::host_mapping::HostMappingKind::SharedAnon
    } else {
        crate::host_mapping::HostMappingKind::PrivateAnon
    };
    let host_mapping =
        crate::host_mapping::OwnedHostMapping::map_shared_anon(size, kind).map_err(|error| {
            TrapError::Hypervisor(format!("mmap guest region (size={size}) failed: {error}"))
        })?;
    let host = host_mapping.as_ptr();
    let size = host_mapping.len();
    // Copy the payload prefix into the freshly-zeroed region; the rest stays
    // zero (lazy). offset_in_mapping + image.len() <= mapped_size is guaranteed
    // by GuestMappingPlan::from_address_space.
    if !mapping.image.is_empty() {
        let off = usize::try_from(mapping.offset_in_mapping)
            .map_err(|_| TrapError::MappingTooLarge(mapping.offset_in_mapping))?;
        unsafe {
            std::ptr::copy_nonoverlapping(
                mapping.image.as_ptr(),
                host.add(off),
                mapping.image.len(),
            );
        }
    }
    Ok((host, size, host_mapping))
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
fn hvf_perms(perms: SegmentPerms) -> applevisor::memory::MemPerms {
    use applevisor::memory::MemPerms;

    // HVF stage-2 quirk on macOS 26 (Tahoe) / Apple Silicon: a stage-2
    // mapping created with `HV_MEMORY_READ | HV_MEMORY_WRITE` (no
    // `HV_MEMORY_EXEC`) fails to translate EL0 data accesses — the guest
    // takes a stage-2 translation fault (DFSC=0x05, "translation fault
    // level 1") even though the IPA falls inside the mapping and the
    // host-side `Memory::read`/`Memory::write` accessors succeed. The
    // ARM stage-2 attribute model has no per-EL data-access bit, so the
    // fault is HVF-specific behaviour rather than ARMv8 architectural.
    //
    // Empirically, escalating the stage-2 permission to
    // `ReadWriteExec` makes the fault go away. The guest still uses
    // stage-1 (`SCTLR_EL1.M=0` in the bootstrap), so the stage-2 X bit
    // is the only thing that controls instruction fetch from the
    // region; the guest is already executing without stage-1 enforcement
    // and the host process is single-tenant, so granting stage-2 X on
    // data/stack regions does not add a meaningful new attack surface.
    //
    // The escalation is gated on the original perms still being some
    // form of `Write` so we don't accidentally upgrade a `Read`-only or
    // `Exec`-only mapping: those translate fine as-is. This keeps the
    // workaround narrow.
    let escalated_perms = SegmentPerms {
        read: perms.read,
        write: perms.write,
        execute: perms.execute || perms.write,
    };

    match (
        escalated_perms.read,
        escalated_perms.write,
        escalated_perms.execute,
    ) {
        (false, false, false) => MemPerms::None,
        (true, false, false) => MemPerms::Read,
        (false, true, false) => MemPerms::Write,
        (false, false, true) => MemPerms::Exec,
        (true, true, false) => MemPerms::ReadWrite,
        (true, false, true) => MemPerms::ReadExec,
        (false, true, true) => MemPerms::WriteExec,
        (true, true, true) => MemPerms::ReadWriteExec,
    }
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
fn hvf_error(error: applevisor::error::HypervisorError) -> TrapError {
    TrapError::Hypervisor(error.to_string())
}

/// Convert a neutral [`carrick_hal::MemPerms`] to the applevisor stage-2
/// `MemPerms` for [`HvfVmState::map_stage2`]. A DIRECT mapping (no RWX
/// escalation): that escalation is the `hvf_perms(SegmentPerms)` boot/alias path;
/// the engine's `map_stage2` callers pass the perms they want verbatim.
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
fn hvf_mem_perms(perms: carrick_hal::MemPerms) -> applevisor::memory::MemPerms {
    use applevisor::memory::MemPerms;
    match (perms.read, perms.write, perms.exec) {
        (false, false, false) => MemPerms::None,
        (true, false, false) => MemPerms::Read,
        (false, true, false) => MemPerms::Write,
        (false, false, true) => MemPerms::Exec,
        (true, true, false) => MemPerms::ReadWrite,
        (true, false, true) => MemPerms::ReadExec,
        (false, true, true) => MemPerms::WriteExec,
        (true, true, true) => MemPerms::ReadWriteExec,
    }
}

/// The HVF concurrent-vCPU budget for the bounded M:N scheduler the engine
/// installs via `GuestVmBackend::vcpu_budget`: physical host cores, capped by
/// HVF's usable per-VM vCPU ceiling. Reclaim recycles vCPUs so >budget guest
/// threads run instead of hanging. macOS/HVF-only: `vcpu_gate` (and the whole HVF
/// backend) is cfg'd out off the HVF lane, and the only caller (the new module's
/// `GuestVmBackend::vcpu_budget`) is macOS-only too.
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
pub(crate) fn hvf_vcpu_budget() -> usize {
    vcpu_gate::budget().max(1)
}

// NOTE: the thread-sibling register seeding (`seed_child_snapshot`) now lives
// ONCE in the shared engine (`carrick_aarch64::seed_sibling_snapshot`), which the
// engine's `build_sibling_spec` applies before `materialize_sibling`. HVF's
// `from_thread_spec` only stands up the vCPU + mirrors the mapping metadata; the
// engine restores the seeded snapshot onto it.

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
#[cfg(test)]
mod vm_create_admission_tests {
    use super::*;

    #[test]
    fn resource_growing_vm_creation_uses_global_permit() {
        assert!(VmCreateAdmission::Initial.global_permit_budget().is_some());
        assert!(
            VmCreateAdmission::ForkRebuild { vfork: false }
                .global_permit_budget()
                .is_some(),
            "plain fork rebuilds create another live one-vCPU VM in the fork tree"
        );
        assert!(
            VmCreateAdmission::ForkRebuild { vfork: true }
                .global_permit_budget()
                .is_none(),
            "vfork parents wait in the fork handler, so the child rebuild must not \
             compete with the parent for the same global permit"
        );
        assert!(
            VmCreateAdmission::ExecveRebuild
                .global_permit_budget()
                .is_none()
        );
        assert!(
            VmCreateAdmission::SharedWaitResume
                .global_permit_budget()
                .is_some()
        );
    }

    #[test]
    fn global_permit_budget_depends_on_admission_kind() {
        // Every gated class is now bounded by the measured system-wide vCPU
        // ceiling (GLOBAL_VCPU_CEILING), NOT the per-VM hv_vm_get_max_vcpu_count
        // the old cap of 12 was clamped from. The true hard limit is discovered
        // at runtime via HV_NO_RESOURCES park+retry, not this soft pre-throttle.
        let ceiling = Some(VmCreateAdmission::GLOBAL_VCPU_CEILING);
        assert_eq!(VmCreateAdmission::Initial.global_permit_budget(), ceiling);
        assert_eq!(
            VmCreateAdmission::ForkRebuild { vfork: false }.global_permit_budget(),
            ceiling,
            "plain fork rebuilds are gated by the same creation ceiling"
        );
        assert_eq!(
            VmCreateAdmission::SharedWaitResume.global_permit_budget(),
            ceiling,
            "shared-wait resume drains parked processes through the creation ceiling"
        );
        // vfork parents wait in the fork handler and execve rebuilds must make
        // progress, so both bypass the global creation permit entirely.
        assert_eq!(
            VmCreateAdmission::ForkRebuild { vfork: true }.global_permit_budget(),
            None
        );
        assert_eq!(
            VmCreateAdmission::ExecveRebuild.global_permit_budget(),
            None
        );
        // The ceiling is the measured margin under the ~126 real host limit, well
        // above the old cap of 12 that starved dozens-of-processes suites.
        assert_eq!(VmCreateAdmission::GLOBAL_VCPU_CEILING, 120);
    }

    #[test]
    fn permit_table_is_the_arena_permit_section() {
        assert_eq!(
            std::mem::size_of::<SharedPermitTable>(),
            std::mem::size_of::<carrick_kernel::arena::PermitSection>()
        );
        assert_eq!(
            std::mem::offset_of!(SharedPermitTable, slots),
            std::mem::offset_of!(carrick_kernel::arena::PermitSection, slots)
        );

        let arena = carrick_kernel::arena::KernelArena::global();
        let section = &arena.layout().permits as *const _ as usize;
        assert_eq!(permit_region().table_addr_for_test(), section);
    }

    #[test]
    fn vm_residency_region_is_the_arena_vm_slots_section() {
        let arena = carrick_kernel::arena::KernelArena::global();
        assert_eq!(
            vm_residency_region().table_addr_for_test(),
            &arena.layout().vm_slots as *const _ as usize,
        );
        // Independent of the permit table.
        assert_ne!(
            vm_residency_region().table_addr_for_test(),
            permit_region().table_addr_for_test(),
        );
    }

    #[test]
    fn vm_residency_record_release_roundtrip_on_test_region() {
        let region = PermitRegion::new_anon_for_test();
        let pid = std::process::id();
        let token = region
            .acquire(atomic_permit_slot::MAX_SLOTS, pid)
            .expect("record acquires unconditionally under MAX_SLOTS");
        region.register(VM_RESIDENCY_LOCAL_KEY, token);
        assert_eq!(region.occupied(), 1);
        region.release_token(VM_RESIDENCY_LOCAL_KEY);
        assert_eq!(region.occupied(), 0);
        // Idempotent: a second release is a no-op.
        region.release_token(VM_RESIDENCY_LOCAL_KEY);
        assert_eq!(region.occupied(), 0);
    }

    #[test]
    fn dual_reclaim_source_merges_and_reclaims_both_tables() {
        use crate::vcpu_permit_reaper::PermitReclaimSource;
        let a = Box::leak(Box::new(PermitRegion::new_anon_for_test()));
        let b = Box::leak(Box::new(PermitRegion::new_anon_for_test()));
        // `force_owner_for_test` overwrites only the pid on an ALREADY-acquired
        // slot (preserving its real Acquiring state and generation) — so a real
        // slot must be acquired first for the slot to count as occupied.
        let token_a = a
            .acquire(atomic_permit_slot::MAX_SLOTS, std::process::id())
            .unwrap();
        let token_b = b
            .acquire(atomic_permit_slot::MAX_SLOTS, std::process::id())
            .unwrap();
        a.force_owner_for_test(token_a.slot, 4242, token_a.generation);
        b.force_owner_for_test(token_b.slot, 4242, token_b.generation);
        let (gen_a, gen_b) = (token_a.generation, token_b.generation);
        let dual = DualReclaimSource(a, b);
        let owners = dual.owner_slots();
        assert!(owners.contains(&(4242, gen_a)));
        assert!(owners.contains(&(4242, gen_b)));
        assert_eq!(dual.reclaim(4242, gen_a) + dual.reclaim(4242, gen_b), 2);
    }

    // ---- Part B: HV_NO_RESOURCES park+retry backpressure ----
    // The live fork-storm never reaches the ~126 hard ceiling under the 120 soft
    // budget, so these drive the bounded retry loop directly (millisecond timings)
    // to prove: transient HV_NO_RESOURCES recovers, a genuinely-full host bounds
    // out and propagates, and a non-NoResources error is never parked on.
    use applevisor::error::HypervisorError;
    use std::cell::Cell;
    use std::time::Duration;

    #[test]
    fn no_resources_backpressure_recovers_after_transient() {
        // NoResources for the first two attempts, then success — the loop must
        // park+retry through them and return Ok, not propagate.
        let calls = Cell::new(0u32);
        let out: Result<u64, TrapError> = create_with_no_resources_backpressure_bounded(
            "test",
            Duration::from_millis(1),
            Duration::from_secs(5),
            || {
                let n = calls.get();
                calls.set(n + 1);
                if n < 2 {
                    Err(HypervisorError::NoResources)
                } else {
                    Ok(42)
                }
            },
        );
        assert_eq!(out.ok(), Some(42), "transient NoResources must recover");
        assert_eq!(calls.get(), 3, "expected two retries then success");
    }

    #[test]
    fn no_resources_backpressure_bounds_out_when_host_is_full() {
        // Always NoResources: the loop must give up after ~max_wait and propagate
        // the error (never hang forever). A tiny max_wait keeps the test fast.
        let calls = Cell::new(0u32);
        let start = std::time::Instant::now();
        let out: Result<u64, TrapError> = create_with_no_resources_backpressure_bounded(
            "test",
            Duration::from_millis(1),
            Duration::from_millis(20),
            || {
                calls.set(calls.get() + 1);
                Err(HypervisorError::NoResources)
            },
        );
        assert!(
            out.is_err(),
            "a genuinely-full host must propagate the error"
        );
        assert!(
            start.elapsed() < Duration::from_secs(2),
            "bounded wait must not hang"
        );
        assert!(
            calls.get() >= 2,
            "expected at least one park+retry before giving up"
        );
    }

    #[test]
    fn no_resources_backpressure_never_parks_on_other_errors() {
        // A non-NoResources error is propagated immediately, with no retry.
        let calls = Cell::new(0u32);
        let out: Result<u64, TrapError> = create_with_no_resources_backpressure_bounded(
            "test",
            Duration::from_secs(30),
            Duration::from_secs(30),
            || {
                calls.set(calls.get() + 1);
                Err(HypervisorError::Busy)
            },
        );
        assert!(out.is_err());
        assert_eq!(
            calls.get(),
            1,
            "a non-NoResources error must not be retried"
        );
    }

    #[test]
    fn global_permit_retries_back_off_to_cap() {
        let mut backoff = GlobalVcpuPermitBackoff::default();
        let delays: Vec<_> = (0..8).map(|_| backoff.next_delay()).collect();

        assert_eq!(
            delays,
            [
                std::time::Duration::from_millis(1),
                std::time::Duration::from_millis(2),
                std::time::Duration::from_millis(4),
                std::time::Duration::from_millis(8),
                std::time::Duration::from_millis(16),
                std::time::Duration::from_millis(32),
                std::time::Duration::from_millis(50),
                std::time::Duration::from_millis(50),
            ]
        );
    }

    #[test]
    fn mn_budget_uses_physical_cores_but_never_exceeds_hvf_cap() {
        // The hypervisor ceiling is the budget; the host's core count is not a
        // correctness bound on how many guest threads may be admitted.
        assert_eq!(vcpu_gate::budget_from_limits(60, 10), 60);
        assert_eq!(vcpu_gate::budget_from_limits(6, 10), 6);
        assert_eq!(vcpu_gate::budget_from_limits(60, 0), 60);
        assert_eq!(vcpu_gate::budget_from_limits(0, 10), 1);
    }

    // ---- Atomic permit slot-table state machine (Option 3, Task 1) ----------
    //
    // These prove the load-bearing invariant the 3b bare-counter attempt lost:
    // ownership is the source of truth, so a crash between acquire and
    // vcpu_create is reclaimable and no sibling teardown or stale event can
    // free a live owner's slot.

    #[test]
    fn acquire_cannot_leave_an_unowned_count() {
        let r = PermitRegion::new_anon_for_test();
        let t = r.acquire(4, std::process::id()).unwrap(); // slot published owned BEFORE any count-only state
        assert_eq!(r.occupied(), 1);
        assert_eq!(r.slot_state(t.slot), SlotState::Acquiring); // owner+gen visible even pre-register
        // a crash here is reclaimable: reap by owner finds the acquiring slot
        r.force_owner_for_test(t.slot, 999_999_999, t.generation);
        assert_eq!(r.reclaim_owner(999_999_999, None), 1);
        assert_eq!(r.occupied(), 0);
    }

    #[test]
    fn vcpu_destroyed_of_unregistered_vcpu_does_not_release_a_permit() {
        let r = PermitRegion::new_anon_for_test();
        let t = r.acquire(4, std::process::id()).unwrap();
        r.register(100, t); // vcpu 100 holds the permit
        r.release_token(999); // an UNPERMITTED sibling vcpu teardown
        assert_eq!(r.occupied(), 1); // must NOT free vcpu 100's permit
        r.release_token(100);
        assert_eq!(r.occupied(), 0);
    }

    #[test]
    fn release_is_generation_checked() {
        let r = PermitRegion::new_anon_for_test();
        let t = r.acquire(4, std::process::id()).unwrap();
        r.register(1, t);
        let stale = PermitToken {
            generation: t.generation.wrapping_sub(1),
            ..t
        };
        assert!(!r.try_free_exact_for_test(stale)); // a stale token/event cannot free a newer owner
        assert_eq!(r.occupied(), 1);
    }

    #[test]
    fn fork_child_reset_clears_local_only() {
        let r = PermitRegion::new_anon_for_test();
        let t = r.acquire(4, std::process::id()).unwrap();
        r.register(1, t);
        r.reset_local_after_fork_child(); // child clears local map
        assert!(r.local_token(1).is_none());
        assert_eq!(r.occupied(), 1); // parent's shared slot untouched
    }

    // ---- Task 3: cooperative release before a fork-child `_exit` ------------
    //
    // `process_exit_cleanup` runs on the exiting child's own thread BEFORE
    // `_exit` skips Rust drops. It drains THIS process's local token map,
    // freeing each named slot with the generation-guarded `free_exact`, so it
    // is idempotent with `vcpu_destroyed` (which may have released already) and
    // the supervisor's later `reclaim_owner`, and it never frees the parent's
    // slots (its local map, after the fork reset, names only this process).

    #[test]
    fn cooperative_release_frees_owned_slots_and_is_idempotent() {
        let r = PermitRegion::new_anon_for_test();
        let pid = std::process::id();
        let t1 = r.acquire(4, pid).unwrap();
        r.register(1, t1);
        let t2 = r.acquire(4, pid).unwrap();
        r.register(2, t2);
        assert_eq!(r.occupied(), 2);

        // The fork-child `_exit` fast path frees both registered slots at once.
        assert_eq!(r.cooperative_release_local(), 2);
        assert_eq!(r.occupied(), 0);
        assert!(r.local_token(1).is_none());
        assert!(r.local_token(2).is_none());

        // Idempotent: a second call (or a late supervisor reclaim) frees nothing.
        assert_eq!(r.cooperative_release_local(), 0);
        assert_eq!(r.occupied(), 0);
    }

    #[test]
    fn cooperative_release_is_idempotent_with_vcpu_destroyed() {
        let r = PermitRegion::new_anon_for_test();
        let pid = std::process::id();
        let t1 = r.acquire(4, pid).unwrap();
        r.register(10, t1);
        let t2 = r.acquire(4, pid).unwrap();
        r.register(20, t2);
        // A normal `vcpu_destroyed` already released one token (removed it from
        // the local map AND freed its slot) before the process exits.
        r.release_token(10);
        assert_eq!(r.occupied(), 1);
        // Cooperative exit frees only the STILL-owned remaining slot; no double-free.
        assert_eq!(r.cooperative_release_local(), 1);
        assert_eq!(r.occupied(), 0);
    }

    #[test]
    fn cooperative_release_no_ops_after_supervisor_reclaim() {
        let r = PermitRegion::new_anon_for_test();
        let pid = std::process::id();
        let t = r.acquire(4, pid).unwrap();
        r.register(1, t);
        // The supervisor won the race and already reclaimed the slot by (pid, gen).
        assert_eq!(r.reclaim_owner(pid, Some(t.generation)), 1);
        assert_eq!(r.occupied(), 0);
        // The local map still names the (now-free) slot, but the generation guard
        // in `free_exact` makes the cooperative release a no-op — no double-free.
        assert_eq!(r.cooperative_release_local(), 0);
        assert_eq!(r.occupied(), 0);
    }

    #[test]
    fn cooperative_release_after_fork_reset_spares_parent_slots() {
        let r = PermitRegion::new_anon_for_test();
        let pid = std::process::id();
        let t = r.acquire(4, pid).unwrap();
        r.register(1, t);
        // Simulate the fork child: the inherited local map is cleared before the
        // child re-acquires its own permits. The parent's shared slot stays owned.
        r.reset_local_after_fork_child();
        // The child's cooperative `_exit` must NOT free the parent's shared slot:
        // its (now-empty) local map names none of the parent's tokens.
        assert_eq!(r.cooperative_release_local(), 0);
        assert_eq!(r.occupied(), 1);
    }

    #[test]
    fn atomic_permit_enabled_from_env_defaults_to_atomic() {
        // The flip: atomic admission is the DEFAULT admission path.
        // Unset → enabled.
        assert!(atomic_permit_enabled_from_env(None));
        // `=1` → enabled (the historical explicit-on still works).
        assert!(atomic_permit_enabled_from_env(Some("1")));
        // Explicit falsey tokens → disabled = the flock fallback.
        assert!(!atomic_permit_enabled_from_env(Some("0")));
        assert!(!atomic_permit_enabled_from_env(Some("false")));
        assert!(!atomic_permit_enabled_from_env(Some("no")));
        // Case-insensitive, tolerant of surrounding whitespace.
        assert!(!atomic_permit_enabled_from_env(Some("FALSE")));
        assert!(!atomic_permit_enabled_from_env(Some(" 0 ")));
        // Any other value falls through to the default (enabled).
        assert!(atomic_permit_enabled_from_env(Some("yes")));
        assert!(atomic_permit_enabled_from_env(Some("")));
    }

    #[test]
    fn cooperative_release_atomic_permit_is_noop_on_flock_path() {
        // `CARRICK_HVF_ATOMIC_PERMIT=0` selects the legacy flock fallback...
        assert!(!atomic_permit_enabled_from_env(Some("0")));
        // ...on which `cooperative_release_atomic_permit` early-returns 0 without
        // touching the region (the permit is fd-lifetime-bound). Mirror that
        // "frees nothing" result against a fresh region: with no owned local
        // slots the cooperative release frees zero and leaves the table empty.
        // (Testing the parse gate here rather than the process-global
        // `atomic_permit_enabled()` cache, which is now DEFAULT-on and cannot be
        // toggled per-test without the edition-2024-unsafe `set_var`.)
        let r = PermitRegion::new_anon_for_test();
        assert_eq!(r.cooperative_release_local(), 0);
        assert_eq!(r.occupied(), 0);
    }

    // ---- Task 4: execve rebuild releases the pre-exec token, no double-free -
    //
    // `execve_rebuild` destroys the inherited pre-exec vCPU with a raw
    // `hv_vcpu_destroy` and calls `vcpu_destroyed(inherited_vcpu_id)` BEFORE
    // creating the replacement VM/vCPU under `VmCreateAdmission::ExecveRebuild`
    // (`global_permit_budget_depends_on_admission_kind` above proves that
    // admission class's budget is `None`, so the replacement acquires no
    // permit at all). After Task 1's tokenization this is ALREADY correct: the
    // pre-exec `vcpu_id` was registered when its process/thread was admitted
    // (`Initial`/`ForkRebuild{vfork:false}`/`SharedWaitResume` all have `Some`
    // budgets), so `vcpu_destroyed`'s `release_token(vcpu_id)` finds it in the
    // local map and frees exactly that slot — no leak, and nothing left for an
    // extra explicit release to double-free. These tests drive that exact
    // sequence against a private `PermitRegion` (they never call
    // `atomic_permit_enabled()` or the real dispatch functions, so they are
    // insulated from the process-global gate — now DEFAULT-on) to PROVE the
    // premise instead of merely asserting it.

    #[test]
    fn execve_rebuild_releases_pre_exec_permit_and_acquires_nothing_new() {
        let r = PermitRegion::new_anon_for_test();
        let pid = std::process::id();

        // Pre-exec admission (e.g. `VmCreateAdmission::Initial`, budget
        // `Some(_)`): `create_vcpu_with_permit` registers the token against
        // the vCPU it just created.
        let pre_exec_vcpu_id = 42u64;
        let budget = VmCreateAdmission::Initial
            .global_permit_budget()
            .expect("Initial admission is budgeted");
        let t = r.acquire(budget, pid).unwrap();
        r.register(pre_exec_vcpu_id, t);
        assert_eq!(r.occupied(), 1);

        // execve_rebuild: hv_vcpu_destroy(inherited_vcpu_id) succeeds, so
        // vcpu_destroyed(inherited_vcpu_id) runs, which dispatches to
        // release_token(pre_exec_vcpu_id) on the atomic path.
        r.release_token(pre_exec_vcpu_id);
        assert_eq!(
            r.occupied(),
            0,
            "the pre-exec permit must already be released by the ordinary \
             vcpu_destroyed path, before the ungated replacement is created"
        );

        // create_vm_with_admission(ExecveRebuild) acquires NOTHING (budget
        // None), so create_vcpu_with_permit registers no token for the
        // replacement vCPU — even if HVF hands back the same numeric id.
        assert_eq!(
            VmCreateAdmission::ExecveRebuild.global_permit_budget(),
            None
        );
        let post_exec_vcpu_id = pre_exec_vcpu_id;
        assert!(r.local_token(post_exec_vcpu_id).is_none());
        assert_eq!(
            r.occupied(),
            0,
            "exec must not leave the table over baseline"
        );

        // A later vcpu_destroyed on the post-exec vCPU (e.g. eventual process
        // exit) must be a safe no-op: it never registered a token.
        r.release_token(post_exec_vcpu_id);
        assert_eq!(r.occupied(), 0);
    }

    #[test]
    fn execve_rebuild_extra_release_would_be_a_harmless_but_pointless_noop() {
        // Guards the "do NOT add an explicit release" half of the premise: an
        // EXTRA release bolted onto execve_rebuild alongside the existing
        // vcpu_destroyed call would target a slot vcpu_destroyed already
        // freed. release_token is token-guarded (the local map entry is gone
        // after the first call), so a redundant second call on the SAME
        // vcpu_id is a no-op, not a double-free — but it also proves such an
        // addition does nothing useful, i.e. it is dead weight at best. This
        // locks in that no-op behavior so nobody "fixes" the proof-passing
        // case with an unnecessary release.
        let r = PermitRegion::new_anon_for_test();
        let pid = std::process::id();
        let t = r.acquire(4, pid).unwrap();
        r.register(7, t);

        r.release_token(7); // the real vcpu_destroyed(inherited_vcpu_id) release
        assert_eq!(r.occupied(), 0);

        r.release_token(7); // a hypothetical redundant "exec path" release
        assert_eq!(
            r.occupied(),
            0,
            "a redundant release on an already-released vcpu_id must stay a no-op"
        );
    }

    #[test]
    fn region_address_is_inherited_across_fork() {
        let _fork_serial = crate::fork_test_lock();
        // The MAP_ANON|MAP_SHARED region must live at the same address in a fork
        // child AND expose the same physical slot table, so a child's acquire is
        // visible to the parent. This is the property flock got from the kernel.
        let r = PermitRegion::new_anon_for_test();
        let parent_addr = r.table_addr_for_test();
        assert_eq!(r.occupied(), 0);
        // SAFETY: the child does only async-signal-safe atomic work on the shared
        // region (no allocation, no locks) before `_exit`, so the multithreaded
        // test harness fork is safe here.
        match unsafe { libc::fork() } {
            -1 => panic!("fork failed"),
            0 => {
                let addr_ok = r.table_addr_for_test() == parent_addr;
                let acquired = r.acquire(4, std::process::id()).is_some();
                unsafe { libc::_exit(if addr_ok && acquired { 0 } else { 1 }) };
            }
            pid => {
                let mut status: libc::c_int = 0;
                let rc = unsafe { libc::waitpid(pid, &mut status, 0) };
                assert_eq!(rc, pid);
                assert!(
                    libc::WIFEXITED(status) && libc::WEXITSTATUS(status) == 0,
                    "child saw a different region address or could not acquire"
                );
                // The child's acquire on the SHARED table is visible in the parent.
                assert_eq!(r.occupied(), 1);
            }
        }
    }

    /// Regression smoke test for the store-buffering over-admit race: with
    /// `AcqRel`/`Acquire` (no total store order), two threads claiming
    /// DIFFERENT slots could each fail to see the other's just-published claim
    /// when checking `occupied()` against `budget`, so both would keep their
    /// claim and the number of SIMULTANEOUSLY-held permits could exceed
    /// `budget` (e.g. 5 outstanding vs a cap of 4). `SeqCst` on the claim CAS
    /// and the `occupied()` loads forbids that outcome.
    ///
    /// NOTE: a memory-ordering bug is not guaranteed to reproduce
    /// deterministically (it depends on the host's actual store-buffering
    /// behavior and scheduling), so this test's value is as a regression
    /// tripwire, not a proof the ordering is correct.
    #[test]
    fn concurrent_acquire_never_over_admits_past_budget() {
        use std::sync::Arc;
        use std::sync::atomic::{AtomicUsize, Ordering};

        let region = Arc::new(PermitRegion::new_anon_for_test());
        let budget = 4usize;
        let held = Arc::new(AtomicUsize::new(0));
        let max_held = Arc::new(AtomicUsize::new(0));
        let iterations = 5_000;

        let handles: Vec<_> = (0..8)
            .map(|_| {
                let region = Arc::clone(&region);
                let held = Arc::clone(&held);
                let max_held = Arc::clone(&max_held);
                std::thread::spawn(move || {
                    let pid = std::process::id();
                    for _ in 0..iterations {
                        if let Some(token) = region.acquire(budget, pid) {
                            let now = held.fetch_add(1, Ordering::SeqCst) + 1;
                            max_held.fetch_max(now, Ordering::SeqCst);
                            // Widen the race window before releasing.
                            std::thread::yield_now();
                            held.fetch_sub(1, Ordering::SeqCst);
                            region.release_unregistered(token);
                        }
                    }
                })
            })
            .collect();

        for h in handles {
            h.join().unwrap();
        }

        let observed = max_held.load(Ordering::SeqCst);
        assert!(
            observed <= budget,
            "observed {observed} concurrently-held permits with budget {budget} \
             — over-admission past the budget cap (store-buffering regression)"
        );
    }

    #[test]
    fn fork_vm_probe_bounds_out_when_residency_is_pinned_and_admits_after_release() {
        let region = PermitRegion::new_anon_for_test();
        let budget = 4;
        let mut tokens = Vec::new();
        for i in 0..budget {
            let t = region
                .acquire(budget, 1000 + i as u32)
                .expect("under budget");
            region.register(i as u64, t);
            tokens.push(t);
        }
        // Pinned at budget: the probe must bound out quickly (test-scale wait).
        let err = probe_vm_slot_budget(&region, budget, std::time::Duration::from_millis(50));
        assert!(matches!(err, Err(TrapError::HostResourceExhausted { .. })));
        // One release frees a hard slot: the probe admits again.
        region.release_token(0);
        assert!(
            probe_vm_slot_budget(&region, budget, std::time::Duration::from_millis(50)).is_ok()
        );
        drop(tokens);
    }
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
#[cfg(test)]
mod frame_inventory_backend_tests {
    use super::*;

    fn exec_mapping_for_order(guest_start: u64, mapped_size: u64) -> GuestMapping {
        GuestMapping {
            guest_start,
            ipa_start: guest_start,
            mapped_size,
            offset_in_mapping: 0,
            payload_size: 0,
            perms: carrick_mem::elf::SegmentPerms::default(),
            shared: false,
            image: std::sync::Arc::new(Vec::new()),
            private_file_backing: None,
        }
    }

    fn id(raw: u64) -> std::num::NonZeroU64 {
        std::num::NonZeroU64::new(raw).unwrap()
    }

    fn empty_inventory_reservation(raw: u64) -> carrick_hal::FrameInventoryReservation {
        let transaction = carrick_hal::KernelTransactionId::from_kernel_allocation(id(raw));
        let capacity = carrick_hal::FrameEventCapacity::for_event_count(1).unwrap();
        carrick_hal::FrameInventoryReservation::from_kernel_candidates(
            carrick_hal::FrameInventoryProvenance::from_kernel_entropy([raw as u8; 32]),
            carrick_hal::FrameInventoryBatch::prepare(transaction, capacity).unwrap(),
            Vec::new(),
            Vec::new(),
        )
    }

    fn inventory_pair(
        raw: u64,
    ) -> (
        carrick_hal::FrameInventoryReservation,
        carrick_hal::FrameInventoryReservation,
    ) {
        (
            empty_inventory_reservation(raw),
            empty_inventory_reservation(raw + 1),
        )
    }

    #[test]
    fn cancelled_process_inventory_does_not_poison_the_next_fork() {
        let ledger = std::sync::Arc::new(parking_lot::Mutex::new(HvpatchFrameInventory::default()));
        let mut state = HvpatchFrameInventoryState::new(std::sync::Arc::clone(&ledger));

        state
            .begin_process_inventory(empty_inventory_reservation(91))
            .expect("first reservation");
        assert!(state.cancel_process_inventory());
        state
            .begin_process_inventory(empty_inventory_reservation(92))
            .expect("retry after an EFAULT/build/spawn failure");
        assert!(state.cancel_process_inventory());
        assert!(ledger.lock().process_reservation.is_none());
    }

    /// A guest `mmap` whose alias install fails used to `abort()` the carrier —
    /// killing every Linux process multiplexed into it — precisely because the
    /// reservation `begin_alias_inventory` armed had nowhere to go: returning
    /// ENOMEM instead would have left it armed and wedged the NEXT guest mmap
    /// with "overlapping HVPatch alias inventory transaction". Prove the
    /// rollback seam actually clears the staging, from BOTH states a failure can
    /// leave: the untouched reservation (`add_alias_with_sharing` returned
    /// early) and the staged commit (stage-1 `map_aliased` failed after stage-2
    /// succeeded).
    #[test]
    fn abandoned_alias_inventory_does_not_poison_the_next_guest_mmap() {
        let ledger = std::sync::Arc::new(parking_lot::Mutex::new(HvpatchFrameInventory::default()));
        let mut state = HvpatchFrameInventoryState::new(std::sync::Arc::clone(&ledger));

        // Failure BEFORE the backend consumed the reservation.
        state
            .begin_alias_inventory(empty_inventory_reservation(81))
            .expect("first alias reservation");
        // Red without the seam: a second arm is refused while staging is live.
        state
            .begin_alias_inventory(empty_inventory_reservation(82))
            .expect_err("overlapping alias inventory must be refused");
        assert!(state.cancel_alias_inventory());
        assert!(ledger.lock().alias_reservation.is_none());
        state
            .begin_alias_inventory(empty_inventory_reservation(83))
            .expect("the mmap after a failed alias install must still arm");

        // Failure AFTER the backend staged its commit (stage-1 unwind path).
        {
            let mut inventory = ledger.lock();
            let reservation = inventory
                .alias_reservation
                .take()
                .expect("armed reservation");
            inventory.alias_commit = Some(reservation.commit(()));
        }
        state
            .begin_alias_inventory(empty_inventory_reservation(84))
            .expect_err("a staged commit must also block a second arm");
        assert!(state.cancel_alias_inventory());
        assert!(ledger.lock().alias_commit.is_none());
        state
            .begin_alias_inventory(empty_inventory_reservation(85))
            .expect("the mmap after a failed stage-1 publication must still arm");
        assert!(state.cancel_alias_inventory());
        assert!(!state.cancel_alias_inventory());
    }

    #[test]
    fn parent_arm_rollback_restores_preexisting_overlapping_ranges_exactly() {
        let broad = carrick_aarch64::vmm::ForkCowRange {
            va: 0x4000_0000,
            len: 0x20_000,
            executable: false,
            kernel_only: false,
        };
        let exact = carrick_aarch64::vmm::ForkCowRange {
            va: 0x4000_8000,
            len: 0x4000,
            executable: false,
            kernel_only: false,
        };
        let mut armed = CowArmedRanges::default();
        armed.arm(&[broad]);
        let before = armed.snapshot();

        armed.arm(&[exact]);
        armed.disarm_ranges(&[exact]);
        assert_ne!(
            armed.ranges, before,
            "the old range-subtraction rollback is lossy"
        );

        armed.restore(before.clone());
        assert_eq!(armed.ranges, before);
    }

    #[test]
    fn global_frame_allocator_reuses_only_released_exact_extents() {
        let mut allocator = GlobalFrameIpaAllocator::new();
        let first = allocator.allocate(0x4000, 0x4000).unwrap();
        let second = allocator.allocate(0x4000, 0x4000).unwrap();
        assert_ne!(first, second, "live frame IPAs must remain globally unique");

        allocator.release(first, 0x4000).unwrap();
        assert_eq!(
            allocator.allocate(0x4000, 0x4000).unwrap(),
            first,
            "an IPA becomes reusable only after its exact frame extent retires"
        );
    }

    #[test]
    fn global_frame_allocator_coalesces_adjacent_retired_extents() {
        let mut allocator = GlobalFrameIpaAllocator::new();
        let first = allocator.allocate(0x4000, 0x4000).unwrap();
        let second = allocator.allocate(0x4000, 0x4000).unwrap();
        allocator.release(second, 0x4000).unwrap();
        allocator.release(first, 0x4000).unwrap();

        assert_eq!(
            allocator.allocate(0x8000, 0x4000).unwrap(),
            first,
            "adjacent retired global IPA extents must form reusable capacity"
        );
    }

    #[test]
    fn global_frame_allocator_rejects_duplicate_or_partial_release() {
        let mut allocator = GlobalFrameIpaAllocator::new();
        let frame = allocator.allocate(0x8000, 0x4000).unwrap();
        assert!(allocator.release(frame, 0).is_err());
        assert!(
            allocator
                .release(
                    carrick_mem::memory::LINUX_HVPATCH_GLOBAL_FRAME_BASE - 0x4000,
                    0x4000,
                )
                .is_err()
        );
        assert!(
            allocator
                .release(
                    carrick_mem::memory::LINUX_HVPATCH_GLOBAL_FRAME_BASE
                        + carrick_mem::memory::LINUX_HVPATCH_GLOBAL_FRAME_SIZE,
                    0x4000,
                )
                .is_err()
        );
        assert!(allocator.release(frame, 0x4000).is_err());
        allocator.release(frame, 0x8000).unwrap();
        assert!(allocator.release(frame, 0x8000).is_err());
    }

    #[test]
    fn global_frame_allocator_honors_large_frame_alignment() {
        const TWO_MIB: u64 = 2 * 1024 * 1024;
        let mut allocator = GlobalFrameIpaAllocator::new();
        let _prefix = allocator.allocate(0x4000, 0x4000).unwrap();
        let large = allocator.allocate(TWO_MIB, TWO_MIB).unwrap();
        assert_eq!(large % TWO_MIB, 0);
    }

    #[test]
    fn global_frame_allocator_rejects_invalid_allocation_arithmetic() {
        let mut allocator = GlobalFrameIpaAllocator::new();
        assert!(allocator.allocate(0x4000, 0).is_err());
        assert!(allocator.allocate(u64::MAX, 0x4000).is_err());
        assert!(
            allocator
                .release(
                    carrick_mem::memory::LINUX_HVPATCH_GLOBAL_FRAME_BASE,
                    u64::MAX,
                )
                .is_err()
        );
    }

    #[test]
    fn fixed_identity_stage2_retirement_does_not_release_global_allocator() {
        assert!(release_retired_stage2_ipa(0x1_0000_0000, 0x70_0000).is_ok());
    }

    #[test]
    fn global_frame_allocator_preserves_large_hole_for_large_request() {
        const LARGE: u64 = 32 * 1024 * 1024 * 1024;
        const SMALL: u64 = 0x4000;
        let arena_base = carrick_mem::memory::LINUX_HVPATCH_GLOBAL_FRAME_BASE;
        let mut allocator = GlobalFrameIpaAllocator::new();
        allocator.next = arena_base + carrick_mem::memory::LINUX_HVPATCH_GLOBAL_FRAME_SIZE;
        allocator.free = vec![(arena_base, LARGE), (arena_base + LARGE + SMALL, SMALL)];

        assert_eq!(
            allocator.allocate(SMALL, SMALL).unwrap(),
            arena_base + LARGE + SMALL,
            "a tiny mapping must consume the smallest fitting hole"
        );
        assert_eq!(
            allocator.allocate(LARGE, 2 * 1024 * 1024).unwrap(),
            arena_base,
            "small mappings must not fragment the scarce 32 GiB exec-frame holes"
        );
    }

    #[test]
    fn global_frame_exec_omits_sparse_mmap_arena_and_reserves_large_extents_first() {
        let mappings = vec![
            exec_mapping_for_order(0x10_0000, 0x4000),
            exec_mapping_for_order(crate::memory::LINUX_PAGE_TABLES_BASE, 0x20_0000),
            exec_mapping_for_order(
                crate::memory::LINUX_MMAP_BASE,
                crate::memory::mmap_arena_size(),
            ),
            exec_mapping_for_order(0x0090_0000_0000, 2 * 1024 * 1024 * 1024),
        ];

        assert_eq!(
            global_frame_exec_lease_order(&mappings, 1),
            vec![1, 3, 0],
            "the hidden semantic mmap arena must consume no exec frame; backed extents remain size-ordered"
        );
    }

    fn root_exec_test_plan() -> GuestMappingPlan {
        let mut data = exec_mapping_for_order(0x20_0000, 0x20_000);
        data.perms = carrick_mem::elf::SegmentPerms {
            read: true,
            write: true,
            execute: false,
        };
        let mut page_tables = exec_mapping_for_order(
            crate::memory::LINUX_PAGE_TABLES_BASE,
            crate::memory::LINUX_PAGE_TABLES_SIZE,
        );
        page_tables.image = std::sync::Arc::new(carrick_mem::memory::stage1_hvpatch_page_tables());
        page_tables.payload_size = page_tables.image.len() as u64;
        let sparse = exec_mapping_for_order(
            crate::memory::LINUX_MMAP_BASE,
            crate::memory::mmap_arena_size(),
        );
        GuestMappingPlan {
            mappings: vec![data, page_tables, sparse],
            entry: 0x20_0000,
            initial_stack_pointer: None,
            el0_trampoline_entry: None,
            el1_vectors_base: None,
            stage1_page_tables_base: Some(crate::memory::LINUX_PAGE_TABLES_BASE),
            ro_spans: vec![carrick_mem::elf::RoSpan {
                start: 0x20_4000,
                len: 0x4000,
                exec: false,
            }],
        }
    }

    #[test]
    fn root_exec_plan_owns_every_materialized_stage2_extent() {
        let plan = root_exec_test_plan();
        let GlobalExecPlan {
            plan: rebuilt,
            mut stage2_leases,
        } = prepare_global_exec_plan(&plan, None).unwrap();
        for mapping in rebuilt
            .mappings
            .iter()
            .filter(|mapping| !is_sparse_hvpatch_mmap_mapping(mapping))
        {
            let key = (mapping.ipa_start, mapping.mapped_size);
            let lease = stage2_leases
                .remove(&key)
                .unwrap_or_else(|| panic!("root exec mapping {key:x?} lost its stage-2 lease"));
            assert_eq!(lease.key(), key);
            assert!(
                lease.release_ipa,
                "replacement root frames are allocator-owned"
            );
            assert_ne!(
                mapping.ipa_start, mapping.guest_start,
                "root exec must not collide with identity frames retained by a child"
            );
        }
        assert!(stage2_leases.is_empty());
    }

    #[test]
    fn consecutive_root_exec_plans_reserve_disjoint_frame_generations() {
        let plan = root_exec_test_plan();
        let first = prepare_global_exec_plan(&plan, None).unwrap();
        let second = prepare_global_exec_plan(&plan, None).unwrap();
        let first_keys = first.stage2_leases.keys().copied().collect::<Vec<_>>();
        let second_keys = second.stage2_leases.keys().copied().collect::<Vec<_>>();

        assert!(
            first_keys
                .iter()
                .all(|first| second_keys.iter().all(|second| first != second)),
            "a successor root image must not reuse a frame still retained by a child or predecessor"
        );
    }

    #[test]
    fn exec_replacement_preserves_canonical_scoped_asid_and_load_barrier_code() {
        let mut input = root_exec_test_plan();
        let mut maintenance = exec_mapping_for_order(
            carrick_mem::memory::LINUX_EL1_MAINT_BASE,
            carrick_mem::memory::LINUX_EL1_MAINT_SIZE,
        );
        maintenance.image = std::sync::Arc::new(carrick_mem::memory::el1_maintenance_bytes());
        maintenance.payload_size = maintenance.image.len() as u64;
        maintenance.perms = carrick_mem::elf::SegmentPerms {
            read: true,
            write: false,
            execute: true,
        };
        input.mappings.push(maintenance);

        let GlobalExecPlan { plan, .. } =
            prepare_global_exec_plan(&input, None).expect("global exec plan");
        let mapping = plan
            .mappings
            .iter()
            .find(|mapping| {
                mapping.guest_start <= carrick_mem::memory::LINUX_EL1_MAINT_BASE
                    && mapping.guest_start + mapping.mapped_size
                        >= carrick_mem::memory::LINUX_EL1_MAINT_BASE
                            + carrick_mem::memory::LINUX_EL1_MAINT_SIZE
            })
            .expect("exec kernel mapping contains maintenance image");
        let bytes_at = |address: u64, expected: Vec<u8>| {
            let offset = usize::try_from(address - mapping.guest_start).unwrap();
            assert_eq!(
                &mapping.image[offset..offset + expected.len()],
                expected.as_slice()
            );
        };
        bytes_at(
            carrick_mem::memory::LINUX_EL1_ASID_MAINT_BASE,
            carrick_mem::memory::el1_asid_maintenance_bytes(),
        );
        bytes_at(
            carrick_mem::memory::LINUX_EL1_LOAD_BARRIER_BASE,
            carrick_mem::memory::el1_load_barrier_bytes(),
        );
    }

    #[test]
    fn exec_reuses_carrier_control_stage2_without_allocating_task_leases() {
        let mut input = root_exec_test_plan();
        for (start, size) in [
            (
                crate::memory::LINUX_EL0_TRAMPOLINE_BASE,
                crate::memory::LINUX_EL0_TRAMPOLINE_SIZE,
            ),
            (
                crate::memory::LINUX_EL1_VECTORS_BASE,
                crate::memory::LINUX_EL1_VECTORS_SIZE,
            ),
            (
                crate::memory::LINUX_EL1_MAINT_BASE,
                crate::memory::LINUX_EL1_MAINT_SIZE,
            ),
            (
                crate::memory::LINUX_SYSCALL_MAILBOX_BASE,
                crate::memory::LINUX_SYSCALL_MAILBOX_ARENA_SIZE,
            ),
        ] {
            input.mappings.push(exec_mapping_for_order(start, size));
        }

        let GlobalExecPlan {
            plan,
            stage2_leases,
        } = prepare_global_exec_plan(&input, None).expect("global exec plan");
        for mapping in plan
            .mappings
            .iter()
            .filter(|mapping| is_persistent_executor_carrier_guest_mapping(mapping))
        {
            assert_eq!(mapping.ipa_start, mapping.guest_start);
            assert!(
                !stage2_leases.contains_key(&(mapping.ipa_start, mapping.mapped_size)),
                "exec must reuse carrier stage-2 rather than hand it to an MM retirement"
            );
        }
        assert_eq!(
            plan.mappings
                .iter()
                .filter(|mapping| is_persistent_executor_carrier_guest_mapping(mapping))
                .count(),
            4
        );
    }

    #[test]
    fn exec_predecessor_backing_stays_live_until_detached_cleanup() {
        let host = crate::host_mapping::OwnedHostMapping::map_shared_anon(
            0x4000,
            crate::host_mapping::HostMappingKind::PrivateAnon,
        )
        .unwrap();
        let host_addr = host.as_ptr();
        let observed = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let mut lease = GlobalFrameStage2Lease::fixed(0x1234_0000, 0x4000);
        lease.drop_backing_audit = Some((host_addr as usize, std::sync::Arc::clone(&observed)));
        let mut mapping =
            thread_sibling_tests::mapped_region(0x1234_0000, 0x1234_4000, 0x1234_0000);
        mapping.host_addr = host_addr;
        mapping.host_mapping = Some(host);
        mapping.stage2_lease = Some(lease);
        let mut task = hvpatch_task_state_test_fixture(7, 0x4000, 7);
        task.pending_exec_stage2_cleanup = Some(PendingExecStage2Cleanup {
            mappings: vec![mapping],
            extents: [(0x1234_0000, 0x4000)].into_iter().collect(),
            mm_root_slot: Some((7 << 20, 0x20_0000)),
            shared_projection: false,
            armed: true,
        });

        assert!(alias_backing_is_live(host_addr as usize));
        HvfVmState::retire_task_state_exec_predecessor(&mut task)
            .expect("post-TLBI detached cleanup");
        assert!(observed.load(std::sync::atomic::Ordering::SeqCst));
        assert!(!alias_backing_is_live(host_addr as usize));
        assert!(task.pending_exec_stage2_cleanup.is_none());
    }

    #[test]
    fn shared_process_exec_splits_inventory_without_retiring_parent_ledger() {
        let mut task = hvpatch_task_state_test_fixture(8, 0x8000, 8);
        task.shared_process_mm = true;
        let parent_ledger = task.frame_inventory.shared_ledger();
        parent_ledger.lock().initialized = true;
        let (_unused, replacement) = inventory_pair(11);

        task.begin_exec_inventory(None, replacement)
            .expect("arm shared-process exec inventory");

        let replacement_ledger = task.frame_inventory.shared_ledger();
        assert!(!std::sync::Arc::ptr_eq(&parent_ledger, &replacement_ledger));
        assert!(parent_ledger.lock().initialized);
        assert!(parent_ledger.lock().retired_reservation.is_none());
        let replacement = replacement_ledger.lock();
        // The replacement ledger is fresh, so a retirement armed against it
        // could only ever stage zero events. It must not be armed at all.
        assert!(replacement.retired_reservation.is_none());
        assert!(replacement.replacement_reservation.is_some());
    }

    /// The seam this pins: the runtime sizes the retirement transaction from
    /// the count the backend reports, then the backend rebases onto a fresh
    /// ledger and stages nothing into it. Reporting the old ledger's extents
    /// for a retained mm made those two disagree, and every vfork+execve died
    /// past its point of no return on the resulting zero-event commit.
    #[test]
    fn retained_old_mm_reports_no_exec_retirement_extents() {
        let mut task = hvpatch_task_state_test_fixture(9, 0x9000, 9);
        {
            let mut ledger = task.frame_inventory.lock();
            ledger.initialized = true;
            ledger.extents.insert(
                (0x9000_0000, 0x4000),
                InventoryExtent {
                    frame: carrick_hal::FrameId::from_kernel_allocation(id(41)),
                    mapping: carrick_hal::MappingId::from_kernel_allocation(id(42)),
                    backing: InventoryBackingIdentity::Private(9),
                    stage2_base: 0x9000_0000,
                    stage2_length: 0x4000,
                },
            );
        }

        assert!(task.exec_retires_old_mm());
        assert_eq!(task.exec_retired_extent_count(), 1);

        task.shared_process_mm = true;
        assert!(!task.exec_retires_old_mm());
        assert_eq!(task.exec_retired_extent_count(), 0);
    }

    #[test]
    fn exec_replacement_keeps_every_representative_leaf_asid_scoped() {
        const NON_GLOBAL: u64 = 1 << 11;
        let GlobalExecPlan { plan, .. } =
            prepare_global_exec_plan(&root_exec_test_plan(), None).expect("global exec plan");
        let tables = plan
            .mappings
            .iter()
            .find(|mapping| mapping.guest_start == carrick_mem::memory::LINUX_PAGE_TABLES_BASE)
            .expect("exec stage-1 table mapping");
        for (name, va) in [
            ("user text", 0x0040_0000),
            ("heap", carrick_mem::memory::LINUX_HEAP_BASE),
            ("mmap", carrick_mem::memory::LINUX_MMAP_BASE),
            (
                "shared aperture",
                carrick_mem::memory::LINUX_SHARED_FILE_BASE,
            ),
            ("stack", carrick_mem::memory::LINUX_STACK_TOP - 0x4000),
            ("EL1 maintenance", carrick_mem::memory::LINUX_EL1_MAINT_BASE),
            (
                "identity control",
                carrick_mem::memory::LINUX_IDENTITY_PAGE_BASE,
            ),
            (
                "syscall mailbox",
                carrick_mem::memory::LINUX_SYSCALL_MAILBOX_BASE,
            ),
            ("Rosetta alias", carrick_mem::memory::LINUX_ROSETTA_VA_BASE),
        ] {
            let leaf = carrick_mem::page_table::terminal_descriptor(
                carrick_mem::page_table::walk_descriptors(
                    tables.image.as_ref(),
                    tables.ipa_start,
                    va,
                ),
            );
            if name != "mmap" {
                assert_ne!(leaf & 0b11, 0, "{name} leaf at {va:#x} is not mapped");
            }
            assert_ne!(
                leaf & NON_GLOBAL,
                0,
                "post-exec {name} leaf at {va:#x} escaped ASID scope"
            );
        }
    }

    #[test]
    fn root_exec_plan_does_not_collide_with_a_live_child_generation() {
        let plan = root_exec_test_plan();
        let child = prepare_global_exec_plan(
            &plan,
            Some((crate::memory::LINUX_HVPATCH_ROOT_SLOT_BASE, 2 * 1024 * 1024)),
        )
        .unwrap();
        let root = prepare_global_exec_plan(&plan, None).unwrap();

        assert!(root.stage2_leases.keys().all(|root_key| {
            child
                .stage2_leases
                .keys()
                .all(|child_key| root_key != child_key)
        }));
    }

    fn exec_authority_fingerprint_fixture() -> ExecAuthorityFingerprint {
        let frame = carrick_hal::FrameId::from_kernel_allocation(id(201));
        let mapping = carrick_hal::MappingId::from_kernel_allocation(id(202));
        let lease = ExecLeaseFingerprint {
            base: 0x9000,
            length: 0x1000,
            mapped: true,
            active: true,
            release_ipa: true,
        };
        ExecAuthorityFingerprint {
            owners: vec![ExecOwnerFingerprint {
                key: (0x9000, 0x1000),
                host: 0x100_0000,
                host_len: 0x1000,
                perms: 7,
                lease,
            }],
            inventory_initialized: true,
            backend_extents: vec![ExecBackendExtentFingerprint {
                key: (0x9000, 0x1000),
                frame,
                mapping,
                backing: InventoryBackingIdentity::Private(1),
                stage2_base: 0x9000,
                stage2_length: 0x1000,
            }],
            frame_references: vec![(frame, 1)],
            extent_references: vec![((frame, 0x9000, 0x1000), 1)],
            stage2_references: vec![((0x9000, 0x1000), 1)],
            mappings: vec![ExecMappingFingerprint {
                start: 0x4000,
                ipa: 0x9000,
                physical_ipa: 0x9000,
                end: 0x5000,
                host: 0x100_0000,
                size: 0x1000,
                physical_size: 0x1000,
                perms: 7,
                has_memory: false,
                host_owner: None,
                stage2_lease: Some(lease),
                is_dynamic_alias: false,
                sharing: GuestMappingSharing::Private,
                guest_writable: true,
                shared_key_base: 0,
                shared_key_offset: 0,
            }],
            allocator: ExecAllocatorFingerprint {
                next: 0xa000,
                free: vec![(0xb000, 0x1000)],
                live: vec![(0x9000, 0x1000)],
            },
            replay_mappings: vec![(0x9000, 0x1000, 0x100_0000, 7)],
        }
    }

    #[test]
    fn exec_authority_rollback_rejects_drift_in_every_published_component() {
        let before = exec_authority_fingerprint_fixture();
        let assert_drift = |mut after: ExecAuthorityFingerprint,
                            mutate: fn(&mut ExecAuthorityFingerprint)| {
            mutate(&mut after);
            assert!(verify_exec_authority_rollback(&before, &after).is_err());
        };

        assert_drift(before.clone(), |after| after.owners[0].perms ^= 1);
        assert_drift(before.clone(), |after| after.inventory_initialized = false);
        assert_drift(before.clone(), |after| {
            after.backend_extents[0].stage2_base += 0x1000
        });
        assert_drift(before.clone(), |after| after.frame_references[0].1 += 1);
        assert_drift(before.clone(), |after| after.extent_references[0].1 += 1);
        assert_drift(before.clone(), |after| after.stage2_references[0].1 += 1);
        assert_drift(before.clone(), |after| {
            after.mappings[0].guest_writable = false
        });
        assert_drift(before.clone(), |after| after.allocator.next += 0x1000);
        assert_drift(before.clone(), |after| {
            after.allocator.free.push((0xc000, 0x1000))
        });
        assert_drift(before.clone(), |after| {
            after.allocator.live.push((0xd000, 0x1000))
        });
        assert_drift(before.clone(), |after| {
            after.replay_mappings.push((0xe000, 0x1000, 0x200_0000, 7))
        });
    }

    fn assert_exec_stage2_injected_failure_restores_old(fail_after_maps: usize) {
        let old = [
            ExecStage2Install::for_test(0x1000, 0x1000),
            ExecStage2Install::for_test(0x3000, 0x1000),
        ];
        let new = [
            ExecStage2Install::for_test(0x9000, 0x1000),
            ExecStage2Install::for_test(0xb000, 0x1000),
        ];
        let installed = std::cell::RefCell::new(
            old.iter()
                .map(ExecStage2Install::key)
                .collect::<std::collections::BTreeSet<_>>(),
        );
        let actions = std::cell::RefCell::new(Vec::new());

        let error = switch_exec_stage2_transaction(
            &old,
            &new,
            Some(fail_after_maps),
            |extent| {
                actions.borrow_mut().push(("unmap", extent.key()));
                if installed.borrow_mut().remove(&extent.key()) {
                    Ok(())
                } else {
                    Err(TrapError::Hypervisor(format!(
                        "unmap absent {:?}",
                        extent.key()
                    )))
                }
            },
            |extent| {
                actions.borrow_mut().push(("map", extent.key()));
                if installed.borrow_mut().insert(extent.key()) {
                    Ok(())
                } else {
                    Err(TrapError::Hypervisor(format!(
                        "map duplicate {:?}",
                        extent.key()
                    )))
                }
            },
        )
        .unwrap_err();

        assert!(
            error
                .to_string()
                .contains("injected HVPatch exec stage-2 map failure")
        );
        assert_eq!(
            *installed.borrow(),
            old.iter().map(ExecStage2Install::key).collect(),
            "an injected replacement failure must restore the exact predecessor stage-2 set"
        );
        let mut expected = old
            .iter()
            .map(|extent| ("unmap", extent.key()))
            .collect::<Vec<_>>();
        expected.extend(
            new[..fail_after_maps]
                .iter()
                .map(|extent| ("map", extent.key())),
        );
        expected.extend(
            new[..fail_after_maps]
                .iter()
                .rev()
                .map(|extent| ("unmap", extent.key())),
        );
        expected.extend(old.iter().map(|extent| ("map", extent.key())));
        assert_eq!(
            *actions.borrow(),
            expected,
            "rollback must remove every published successor in reverse order before restoring every predecessor"
        );
    }

    #[test]
    fn exec_stage2_failure_after_teardown_restores_predecessor_exactly() {
        assert_exec_stage2_injected_failure_restores_old(0);
    }

    #[test]
    fn exec_stage2_failure_after_one_map_removes_successor_and_restores_predecessor() {
        assert_exec_stage2_injected_failure_restores_old(1);
    }

    #[test]
    fn exec_stage2_rollback_restores_predecessor_replay_registration() {
        let mut predecessor = ExecStage2Install::for_test(0x1000, 0x1000);
        predecessor.replay_registered = true;
        let replacement = ExecStage2Install::for_test(0x9000, 0x1000);
        let installed =
            std::cell::RefCell::new(std::collections::BTreeSet::from([predecessor.key()]));
        let replay = std::cell::RefCell::new(std::collections::BTreeSet::from([predecessor
            .replay_key()
            .unwrap()]));

        let error = switch_exec_stage2_transaction(
            &[predecessor],
            &[replacement],
            Some(0),
            |extent| {
                installed.borrow_mut().remove(&extent.key());
                if let Some(key) = extent.replay_key() {
                    replay.borrow_mut().remove(&key);
                }
                Ok(())
            },
            |extent| {
                installed.borrow_mut().insert(extent.key());
                if let Some(key) = extent.replay_key() {
                    replay.borrow_mut().insert(key);
                }
                Ok(())
            },
        )
        .unwrap_err();

        assert!(
            error
                .to_string()
                .contains("injected HVPatch exec stage-2 map failure")
        );
        assert_eq!(
            *installed.borrow(),
            std::collections::BTreeSet::from([predecessor.key()])
        );
        assert_eq!(
            *replay.borrow(),
            std::collections::BTreeSet::from([predecessor.replay_key().unwrap()])
        );
    }

    #[test]
    fn root_exec_rebuilds_tables_with_sparse_and_hvpatch_reservations() {
        let plan = root_exec_test_plan();

        let GlobalExecPlan {
            plan: rebuilt,
            stage2_leases,
        } = prepare_global_exec_plan(&plan, None).unwrap();
        assert_eq!(
            rebuilt.stage1_page_tables_base,
            rebuilt
                .mappings
                .iter()
                .find(|mapping| mapping.guest_start == crate::memory::LINUX_PAGE_TABLES_BASE)
                .map(|mapping| mapping.ipa_start)
        );
        assert_eq!(stage2_leases.len(), 2, "the sparse arena owns no frame");
        let table = rebuilt
            .mappings
            .iter()
            .find(|mapping| mapping.guest_start == crate::memory::LINUX_PAGE_TABLES_BASE)
            .unwrap();
        let mut manager = crate::page_table::PageTableManager::new(
            table.image.as_ref().clone(),
            rebuilt.stage1_page_tables_base.unwrap(),
        );
        assert_eq!(
            manager.translate(0x20_0000),
            rebuilt
                .mappings
                .iter()
                .find(|mapping| mapping.guest_start == 0x20_0000)
                .map(|mapping| mapping.ipa_start)
        );
        assert_eq!(manager.translate(crate::memory::LINUX_MMAP_BASE), None);
        assert_eq!(
            manager.translate(crate::memory::LINUX_HVPATCH_ROOT_SLOT_BASE),
            None
        );
        assert!(
            !manager.set_readonly(0x20_4000, 0x4000, false).unwrap(),
            "root exec must preserve the ELF read-only span"
        );
    }

    #[test]
    fn sparse_exec_omission_requires_exact_private_hidden_arena() {
        let exact = exec_mapping_for_order(
            crate::memory::LINUX_MMAP_BASE,
            crate::memory::mmap_arena_size(),
        );
        assert!(is_sparse_hvpatch_mmap_mapping(&exact));

        let mut shared = exact.clone();
        shared.shared = true;
        assert!(!is_sparse_hvpatch_mmap_mapping(&shared));

        let shorter = exec_mapping_for_order(
            crate::memory::LINUX_MMAP_BASE,
            crate::memory::mmap_arena_size() - 0x4000,
        );
        assert!(!is_sparse_hvpatch_mmap_mapping(&shorter));

        let shifted = exec_mapping_for_order(
            crate::memory::LINUX_MMAP_BASE + 0x4000,
            crate::memory::mmap_arena_size(),
        );
        assert!(!is_sparse_hvpatch_mmap_mapping(&shifted));
    }

    #[test]
    fn reserved_global_stage2_lease_rolls_back_before_map() {
        let lease = GlobalFrameStage2Lease::reserve(0x4000, 0x4000).unwrap();
        let key = lease.key();
        assert_eq!(
            global_frame_ipa_allocator().lock().live.get(&key.0),
            Some(&key.1)
        );
        drop(lease);
        assert!(
            !global_frame_ipa_allocator()
                .lock()
                .live
                .contains_key(&key.0),
            "dropping a not-yet-mapped child/exec lease must return its IPA"
        );
    }

    #[test]
    fn mapped_host_address_is_not_proof_of_a_retired_global_owner() {
        const RETIRED_IPA: u64 = 0x7e00_0000_0000;
        const LIVE_IPA: u64 = RETIRED_IPA + 0x4000;
        const LENGTH: u64 = 0x4000;

        let host_mapping = crate::host_mapping::OwnedHostMapping::map_shared_anon(
            LENGTH as usize,
            crate::host_mapping::HostMappingKind::FrameCow,
        )
        .unwrap();
        let host_addr = host_mapping.as_ptr() as usize;
        let owner = GlobalFrameHostOwner {
            _mapping: host_mapping,
            // This test exercises owner identity without installing stage-2.
            _lease: GlobalFrameStage2Lease::fixed(LIVE_IPA, LENGTH),
            perms: u64::from(applevisor::memory::MemPerms::ReadWriteExec),
            generation: next_global_frame_owner_generation(),
        };
        assert!(
            global_frame_host_owners()
                .lock()
                .insert((LIVE_IPA, LENGTH), owner)
                .is_none()
        );

        assert!(
            alias_backing_is_live(host_addr),
            "the superseded mapped-address predicate must admit this live host VA"
        );
        let generation = global_frame_host_owner_generation(LIVE_IPA, LENGTH);
        assert_ne!(generation, 0, "a registered owner carries an incarnation");
        assert!(global_frame_host_owner_matches(
            LIVE_IPA, LENGTH, host_addr, generation
        ));
        assert!(
            !global_frame_host_owner_matches(RETIRED_IPA, LENGTH, host_addr, generation),
            "a live host VA owned by another IPA must not resurrect a retired lease"
        );

        let owner = global_frame_host_owners()
            .lock()
            .remove(&(LIVE_IPA, LENGTH))
            .unwrap();
        drop(owner);
        assert!(!global_frame_host_owner_matches(
            LIVE_IPA, LENGTH, host_addr, generation
        ));

        // The point of the incarnation: re-registering the SAME (ipa, length)
        // on the SAME recycled host VA must NOT re-authenticate the stale row.
        // Darwin hands that VA straight back — measured 499/499 — so without
        // this the row silently passes and the reuse scrub zeroes a live
        // granule.
        let remap = crate::host_mapping::OwnedHostMapping::map_shared_anon(
            LENGTH as usize,
            crate::host_mapping::HostMappingKind::FrameCow,
        )
        .unwrap();
        let reused_addr = remap.as_ptr() as usize;
        let successor = GlobalFrameHostOwner {
            _mapping: remap,
            _lease: GlobalFrameStage2Lease::fixed(LIVE_IPA, LENGTH),
            perms: u64::from(applevisor::memory::MemPerms::ReadWriteExec),
            generation: next_global_frame_owner_generation(),
        };
        let successor_generation = successor.generation;
        global_frame_host_owners()
            .lock()
            .insert((LIVE_IPA, LENGTH), successor);
        assert_ne!(successor_generation, generation);
        assert!(
            !global_frame_host_owner_matches(LIVE_IPA, LENGTH, reused_addr, generation),
            "a stale row must not authenticate against a NEW incarnation of the \
             same (ipa, length, host VA)"
        );
        assert!(
            global_frame_host_owner_matches(LIVE_IPA, LENGTH, reused_addr, successor_generation),
            "the successor's own rows still authenticate"
        );
        global_frame_host_owners()
            .lock()
            .remove(&(LIVE_IPA, LENGTH));
    }

    #[test]
    fn child_local_mapping_authenticates_through_its_own_raii_lease() {
        let ipa = carrick_mem::memory::LINUX_HVPATCH_GLOBAL_FRAME_BASE + 0x7f00_0000;
        let size = 0x4000usize;
        let host_mapping = crate::host_mapping::OwnedHostMapping::map_shared_anon(
            size,
            crate::host_mapping::HostMappingKind::PerMmKernelState,
        )
        .unwrap();
        let host_addr = host_mapping.as_ptr();
        let mut lease = GlobalFrameStage2Lease::fixed(ipa, size as u64);
        lease.mark_mapped();
        let mut mapping = HvfMappedRegion {
            start: 0x002d_0000_0000,
            end: 0x002d_0000_4000,
            ipa,
            physical_ipa: ipa,
            host_addr,
            size,
            physical_size: size,
            perms: applevisor::memory::MemPerms::ReadWriteExec,
            memory: None,
            host_mapping: Some(host_mapping),
            stage2_lease: Some(lease),
            is_dynamic_alias: false,
            sharing: GuestMappingSharing::Private,
            guest_writable: true,
            shared_key_base: 0,
            shared_key_offset: 0,
            owner_generation: 0,
        };

        assert!(global_frame_region_owner_matches(&mapping));

        // No stage-2 mapping was installed in this pure ownership test.
        mapping.stage2_lease.as_mut().unwrap().active = false;
    }

    #[test]
    fn lease_retirement_waits_for_the_last_global_stage2_reference() {
        let frame = carrick_hal::FrameId::from_kernel_allocation(id(31));
        let mut inventory = HvpatchFrameInventory::default();
        let lease = (0xa000_0000_0000, 0x8000);
        for (index, gpa) in [lease.0, lease.0 + 0x4000].into_iter().enumerate() {
            let mapping = carrick_hal::MappingId::from_kernel_allocation(id(32 + index as u64));
            inventory.extents.insert(
                (gpa, 0x4000),
                InventoryExtent {
                    frame,
                    mapping,
                    backing: InventoryBackingIdentity::Private(9),
                    stage2_base: lease.0,
                    stage2_length: lease.1,
                },
            );
        }
        {
            let mut registry = inventory.frames.lock();
            registry.references.insert(frame, 3);
            registry
                .extent_references
                .insert((frame, lease.0, 0x4000), 1);
            registry
                .extent_references
                .insert((frame, lease.0 + 0x4000, 0x4000), 1);
            registry.stage2_references.insert(lease, 3);
        }
        let leases = std::collections::BTreeSet::from([lease]);
        let authority_agrees = |_frame| Some(2usize);
        let shared =
            HvfVmState::inventory_lease_retirement_shape(&inventory, &leases, &authority_agrees)
                .unwrap();
        assert!(shared.frames.is_empty());
        assert!(shared.stage2_leases.is_empty());

        {
            let mut registry = inventory.frames.lock();
            registry.references.insert(frame, 2);
            registry.stage2_references.insert(lease, 2);
        }
        let final_owner =
            HvfVmState::inventory_lease_retirement_shape(&inventory, &leases, &authority_agrees)
                .unwrap();
        assert_eq!(
            final_owner.frames,
            std::collections::BTreeSet::from([frame])
        );
        assert_eq!(final_owner.stage2_leases, leases);
    }

    /// A frame this mm has finished with, which a SIBLING mm still maps.
    ///
    /// The per-mm populations say retire: this inventory holds the only extent
    /// naming the frame and the backend reference count it tracks falls to
    /// zero. The authority disagrees, because a forked sibling still has the
    /// frame mapped, and `RetireFrame` rejects any frame whose VM-wide mapping
    /// count is non-zero — which aborted the carrier
    /// (`FATAL: apply HVPatch alias retirement inventory: frame ... still has
    /// live mappings`, seen on `arm64:musl:recursionguard` under gate load).
    /// Retirement must defer to the authority's count.
    #[test]
    fn lease_retirement_defers_to_a_sibling_mm_still_mapping_the_frame() {
        let frame = carrick_hal::FrameId::from_kernel_allocation(id(71));
        let mapping = carrick_hal::MappingId::from_kernel_allocation(id(72));
        let lease = (0xb000_0000_0000, 0x4000);
        let mut inventory = HvpatchFrameInventory::default();
        inventory.extents.insert(
            (lease.0, 0x4000),
            InventoryExtent {
                frame,
                mapping,
                backing: InventoryBackingIdentity::Private(11),
                stage2_base: lease.0,
                stage2_length: lease.1,
            },
        );
        {
            let mut registry = inventory.frames.lock();
            registry.references.insert(frame, 1);
            registry
                .extent_references
                .insert((frame, lease.0, 0x4000), 1);
            registry.stage2_references.insert(lease, 1);
        }
        let leases = std::collections::BTreeSet::from([lease]);

        // Two mms map the frame; this transaction unmaps one of them.
        let sibling_still_maps = |_frame| Some(2usize);
        let shape =
            HvfVmState::inventory_lease_retirement_shape(&inventory, &leases, &sibling_still_maps)
                .unwrap();
        assert_eq!(shape.mappings.len(), 1, "the mapping is still unmapped");
        assert!(
            shape.frames.is_empty(),
            "a frame a sibling mm still maps must not be retired: {:?}",
            shape.frames
        );

        // Last mm out does retire it.
        let last_owner = |_frame| Some(1usize);
        let shape =
            HvfVmState::inventory_lease_retirement_shape(&inventory, &leases, &last_owner).unwrap();
        assert_eq!(shape.frames, std::collections::BTreeSet::from([frame]));
    }

    #[test]
    fn partial_semantic_cow_retains_the_old_physical_compound() {
        let old_frame = carrick_hal::FrameId::from_kernel_allocation(id(41));
        let old_mapping = carrick_hal::MappingId::from_kernel_allocation(id(42));
        let physical_ipa = carrick_mem::memory::LINUX_HVPATCH_GLOBAL_FRAME_BASE + 0x20_0000;
        let mut inventory = HvpatchFrameInventory::default();
        inventory.extents.insert(
            (physical_ipa, CowArmedRanges::COMPOUND_SIZE),
            InventoryExtent {
                frame: old_frame,
                mapping: old_mapping,
                backing: InventoryBackingIdentity::Private(1),
                stage2_base: physical_ipa,
                stage2_length: CowArmedRanges::COMPOUND_SIZE,
            },
        );
        {
            let mut frames = inventory.frames.lock();
            frames.references.insert(old_frame, 1);
            frames
                .extent_references
                .insert((old_frame, physical_ipa, CowArmedRanges::COMPOUND_SIZE), 1);
            frames
                .stage2_references
                .insert((physical_ipa, CowArmedRanges::COMPOUND_SIZE), 1);
        }

        let shape = HvfVmState::cow_inventory_split_shape(&inventory, physical_ipa, true)
            .expect("partial semantic COW split shape");

        assert_eq!(
            shape.fragments,
            vec![(physical_ipa, CowArmedRanges::COMPOUND_SIZE)],
            "a sibling leaf still naming the source frame keeps its exact physical compound live",
        );
        assert!(
            !shape.retire_old_frame,
            "the source frame cannot retire while this mm retains one of its sibling leaves",
        );
    }

    #[test]
    fn retained_sibling_detection_reads_exact_old_frame_leaves() {
        let va = 0x6000_004000;
        let physical_ipa = carrick_mem::memory::LINUX_HVPATCH_GLOBAL_FRAME_BASE + 0x24_0000;
        let one_page = CowArmedSpan {
            va: va + 0x1000,
            len: 0x1000,
            executable: false,
            kernel_only: false,
        };
        let old_ipa = physical_ipa + 0x1000;

        assert!(cow_source_has_retained_sibling(
            one_page,
            old_ipa,
            physical_ipa,
            |page_va| (page_va == va).then_some(physical_ipa),
        ));
        assert!(
            !cow_source_has_retained_sibling(one_page, old_ipa, physical_ipa, |page_va| (page_va
                == va + 0x1000)
                .then_some(old_ipa),),
            "the semantic pages repointed by this transaction are not retained siblings",
        );
        assert!(
            !cow_source_has_retained_sibling(one_page, old_ipa, physical_ipa, |page_va| (page_va
                == va)
                .then_some(physical_ipa + 0x8000),),
            "a sibling VA naming another physical frame cannot retain this source",
        );
    }

    #[test]
    fn begin_exec_injection_is_owned_and_consumed_by_only_the_armed_engine_state() {
        let ledger = std::sync::Arc::new(parking_lot::Mutex::new(HvpatchFrameInventory::default()));
        let mut engine_a = HvpatchFrameInventoryState::new(std::sync::Arc::clone(&ledger));
        let mut engine_b = HvpatchFrameInventoryState::new(std::sync::Arc::clone(&ledger));

        engine_a.inject_next_begin_exec_inventory_failure();

        let (b_retired, b_replacement) = inventory_pair(1);
        engine_b
            .begin_exec_inventory(Some(b_retired), b_replacement)
            .expect("unarmed engine B must not consume engine A's injection");
        {
            let mut ledger = ledger.lock();
            drop(ledger.retired_reservation.take());
            drop(ledger.replacement_reservation.take());
        }

        let (a_retired, a_replacement) = inventory_pair(3);
        let error = engine_a
            .begin_exec_inventory(Some(a_retired), a_replacement)
            .expect_err("armed engine A must receive its own injected error");
        assert!(
            error
                .to_string()
                .contains("injected HVPatch begin_exec_inventory failure")
        );

        let (retry_retired, retry_replacement) = inventory_pair(5);
        engine_a
            .begin_exec_inventory(Some(retry_retired), retry_replacement)
            .expect("engine A injection must be consumed exactly once");
    }

    #[test]
    fn exec_keeps_a_physical_extent_owned_by_another_mm() {
        let shared = carrick_hal::FrameId::from_kernel_allocation(id(1));
        let private = carrick_hal::FrameId::from_kernel_allocation(id(2));
        let mut inventory = HvpatchFrameInventory::default();
        inventory.extents.insert(
            (0x4000, 0x4000),
            InventoryExtent {
                frame: shared,
                mapping: carrick_hal::MappingId::from_kernel_allocation(id(3)),
                backing: InventoryBackingIdentity::SharedFile {
                    device: 1,
                    inode: 2,
                    offset: 0,
                    length: 0x4000,
                },
                stage2_base: 0x4000,
                stage2_length: 0x4000,
            },
        );
        inventory.extents.insert(
            (0x8000, 0x4000),
            InventoryExtent {
                frame: private,
                mapping: carrick_hal::MappingId::from_kernel_allocation(id(4)),
                backing: InventoryBackingIdentity::Private(1),
                stage2_base: 0x8000,
                stage2_length: 0x4000,
            },
        );
        {
            let mut frames = inventory.frames.lock();
            frames.references.insert(shared, 2);
            frames.references.insert(private, 1);
            frames.extent_references.insert((shared, 0x4000, 0x4000), 2);
            frames
                .extent_references
                .insert((private, 0x8000, 0x4000), 1);
            frames.stage2_references.insert((0x4000, 0x4000), 2);
            frames.stage2_references.insert((0x8000, 0x4000), 1);
        }

        let extents = final_exec_physical_extents(&inventory).unwrap();
        assert_eq!(
            extents,
            std::collections::BTreeSet::from([(0x8000, 0x4000)])
        );

        // The same shared frame may also be mapped at another IPA. Once this
        // exact IPA has no other owner it is independently removable even while
        // the frame itself remains live.
        inventory
            .frames
            .lock()
            .stage2_references
            .insert((0x4000, 0x4000), 1);
        let extents = final_exec_physical_extents(&inventory).unwrap();
        assert_eq!(
            extents,
            std::collections::BTreeSet::from([(0x4000, 0x4000), (0x8000, 0x4000)])
        );
    }

    #[test]
    fn fork_inherits_private_and_shared_frames_before_any_write() {
        let ipa = carrick_mem::memory::LINUX_HVPATCH_ROOT_SLOT_BASE + 0x20_0000;
        let size = 0x4000;
        let frame = carrick_hal::FrameId::from_kernel_allocation(id(11));
        let backing = InventoryBackingIdentity::SharedAnon(17);
        let extent = InventoryExtent {
            frame,
            mapping: carrick_hal::MappingId::from_kernel_allocation(id(12)),
            backing,
            stage2_base: ipa,
            stage2_length: size,
        };
        let parent_inventory = std::collections::BTreeMap::from([((ipa, size), extent)]);
        let mapping = |sharing| ThreadMappingDesc {
            start: 0x1382_8ed0_0000,
            ipa,
            end: 0x1382_8ed0_0000 + size,
            host_addr: 0x1000usize as *mut u8,
            size: size as usize,
            physical_ipa: ipa,
            physical_host_addr: 0x1000usize as *mut u8,
            physical_size: size as usize,
            perms: applevisor::memory::MemPerms::ReadWrite,
            is_dynamic_alias: true,
            sharing,
            guest_writable: true,
            shared_key_base: 0,
            shared_key_offset: 0,
        };

        let inherited = inherited_fork_inventory_extents(
            &mapping(GuestMappingSharing::ForkSharedAnonymous),
            &parent_inventory,
        )
        .pop()
        .expect("shared-anonymous mapping reuses the parent extent")
        .1;
        assert_eq!(inherited.frame, frame);
        assert_eq!(inherited.backing, backing);

        assert_eq!(
            fork_mapping_disposition(&mapping(GuestMappingSharing::Private), false),
            ForkMappingDisposition::SharedFrameReadOnly,
            "private fork mappings must not take an eager writable snapshot",
        );
        assert_eq!(
            fork_mapping_disposition(&mapping(GuestMappingSharing::Private), true),
            ForkMappingDisposition::SharedFrameWritable,
            "CLONE_VM must preserve the parent's writable user-frame identity",
        );
        let mut kernel_state = mapping(GuestMappingSharing::Private);
        kernel_state.start = crate::memory::LINUX_SYSCALL_MAILBOX_BASE;
        kernel_state.end = kernel_state.start + size;
        assert_ne!(
            fork_mapping_disposition(&kernel_state, true),
            ForkMappingDisposition::SharedFrameWritable,
            "CLONE_VM must still isolate per-process EL1 control state",
        );
        assert_ne!(
            fork_mapping_disposition(&kernel_state, false),
            ForkMappingDisposition::SharedFrameReadOnly,
            "EL1-only per-mm control state must not enter fault-driven guest COW",
        );
        let inherited_private = inherited_fork_inventory_extents(
            &mapping(GuestMappingSharing::Private),
            &parent_inventory,
        )
        .pop()
        .expect("private fork mapping must initially reuse the parent frame read-only")
        .1;
        assert_eq!(inherited_private.frame, frame);
        assert_eq!(inherited_private.backing, backing);
        assert_ne!(
            HvfVmState::shared_anon_backing_identity(),
            HvfVmState::shared_anon_backing_identity(),
            "independent shared-anonymous mappings must never deduplicate globally"
        );
    }

    #[test]
    fn cow_fault_classifier_accepts_only_el0_write_permission_aborts() {
        const DATA_ABORT_LOWER_EL: u64 = 0x24 << 26;
        const WRITE: u64 = 1 << 6;
        for permission_level in [0x0d_u64, 0x0e, 0x0f] {
            assert!(is_stage1_cow_write_fault(
                DATA_ABORT_LOWER_EL | WRITE | permission_level
            ));
        }
        assert!(!is_stage1_cow_write_fault(DATA_ABORT_LOWER_EL | 0x0f));
        assert!(!is_stage1_cow_write_fault(
            DATA_ABORT_LOWER_EL | WRITE | 0x07
        ));
        assert!(is_stage1_cow_write_fault((0x25 << 26) | WRITE | 0x0f));
        assert!(!is_stage1_cow_write_fault((0x21 << 26) | WRITE | 0x0f));
    }

    #[test]
    fn backing_maintenance_cow_bypasses_stale_unmapped_permission() {
        use carrick_aarch64::vmm::FrameCowWriteIntent;

        assert!(frame_cow_write_is_denied(
            true,
            FrameCowWriteIntent::GuestVisible,
        ));
        assert!(
            !frame_cow_write_is_denied(true, FrameCowWriteIntent::BackingMaintenance),
            "an internal zero scrub must split the frame before mmap publishes the new VMA permission",
        );
        assert!(
            !frame_cow_write_is_denied(true, FrameCowWriteIntent::PrivilegedInternal),
            "a Carrick-owned unchecked write must split without changing guest permissions",
        );
    }

    #[test]
    fn concurrent_cow_loser_retries_only_an_exact_live_writable_winner() {
        assert_eq!(
            unarmed_permission_fault_route(true, false, true, true),
            UnarmedPermissionFaultRoute::RetryCommittedWinner,
            "a sibling winner removes the arm before the losing vCPU resumes"
        );
        assert_eq!(
            unarmed_permission_fault_route(true, false, false, true),
            UnarmedPermissionFaultRoute::RetryCommittedWinner,
            "the last armed page may be removed by the winner before the loser resumes"
        );
        assert_eq!(
            unarmed_permission_fault_route(true, false, true, false),
            UnarmedPermissionFaultRoute::MissingArm,
            "a still-read-only private leaf without its arm is structural corruption"
        );
        assert_eq!(
            unarmed_permission_fault_route(true, true, true, false),
            UnarmedPermissionFaultRoute::NotCow,
            "mprotect-denied writes remain ordinary guest faults"
        );
        assert_eq!(
            unarmed_permission_fault_route(true, false, false, false),
            UnarmedPermissionFaultRoute::NotCow,
            "an address space with no fork arms is not routed into COW"
        );
    }

    #[test]
    fn retired_invalid_output_materializes_before_a_stale_cow_arm() {
        use carrick_aarch64::vmm::FrameCowWriteIntent;

        assert_eq!(
            frame_cow_write_route(FrameCowWriteIntent::BackingMaintenance, true, true, false),
            FrameCowWriteRoute::MaterializeRetired,
            "same-VA reuse must not COW an IPA after its exact stage-2 lease retired",
        );
        assert_eq!(
            frame_cow_write_route(FrameCowWriteIntent::BackingMaintenance, true, false, false),
            FrameCowWriteRoute::CopyOnWrite,
            "a still-live fork-shared physical source remains an ordinary COW",
        );
        assert_eq!(
            frame_cow_write_route(FrameCowWriteIntent::GuestVisible, true, true, false),
            FrameCowWriteRoute::CopyOnWrite,
            "guest faults never use the pre-publication backing-maintenance route",
        );
        // The corruption shape: an UNARMED maintenance write whose retained
        // output names a frame other mms still reference must materialize a
        // private replacement — never write Direct through the shared frame
        // (the CPython forkserver interned-dict zeroing).
        assert_eq!(
            frame_cow_write_route(FrameCowWriteIntent::BackingMaintenance, false, false, true),
            FrameCowWriteRoute::MaterializeRetired,
            "an unarmed maintenance write must not go direct through a shared frame",
        );
        assert_eq!(
            frame_cow_write_route(FrameCowWriteIntent::BackingMaintenance, false, false, false),
            FrameCowWriteRoute::Direct,
            "an unshared retained frame is this mm's own; direct scrub is correct",
        );

        let va = 0x0600_000a_9000;
        let mut armed = CowArmedRanges::default();
        armed.arm(&[carrick_aarch64::vmm::ForkCowRange {
            va,
            len: 0x5000,
            executable: true,
            kernel_only: false,
        }]);
        armed.disarm(CowArmedSpan {
            va,
            len: 0x3000,
            executable: false,
            kernel_only: false,
        });
        assert!(
            armed.span_for(va).is_none(),
            "fresh private leaves must not be forced back to RO by the retired frame's arm",
        );
        assert!(
            armed.span_for(va + 0x3000).is_some(),
            "materializing one compound fragment must preserve adjacent arms",
        );
    }

    #[test]
    fn cow_armed_ranges_split_one_compound_and_leave_peers_armed() {
        let base = 0x4000_0000;
        let mut armed = CowArmedRanges::default();
        armed.arm(&[carrick_aarch64::vmm::ForkCowRange {
            va: base,
            len: 4 * CowArmedRanges::COMPOUND_SIZE as usize,
            executable: false,
            kernel_only: false,
        }]);
        let writer = armed
            .span_for(base + CowArmedRanges::COMPOUND_SIZE + 8)
            .expect("second compound is armed");
        assert_eq!(writer.va, base + CowArmedRanges::COMPOUND_SIZE);
        assert_eq!(writer.len, CowArmedRanges::COMPOUND_SIZE as usize);
        armed.disarm(writer);
        assert!(armed.span_for(writer.va).is_none());
        assert!(armed.span_for(base).is_some());
        assert!(
            armed
                .span_for(base + 2 * CowArmedRanges::COMPOUND_SIZE)
                .is_some()
        );
    }

    #[test]
    fn cow_armed_ranges_disjoint_overlap_query_is_empty() {
        let base = 0x4000_0000;
        let mut armed = CowArmedRanges::default();
        armed.arm(&[carrick_aarch64::vmm::ForkCowRange {
            va: base,
            len: CowArmedRanges::COMPOUND_SIZE as usize,
            executable: false,
            kernel_only: false,
        }]);

        assert!(
            armed
                .overlapping(base + 2 * CowArmedRanges::COMPOUND_SIZE, 0x1000)
                .is_empty()
        );
    }

    #[test]
    fn cow_armed_ranges_prefer_exact_alias_fragment_over_broad_arena() {
        let arena = 0x0060_0000_0000;
        let alias = arena + 0xa8_000;
        let mut armed = CowArmedRanges::default();
        armed.arm(&[
            carrick_aarch64::vmm::ForkCowRange {
                va: arena,
                len: 0x8000_0000,
                executable: false,
                kernel_only: false,
            },
            carrick_aarch64::vmm::ForkCowRange {
                va: alias,
                len: 0x2000,
                executable: false,
                kernel_only: false,
            },
            carrick_aarch64::vmm::ForkCowRange {
                va: alias + 0x2000,
                len: 0x2000,
                executable: false,
                kernel_only: false,
            },
        ]);

        let span = armed
            .span_for(alias + 0x1000)
            .expect("exact alias fragment is armed");
        assert_eq!(
            span,
            CowArmedSpan {
                va: alias,
                len: 0x2000,
                executable: false,
                kernel_only: false,
            },
            "an adjacent frame at aa must not be repointed by the a8-aa COW"
        );
    }

    #[test]
    fn inherited_private_frame_skips_duplicate_stage2_install() {
        let inherited = carrick_hal::FrameId::from_kernel_allocation(id(99));
        assert!(!process_mapping_needs_stage2_install(Some(inherited)));
        assert!(process_mapping_needs_stage2_install(None));
    }

    #[test]
    fn fork_translation_accepts_winning_overlay_independent_of_descriptor_order() {
        let mapping = |ipa, host| ProcessMappingDesc {
            start: 0x4000_0000,
            ipa,
            end: 0x4000_4000,
            host: ForkMappingHost::Borrowed(host as *mut u8),
            size: 0x4000,
            physical_ipa: ipa,
            physical_host_addr: host as *mut u8,
            physical_size: 0x4000,
            inventory_backing: InventoryBackingIdentity::Private(ipa),
            perms: applevisor::memory::MemPerms::ReadWrite,
            is_dynamic_alias: true,
            sharing: GuestMappingSharing::Private,
            guest_writable: true,
            shared_key_base: 0,
            shared_key_offset: 0,
            inherited_frame: None,
            stage2_lease: None,
        };
        let winning_ipa = 0x9b00_028000;
        let stale_ipa = 0x9b00_008000;
        let mappings = vec![
            mapping(winning_ipa, 0x2000_0000),
            mapping(stale_ipa, 0x3000_0000),
        ];

        assert!(fork_translation_has_overlay_owner(
            &mappings,
            1,
            0x4000_0000,
            winning_ipa,
        ));
    }
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
#[cfg(test)]
mod alias_remap_limiter_tests {
    use super::*;

    #[test]
    fn exact_replay_marker_turns_a_sibling_race_into_success() {
        let backing = AliasBacking {
            start: 0x1000,
            ipa: crate::memory::LINUX_ALIAS_IPA_BASE + 0x7f00_0000,
            host_addr: 0x1234_0000,
            size: HVF_PAGE_SIZE as usize,
            physical_ipa: crate::memory::LINUX_ALIAS_IPA_BASE + 0x7f00_0000,
            physical_host_addr: 0x1234_0000,
            physical_size: HVF_PAGE_SIZE as usize,
            perms: u64::from(applevisor::memory::MemPerms::ReadWrite),
            guest_writable: true,
            sharing: GuestMappingSharing::Private,
            ownership_scope: AliasOwnershipScope::Root,
            inventory_backing: InventoryBackingIdentity::Private(1),
            shared_key_base: 0,
            shared_key_offset: 0,
            owner_generation: 0,
        };
        let key = replay_mapping_key(backing);
        replay_mappings().lock().insert(key);

        // The exact installed marker returns before touching Hypervisor.framework.
        let result = unsafe { inventory_hv_vm_map_replay(backing) };
        assert_eq!(result, 0);
        assert!(replay_mappings().lock().contains(&key));

        forget_replay_extent(backing.ipa, backing.size);
        assert!(!replay_mappings().lock().contains(&key));
    }

    #[test]
    fn caps_repeated_faults_on_one_alias_backing() {
        let mut limiter = AliasRemapLimiter::default();
        let ipa = crate::memory::LINUX_ALIAS_IPA_BASE + 0x20_0000;

        for _ in 0..AliasRemapLimiter::MAX_ATTEMPTS_PER_IPA {
            assert!(limiter.allow(ipa));
        }
        assert!(!limiter.allow(ipa));
    }

    #[test]
    fn alias_replacement_keeps_one_replay_identity_per_ipa() {
        let original = AliasBacking {
            start: 0x1000,
            ipa: crate::memory::LINUX_ALIAS_IPA_BASE + 0x7e00_0000,
            host_addr: 0x1234_0000,
            size: HVF_PAGE_SIZE as usize,
            physical_ipa: crate::memory::LINUX_ALIAS_IPA_BASE + 0x7e00_0000,
            physical_host_addr: 0x1234_0000,
            physical_size: HVF_PAGE_SIZE as usize,
            perms: u64::from(applevisor::memory::MemPerms::ReadWrite),
            guest_writable: true,
            sharing: GuestMappingSharing::Private,
            ownership_scope: AliasOwnershipScope::Root,
            inventory_backing: InventoryBackingIdentity::Private(2),
            shared_key_base: 0,
            shared_key_offset: 0,
            owner_generation: 0,
        };
        let replacement = AliasBacking {
            host_addr: 0x5678_0000,
            physical_host_addr: 0x5678_0000,
            ..original
        };
        register_shared_alias(original);
        register_shared_alias(replacement);

        let replay = replay_mappings().lock();
        assert!(!replay.contains(&replay_mapping_key(original)));
        assert!(replay.contains(&replay_mapping_key(replacement)));
        assert_eq!(
            replay
                .iter()
                .filter(|(ipa, _, _, _)| *ipa == original.ipa)
                .count(),
            1
        );
        drop(replay);
        forget_replay_extent(original.ipa, original.size);
        alias_registry()
            .lock()
            .retain(|alias| alias.ipa != original.ipa);
    }

    #[test]
    fn permits_many_distinct_alias_backings() {
        let mut limiter = AliasRemapLimiter::default();

        for i in 0..64 {
            let ipa = crate::memory::LINUX_ALIAS_IPA_BASE + i * 0x20_0000;
            assert!(
                limiter.allow(ipa),
                "alias backing {i} should not hit a global cap"
            );
        }
    }

    #[test]
    fn exhausted_alias_does_not_block_a_different_alias() {
        let mut limiter = AliasRemapLimiter::default();
        let first = crate::memory::LINUX_ALIAS_IPA_BASE;
        let second = first + 0x20_0000;

        for _ in 0..AliasRemapLimiter::MAX_ATTEMPTS_PER_IPA {
            assert!(limiter.allow(first));
        }

        assert!(!limiter.allow(first));
        assert!(limiter.allow(second));
        assert!(!limiter.allow(first));
    }
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
#[cfg(test)]
mod memory_protection_tests {
    use super::*;

    #[test]
    fn exec_level_classifies_el0_as_guest_el1_as_kernel() {
        // PSTATE M[3:0]: EL0t=0b0000, EL1t=0b0100, EL1h=0b0101.
        assert_eq!(ExecLevel::from_pstate(0b0000), ExecLevel::Guest);
        assert!(ExecLevel::from_pstate(0b0000).is_guest());
        // EL0t with DAIF/nzcv bits set high is still EL0 (only M[3:2] matter).
        assert_eq!(ExecLevel::from_pstate(0x6000_0000), ExecLevel::Guest);
        assert_eq!(ExecLevel::from_pstate(0b0100), ExecLevel::Kernel); // EL1t
        assert_eq!(ExecLevel::from_pstate(0b0101), ExecLevel::Kernel); // EL1h
        assert!(!ExecLevel::from_pstate(0b0101).is_guest());
    }

    #[test]
    fn cloned_protection_metadata_shares_updates_across_thread_engines() {
        let protections = std::sync::Arc::new(MemoryProtections::default());
        let sibling = std::sync::Arc::clone(&protections);

        protections.set_no_access(0x4000, 0x2000, true);
        assert!(sibling.range_no_access(0x4fff, 1));

        sibling.set_no_access(0x5000, 0x1000, false);
        assert!(protections.range_no_access(0x4000, 1));
        assert!(protections.range_no_access(0x4fff, 1));
        assert!(!protections.range_no_access(0x5000, 1));
        assert!(!protections.range_no_access(0x6000 - 1, 1));
    }

    #[test]
    fn protection_ranges_are_sorted_coalesced_and_split_on_clear() {
        let protections = MemoryProtections::default();

        protections.set_no_access(0x3000, 0x1000, true);
        protections.set_no_access(0x1000, 0x1000, true);
        protections.set_no_access(0x2000, 0x1000, true);

        assert_eq!(protections.snapshot(), vec![(0x1000, 0x4000)]);
        assert!(protections.range_no_access(0x1800, 1));
        assert!(protections.range_no_access(0x3fff, 1));
        assert!(!protections.range_no_access(0x4000, 1));

        protections.set_no_access(0x2000, 0x800, false);

        assert_eq!(
            protections.snapshot(),
            vec![(0x1000, 0x2000), (0x2800, 0x4000)]
        );
        assert!(!protections.range_no_access(0x2000, 0x800));
        assert!(protections.range_no_access(0x2800, 1));
    }
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
#[cfg(test)]
mod thread_sibling_tests {
    use super::*;

    // NOTE: the thread-sibling register SEEDING tests (child_resumes_at_post_
    // syscall_pc_with_x0_zero / child_uses_clone_stack_and_tls /
    // child_keeps_parent_tls_when_clone_tls_is_zero / child_copies_all_other_
    // gprs_and_sysregs) moved with `seed_child_snapshot` into the shared engine:
    // they live ONCE in `carrick_aarch64`'s `seed_applies_thread_entry_deltas`
    // (over the neutral `Aarch64VcpuSnapshot`). HVF no longer owns the seeding, so
    // it no longer owns those assertions.

    #[test]
    fn decodes_el0_counter_register_traps() {
        let cntfrq = (AARCH64_SYS64_EXCEPTION_CLASS << AARCH64_EXCEPTION_CLASS_SHIFT)
            | AARCH64_SYS64_ISS_SYS_CNTFRQ
            | (1 << AARCH64_SYS64_ISS_RT_SHIFT);
        let cntvct = (AARCH64_SYS64_EXCEPTION_CLASS << AARCH64_EXCEPTION_CLASS_SHIFT)
            | AARCH64_SYS64_ISS_SYS_CNTVCT
            | (2 << AARCH64_SYS64_ISS_RT_SHIFT);

        assert_eq!(
            decode_el0_sys64_read(cntfrq),
            Some((1, El0SysRegRead::CntfrqEl0))
        );
        assert_eq!(
            decode_el0_sys64_read(cntvct),
            Some((2, El0SysRegRead::CntvctEl0))
        );
        // CTR_EL0 / DCZID_EL0 — the cache-geometry reads glibc 2.41 does at
        // startup. The faulting `mrs x1, ctr_el0` observed from python:3.12-slim
        // was ESR_EL1=0x6232c021 (EC=0x18, Rt=1): decode it directly.
        assert_eq!(
            decode_el0_sys64_read(0x6232c021),
            Some((1, El0SysRegRead::CtrEl0))
        );
        let dczid = (AARCH64_SYS64_EXCEPTION_CLASS << AARCH64_EXCEPTION_CLASS_SHIFT)
            | AARCH64_SYS64_ISS_SYS_DCZID
            | (3 << AARCH64_SYS64_ISS_RT_SHIFT);
        assert_eq!(
            decode_el0_sys64_read(dczid),
            Some((3, El0SysRegRead::DczidEl0))
        );
        assert_eq!(decode_el0_sys64_read(0), None);
    }

    #[test]
    fn thread_mapping_descriptor_preserves_shared_mapping_metadata() {
        // `into_unowned_region` (the surviving half of the old `ThreadMappingDesc`
        // round-trip; `from_region` moved to the engine's sibling-builder seam)
        // must re-materialise the syscall-path metadata UNOWNED (memory/host_mapping
        // = None) so a sibling never frees the main engine's buffers.
        let desc = ThreadMappingDesc {
            start: 0x1000,
            ipa: 0x1000,
            end: 0x5000,
            host_addr: 0x7000usize as *mut u8,
            size: 0x4000,
            physical_ipa: 0x1000,
            physical_host_addr: 0x7000usize as *mut u8,
            physical_size: 0x4000,
            perms: applevisor::memory::MemPerms::ReadWrite,
            is_dynamic_alias: true,
            sharing: GuestMappingSharing::GlobalShared,
            guest_writable: true,
            shared_key_base: 0,
            shared_key_offset: 0,
        };

        let copied = desc.into_unowned_region();

        assert_eq!(copied.start, 0x1000);
        assert_eq!(copied.end, 0x5000);
        assert_eq!(copied.host_addr, 0x7000usize as *mut u8);
        assert_eq!(copied.size, 0x4000);
        assert_eq!(copied.perms, applevisor::memory::MemPerms::ReadWrite);
        assert!(copied.memory.is_none());
        assert!(copied.host_mapping.is_none());
        assert_eq!(copied.sharing, GuestMappingSharing::GlobalShared);
    }

    #[test]
    fn global_frame_futex_resolves_raw_backing_ipa_not_semantic_va() {
        // Global-frame HVPatch deliberately has start != ipa. The neutral
        // AArch64 engine passes the translated backing GPA to the VMM seam, so
        // subtracting the semantic VA selects no word (and routes a shared
        // anonymous futex through the process-private table after fork).
        let view = MappingView {
            start: 0x0090_0000_0000,
            end: 0x0090_0000_4000,
            ipa: 0x00a3_0010_0000,
            host_addr: 0x1000usize as *mut u8,
            guest_writable: true,
            sharing: GuestMappingSharing::GlobalShared,
            shared_key_base: 0,
            shared_key_offset: 0,
        };
        let location = view
            .shared_futex_location_for_ipa(view.ipa + 4)
            .expect("global shared frame must expose its translated host word");
        assert_eq!(location.wait_addr().raw(), 0x1004);
        assert_eq!(location.waiter_key(), 0x1004);
    }

    #[test]
    fn shared_futex_route_skips_private_row_at_recycled_ipa() {
        let backing_ipa = carrick_mem::memory::LINUX_HVPATCH_GLOBAL_FRAME_BASE + 0x80_0000;
        let mut shared = mapped_region(0x100_0080_0000, 0x100_0080_4000, backing_ipa);
        shared.host_addr = 0x1046_78000usize as *mut u8;
        shared.sharing = GuestMappingSharing::GlobalShared;
        let mut retired_private = mapped_region(0x6000_005000, 0x6000_009000, backing_ipa);
        retired_private.host_addr = 0x1177_d0000usize as *mut u8;
        // Newest-first raw IPA lookup sees this unrelated private row first.
        let mappings = [shared, retired_private];

        let location = HvfVmState::shared_futex_mapping_for_ipa(&mappings, backing_ipa + 4, false)
            .expect("the older exact shared owner must remain routable");

        assert_eq!(location.wait_addr().raw(), 0x1046_78004);
        assert_eq!(location.waiter_key(), 0x1046_78004);
    }

    pub(super) fn mapped_region(start: u64, end: u64, ipa: u64) -> HvfMappedRegion {
        HvfMappedRegion {
            start,
            ipa,
            physical_ipa: ipa,
            end,
            host_addr: std::ptr::null_mut(),
            size: usize::try_from(end - start).unwrap(),
            physical_size: usize::try_from(end - start).unwrap(),
            perms: applevisor::memory::MemPerms::ReadWrite,
            memory: None,
            host_mapping: None,
            stage2_lease: None,
            is_dynamic_alias: false,
            sharing: GuestMappingSharing::Private,
            guest_writable: true,
            shared_key_base: 0,
            shared_key_offset: 0,
            owner_generation: 0,
        }
    }

    #[derive(Debug, Clone, Copy)]
    struct FakeStageSegment {
        va_start: u64,
        va_end: u64,
        ipa_start: u64,
    }

    impl FakeStageSegment {
        fn new(va_start: u64, va_end: u64, ipa_start: u64) -> Self {
            Self {
                va_start,
                va_end,
                ipa_start,
            }
        }

        fn translate(self, va: u64) -> Option<u64> {
            (va >= self.va_start && va < self.va_end)
                .then_some(self.ipa_start + (va - self.va_start))
        }
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    struct FakeCopyChunk {
        mapping_idx: usize,
        len: usize,
        mapping_offset: usize,
    }

    struct FakeStageCopyHarness {
        mappings: Vec<HvfMappedRegion>,
        backing: Vec<Vec<u8>>,
        stage: Vec<FakeStageSegment>,
    }

    impl FakeStageCopyHarness {
        fn new(mappings: Vec<HvfMappedRegion>, stage: Vec<FakeStageSegment>) -> Self {
            let backing = mappings
                .iter()
                .map(|mapping| vec![0; mapping.size])
                .collect();
            Self {
                mappings,
                backing,
                stage,
            }
        }

        fn read(&self, address: u64, length: usize) -> Result<Vec<u8>, MemoryError> {
            let plan = self.plan(address, length)?;
            let mut bytes = vec![0; length];
            let mut copied = 0usize;
            for chunk in plan {
                let src = &self.backing[chunk.mapping_idx]
                    [chunk.mapping_offset..chunk.mapping_offset + chunk.len];
                bytes[copied..copied + chunk.len].copy_from_slice(src);
                copied += chunk.len;
            }
            Ok(bytes)
        }

        fn write(
            &mut self,
            address: u64,
            bytes: &[u8],
            require_guest_writable: bool,
        ) -> Result<(), MemoryError> {
            let plan = self.plan(address, bytes.len())?;
            if require_guest_writable
                && plan
                    .iter()
                    .any(|chunk| !self.mappings[chunk.mapping_idx].guest_writable)
            {
                return Err(MemoryError::OutOfBounds {
                    address,
                    length: bytes.len(),
                });
            }

            let mut copied = 0usize;
            for chunk in plan {
                let dst = &mut self.backing[chunk.mapping_idx]
                    [chunk.mapping_offset..chunk.mapping_offset + chunk.len];
                dst.copy_from_slice(&bytes[copied..copied + chunk.len]);
                copied += chunk.len;
            }
            Ok(())
        }

        fn mapping_bytes(&self, idx: usize) -> &[u8] {
            &self.backing[idx]
        }

        fn zero_copy_eligible(&self, address: u64, length: usize) -> bool {
            let Ok(plan) = self.plan(address, length) else {
                return false;
            };
            let Some(first) = plan.first() else {
                return false;
            };
            let first_mapping = &self.mappings[first.mapping_idx];
            let first_physical = first_mapping.ipa + first.mapping_offset as u64;
            let mut copied = 0usize;
            for chunk in &plan {
                let mapping = &self.mappings[chunk.mapping_idx];
                let physical = mapping.ipa + chunk.mapping_offset as u64;
                if chunk.mapping_idx != first.mapping_idx
                    || physical != first_physical + copied as u64
                {
                    return false;
                }
                copied += chunk.len;
            }
            true
        }

        fn plan(&self, address: u64, length: usize) -> Result<Vec<FakeCopyChunk>, MemoryError> {
            let mut copied = 0usize;
            let mut plan = Vec::new();
            while copied < length {
                let (chunk_address, chunk_len) =
                    HvfVmState::guest_copy_chunk(address, copied, length)?;
                let stage1_ipa = crate::memory::is_high_va(chunk_address)
                    .then(|| self.translate(chunk_address))
                    .flatten();
                let mapping_idx = HvfVmState::mapping_index_for_range(
                    &self.mappings,
                    chunk_address,
                    chunk_len,
                    stage1_ipa,
                )
                .ok_or(MemoryError::OutOfBounds { address, length })?;
                let mapping_offset =
                    usize::try_from(chunk_address - self.mappings[mapping_idx].start).unwrap();
                plan.push(FakeCopyChunk {
                    mapping_idx,
                    len: chunk_len,
                    mapping_offset,
                });
                copied += chunk_len;
            }
            Ok(plan)
        }

        fn translate(&self, va: u64) -> Option<u64> {
            let va = strip_pointer_tag(va);
            self.stage.iter().find_map(|segment| segment.translate(va))
        }
    }

    #[test]
    fn high_va_mapping_lookup_prefers_stage1_ipa_owner_over_newer_va_overlap() {
        let b_start = crate::memory::LINUX_HIGH_VA_THRESHOLD + 0x3000;
        let b_ipa = crate::memory::LINUX_ALIAS_IPA_BASE + 0x20_0000;
        let mappings = vec![
            mapped_region(b_start, b_start + 0x4000, b_ipa),
            // Newer region A over-claims into B's VA range because the host
            // mapping size was rounded to 16 KiB. The guest stage-1 walk still
            // says B owns b_start+0x1000, so B must win.
            mapped_region(
                crate::memory::LINUX_HIGH_VA_THRESHOLD,
                crate::memory::LINUX_HIGH_VA_THRESHOLD + 0x4000,
                crate::memory::LINUX_ALIAS_IPA_BASE,
            ),
        ];

        let idx = HvfVmState::mapping_index_for_range(
            &mappings,
            b_start + 0x1000,
            8,
            Some(b_ipa + 0x1000),
        );

        assert_eq!(idx, Some(0));
    }

    #[test]
    fn guest_copy_chunks_reselect_stage1_owner_across_alias_boundary() {
        let old_start = crate::memory::LINUX_HIGH_VA_THRESHOLD;
        let old_ipa = crate::memory::LINUX_ALIAS_IPA_BASE;
        let new_start = old_start + 0x3000;
        let new_ipa = old_ipa + 0x20_0000;
        let mappings = vec![
            mapped_region(old_start, old_start + 0x9000, old_ipa),
            mapped_region(new_start, new_start + 0x6000, new_ipa),
        ];
        let address = old_start + 0x2f50;
        let length = 0x5000usize;

        // The old single-region path would select the owner for the range's
        // start and use it for bytes after new_start, even though stage-1 has
        // already repointed that tail to the newer alias.
        assert_eq!(
            HvfVmState::mapping_index_for_range(
                &mappings,
                address,
                length,
                Some(old_ipa + (address - old_start)),
            ),
            Some(0),
        );

        let mut offset = 0usize;
        let mut owners = Vec::new();
        while offset < length {
            let (chunk_address, chunk_len) =
                HvfVmState::guest_copy_chunk(address, offset, length).unwrap();
            let stage1_ipa = if chunk_address < new_start {
                old_ipa + (chunk_address - old_start)
            } else {
                new_ipa + (chunk_address - new_start)
            };
            let idx = HvfVmState::mapping_index_for_range(
                &mappings,
                chunk_address,
                chunk_len,
                Some(stage1_ipa),
            )
            .unwrap();
            if owners.last() != Some(&idx) {
                owners.push(idx);
            }
            offset += chunk_len;
        }

        assert_eq!(owners, vec![0, 1]);
    }

    #[test]
    fn fake_stage1_copy_writes_tail_to_live_owner_backing() {
        let old_start = crate::memory::LINUX_HIGH_VA_THRESHOLD;
        let old_ipa = crate::memory::LINUX_ALIAS_IPA_BASE;
        let new_start = old_start + 0x3000;
        let new_ipa = old_ipa + 0x20_0000;
        let mut harness = FakeStageCopyHarness::new(
            vec![
                mapped_region(old_start, old_start + 0x9000, old_ipa),
                mapped_region(new_start, new_start + 0x6000, new_ipa),
            ],
            vec![
                FakeStageSegment::new(old_start, new_start, old_ipa),
                FakeStageSegment::new(new_start, new_start + 0x6000, new_ipa),
            ],
        );
        let address = old_start + 0x2f50;
        let length = 0x2400usize;
        let boundary_prefix = usize::try_from(new_start - address).unwrap();
        let source: Vec<u8> = (0..length).map(|idx| (idx % 251) as u8).collect();

        harness.write(address, &source, false).unwrap();

        assert_eq!(harness.read(address, length).unwrap(), source);
        assert_eq!(
            &harness.mapping_bytes(0)[0x2f50..0x3000],
            &source[..boundary_prefix]
        );
        assert!(
            harness.mapping_bytes(0)[0x3000..0x5350]
                .iter()
                .all(|byte| *byte == 0)
        );
        assert_eq!(
            &harness.mapping_bytes(1)[..length - boundary_prefix],
            &source[boundary_prefix..]
        );
    }

    #[test]
    fn zero_copy_declines_cross_fragment_stage1_range() {
        let old_start = crate::memory::LINUX_HIGH_VA_THRESHOLD;
        let old_ipa = crate::memory::LINUX_ALIAS_IPA_BASE;
        let new_start = old_start + 0x3000;
        let new_ipa = old_ipa + 0x20_0000;
        let harness = FakeStageCopyHarness::new(
            vec![
                mapped_region(old_start, old_start + 0x9000, old_ipa),
                mapped_region(new_start, new_start + 0x6000, new_ipa),
            ],
            vec![
                FakeStageSegment::new(old_start, new_start, old_ipa),
                FakeStageSegment::new(new_start, new_start + 0x6000, new_ipa),
            ],
        );

        assert!(harness.zero_copy_eligible(old_start + 0x1000, 0x1000));
        assert!(!harness.zero_copy_eligible(old_start + 0x2ff0, 0x1020));
    }

    #[test]
    fn fake_stage1_checked_write_rejects_readonly_tail_without_partial_write() {
        let old_start = crate::memory::LINUX_HIGH_VA_THRESHOLD;
        let old_ipa = crate::memory::LINUX_ALIAS_IPA_BASE;
        let new_start = old_start + 0x3000;
        let new_ipa = old_ipa + 0x20_0000;
        let mut new_region = mapped_region(new_start, new_start + 0x6000, new_ipa);
        new_region.guest_writable = false;
        let mut harness = FakeStageCopyHarness::new(
            vec![
                mapped_region(old_start, old_start + 0x9000, old_ipa),
                new_region,
            ],
            vec![
                FakeStageSegment::new(old_start, new_start, old_ipa),
                FakeStageSegment::new(new_start, new_start + 0x6000, new_ipa),
            ],
        );
        let address = old_start + 0x2f50;
        let source = vec![0xa5; 0x2400];

        assert!(harness.write(address, &source, true).is_err());
        assert!(harness.mapping_bytes(0).iter().all(|byte| *byte == 0));
        assert!(harness.mapping_bytes(1).iter().all(|byte| *byte == 0));
    }

    #[test]
    fn mapping_lookup_falls_back_to_newest_overlap_without_stage1_ipa() {
        let start = crate::memory::LINUX_HIGH_VA_THRESHOLD;
        let old = mapped_region(start, start + 0x4000, crate::memory::LINUX_ALIAS_IPA_BASE);
        let new = mapped_region(
            start,
            start + 0x4000,
            crate::memory::LINUX_ALIAS_IPA_BASE + 0x20_0000,
        );
        let mappings = vec![old, new];

        let idx = HvfVmState::mapping_index_for_range(&mappings, start + 0x1000, 8, None);

        assert_eq!(idx, Some(1));
    }

    #[test]
    fn raw_ipa_lookup_selects_rebased_mm_global_frame_backing() {
        let guest_va = crate::memory::LINUX_PAGE_TABLES_BASE;
        let root_slot_ipa = crate::memory::LINUX_HVPATCH_ROOT_SLOT_BASE;
        let mappings = vec![mapped_region(
            guest_va,
            guest_va + crate::memory::LINUX_PAGE_TABLES_SIZE,
            root_slot_ipa,
        )];

        let mapping = HvfVmState::mapping_for_ipa_range(&mappings, root_slot_ipa + 0x4000, 8)
            .expect("rebased page-table IPA must resolve by IPA, not guest VA");

        assert_eq!(mapping.start, guest_va);
        assert_eq!(mapping.ipa, root_slot_ipa);
        assert!(
            HvfVmState::mapping_for_ipa_range(&mappings, guest_va + 0x4000, 8).is_none(),
            "raw GPA access must not silently select a VA-only match"
        );
    }

    #[test]
    fn mailbox_route_rejects_unrelated_retired_row_at_recycled_ipa() {
        let mailbox_va = crate::memory::LINUX_SYSCALL_MAILBOX_BASE;
        let recycled_ipa = carrick_mem::memory::LINUX_HVPATCH_GLOBAL_FRAME_BASE + 0x3c_000;
        let mut mailbox = mapped_region(mailbox_va, mailbox_va + 0x1_0000, recycled_ipa);
        mailbox.host_addr = 0x1177_bc000usize as *mut u8;
        let mut retired = mapped_region(0x6000_005000, 0x6000_009000, recycled_ipa);
        retired.host_addr = 0x10e2_90000usize as *mut u8;
        // The retired row is newer in this vCPU-local metadata Vec. A raw IPA
        // search therefore selects it even though it cannot represent the
        // mailbox VA in the live stage-1 graph.
        let mappings = [mailbox, retired];

        let selected = HvfVmState::mailbox_mapping_for_range(
            &mappings,
            mailbox_va + 0x400,
            recycled_ipa + 0x400,
            carrick_aarch64::mailbox::AARCH64_SYSCALL_MAILBOX_SIZE as usize,
        )
        .expect("live mailbox route");

        assert_eq!(
            selected.start, mailbox_va,
            "mailbox lookup must preserve semantic VA while authenticating the translated IPA",
        );
        assert_eq!(selected.host_addr as usize, 0x1177_bc000);
    }

    #[test]
    fn neutral_persistent_worker_resolves_slot_zero_only_from_carrier_mappings() {
        let carrier_region = |start: u64, size: u64, host: usize| {
            let mut region = mapped_region(start, start + size, start);
            region.host_addr = host as *mut u8;
            region
        };
        let mappings = vec![
            carrier_region(
                crate::memory::LINUX_EL0_TRAMPOLINE_BASE,
                crate::memory::LINUX_EL0_TRAMPOLINE_SIZE,
                0x1100_0000,
            ),
            carrier_region(
                crate::memory::LINUX_EL1_VECTORS_BASE,
                crate::memory::LINUX_EL1_VECTORS_SIZE,
                0x1200_0000,
            ),
            carrier_region(
                crate::memory::LINUX_EL1_MAINT_BASE,
                crate::memory::LINUX_EL1_MAINT_SIZE,
                0x1300_0000,
            ),
            carrier_region(
                crate::memory::LINUX_SYSCALL_MAILBOX_BASE,
                crate::memory::LINUX_SYSCALL_MAILBOX_ARENA_SIZE,
                0x1400_0000,
            ),
            mapped_region(0x0040_0000, 0x0040_4000, 0x0040_0000),
            mapped_region(
                crate::memory::LINUX_PAGE_TABLES_BASE,
                crate::memory::LINUX_PAGE_TABLES_BASE + crate::memory::LINUX_PAGE_TABLES_SIZE,
                crate::memory::LINUX_PAGE_TABLES_BASE,
            ),
        ];
        let carrier = persistent_executor_carrier_mappings(&mappings);
        assert_eq!(
            carrier.len(),
            4,
            "task image and stage-1 root stay task-owned"
        );

        let neutral = HvfTaskState::neutral();
        neutral
            .audit_neutral()
            .expect("idle worker stays task-neutral");
        assert!(
            persistent_carrier_host_pointer(
                &[],
                crate::memory::LINUX_SYSCALL_MAILBOX_BASE,
                carrick_aarch64::mailbox::AARCH64_SYSCALL_MAILBOX_SIZE as usize,
            )
            .is_none(),
            "the signed startup failure had no carrier mapping projection"
        );
        let pointer = persistent_carrier_host_pointer(
            &carrier,
            crate::memory::LINUX_SYSCALL_MAILBOX_BASE,
            carrick_aarch64::mailbox::AARCH64_SYSCALL_MAILBOX_SIZE as usize,
        )
        .expect("slot zero resolves from executor-local carrier metadata");
        assert_eq!(pointer.as_ptr() as usize, 0x1400_0000);
    }

    #[test]
    fn persistent_carrier_authority_outlives_terminal_task_cleanup_and_drops_stage2_first() {
        let mut task_mappings = vec![mapped_region(0x0040_0000, 0x0040_4000, 0x0040_0000)];
        let mut drop_observations = Vec::new();
        for (start, size) in [
            (
                crate::memory::LINUX_EL0_TRAMPOLINE_BASE,
                crate::memory::LINUX_EL0_TRAMPOLINE_SIZE,
            ),
            (
                crate::memory::LINUX_EL1_VECTORS_BASE,
                crate::memory::LINUX_EL1_VECTORS_SIZE,
            ),
            (
                crate::memory::LINUX_EL1_MAINT_BASE,
                crate::memory::LINUX_EL1_MAINT_SIZE,
            ),
            (
                crate::memory::LINUX_SYSCALL_MAILBOX_BASE,
                crate::memory::LINUX_SYSCALL_MAILBOX_ARENA_SIZE,
            ),
        ] {
            let size = usize::try_from(size).unwrap();
            let host = crate::host_mapping::OwnedHostMapping::map_shared_anon(
                size,
                crate::host_mapping::HostMappingKind::PrivateAnon,
            )
            .unwrap();
            let host_addr = host.as_ptr();
            let observed = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
            let mut lease = GlobalFrameStage2Lease::fixed(start, size as u64);
            lease.drop_backing_audit = Some((host_addr as usize, std::sync::Arc::clone(&observed)));
            let mut region = mapped_region(start, start + size as u64, start);
            region.host_addr = host_addr;
            region.host_mapping = Some(host);
            region.stage2_lease = Some(lease);
            task_mappings.push(region);
            drop_observations.push((host_addr as usize, observed));
        }
        assert_eq!(
            task_mappings
                .iter()
                .filter(|mapping| mapping_belongs_to_task_inventory(true, mapping))
                .count(),
            1,
            "Kernel MM inventory must never acquire carrier control extents"
        );

        let authority = PersistentCarrierMappings::extract(&mut task_mappings)
            .expect("extract exact carrier mapping authority");
        assert_eq!(
            task_mappings.len(),
            1,
            "task retains only its own image mapping"
        );
        let worker = std::sync::Arc::new(authority);
        let factory = std::sync::Arc::clone(&worker);
        drop(task_mappings);

        let mailbox = worker
            .host_pointer(
                crate::memory::LINUX_SYSCALL_MAILBOX_BASE,
                carrick_aarch64::mailbox::AARCH64_SYSCALL_MAILBOX_SIZE as usize,
            )
            .expect("terminal task cleanup cannot invalidate a live worker mailbox");
        // SAFETY: the carrier authority owns the complete mailbox mapping.
        unsafe { mailbox.as_ptr().write_volatile(0x5a) };
        drop(worker);
        assert!(
            drop_observations
                .iter()
                .all(|(host, _)| alias_backing_is_live(*host))
        );

        drop(factory);
        assert!(drop_observations.iter().all(|(host, observed)| {
            observed.load(std::sync::atomic::Ordering::SeqCst) && !alias_backing_is_live(*host)
        }));
    }

    #[test]
    fn persistent_worker_invariant_configuration_is_complete_and_audited() {
        let mailbox_sp = crate::memory::LINUX_SYSCALL_MAILBOX_BASE;
        let mut registers = std::collections::HashMap::new();
        configure_persistent_executor_invariant_registers(|register, value| {
            registers.insert(register, value);
            Ok(())
        })
        .expect("fake executor invariant configuration");
        registers.insert(PersistentExecutorInvariantRegister::SpEl1, mailbox_sp);

        audit_persistent_executor_invariant_registers(
            |register| Ok(*registers.get(&register).unwrap_or(&0)),
            mailbox_sp,
        )
        .expect("complete fake executor invariant image");

        for value in registers.values_mut() {
            *value ^= 0x55aa_0000;
        }
        restore_persistent_executor_invariant_registers(
            |register, value| {
                registers.insert(register, value);
                Ok(())
            },
            mailbox_sp,
        )
        .expect("detach restores every executor-local invariant");
        audit_persistent_executor_invariant_registers(
            |register| Ok(*registers.get(&register).unwrap_or(&0)),
            mailbox_sp,
        )
        .expect("restored fake executor invariant image");

        for missing in PERSISTENT_EXECUTOR_INVARIANT_REGISTERS {
            let mut partial = registers.clone();
            partial.remove(&missing);
            assert!(
                audit_persistent_executor_invariant_registers(
                    |register| {
                        partial.get(&register).copied().ok_or_else(|| {
                            TrapError::Hypervisor(format!("fake executor omitted {register:?}"))
                        })
                    },
                    mailbox_sp,
                )
                .is_err(),
                "missing {missing:?} must fail closed",
            );
        }

        let factory = include_str!("trap.rs")
            .split("pub(crate) fn from_persistent_executor_spec")
            .nth(1)
            .and_then(|tail| {
                tail.split("pub(crate) fn audit_persistent_executor_idle")
                    .next()
            })
            .expect("persistent factory body");
        let configure = factory
            .find("Self::configure_executor_invariants(&vcpu)")
            .expect("factory configures the fresh owner-thread vCPU");
        let allocate = factory
            .find("Self::allocate_persistent_mailbox_for_vcpu")
            .expect("factory binds executor-local SP_EL1");
        let audit = factory
            .find("Self::audit_executor_invariants(&vcpu, mailbox.slot().guest_address())")
            .expect("factory audits invariants and mailbox SP before publication");
        assert!(configure < allocate && allocate < audit);
    }
}

// ---------------------------------------------------------------------------
// carrick-hal trait impls: RegAccess + ThreadedEngine
//
// These are forwarding impls only.  Every method delegates to an existing
// HvfTrapEngine / HvfInner method verbatim.  No behaviour is changed.
//
// The HAL Reg/SysReg enums were designed for KVM's register naming; we map
// each variant to the equivalent applevisor register below.
//
// HypervisorError does not carry a POSIX errno.  We map any HVF error to
// EIO (5) — a generic I/O error the caller can distinguish from EINVAL/ENOSYS.
// ---------------------------------------------------------------------------

/// Convert an applevisor error to a HAL OsError, using EIO as the errno.
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
#[inline]
pub(crate) fn hvf_os_error(_e: applevisor::error::HypervisorError) -> carrick_hal::OsError {
    carrick_hal::OsError::from_raw(libc::EIO)
}

/// Map a HAL [`carrick_hal::Reg`] to the corresponding applevisor value and
/// read it from `vcpu`.  On non-HVF targets returns ENOSYS (never called).
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
pub(crate) fn hvf_get_reg(
    vcpu: &applevisor::vcpu::Vcpu,
    r: carrick_hal::Reg,
) -> Result<u64, carrick_hal::OsError> {
    // `applevisor::prelude::*` brings `Reg`/`SysReg`; we locally shadow the
    // HAL types only inside the `match r` arm patterns.
    use applevisor::prelude::*;
    let hal_r = r;
    match hal_r {
        carrick_hal::Reg::X(n) => match GPR_TABLE.get(n as usize) {
            Some(&reg) => vcpu.get_reg(reg).map_err(hvf_os_error),
            None => Err(carrick_hal::OsError::from_raw(libc::EINVAL)),
        },
        carrick_hal::Reg::Sp => vcpu.get_sys_reg(SysReg::SP_EL0).map_err(hvf_os_error),
        carrick_hal::Reg::Pc => vcpu.get_reg(Reg::PC).map_err(hvf_os_error),
        carrick_hal::Reg::Pstate => vcpu.get_reg(Reg::CPSR).map_err(hvf_os_error),
        carrick_hal::Reg::SpEl1 => vcpu.get_sys_reg(SysReg::SP_EL1).map_err(hvf_os_error),
        carrick_hal::Reg::ElrEl1 => vcpu.get_sys_reg(SysReg::ELR_EL1).map_err(hvf_os_error),
        carrick_hal::Reg::SpsrEl1 => vcpu.get_sys_reg(SysReg::SPSR_EL1).map_err(hvf_os_error),
        _ => Err(carrick_hal::OsError::from_raw(libc::EINVAL)),
    }
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
pub(crate) fn hvf_set_reg(
    vcpu: &applevisor::vcpu::Vcpu,
    r: carrick_hal::Reg,
    v: u64,
) -> Result<(), carrick_hal::OsError> {
    use applevisor::prelude::*;
    let hal_r = r;
    match hal_r {
        carrick_hal::Reg::X(n) => match GPR_TABLE.get(n as usize) {
            Some(&reg) => vcpu.set_reg(reg, v).map_err(hvf_os_error),
            None => Err(carrick_hal::OsError::from_raw(libc::EINVAL)),
        },
        carrick_hal::Reg::Sp => vcpu.set_sys_reg(SysReg::SP_EL0, v).map_err(hvf_os_error),
        carrick_hal::Reg::Pc => vcpu.set_reg(Reg::PC, v).map_err(hvf_os_error),
        carrick_hal::Reg::Pstate => vcpu.set_reg(Reg::CPSR, v).map_err(hvf_os_error),
        carrick_hal::Reg::SpEl1 => vcpu.set_sys_reg(SysReg::SP_EL1, v).map_err(hvf_os_error),
        carrick_hal::Reg::ElrEl1 => vcpu.set_sys_reg(SysReg::ELR_EL1, v).map_err(hvf_os_error),
        carrick_hal::Reg::SpsrEl1 => vcpu.set_sys_reg(SysReg::SPSR_EL1, v).map_err(hvf_os_error),
        _ => Err(carrick_hal::OsError::from_raw(libc::EINVAL)),
    }
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
pub(crate) fn hvf_get_sys_reg(
    vcpu: &applevisor::vcpu::Vcpu,
    r: carrick_hal::SysReg,
) -> Result<u64, carrick_hal::OsError> {
    use applevisor::prelude::*;
    let hvf_reg = match r {
        carrick_hal::SysReg::Sctlr => SysReg::SCTLR_EL1,
        carrick_hal::SysReg::Ttbr0 => SysReg::TTBR0_EL1,
        carrick_hal::SysReg::Ttbr1 => SysReg::TTBR1_EL1,
        carrick_hal::SysReg::Tcr => SysReg::TCR_EL1,
        carrick_hal::SysReg::Mair => SysReg::MAIR_EL1,
        carrick_hal::SysReg::Vbar => SysReg::VBAR_EL1,
        carrick_hal::SysReg::Cpacr => SysReg::CPACR_EL1,
        carrick_hal::SysReg::TpidrEl0 => SysReg::TPIDR_EL0,
        // x86_64 FsBase/GsBase are a disjoint ISA view; never on the macOS/HVF lane.
        _ => return Err(carrick_hal::OsError::from_raw(libc::EINVAL)),
    };
    vcpu.get_sys_reg(hvf_reg).map_err(hvf_os_error)
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
pub(crate) fn hvf_set_sys_reg(
    vcpu: &applevisor::vcpu::Vcpu,
    r: carrick_hal::SysReg,
    v: u64,
) -> Result<(), carrick_hal::OsError> {
    use applevisor::prelude::*;
    let hvf_reg = match r {
        carrick_hal::SysReg::Sctlr => SysReg::SCTLR_EL1,
        carrick_hal::SysReg::Ttbr0 => SysReg::TTBR0_EL1,
        carrick_hal::SysReg::Ttbr1 => SysReg::TTBR1_EL1,
        carrick_hal::SysReg::Tcr => SysReg::TCR_EL1,
        carrick_hal::SysReg::Mair => SysReg::MAIR_EL1,
        carrick_hal::SysReg::Vbar => SysReg::VBAR_EL1,
        carrick_hal::SysReg::Cpacr => SysReg::CPACR_EL1,
        carrick_hal::SysReg::TpidrEl0 => SysReg::TPIDR_EL0,
        // x86_64 FsBase/GsBase are a disjoint ISA view; never on the macOS/HVF lane.
        _ => return Err(carrick_hal::OsError::from_raw(libc::EINVAL)),
    };
    vcpu.set_sys_reg(hvf_reg, v).map_err(hvf_os_error)
}

#[cfg(test)]
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
mod tag_strip_tests {
    use super::{
        AliasBacking, AliasOwnershipScope, CowArmedSpan, GuestMappingPlan, GuestMappingSharing,
        HVF_PAGE_SIZE, HvfMappedRegion, InventoryBackingIdentity, ThreadMappingDesc,
        alias_is_owned_by_process, alias_matches_process_scope, alias_registry,
        current_dynamic_alias_ipas, forget_replay_extent, inherited_fork_inventory_extents,
        lookup_shared_alias, mapping_is_current_for_process_fork_indexed, missing_process_aliases,
        process_alias_index,
    };
    /// Test adapter preserving the retired linear signature over the index.
    fn mapping_is_current_for_process_fork_test(
        mapping: &HvfMappedRegion,
        aliases: &[AliasBacking],
        mm_root_slot: Option<(u64, u64)>,
    ) -> bool {
        mapping_is_current_for_process_fork_indexed(
            mapping,
            &process_alias_index(aliases, mm_root_slot),
        )
    }
    #[allow(unused_imports)]
    use super::{
        next_vdso_rng_generation, reapply_global_exec_readonly_spans,
        rebind_inherited_alias_to_process, register_shared_alias,
        retained_private_reuse_alias_fragment, retired_alias_disarm_spans, strip_pointer_tag,
        unregister_alias, unregister_alias_entries,
    };

    #[test]
    fn logical_hvpatch_processes_receive_distinct_vdso_rng_generations() {
        let parent = next_vdso_rng_generation();
        let child = next_vdso_rng_generation();

        assert_ne!(parent, 0);
        assert_ne!(child, 0);
        assert_ne!(parent, child);
    }

    static EXEC_PAYLOAD_ENV_LOCK: parking_lot::Mutex<()> = parking_lot::Mutex::new(());

    #[test]
    fn guest_mapping_plan_shares_address_space_payload() {
        let _env_guard = EXEC_PAYLOAD_ENV_LOCK.lock();
        let perms = carrick_mem::elf::SegmentPerms {
            read: true,
            write: false,
            execute: true,
        };
        let image = carrick_mem::memory::AddressSpace::from_segments(
            0x1_0000,
            [(0x1_0000, perms, vec![0xaa; 0x4000], 0x4000)],
        )
        .expect("one valid region");

        let plan = GuestMappingPlan::from_address_space(&image).expect("mapping plan");
        let cloned_plan = plan.clone();

        assert_eq!(
            plan.mappings[0].image.as_ptr(),
            image.regions()[0].bytes().as_ptr(),
            "mapping-plan construction must not copy immutable image bytes"
        );
        assert_eq!(
            cloned_plan.mappings[0].image.as_ptr(),
            plan.mappings[0].image.as_ptr(),
            "mapping-plan clones must share immutable image bytes"
        );
    }

    #[test]
    fn global_exec_readonly_spans_preserve_rebased_ipa() {
        let va = 0x20_0000;
        let ipa = 0x5000_0000;
        let mut tables = carrick_mem::page_table::PageTableManager::new(
            carrick_mem::memory::stage1_identity_page_tables(),
            carrick_mem::memory::LINUX_PAGE_TABLES_BASE,
        );
        tables
            .map_aliased(va, ipa, 0x20_000, true)
            .expect("rebase merged writable load region");

        reapply_global_exec_readonly_spans(
            &mut tables,
            &[carrick_mem::elf::RoSpan {
                start: va + 0x4000,
                len: 0x2000,
                exec: false,
            }],
        )
        .expect("restore PT_LOAD protection");

        assert_eq!(tables.translate(va + 0x4000), Some(ipa + 0x4000));
        assert!(
            !tables
                .set_readonly(va + 0x4000, 0x1000, false)
                .expect("span is already read-only"),
            "reapplying the same read-only protection must be a no-op"
        );
        assert!(
            !tables
                .set_rw(va + 0x3000, 0x1000, true)
                .expect("prefix remains writable"),
            "the page before the span must retain the merged mapping's RWX attributes"
        );
        assert!(
            !tables
                .set_rw(va + 0x6000, 0x1000, true)
                .expect("suffix remains writable"),
            "the page after the span must retain the merged mapping's RWX attributes"
        );
    }

    #[test]
    fn guest_mapping_plan_payload_sharing_hatch_restores_deep_copy() {
        let _env_guard = EXEC_PAYLOAD_ENV_LOCK.lock();
        let prior = std::env::var_os("CARRICK_HVPATCH_SHARE_EXEC_PAYLOAD");
        // SAFETY: no other test reads or writes this diagnostic-only variable.
        unsafe { std::env::set_var("CARRICK_HVPATCH_SHARE_EXEC_PAYLOAD", "0") };

        let perms = carrick_mem::elf::SegmentPerms {
            read: true,
            write: false,
            execute: true,
        };
        let image = carrick_mem::memory::AddressSpace::from_segments(
            0x1_0000,
            [(0x1_0000, perms, vec![0xaa; 0x4000], 0x4000)],
        )
        .expect("one valid region");
        let plan = GuestMappingPlan::from_address_space(&image).expect("mapping plan");

        match prior {
            Some(value) => {
                // SAFETY: restores the value this test replaced.
                unsafe { std::env::set_var("CARRICK_HVPATCH_SHARE_EXEC_PAYLOAD", value) };
            }
            None => {
                // SAFETY: restores the absence this test replaced.
                unsafe { std::env::remove_var("CARRICK_HVPATCH_SHARE_EXEC_PAYLOAD") };
            }
        }

        assert_ne!(
            plan.mappings[0].image.as_ptr(),
            image.regions()[0].bytes().as_ptr(),
            "the =0 bisection hatch must restore the pre-optimization payload copy"
        );
        assert_eq!(
            plan.mappings[0].image.as_slice(),
            image.regions()[0].bytes()
        );
    }

    #[test]
    fn guest_mapping_plan_keeps_full_stack_extent_but_only_initialized_tail_payload() {
        let image = carrick_mem::memory::AddressSpace::from_regions(0x1_0000, Vec::new())
            .expect("empty image")
            .with_linux_initial_stack([b"tool".as_slice()], [b"KEY=value".as_slice()])
            .expect("initial stack");
        let plan = GuestMappingPlan::from_address_space(&image).expect("mapping plan");
        let stack_start =
            carrick_mem::memory::LINUX_STACK_TOP - carrick_mem::memory::LINUX_STACK_SIZE;
        let mapping = plan
            .mappings
            .iter()
            .find(|mapping| mapping.guest_start == stack_start)
            .expect("stack mapping");

        assert_eq!(
            mapping.mapped_size,
            carrick_mem::memory::LINUX_STACK_SIZE,
            "Linux stack growth must retain the full RLIMIT_STACK extent"
        );
        assert!(mapping.offset_in_mapping > 7 * 1024 * 1024);
        assert!(mapping.image.len() < 64 * 1024);
        assert_eq!(
            mapping.offset_in_mapping + mapping.image.len() as u64,
            mapping.mapped_size,
            "the sparse payload must cover the initialized tail through stack top"
        );
        let source = image
            .regions()
            .iter()
            .find(|region| region.start == stack_start)
            .expect("source stack");
        assert_eq!(
            mapping.image.as_slice(),
            &source.bytes()[mapping.offset_in_mapping as usize..]
        );
    }

    #[test]
    fn private_exec_file_artifact_reuses_bytes_but_each_mapping_is_cow() {
        use std::os::fd::AsRawFd;

        let source = std::sync::Arc::new(vec![0xA5; super::HVF_PAGE_SIZE as usize]);
        let first = super::cached_exec_private_file_backing(
            std::sync::Arc::clone(&source),
            super::HVF_PAGE_SIZE as usize,
        )
        .expect("cache private executable artifact");
        let second = super::cached_exec_private_file_backing(
            std::sync::Arc::clone(&source),
            super::HVF_PAGE_SIZE as usize,
        )
        .expect("reuse private executable artifact");
        assert_eq!(
            first, second,
            "the same immutable payload must reuse one artifact"
        );

        let mapped = crate::host_mapping::OwnedHostMapping::map_private_file(
            first.file.as_raw_fd(),
            0,
            super::HVF_PAGE_SIZE as usize,
        )
        .expect("map private executable artifact");
        unsafe { mapped.as_ptr().write_volatile(0x5A) };
        assert_eq!(unsafe { mapped.as_ptr().read_volatile() }, 0x5A);

        let fresh = crate::host_mapping::OwnedHostMapping::map_private_file(
            second.file.as_raw_fd(),
            0,
            super::HVF_PAGE_SIZE as usize,
        )
        .expect("map fresh private executable artifact");
        assert_eq!(
            unsafe { fresh.as_ptr().read_volatile() },
            0xA5,
            "one exec's COW write must not contaminate the cached artifact"
        );
    }

    #[test]
    fn strips_top_16_bits() {
        // Rosetta's RWX ExecutableHeap hint, and an x86-64 high-half address.
        assert_eq!(
            strip_pointer_tag(0xffff_fff7_ff70_0000),
            0x0000_fff7_ff70_0000
        );
        assert_eq!(
            strip_pointer_tag(0xffff_ffff_fff3_a000),
            0x0000_ffff_fff3_a000
        );
        // Native (top-byte-zero) pointers are untouched.
        assert_eq!(
            strip_pointer_tag(0x0000_0001_2345_6000),
            0x0000_0001_2345_6000
        );
    }

    #[test]
    fn fork_footprint_classifies_guest_mapping_roles() {
        assert_eq!(
            super::fork_footprint_class_id(crate::memory::LINUX_MMAP_BASE, false, true),
            super::FORK_FOOTPRINT_CLASS_PRIVATE_MMAP_ARENA
        );
        assert_eq!(
            super::fork_footprint_class_id(crate::memory::LINUX_HEAP_BASE, false, true),
            super::FORK_FOOTPRINT_CLASS_PRIVATE_HEAP
        );
        assert_eq!(
            super::fork_footprint_class_id(crate::memory::LINUX_PRIVATE_OVERLAY_BASE, false, true),
            super::FORK_FOOTPRINT_CLASS_PRIVATE_OVERLAY
        );
        assert_eq!(
            super::fork_footprint_class_id(crate::memory::LINUX_SHARED_FILE_BASE, true, true),
            super::FORK_FOOTPRINT_CLASS_SHARED_APERTURE
        );
        assert_eq!(
            super::fork_footprint_class_id(crate::memory::LINUX_HIGH_VA_THRESHOLD, false, true),
            super::FORK_FOOTPRINT_CLASS_PRIVATE_HIGH_ALIAS
        );
        assert_eq!(
            super::fork_footprint_class_id(0x4000, false, false),
            super::FORK_FOOTPRINT_CLASS_PRIVATE_RO_OR_INTERNAL
        );
        assert_eq!(
            super::fork_footprint_class_id(crate::memory::LINUX_PAGE_TABLES_BASE, false, true),
            super::FORK_FOOTPRINT_CLASS_PRIVATE_PAGE_TABLES
        );
    }

    #[test]
    fn private_alias_scope_separates_root_and_child_mm_root_slots() {
        let root_slot = (
            carrick_mem::memory::LINUX_HVPATCH_ROOT_SLOT_BASE,
            2 * 1024 * 1024,
        );
        assert!(alias_matches_process_scope(
            AliasOwnershipScope::MmRootSlot {
                base: root_slot.0,
                size: root_slot.1
            },
            Some(root_slot)
        ));
        assert!(!alias_matches_process_scope(
            AliasOwnershipScope::Root,
            Some(root_slot)
        ));
        assert!(alias_matches_process_scope(AliasOwnershipScope::Root, None));
        assert!(!alias_matches_process_scope(
            AliasOwnershipScope::MmRootSlot {
                base: root_slot.0,
                size: root_slot.1
            },
            None
        ));
        assert!(!alias_matches_process_scope(
            AliasOwnershipScope::MmRootSlot {
                base: root_slot.0 + root_slot.1,
                size: root_slot.1
            },
            Some(root_slot)
        ));
        assert!(alias_matches_process_scope(
            AliasOwnershipScope::Global,
            Some(root_slot)
        ));
    }

    #[test]
    fn fork_shared_anonymous_alias_stays_process_scoped() {
        let parent_root_slot = (
            carrick_mem::memory::LINUX_HVPATCH_ROOT_SLOT_BASE,
            2 * 1024 * 1024,
        );
        let foreign_root_slot = (parent_root_slot.0 + parent_root_slot.1, parent_root_slot.1);
        let requested = carrick_mem::memory::LINUX_ALIAS_IPA_BASE;
        let sharing = GuestMappingSharing::ForkSharedAnonymous;
        assert!(sharing.shares_across_fork());
        assert!(!sharing.uses_global_ipa());
        assert!(!sharing.has_shared_futex_identity());

        // A MAP_SHARED anonymous alias needs a fork-shared backing, but that
        // does not make it a shared-file/futex identity. Its physical frame
        // still owns one stable global IPA; semantic visibility remains scoped
        // to the owning mm and explicitly inherited descendants.
        let ipa = requested;
        assert_eq!(ipa, requested);

        let alias = AliasBacking {
            start: 0x1400_0000_0000,
            ipa,
            host_addr: 0x1000,
            size: 0x4000,
            physical_ipa: ipa,
            physical_host_addr: 0x1000,
            physical_size: 0x4000,
            perms: u64::from(applevisor::memory::MemPerms::ReadWrite),
            guest_writable: true,
            sharing,
            ownership_scope: AliasOwnershipScope::MmRootSlot {
                base: parent_root_slot.0,
                size: parent_root_slot.1,
            },
            inventory_backing: InventoryBackingIdentity::SharedAnon(41),
            shared_key_base: 0,
            shared_key_offset: 0,
            owner_generation: 0,
        };
        assert_eq!(
            missing_process_aliases(
                &std::collections::HashSet::new(),
                &[alias],
                Some(parent_root_slot)
            )
            .len(),
            1,
            "the owning mm must inventory its sibling-owned alias"
        );
        assert!(
            missing_process_aliases(
                &std::collections::HashSet::new(),
                &[alias],
                Some(foreign_root_slot)
            )
            .is_empty(),
            "an unrelated mm must not acquire anonymous backing through global alias scope"
        );
    }

    #[test]
    fn address_space_replacement_drops_only_its_private_alias_scope() {
        let root_slot = (0x9000_0000, 0x20_0000);
        assert!(alias_is_owned_by_process(AliasOwnershipScope::Root, None));
        assert!(!alias_is_owned_by_process(
            AliasOwnershipScope::Root,
            Some(root_slot)
        ));
        assert!(alias_is_owned_by_process(
            AliasOwnershipScope::MmRootSlot {
                base: root_slot.0,
                size: root_slot.1,
            },
            Some(root_slot)
        ));
        assert!(!alias_is_owned_by_process(
            AliasOwnershipScope::MmRootSlot {
                base: root_slot.0 + root_slot.1,
                size: root_slot.1,
            },
            Some(root_slot)
        ));
        assert!(!alias_is_owned_by_process(
            AliasOwnershipScope::Global,
            Some(root_slot)
        ));
    }

    #[test]
    fn fork_shared_anonymous_alias_survives_a_second_fork_without_global_scope() {
        let parent_root_slot = (
            carrick_mem::memory::LINUX_HVPATCH_ROOT_SLOT_BASE,
            2 * 1024 * 1024,
        );
        let child_root_slot = (parent_root_slot.0 + parent_root_slot.1, parent_root_slot.1);
        let grandchild_root_slot = (child_root_slot.0 + child_root_slot.1, child_root_slot.1);
        let unrelated_root_slot = (
            grandchild_root_slot.0 + grandchild_root_slot.1,
            grandchild_root_slot.1,
        );
        let frame_ipa = carrick_mem::memory::LINUX_HVPATCH_GLOBAL_FRAME_BASE + 0x20_0000;
        let alias = rebind_inherited_alias_to_process(
            AliasBacking {
                start: 0x1382_8ed0_0000,
                ipa: frame_ipa,
                host_addr: 0x1000,
                size: 0x4000,
                physical_ipa: frame_ipa,
                physical_host_addr: 0x1000,
                physical_size: 0x4000,
                perms: u64::from(applevisor::memory::MemPerms::ReadWrite),
                guest_writable: true,
                sharing: GuestMappingSharing::ForkSharedAnonymous,
                ownership_scope: AliasOwnershipScope::MmRootSlot {
                    base: parent_root_slot.0,
                    size: parent_root_slot.1,
                },
                inventory_backing: InventoryBackingIdentity::SharedAnon(42),
                shared_key_base: 0,
                shared_key_offset: 0,
                owner_generation: 0,
            },
            child_root_slot,
        );

        assert_eq!(
            missing_process_aliases(
                &std::collections::HashSet::new(),
                &[alias],
                Some(child_root_slot),
            )
            .len(),
            1,
            "a child forking a grandchild must retain its inherited anonymous frame"
        );
        assert_eq!(
            missing_process_aliases(
                &std::collections::HashSet::new(),
                &[alias],
                Some(child_root_slot),
            )[0]
            .inventory_backing,
            InventoryBackingIdentity::SharedAnon(42),
            "scope rebinding must not mint a new backing identity",
        );
        let frame =
            carrick_hal::FrameId::from_kernel_allocation(std::num::NonZeroU64::new(9101).unwrap());
        let inventory = std::collections::BTreeMap::from([(
            (alias.physical_ipa, alias.physical_size as u64),
            super::InventoryExtent {
                frame,
                mapping: carrick_hal::MappingId::from_kernel_allocation(
                    std::num::NonZeroU64::new(9102).unwrap(),
                ),
                backing: alias.inventory_backing,
                stage2_base: alias.physical_ipa,
                stage2_length: alias.physical_size as u64,
            },
        )]);
        let child_source = super::ThreadMappingDesc::from_alias(alias).unwrap();
        let grandchild_extent = inherited_fork_inventory_extents(&child_source, &inventory)
            .pop()
            .expect("grandchild retains exact inherited mapping")
            .1;
        assert_eq!(grandchild_extent.frame, frame);
        assert_eq!(grandchild_extent.backing, alias.inventory_backing);

        let grandchild_alias = rebind_inherited_alias_to_process(alias, grandchild_root_slot);
        assert_eq!(
            missing_process_aliases(
                &std::collections::HashSet::new(),
                &[grandchild_alias],
                Some(grandchild_root_slot),
            )[0]
            .inventory_backing,
            alias.inventory_backing,
            "grandchild publication must retain the inherited frame identity",
        );
        assert!(
            missing_process_aliases(
                &std::collections::HashSet::new(),
                &[grandchild_alias],
                Some(unrelated_root_slot),
            )
            .is_empty(),
            "an unrelated mm must not gain the inherited frame"
        );
    }

    #[test]
    fn alias_registry_partial_unmap_preserves_exact_live_fragments() {
        let va = 0x1383_0000_0000;
        let ipa = carrick_mem::memory::LINUX_ALIAS_IPA_BASE + 0x7d00_0000;
        let alias = AliasBacking {
            start: va,
            ipa,
            host_addr: 0x1234_0000,
            size: 0xc000,
            physical_ipa: ipa,
            physical_host_addr: 0x1234_0000,
            physical_size: 0xc000,
            perms: u64::from(applevisor::memory::MemPerms::ReadWrite),
            guest_writable: true,
            sharing: GuestMappingSharing::GlobalShared,
            ownership_scope: AliasOwnershipScope::Global,
            inventory_backing: InventoryBackingIdentity::SharedFile {
                device: 1,
                inode: 2,
                offset: 0x8000,
                length: 0xc000,
            },
            shared_key_base: 7,
            shared_key_offset: 0x8000,
            owner_generation: 0,
        };
        let retained = std::collections::BTreeSet::new();
        assert!(
            retired_alias_disarm_spans(&[alias], va + 0x4000, 0x4000, None, &retained).is_empty(),
            "a semantic hole in a retained physical frame must keep its COW arm for same-VA reuse",
        );
        assert_eq!(
            retired_alias_disarm_spans(
                &[alias],
                va + 0x4000,
                0x4000,
                None,
                &std::collections::BTreeSet::from([(ipa, 0xc000)]),
            ),
            vec![CowArmedSpan {
                va: va + 0x4000,
                len: 0x4000,
                executable: false,
                kernel_only: false,
            }],
            "only retirement of the whole physical lease may disarm the semantic hole",
        );
        register_shared_alias(alias);

        let retired = unregister_alias(va + 0x4000, 0x4000, None);
        assert!(
            retired.is_empty(),
            "a partial semantic unmap must retain its containing stage-2 lease"
        );
        let mut fragments: Vec<_> = alias_registry()
            .lock()
            .iter()
            .copied()
            .filter(|entry| entry.start >= va && entry.start < va + 0xc000)
            .collect();
        fragments.sort_by_key(|entry| entry.start);

        assert_eq!(fragments.len(), 2);
        assert_eq!(
            (fragments[0].start, fragments[0].ipa, fragments[0].size),
            (va, ipa, 0x4000)
        );
        assert_eq!(
            (fragments[1].start, fragments[1].ipa, fragments[1].size),
            (va + 0x8000, ipa + 0x8000, 0x4000),
        );
        assert_eq!(fragments[1].host_addr, alias.host_addr + 0x8000);
        assert_eq!(
            fragments[1].shared_key_offset,
            alias.shared_key_offset + 0x8000
        );

        let physical_extent = super::InventoryExtent {
            frame: carrick_hal::FrameId::from_kernel_allocation(
                std::num::NonZeroU64::new(9001).unwrap(),
            ),
            mapping: carrick_hal::MappingId::from_kernel_allocation(
                std::num::NonZeroU64::new(9002).unwrap(),
            ),
            backing: alias.inventory_backing,
            stage2_base: alias.physical_ipa,
            stage2_length: alias.physical_size as u64,
        };
        let inventory = std::collections::BTreeMap::from([(
            (alias.physical_ipa, alias.physical_size as u64),
            physical_extent,
        )]);
        for fragment in fragments {
            let desc = super::ThreadMappingDesc::from_alias(fragment).unwrap();
            assert_eq!(
                inherited_fork_inventory_extents(&desc, &inventory)
                    .pop()
                    .expect("fragment retains inherited mapping")
                    .1
                    .frame,
                physical_extent.frame,
                "each exact semantic fragment must remain forkable through the whole physical extent",
            );
        }

        assert_eq!(
            unregister_alias(va, 0xc000, None),
            std::collections::BTreeSet::from([(ipa, 0xc000)]),
            "the last semantic fragment retires the exact physical lease"
        );
    }

    #[test]
    fn retained_private_reuse_republishes_semantic_fragment_before_sibling_unmap() {
        let va = 0x1383_0800_0000;
        let physical_ipa = carrick_mem::memory::LINUX_ALIAS_IPA_BASE + 0x7c80_0000;
        let root_slot = (
            carrick_mem::memory::LINUX_HVPATCH_ROOT_SLOT_BASE,
            2 * 1024 * 1024,
        );
        let scope = AliasOwnershipScope::MmRootSlot {
            base: root_slot.0,
            size: root_slot.1,
        };
        // A prior partial munmap carved the second Linux page out of this
        // still-live 16 KiB private frame. The first page is the remaining
        // semantic owner; the invalid second leaf retains its output IPA for
        // low-arena same-VA reuse.
        let prefix = AliasBacking {
            start: va,
            ipa: physical_ipa,
            host_addr: 0x4234_0000,
            size: 0x1000,
            physical_ipa,
            physical_host_addr: 0x4234_0000,
            physical_size: 0x4000,
            perms: u64::from(applevisor::memory::MemPerms::ReadWriteExec),
            guest_writable: true,
            sharing: GuestMappingSharing::Private,
            ownership_scope: scope,
            inventory_backing: InventoryBackingIdentity::Private(46),
            shared_key_base: 0,
            shared_key_offset: 0,
            owner_generation: 0,
        };
        let mut registry = vec![prefix];

        let reused = retained_private_reuse_alias_fragment(
            &registry,
            va + 0x1000,
            physical_ipa + 0x1000,
            0x1000,
            Some(root_slot),
        )
        .expect("reused Linux page must regain semantic lifetime ownership");
        assert_eq!(reused.start, va + 0x1000);
        assert_eq!(reused.ipa, physical_ipa + 0x1000);
        assert_eq!(reused.host_addr, prefix.physical_host_addr + 0x1000);
        assert_eq!(reused.size, 0x1000);
        assert_eq!(reused.physical_ipa, physical_ipa);
        registry.push(reused);

        assert!(
            unregister_alias_entries(&mut registry, va, 0x1000, Some(root_slot)).is_empty(),
            "unmapping the old sibling must retain the frame owned by the reused page",
        );
        assert_eq!(registry, vec![reused]);
        assert_eq!(
            unregister_alias_entries(&mut registry, va + 0x1000, 0x1000, Some(root_slot),),
            std::collections::BTreeSet::from([(physical_ipa, 0x4000)]),
            "the physical lease retires only after the reused page is also unmapped",
        );
    }

    #[test]
    fn alias_registry_prefix_unmap_preserves_exact_suffix() {
        let va = 0x1383_1000_0000;
        let ipa = carrick_mem::memory::LINUX_ALIAS_IPA_BASE + 0x7c00_0000;
        let alias = AliasBacking {
            start: va,
            ipa,
            host_addr: 0x2234_0000,
            size: 0xc000,
            physical_ipa: ipa,
            physical_host_addr: 0x2234_0000,
            physical_size: 0xc000,
            perms: u64::from(applevisor::memory::MemPerms::ReadWrite),
            guest_writable: true,
            sharing: GuestMappingSharing::ForkSharedAnonymous,
            ownership_scope: AliasOwnershipScope::Root,
            inventory_backing: InventoryBackingIdentity::SharedAnon(44),
            shared_key_base: 0,
            shared_key_offset: 0,
            owner_generation: 0,
        };
        register_shared_alias(alias);
        unregister_alias(va, 0x4000, None);
        let fragment = alias_registry()
            .lock()
            .iter()
            .find(|entry| entry.start == va + 0x4000)
            .copied()
            .expect("suffix fragment");
        assert_eq!(
            (fragment.ipa, fragment.host_addr, fragment.size),
            (ipa + 0x4000, alias.host_addr + 0x4000, 0x8000)
        );
        assert_eq!(
            (fragment.physical_ipa, fragment.physical_size),
            (ipa, 0xc000)
        );
        let frame =
            carrick_hal::FrameId::from_kernel_allocation(std::num::NonZeroU64::new(9011).unwrap());
        let inventory = std::collections::BTreeMap::from([(
            (alias.physical_ipa, alias.physical_size as u64),
            super::InventoryExtent {
                frame,
                mapping: carrick_hal::MappingId::from_kernel_allocation(
                    std::num::NonZeroU64::new(9012).unwrap(),
                ),
                backing: alias.inventory_backing,
                stage2_base: alias.physical_ipa,
                stage2_length: alias.physical_size as u64,
            },
        )]);
        assert_eq!(
            inherited_fork_inventory_extents(
                &super::ThreadMappingDesc::from_alias(fragment).unwrap(),
                &inventory,
            )
            .pop()
            .expect("suffix retains inherited mapping")
            .1
            .frame,
            frame,
            "the exact suffix must remain forkable through the retained physical extent",
        );
        unregister_alias(va, 0xc000, None);
    }

    #[test]
    fn alias_registry_suffix_unmap_preserves_exact_prefix() {
        let va = 0x1383_2000_0000;
        let ipa = carrick_mem::memory::LINUX_ALIAS_IPA_BASE + 0x7b00_0000;
        let alias = AliasBacking {
            start: va,
            ipa,
            host_addr: 0x3234_0000,
            size: 0xc000,
            physical_ipa: ipa,
            physical_host_addr: 0x3234_0000,
            physical_size: 0xc000,
            perms: u64::from(applevisor::memory::MemPerms::ReadWrite),
            guest_writable: true,
            sharing: GuestMappingSharing::ForkSharedAnonymous,
            ownership_scope: AliasOwnershipScope::Root,
            inventory_backing: InventoryBackingIdentity::SharedAnon(45),
            shared_key_base: 0,
            shared_key_offset: 0,
            owner_generation: 0,
        };
        register_shared_alias(alias);
        unregister_alias(va + 0x8000, 0x4000, None);
        let fragment = alias_registry()
            .lock()
            .iter()
            .find(|entry| entry.start == va)
            .copied()
            .expect("prefix fragment");
        assert_eq!(
            (fragment.ipa, fragment.host_addr, fragment.size),
            (ipa, alias.host_addr, 0x8000)
        );
        assert_eq!(
            (fragment.physical_ipa, fragment.physical_size),
            (ipa, 0xc000)
        );
        let frame =
            carrick_hal::FrameId::from_kernel_allocation(std::num::NonZeroU64::new(9021).unwrap());
        let inventory = std::collections::BTreeMap::from([(
            (alias.physical_ipa, alias.physical_size as u64),
            super::InventoryExtent {
                frame,
                mapping: carrick_hal::MappingId::from_kernel_allocation(
                    std::num::NonZeroU64::new(9022).unwrap(),
                ),
                backing: alias.inventory_backing,
                stage2_base: alias.physical_ipa,
                stage2_length: alias.physical_size as u64,
            },
        )]);
        assert_eq!(
            inherited_fork_inventory_extents(
                &super::ThreadMappingDesc::from_alias(fragment).unwrap(),
                &inventory,
            )
            .pop()
            .expect("prefix retains inherited mapping")
            .1
            .frame,
            frame,
            "the exact prefix must remain forkable through the retained physical extent",
        );
        unregister_alias(va, 0xc000, None);
    }

    #[test]
    fn alias_registry_full_semantic_unmap_rejects_hvf_padding() {
        let va = 0x1383_3000_0000;
        let ipa = carrick_mem::memory::LINUX_ALIAS_IPA_BASE + 0x7a00_0000;
        let guest_size = 0x1000;
        let physical_size = HVF_PAGE_SIZE as usize;
        let host_mapping = crate::host_mapping::OwnedHostMapping::map_shared_anon(
            physical_size,
            crate::host_mapping::HostMappingKind::SharedAnon,
        )
        .expect("16-KiB physical alias backing");
        let region = HvfMappedRegion {
            start: va,
            ipa,
            physical_ipa: ipa,
            end: va + guest_size as u64,
            host_addr: host_mapping.as_ptr(),
            size: host_mapping.len(),
            physical_size,
            perms: applevisor::memory::MemPerms::ReadWrite,
            memory: None,
            host_mapping: None,
            stage2_lease: None,
            is_dynamic_alias: true,
            sharing: GuestMappingSharing::ForkSharedAnonymous,
            guest_writable: true,
            shared_key_base: 0,
            shared_key_offset: 0,
            owner_generation: 0,
        };
        let desc = ThreadMappingDesc::from_region(&region);
        assert_eq!(desc.size, guest_size, "thread/fork semantics stay exact");
        assert_eq!(
            desc.physical_size, physical_size,
            "the whole HVF granule remains the replay/lifetime extent"
        );
        let alias = AliasBacking {
            start: desc.start,
            ipa: desc.ipa,
            host_addr: desc.host_addr as usize,
            size: desc.size,
            physical_ipa: desc.physical_ipa,
            physical_host_addr: desc.physical_host_addr as usize,
            physical_size: desc.physical_size,
            perms: u64::from(desc.perms),
            guest_writable: desc.guest_writable,
            sharing: desc.sharing,
            ownership_scope: AliasOwnershipScope::Root,
            inventory_backing: InventoryBackingIdentity::SharedAnon(46),
            shared_key_base: 0,
            shared_key_offset: 0,
            owner_generation: 0,
        };
        register_shared_alias(alias);

        unregister_alias(va, guest_size, None);
        let fragments: Vec<_> = alias_registry()
            .lock()
            .iter()
            .copied()
            .filter(|entry| entry.physical_ipa == ipa)
            .collect();
        let padding_replay_candidate = lookup_shared_alias(ipa + guest_size as u64);
        let fork_candidates =
            missing_process_aliases(&std::collections::HashSet::new(), &fragments, None);

        alias_registry()
            .lock()
            .retain(|entry| entry.physical_ipa != ipa);
        forget_replay_extent(ipa, physical_size);

        assert!(
            fragments.is_empty(),
            "fully unmapping the 4-KiB guest extent must not retain 12 KiB of HVF padding"
        );
        assert!(
            padding_replay_candidate.is_none(),
            "physical padding must not resolve into a lazy replay authority"
        );
        assert!(
            fork_candidates.is_empty(),
            "physical padding must not enter a descendant's semantic inventory"
        );
    }

    #[test]
    fn fork_source_uses_live_alias_inventory_not_retired_mapping_owners() {
        let root_slot = (
            carrick_mem::memory::LINUX_HVPATCH_ROOT_SLOT_BASE,
            2 * 1024 * 1024,
        );
        let va = 0x1382_8ed0_0000;
        let retired_ipa = root_slot.0 + 0x20_0000;
        let live_ipa = root_slot.0 + 0x40_0000;
        let mapping = |ipa, host_addr, is_dynamic_alias| HvfMappedRegion {
            start: va,
            ipa,
            physical_ipa: ipa,
            end: va + 0x4000,
            host_addr: host_addr as *mut u8,
            size: 0x4000,
            physical_size: 0x4000,
            perms: applevisor::memory::MemPerms::ReadWrite,
            memory: None,
            host_mapping: None,
            stage2_lease: None,
            is_dynamic_alias,
            sharing: GuestMappingSharing::Private,
            guest_writable: true,
            shared_key_base: 0,
            shared_key_offset: 0,
            owner_generation: 0,
        };
        let live_alias = AliasBacking {
            start: va,
            ipa: live_ipa,
            host_addr: 0x3000,
            size: 0x4000,
            physical_ipa: live_ipa,
            physical_host_addr: 0x3000,
            physical_size: 0x4000,
            perms: u64::from(applevisor::memory::MemPerms::ReadWrite),
            guest_writable: true,
            sharing: GuestMappingSharing::ForkSharedAnonymous,
            ownership_scope: AliasOwnershipScope::MmRootSlot {
                base: root_slot.0,
                size: root_slot.1,
            },
            inventory_backing: InventoryBackingIdentity::SharedAnon(43),
            shared_key_base: 0,
            shared_key_offset: 0,
            owner_generation: 0,
        };

        assert!(
            !mapping_is_current_for_process_fork_test(
                &mapping(retired_ipa, 0x2000, true),
                &[live_alias],
                Some(root_slot),
            ),
            "a retained stage-2 lifetime owner is not a live child mapping"
        );
        assert!(mapping_is_current_for_process_fork_test(
            &mapping(live_ipa, 0x3000, true),
            &[live_alias],
            Some(root_slot),
        ));
        assert!(
            mapping_is_current_for_process_fork_test(
                &mapping(root_slot.0, 0x4000, false),
                &[],
                Some(root_slot),
            ),
            "structural boot mappings do not depend on the dynamic alias registry"
        );
    }

    #[test]
    fn sparse_shared_aperture_owner_does_not_require_a_base_leaf() {
        assert!(!super::fork_mapping_requires_base_translation(
            crate::memory::LINUX_SHARED_FILE_BASE,
            crate::memory::LINUX_SHARED_FILE_SIZE as usize,
            false,
        ));
        assert!(super::fork_mapping_requires_base_translation(
            crate::memory::LINUX_SHARED_FILE_BASE,
            0x4000,
            true,
        ));
        assert!(super::fork_mapping_requires_base_translation(
            crate::memory::LINUX_MMAP_BASE,
            crate::memory::mmap_arena_size() as usize,
            false,
        ));
    }

    #[test]
    fn process_fork_includes_sibling_owned_private_aliases() {
        let root_slot = (
            carrick_mem::memory::LINUX_HVPATCH_ROOT_SLOT_BASE,
            2 * 1024 * 1024,
        );
        let local_ipa = root_slot.0 + 0x20_0000;
        let sibling_ipa = root_slot.0 + 0x40_0000;
        let foreign_ipa = root_slot.0 + root_slot.1 + 0x20_0000;
        let alias = |ipa, ownership_scope| AliasBacking {
            start: 0x1400_0000_0000 + ipa,
            ipa,
            host_addr: 0x1000,
            size: 0x4000,
            physical_ipa: ipa,
            physical_host_addr: 0x1000,
            physical_size: 0x4000,
            perms: u64::from(applevisor::memory::MemPerms::ReadWrite),
            guest_writable: true,
            sharing: GuestMappingSharing::Private,
            ownership_scope,
            inventory_backing: InventoryBackingIdentity::Private(ipa),
            shared_key_base: 0,
            shared_key_offset: 0,
            owner_generation: 0,
        };
        let local_ipas = std::collections::HashSet::from([local_ipa]);
        let local_scope = AliasOwnershipScope::MmRootSlot {
            base: root_slot.0,
            size: root_slot.1,
        };
        let aliases = [
            alias(local_ipa, local_scope),
            alias(sibling_ipa, local_scope),
            alias(
                foreign_ipa,
                AliasOwnershipScope::MmRootSlot {
                    base: root_slot.0 + root_slot.1,
                    size: root_slot.1,
                },
            ),
        ];

        let missing = missing_process_aliases(&local_ipas, &aliases, Some(root_slot));

        assert_eq!(missing.len(), 1);
        assert_eq!(missing[0].ipa, sibling_ipa);
    }

    #[test]
    fn retired_local_alias_row_does_not_mask_live_fragment_at_same_ipa() {
        let root_slot = (0x9000_0000, 0x20_0000);
        let va = 0x0060_000a_8000;
        let ipa = 0x009b_0033_8000;
        let mapping = HvfMappedRegion {
            start: va,
            ipa,
            physical_ipa: ipa,
            end: va + 0x4000,
            host_addr: 0x2000 as *mut u8,
            size: 0x4000,
            physical_size: 0x4000,
            perms: applevisor::memory::MemPerms::ReadWrite,
            memory: None,
            host_mapping: None,
            stage2_lease: None,
            is_dynamic_alias: true,
            sharing: GuestMappingSharing::Private,
            guest_writable: true,
            shared_key_base: 0,
            shared_key_offset: 0,
            owner_generation: 0,
        };
        let live_fragment = AliasBacking {
            start: va + 0x2000,
            ipa: ipa + 0x2000,
            host_addr: 0x4000,
            size: 0x2000,
            physical_ipa: ipa,
            physical_host_addr: 0x2000,
            physical_size: 0x4000,
            perms: u64::from(applevisor::memory::MemPerms::ReadWrite),
            guest_writable: true,
            sharing: GuestMappingSharing::Private,
            ownership_scope: AliasOwnershipScope::MmRootSlot {
                base: root_slot.0,
                size: root_slot.1,
            },
            inventory_backing: InventoryBackingIdentity::Private(44),
            shared_key_base: 0,
            shared_key_offset: 0,
            owner_generation: 0,
        };
        let aliases = [live_fragment];

        let current = current_dynamic_alias_ipas(&[mapping], &aliases, Some(root_slot));
        assert!(current.is_empty(), "the unsplit local owner is retired");
        assert_eq!(
            missing_process_aliases(&current, &aliases, Some(root_slot)),
            vec![live_fragment],
            "the retired row must not suppress the live suffix from fork arming",
        );
    }
}
