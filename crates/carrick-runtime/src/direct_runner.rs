//! Wire tier D's directly-executed guests to the real syscall dispatcher.
//!
//! Tier D (`carrick_native_darwin::direct`) runs guest code natively and sends
//! every patched `svc` to a handler. This module is what that handler calls:
//! the same `SyscallDispatcher` the translated lane uses, so the two tiers
//! differ only in how guest code REACHES a syscall, never in what a syscall
//! means. One dispatcher is the point — a second implementation would give
//! every future conformance result two answers to reconcile.
//!
//! # Guest VA is host VA
//!
//! The guest executes in carrick's own address space, so a pointer it hands to
//! a syscall is already a valid host pointer. `IdentityMemory` is therefore a
//! near-empty `GuestMemory`: no translation table, no guest-physical mapping,
//! no alias window. That is the structural simplification direct execution
//! buys, and it is why this file is short.
//!
//! # Threads
//!
//! A guest `clone(CLONE_VM|CLONE_THREAD)` spawns a real host thread whose
//! guest enters tier D with its own `DirectThreadSlots` (roadmap Phase 1
//! item 4): the emitted veneers and islands resolve per-thread state through
//! Darwin's TSD (`carrick_native_darwin::direct::thread_slots_tsd`), so one
//! patched image serves every thread. Syscalls dispatch through
//! `dispatch_threaded` — the same thread-aware path the DSR native lane uses
//! — with this runner's `ThreadRegistry` and `FutexTable`; `exit(2)` from a
//! non-last thread retires just that thread (CLEARTID write + futex wake),
//! and `FUTEX_WAIT` parks on the shared table.
//!
//! # How a run ends: the guest-leave contract
//!
//! A tier-D guest leaves through the handler, never by returning to Rust with
//! its own stack discipline (the full contract lives in
//! `carrick_native_darwin::direct`). Concretely for this runner: any dispatch
//! outcome that ends or suspends the run — `Exit`, a thread's `ThreadExit`,
//! and every outcome tier D does not implement yet (`Execve`, `Fork`, signal
//! delivery, fd waits) — makes the handler request a leave. The island's
//! leave leg then returns control to `DirectLoadGroup::enter`'s caller with
//! the guest's complete state parked in its per-thread context, and
//! `DirectRunner::outcome` names why the run stopped. The guest is never
//! resumed past such a syscall with a fabricated errno.

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, Instant};

use carrick_abi::{CanonicalNr, LinuxGuestAbi, NativeNr, SigSet};
use carrick_guest_mem::{GuestMemory, MemoryError};
use carrick_hal::{Reg, RegAccess, SysReg, SyscallTrap, TrapError};
use carrick_native_darwin::direct::{
    DirectLoadGroup, DirectThreadSlots, GuestContext, InstalledThreadSlots,
    current_thread_slots_ptr, install_dynamic_publication_handler,
};

use crate::compat::{CompatEvent, CompatReporter, SyscallArgs};
use crate::dispatch::{DispatchOutcome, SyscallDispatcher, SyscallRequest};
use crate::thread::ThreadId;

/// Lock without poisoning semantics: the guarded state is only mutated by
/// guest threads parked in the handler, so a poisoned lock means a panic
/// already unwound past us and the data is still sound.
fn lock<T>(mutex: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    mutex
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

/// As [`lock`], for the registry's `RwLock` (read side).
fn read_lock<T>(lock: &RwLock<T>) -> std::sync::RwLockReadGuard<'_, T> {
    lock.read()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

/// As [`lock`], for the registry's `RwLock` (write side — fork-child reset
/// only).
fn write_lock<T>(lock: &RwLock<T>) -> std::sync::RwLockWriteGuard<'_, T> {
    lock.write()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

/// Exact control arm for the Tier-D pristine-discard optimization. Default
/// on; `0` restores the prior unconditional zero + i-cache publication for a
/// same-binary performance comparison.
fn pristine_dynamic_exec_discard_enabled() -> bool {
    static ENABLED: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *ENABLED.get_or_init(|| {
        std::env::var_os("CARRICK_TIER_D_PRISTINE_DISCARD").as_deref()
            != Some(std::ffi::OsStr::new("0"))
    })
}

/// Apple Silicon's host page size. On the identity tier this IS the guest's
/// page size (`AT_PAGESZ`, brk/mmap granularity): guest mappings are host
/// mappings, so nothing smaller is protectable or mappable.
const HOST_PAGE_SIZE: u64 = 16 * 1024;

/// Guest memory for a directly-executed image: guest addresses ARE host
/// addresses.
///
/// Accesses are bounds-checked against the window the runner was built with,
/// so a guest pointer that escapes it surfaces as `EFAULT` rather than as a
/// segfault inside carrick.
#[derive(Debug, Clone, Copy)]
pub struct IdentityMemory {
    base: u64,
    len: u64,
}

impl IdentityMemory {
    pub fn new(base: u64, len: u64) -> Self {
        Self { base, len }
    }

    fn resolve(&self, address: u64, length: usize) -> Result<*mut u8, MemoryError> {
        let end = address
            .checked_add(length as u64)
            .ok_or(MemoryError::OutOfBounds { address, length })?;
        if address < self.base || end > self.base.saturating_add(self.len) {
            return Err(MemoryError::OutOfBounds { address, length });
        }
        Ok(address as usize as *mut u8)
    }
}

impl GuestMemory for IdentityMemory {
    /// Kernel-verified copyin: the identity tier keeps NO mapping table, so
    /// a guest pointer's validity is only decidable by the kernel. A raw
    /// `memcpy` here SIGSEGVed the whole process on the first bad pointer a
    /// guest handed a syscall (dash's execve argv walk over-read past a
    /// mapping edge — layout-probabilistic, caught live by CrashReporter);
    /// `mach_vm_read_overwrite` performs the same copy with the kernel
    /// checking every page, returning an error the dispatcher lowers to
    /// EFAULT — exactly Linux's copy_from_user contract. Costs a mach trap
    /// per access; a guarded-copy fast path is a named tier-D perf lever.
    fn read_bytes_raw(&self, address: u64, length: usize) -> Result<Vec<u8>, MemoryError> {
        self.resolve(address, length)?;
        let mut out = vec![0_u8; length];
        if length == 0 {
            return Ok(out);
        }
        let mut out_size: mach2::vm_types::mach_vm_size_t = 0;
        // SAFETY: destination is the freshly allocated buffer; the kernel
        // validates the source range and copies at most `length` bytes.
        let kr = unsafe {
            mach2::vm::mach_vm_read_overwrite(
                mach2::traps::mach_task_self(),
                address,
                length as mach2::vm_types::mach_vm_size_t,
                out.as_mut_ptr() as mach2::vm_types::mach_vm_address_t,
                &mut out_size,
            )
        };
        if kr != mach2::kern_return::KERN_SUCCESS || out_size != length as u64 {
            return Err(MemoryError::OutOfBounds { address, length });
        }
        Ok(out)
    }

    /// Kernel-verified copyout (see [`Self::read_bytes_raw`]): `mach_vm_write`
    /// refuses unmapped and non-writable targets instead of faulting.
    fn write_bytes_raw(&mut self, address: u64, bytes: &[u8]) -> Result<(), MemoryError> {
        self.resolve(address, bytes.len())?;
        if bytes.is_empty() {
            return Ok(());
        }
        // `mach_vm_write` counts in u32; chunk so a giant write still lands.
        for (index, chunk) in bytes.chunks(u32::MAX as usize).enumerate() {
            let target = address + (index as u64) * u64::from(u32::MAX);
            // SAFETY: source is our live slice; the kernel validates the
            // destination range and its writability.
            let kr = unsafe {
                mach2::vm::mach_vm_write(
                    mach2::traps::mach_task_self(),
                    target,
                    chunk.as_ptr() as mach2::vm_types::vm_offset_t,
                    chunk.len() as mach2::message::mach_msg_type_number_t,
                )
            };
            if kr != mach2::kern_return::KERN_SUCCESS {
                return Err(MemoryError::OutOfBounds {
                    address,
                    length: bytes.len(),
                });
            }
        }
        Ok(())
    }
}

/// The exec stack for a directly-executed guest: a host allocation holding
/// the argc/argv/envp/auxv image execve(2) would build, with `sp()` ready for
/// [`carrick_native_darwin::direct::DirectLoadGroup::enter_on_stack`].
///
/// Guest VA is host VA on this tier, so the pointers serialized into the
/// arrays are the allocation's own addresses — nothing to relocate. The
/// serializer and the auxv builder are carrick-mem's, shared with the VMM
/// lanes: one implementation of the exec-stack ABI, not a second drifting
/// copy. The vDSO is NOT advertised (`AT_SYSINFO_EHDR` absent) because tier D
/// does not map one; libc falls back to real syscalls, which the islands
/// service.
pub struct DirectStack {
    base: *mut u8,
    len: usize,
    sp: u64,
    auxv_image: Vec<u8>,
}

// SAFETY: the mapping is owned solely by this value and unmapped in `Drop`.
unsafe impl Send for DirectStack {}

impl DirectStack {
    /// Linux's default `RLIMIT_STACK`.
    pub const SIZE: usize = 8 * 1024 * 1024;

    /// Build the stack for `main_elf` mapped at `main_bias` (the load group's
    /// `main().bias()`).
    ///
    /// `interpreter_base` is the interpreter's load bias when the image is
    /// dynamic — it becomes `AT_BASE`, which ld.so requires to find itself; a
    /// missing `AT_BASE` on a dynamic target and a bogus one on a static
    /// target are both real, shipped bug shapes, so the caller states it
    /// explicitly.
    pub fn build(
        main_elf: &[u8],
        main_bias: u64,
        interpreter_base: Option<u64>,
        argv: &[Vec<u8>],
        envp: &[Vec<u8>],
    ) -> std::io::Result<Self> {
        use goblin::elf::header::EM_AARCH64;
        let plan = carrick_mem::elf::plan_elf_load_bytes_for(main_elf, EM_AARCH64)
            .map_err(std::io::Error::other)?
            .with_load_bias(main_bias);
        let mut auxv = carrick_mem::memory::linux_auxv_from_load_plan_with_vdso(
            &plan,
            interpreter_base,
            false,
        );
        // AT_PAGESZ must be the HOST page size on the identity tier: guest
        // mappings ARE host mappings, so every size/alignment libc derives
        // from it must be host-granular. The default 4096 made glibc round
        // its RELRO bounds to 4 KiB and the host mprotect EINVALed — ld.so
        // itself reported "cannot apply additional memory protection after
        // relocation" and exited 127.
        for entry in &mut auxv {
            if entry.a_type == carrick_abi::LINUX_AT_PAGESZ {
                *entry =
                    carrick_abi::LinuxAuxvEntry::new(carrick_abi::LINUX_AT_PAGESZ, HOST_PAGE_SIZE);
            }
        }
        let len = Self::SIZE;
        // SAFETY: fresh anonymous host mapping; the kernel picks the address.
        let base = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                len,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_PRIVATE | libc::MAP_ANON,
                -1,
                0,
            )
        };
        if base == libc::MAP_FAILED {
            return Err(std::io::Error::last_os_error());
        }
        let base = base.cast::<u8>();
        let stack_top = base as u64 + len as u64;
        let (region, sp, auxv_image) = carrick_mem::memory::build_linux_initial_stack(
            argv.to_vec(),
            envp.to_vec(),
            &auxv,
            None,
            stack_top,
            len as u64,
        )
        .map_err(|error| {
            // SAFETY: undo the mapping this constructor owns before failing.
            unsafe { libc::munmap(base.cast(), len) };
            std::io::Error::other(error)
        })?;
        // Everything the serializer initialized sits at or above the SP
        // offset (strings at the top, pointer arrays at SP); the pages below
        // are the guest's to grow into and stay untouched zero-fill.
        let initialized = (sp - region.start) as usize;
        // SAFETY: `region` spans exactly [base, base+len); copying its
        // initialized tail into the live mapping at the same offsets.
        unsafe {
            std::ptr::copy_nonoverlapping(
                region.bytes()[initialized..].as_ptr(),
                base.add(initialized),
                region.bytes().len() - initialized,
            );
        }
        Ok(Self {
            base,
            len,
            sp,
            auxv_image,
        })
    }

    /// The initial guest SP: 16-aligned, pointing at argc.
    pub fn sp(&self) -> u64 {
        self.sp
    }

    /// The exact auxv byte image on the stack (`/proc/self/auxv`'s content).
    pub fn auxv_image(&self) -> &[u8] {
        &self.auxv_image
    }
}

impl Drop for DirectStack {
    fn drop(&mut self) {
        // SAFETY: this value owns the mapping.
        unsafe { libc::munmap(self.base.cast(), self.len) };
    }
}

/// Why a directly-executed guest stopped.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DirectRunOutcome {
    Exited {
        code: i32,
    },
    /// The Linux process was terminated by the default action for this guest
    /// signal. Kept distinct from `Exited { 128 + signum }`: the shipped
    /// driver must make its host child die by the mapped host signal so a
    /// guest parent observes `WIFSIGNALED`, not a normal shell-style exit.
    Signaled {
        signum: i32,
    },
    /// A fully prepared eligible Tier-D image is waiting outside the guest
    /// boundary. The driver drops the outgoing group/stack, commits exec
    /// process state, then enters this replacement without a host execve.
    ExecReplacement,
    /// The dispatcher produced an outcome tier D does not implement yet
    /// (fd waits, fork, execve, signal delivery). Named rather than
    /// approximated: the guest LEAVES through the island's leave leg with its
    /// full state parked in the context — never resumed with a fabricated
    /// errno — and the translated lane's loop shows what tier D has to grow
    /// before it can claim these outcomes.
    Unsupported {
        syscall: u64,
        outcome: String,
    },
}

/// What the island should do when the handler returns.
enum ServiceVerdict {
    /// Write `x0` and resume the guest at the instruction after the `svc`.
    Resume(i64),
    /// Leave guest execution: the run's outcome is recorded and the guest's
    /// state stays parked in the context (guest-leave contract).
    Leave,
}

/// The identity tier's program break: a lazily created host reservation the
/// guest's `brk(2)` grows into.
///
/// Linux puts the initial break after the main image's bss; the VALUE is
/// unobservable to a correct guest (it only uses what `brk` returns), so the
/// identity tier reserves an arbitrary host range instead. Growth commits
/// pages (`mprotect` RW over untouched reservation = zero-fill on first
/// touch); shrink REPLACES the released pages with a fresh `PROT_NONE`
/// mapping so a later regrowth re-delivers zeros — the anonymous-memory
/// guarantee is immovable.
struct IdentityBrk {
    base: u64,
    current: u64,
}

impl IdentityBrk {
    /// 1 GiB of reserved (PROT_NONE, uncommitted) break headroom.
    const RESERVE: usize = 1 << 30;
}

/// Placement hint cursor for the identity tier's non-fixed anonymous
/// mappings.
///
/// Without a hint the kernel packs guest reservations into the crowded
/// region near the images and dyld's neighbors, and a `MAP_FIXED` exec
/// window landing there can find NO free island-arena slot within the
/// ±128 MiB `b` range — observed as a load- and layout-probabilistic
/// fail-closed refusal (`island for site 0x106c50000 out of ±128 MiB branch
/// range`, ~1/30 runs of the CPython print gate). Hinting reservations into
/// sparse space keeps the arena neighborhood free. This is a HINT: without
/// `MAP_FIXED` the kernel relocates when the range is occupied, so the
/// fallback is exactly the unhinted behavior — never a clobber, never an
/// error.
///
/// The base sits at the DSR biased lane's reservation ceiling
/// ([`carrick_dsr::address::BIASED_HOST_RESERVATION_CEILING`], 5 TiB): a
/// first cut used 32 GiB — exactly `BIAS_CANDIDATES[0]` — and this cursor's
/// process-lifetime guest mappings then starved the biased lane's
/// candidate probe into `NoCollisionFreeBias` when both tiers ran in one
/// process. Probed on this host: plain-anon hints are honored at 5 TiB
/// (and everywhere sampled from 32 GiB to 15 TiB); below 32 GiB they are
/// relocated into the default anon area (0x7000000000 — the crowd to
/// avoid).
static ANON_HINT_CURSOR: AtomicU64 =
    AtomicU64::new(carrick_dsr::address::BIASED_HOST_RESERVATION_CEILING);

/// One plain anonymous PRIVATE RW mapping this runner created for the guest,
/// tracked so `mremap` can be serviced with PROOF instead of guesswork: the
/// identity tier keeps no general mapping table, and moving or growing a
/// mapping is only sound when its backing is known to be private anonymous
/// memory whose contents a copy preserves. Any protection change over a
/// tracked range untracks it (`mremap` there fails closed).
#[derive(Debug, Clone, Copy)]
struct AnonRwRange {
    base: u64,
    end: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum IdentityMadviseRange {
    PlainAnonRw,
    PlainAnonNone,
    PlainAnonMixed,
    DynamicExec,
}

/// Whether `[lo, hi)` is completely covered by the union of the supplied
/// private-anonymous provenance spans. Protection splits may make adjacent
/// pieces separate entries; overlap and adjacency both close the cursor.
fn anon_range_union_covers(rw: &[AnonRwRange], none: &[AnonRwRange], lo: u64, hi: u64) -> bool {
    if lo >= hi {
        return false;
    }
    let mut spans: Vec<_> = rw.iter().chain(none).copied().collect();
    spans.sort_unstable_by_key(|span| span.base);
    let mut cursor = lo;
    for span in spans {
        if span.end <= cursor || hi <= span.base {
            continue;
        }
        if cursor < span.base {
            return false;
        }
        cursor = cursor.max(span.end);
        if hi <= cursor {
            return true;
        }
    }
    false
}

/// Remove `[lo, hi)` from the tracked ranges, splitting an entry that
/// straddles it.
fn subtract_anon_range(table: &mut Vec<AnonRwRange>, lo: u64, hi: u64) {
    if lo >= hi {
        return;
    }
    let mut split = Vec::new();
    table.retain_mut(|entry| {
        if entry.end <= lo || hi <= entry.base {
            return true;
        }
        if entry.base < lo && hi < entry.end {
            split.push(AnonRwRange {
                base: hi,
                end: entry.end,
            });
            entry.end = lo;
            return true;
        }
        if entry.base < lo {
            entry.end = lo;
            return true;
        }
        if hi < entry.end {
            entry.base = hi;
            return true;
        }
        false
    });
    table.extend(split);
}

/// A directly-executed guest plus the dispatcher that serves it.
///
/// Shared (`&self`) by every guest THREAD of the run: syscalls dispatch
/// through [`SyscallDispatcher::dispatch_threaded`] — the same thread-aware
/// path the DSR native lane uses — with this runner's own `ThreadRegistry`
/// and `FutexTable`, and all runner state is behind atomics/mutexes.
pub struct DirectRunner {
    dispatcher: SyscallDispatcher,
    /// One process-lifetime reporter, matching the shared dispatcher path.
    /// Identity-memory syscalls bypass `dispatch_threaded`, so the runner
    /// brackets those six calls itself; otherwise Tier-D mmap/mprotect work
    /// is invisible to the standard syscall probes and counters.
    reporter: CompatReporter,
    memory: IdentityMemory,
    /// The PROCESS outcome, first-wins: `exit_group`, a named unsupported
    /// leave, or (when the last thread leaves via `exit(2)`) that thread's
    /// code.
    outcome: Mutex<Option<DirectRunOutcome>>,
    /// Set with a process-ending outcome so futex-parked guest threads
    /// retire instead of blocking a run that is over.
    exiting: AtomicBool,
    syscalls: AtomicU64,
    brk: Mutex<Option<IdentityBrk>>,
    /// Plain anonymous private RW mappings this runner created — the only
    /// ranges `mremap` is provably safe to service (see [`AnonRwRange`]).
    anon_rw: Mutex<Vec<AnonRwRange>>,
    /// Untouched private anonymous PROT_NONE reservations. A Linux RWX
    /// promotion is lowered to MAP_JIT only inside this provenance class:
    /// replacing it preserves bytes because every page is provably zero and
    /// inaccessible since creation.
    anon_none: Mutex<Vec<AnonRwRange>>,
    /// Every ordinary host mapping created on behalf of this identity guest,
    /// independent of its current protection/provenance.  A real host
    /// `execve` used to retire these implicitly; an in-process exec must own
    /// the complete catalog so it can unmap the outgoing address space before
    /// entering the replacement image.  Load-group images/windows and the
    /// initial stack have their own RAII owners and are deliberately absent.
    owned_mappings: Mutex<Vec<AnonRwRange>>,
    /// One guest thread = one host thread; tids come from here (main tid =
    /// host pid, exactly the native lane's convention). Behind an `RwLock`
    /// solely so a FORK CHILD can replace it with a fresh registry keyed to
    /// its own pid (`ThreadRegistry`'s main tid is immutable by design);
    /// every other access is a read.
    registry: RwLock<Arc<crate::thread::ThreadRegistry>>,
    /// Explicit Linux identity for each backend-local execution thread.
    linux_tids: RwLock<std::collections::BTreeMap<ThreadId, crate::kernel::LinuxTid>>,
    /// Private-futex parking for this guest, shared with the dispatcher's
    /// futex handler so waits and wakes meet in one table. `Arc` so it can be
    /// published as the PROCESS-current table
    /// (`crate::thread::set_current_futex_table`) — that is how out-of-band
    /// wake sources (timer fallback threads via
    /// `notify_current_futex_signal_pending`) reach futex-parked tier-D
    /// guest threads when a signal becomes pending.
    futex: Arc<crate::thread::FutexTable>,
    /// Host threads spawned for guest `clone(CLONE_THREAD)`s; joined by
    /// [`with_runner`] before it returns.
    threads: Mutex<Vec<std::thread::JoinHandle<()>>>,
    /// Execve services for the SHIPPED driver: the execution plan and trap
    /// budget `tier_d_service_execve` forwards into the existing capsule
    /// self-re-exec path. `None` outside the shipped binary (unit tests):
    /// `begin_guest_exec` re-execs `current_exe`, which is only sound when
    /// that executable is the carrick CLI — a test binary would re-enter its
    /// own harness — so without services an execve LEAVES named, as before.
    exec: Option<DirectExecServices>,
    /// Fully prepared incoming image for an `ExecReplacement` outcome.
    exec_replacement: Mutex<Option<DirectExecReplacement>>,
    /// Child-side write end of the private vfork completion pipe.  Host
    /// execve formerly closed this through FD_CLOEXEC; in-process exec closes
    /// it explicitly at the commit point so the parent cannot resume early.
    vfork_completion_fd: Mutex<Option<i32>>,
    /// True in a host process created by THIS runner servicing a guest
    /// `fork(2)`: the run loop above `with_runner` must `_exit` with the
    /// child's outcome instead of continuing the caller's control flow
    /// (the shipped driver's child branch already does; tests must too).
    forked_child: AtomicBool,
}

/// What [`DirectRunner`] needs to service `execve(2)` through the existing
/// host self-re-exec capsule (see [`DirectRunner::exec`]). Crate-visible
/// only: the plan type is the driver's, and only the shipped driver may
/// install exec services (a test binary must not self-re-exec).
pub(crate) struct DirectExecServices {
    pub(crate) plan: crate::page_profile::ExecutionPlan,
    pub(crate) max_traps: usize,
}

/// A replacement Tier-D image whose complete fallible preparation happened
/// while the outgoing guest was still intact.  Once stored on the runner,
/// leaving the syscall island is the exec point of no return; the driver can
/// commit without parsing, allocating, or scanning any new executable bytes.
pub(crate) struct DirectExecReplacement {
    pub(crate) group: DirectLoadGroup,
    pub(crate) stack: DirectStack,
    pub(crate) resolved: String,
    pub(crate) argv: Vec<Vec<u8>>,
    pub(crate) env: Vec<Vec<u8>>,
}

impl Drop for DirectRunner {
    fn drop(&mut self) {
        self.retire_identity_memory();
        if let Some(fd) = lock(&self.vfork_completion_fd).take() {
            // SAFETY: the runner owns this raw child-side pipe fd.
            unsafe { libc::close(fd) };
        }
    }
}

impl DirectRunner {
    pub fn new(dispatcher: SyscallDispatcher, memory: IdentityMemory) -> Self {
        let futex = Arc::new(crate::thread::FutexTable::new());
        let registry = Arc::new(crate::thread::ThreadRegistry::new(
            ThreadId::main_from_host_pid(),
        ));
        // `/proc/self/task`, per-tid `/proc` state, and async thread-directed
        // routing resolve through the process-current registry because those
        // paths do not carry a syscall context. Tier D owns a real MT
        // registry too; failing to publish it made CPython count one task
        // before fork and suppress its required multithreaded-fork warning.
        crate::thread::set_current_registry(Arc::clone(&registry));
        // Publish the table process-wide so timer fallback threads
        // (`deliver_native_process_signal` → notify_current_futex_signal_
        // pending) wake tier-D futex parks, and register the native
        // TimerDelivery so a tier-D guest's setitimer/timer_settime arms the
        // fallback threads at all (set-once; the DSR boot registers the same
        // implementation).
        crate::thread::set_current_futex_table(&futex);
        crate::native_darwin::ensure_native_timer_delivery();
        let root_linux_tid = match dispatcher.capture_one_task_context() {
            Ok(context) => context.thread().key().tid,
            Err(error) => {
                tracing::error!(%error, "direct runner lost its one-task Kernel binding");
                std::process::abort();
            }
        };
        Self {
            dispatcher,
            reporter: CompatReporter::default(),
            memory,
            outcome: Mutex::new(None),
            exiting: AtomicBool::new(false),
            syscalls: AtomicU64::new(0),
            brk: Mutex::new(None),
            anon_rw: Mutex::new(Vec::new()),
            anon_none: Mutex::new(Vec::new()),
            owned_mappings: Mutex::new(Vec::new()),
            registry: RwLock::new(registry),
            linux_tids: RwLock::new(std::collections::BTreeMap::from([(
                ThreadId::main_from_host_pid(),
                root_linux_tid,
            )])),
            futex,
            threads: Mutex::new(Vec::new()),
            exec: None,
            exec_replacement: Mutex::new(None),
            vfork_completion_fd: Mutex::new(None),
            forked_child: AtomicBool::new(false),
        }
    }

    /// Record one ordinary guest mapping. MAP_FIXED replacement first
    /// subtracts the target from the catalog so the owned spans stay
    /// non-overlapping and exec teardown never reaches outside guest memory.
    fn record_owned_mapping(&self, base: u64, length: u64) {
        let end = base.saturating_add(length.next_multiple_of(HOST_PAGE_SIZE));
        carrick_native_darwin::direct::reserve_exec_hints_past(end);
        let mut mappings = lock(&self.owned_mappings);
        subtract_anon_range(&mut mappings, base, end);
        mappings.push(AnonRwRange { base, end });
    }

    fn forget_owned_mapping(&self, base: u64, length: u64) {
        let end = base.saturating_add(length.next_multiple_of(HOST_PAGE_SIZE));
        subtract_anon_range(&mut lock(&self.owned_mappings), base, end);
    }

    /// Retire all identity-memory state owned by the outgoing guest.  The
    /// caller separately drops its `DirectLoadGroup` and `DirectStack`, whose
    /// mappings are not part of this catalog.
    fn retire_identity_memory(&self) {
        for mapping in std::mem::take(&mut *lock(&self.owned_mappings)) {
            // SAFETY: the catalog contains only successful guest mmap results.
            unsafe {
                libc::munmap(
                    mapping.base as usize as *mut libc::c_void,
                    (mapping.end - mapping.base) as usize,
                );
            }
        }
        if let Some(brk) = lock(&self.brk).take() {
            // SAFETY: this runner owns the reservation.
            unsafe { libc::munmap(brk.base as usize as *mut libc::c_void, IdentityBrk::RESERVE) };
        }
        lock(&self.anon_rw).clear();
        lock(&self.anon_none).clear();
    }

    /// Remember the child-side vfork completion fd until exec commits (or
    /// process exit/drop closes it).
    fn hold_vfork_completion_fd(&self, fd: i32) {
        let prior = lock(&self.vfork_completion_fd).replace(fd);
        debug_assert!(prior.is_none(), "one live vfork completion per process");
        if let Some(prior) = prior {
            // SAFETY: defensive leak avoidance for a violated invariant.
            unsafe { libc::close(prior) };
        }
    }

    /// Commit the runner-owned half of an in-process exec replacement after
    /// the new group and stack have been prepared and the old group/stack
    /// have been dropped.  Closing the vfork completion fd is intentionally
    /// last: that close publishes successful exec to the suspended parent.
    pub(crate) fn commit_in_process_exec(&self) {
        self.retire_identity_memory();
        *lock(&self.outcome) = None;
        self.exiting.store(false, Ordering::SeqCst);
        if let Some(fd) = lock(&self.vfork_completion_fd).take() {
            // SAFETY: the runner owns this child-side raw fd.
            unsafe { libc::close(fd) };
        }
    }

    /// Install execve services (shipped driver only — see [`Self::exec`]).
    pub(crate) fn enable_exec_services(&mut self, services: DirectExecServices) {
        self.exec = Some(services);
    }

    pub fn outcome(&self) -> Option<DirectRunOutcome> {
        lock(&self.outcome).clone()
    }

    pub(crate) fn take_exec_replacement(&self) -> Option<DirectExecReplacement> {
        lock(&self.exec_replacement).take()
    }
    pub fn syscalls(&self) -> u64 {
        self.syscalls.load(Ordering::Relaxed)
    }
    pub fn dispatcher(&self) -> &SyscallDispatcher {
        &self.dispatcher
    }

    /// True when THIS host process is a fork child this runner created for a
    /// guest `fork(2)`. The caller above [`with_runner`] must `_exit` with
    /// the child's outcome instead of continuing its own control flow — the
    /// shipped driver's forked child branch does so structurally; a test
    /// harness must check this explicitly or the child re-runs the harness.
    pub fn forked_guest_child(&self) -> bool {
        self.forked_child.load(Ordering::Acquire)
    }

    /// A guest process fork can originate on a guest clone-thread, hence on
    /// a Rust-spawned host pthread rather than the host process's primordial
    /// thread. In that child the closure below is the only surviving guest
    /// thread. Returning from it would merely `pthread_exit`: process helper
    /// threads (notably the Mach exception server) would keep the child and
    /// all inherited pipe fds alive forever. Complete the Linux process-exit
    /// handoff explicitly instead.
    fn terminate_forked_child_from_guest_thread(&self) {
        if !self.forked_guest_child() {
            return;
        }
        // The forking guest thread can retire before another guest thread in
        // the child (CPython's join-on-shutdown case). No process outcome then
        // exists yet; that sibling must keep running and will perform this
        // handoff when it becomes the last/terminal thread.
        let Some(outcome) = self.outcome() else {
            return;
        };
        self.dispatcher.cleanup_sysv_ipc_on_process_exit();
        match outcome {
            DirectRunOutcome::Exited { code } => {
                crate::native_darwin::native_tier_census("fork-child-exit", "", &code.to_string());
                crate::exec_helpers::forked_child_exit(
                    code,
                    self.dispatcher.stdout(),
                    self.dispatcher.stderr(),
                )
            }
            DirectRunOutcome::Signaled { signum } => {
                crate::native_darwin::native_tier_census(
                    "fork-child-signal",
                    "",
                    &signum.to_string(),
                );
                crate::exec_helpers::forked_child_die_by_signal(
                    signum,
                    self.dispatcher.stdout(),
                    self.dispatcher.stderr(),
                )
            }
            // The outer direct driver owns the replacement commit. Returning
            // from this guest thread lets `with_runner` join it and hand the
            // prepared image to that driver; it is not a process exit.
            DirectRunOutcome::ExecReplacement => {}
            DirectRunOutcome::Unsupported { syscall, outcome } => {
                crate::native_darwin::native_tier_census(
                    "fork-child-unsupported",
                    "",
                    &format!("syscall={syscall} {outcome}"),
                );
                crate::exec_helpers::forked_child_exit(
                    125,
                    self.dispatcher.stdout(),
                    self.dispatcher.stderr(),
                )
            }
        }
    }

    /// The registry key of the guest thread running on THIS host thread
    /// (installed by [`with_runner`] / the clone spawn path).
    fn current_tid(&self) -> ThreadId {
        let tid = ACTIVE_TID.with(std::cell::Cell::get);
        if tid == ThreadId::NONE {
            read_lock(&self.registry).main_tid()
        } else {
            tid
        }
    }

    fn current_linux_tid(&self) -> Option<crate::kernel::LinuxTid> {
        read_lock(&self.linux_tids)
            .get(&self.current_tid())
            .copied()
    }

    /// The main guest thread's registry key.
    fn main_tid(&self) -> ThreadId {
        read_lock(&self.registry).main_tid()
    }

    /// Record a PROCESS-ending outcome (first one wins) and nudge parked
    /// guest threads so they observe it and retire.
    fn end_process(&self, outcome: DirectRunOutcome) {
        let mut slot = lock(&self.outcome);
        if slot.is_none() {
            if let DirectRunOutcome::Unsupported { syscall, outcome } = &outcome {
                crate::probes::native_tierd_unsupported(*syscall, outcome);
                // A non-main guest thread can be the first to hit the
                // fail-closed boundary. Its thread-retirement path exits the
                // host process with 125 before the outer driver regains
                // control, so the driver's `direct-leave` census below never
                // runs. Persist the same terminal fact here while the exact
                // first-wins outcome is still known; this remains zero-cost
                // unless the caller explicitly sets CARRICK_TIER_CENSUS.
                crate::native_darwin::native_tier_census(
                    "direct-unsupported",
                    "",
                    &format!("syscall={syscall} {outcome}"),
                );
            }
            *slot = Some(outcome);
        }
        drop(slot);
        self.exiting.store(true, Ordering::SeqCst);
        self.futex.notify_signal_pending();
        // Futex parking and fd/sleep parking are independent. Every tier-D
        // host thread owns a registered `ThreadWaiter`; broadcast after the
        // durable `exiting` store so dispatcher-aware waits recheck it and
        // retire promptly instead of joining behind an arbitrarily long
        // guest nanosleep/select timeout.
        crate::host_signal::wake_all_waiters();
    }

    /// One thread's `exit(2)` bookkeeping — Linux's CLEARTID contract (write
    /// 0, wake one futex waiter: pthread_join's wait) plus registry/signal
    /// teardown. When this was the LAST live thread the process ends with
    /// this thread's code.
    fn finish_thread_bookkeeping(&self, tid: ThreadId, code: i32) {
        if let Some(address) = read_lock(&self.registry).clear_child_tid(tid)
            && address != 0
        {
            let mut memory = self.memory;
            let _ = memory.write_bytes_raw(address, &0_i32.to_le_bytes());
            self.futex.wake(address, 1);
        }
        let last = read_lock(&self.registry).exit(tid);
        let linux_tid = write_lock(&self.linux_tids).remove(&tid);
        if !last
            && let Some(linux_tid) = linux_tid
            && let Err(error) = self.dispatcher.exit_one_task_thread(linux_tid)
        {
            self.end_process(DirectRunOutcome::Unsupported {
                syscall: 93,
                outcome: format!("retire tier-D one-task Kernel thread: {error}"),
            });
        }
        self.dispatcher.forget_thread_signal_state(tid);
        if last {
            let mut slot = lock(&self.outcome);
            if slot.is_none() {
                *slot = Some(DirectRunOutcome::Exited { code });
            }
        }
    }

    /// Join every host thread spawned for a guest clone. Called by
    /// [`with_runner`] after the main guest thread leaves, so the returned
    /// outcome is final and no spawned thread outlives the borrows it holds.
    fn join_guest_threads(&self) {
        loop {
            let handles = std::mem::take(&mut *lock(&self.threads));
            if handles.is_empty() {
                return;
            }
            for handle in handles {
                let _ = handle.join();
            }
        }
    }

    /// Cooperate with a sibling's process-creating fork at a lock-safe
    /// syscall boundary.
    ///
    /// Tier D has no vCPU to release: the guest is already parked in an
    /// island handler and callers reach this only without temporary
    /// dispatcher/runner guards. The shared barrier still supplies the
    /// across-fork mutex and child-reset contract used by every native tier.
    fn park_for_fork_quiesce(&self) {
        if crate::fork_quiesce::is_quiescing() {
            crate::fork_quiesce::barrier().park_if_quiescing();
        }
    }

    /// Identity lowering of the guest's MEMORY-MODEL syscalls.
    ///
    /// On tier D, guest VA IS host VA, so the only correct service for mmap
    /// and friends is the host's own primitive: the shared dispatcher's
    /// memory subsystem models a boot-mapped guest arena (the VMM lanes'
    /// world) and hands out guest VAs with NO host mapping behind them.
    /// Proven by fault: real ld.so's first malloc received `0x6000000010`
    /// from the arena and its memset SIGBUSed (lldb: `str q0, [x0]`,
    /// x0=0x6000000010, x8 still 222). This is not a second dispatcher —
    /// it is the tier's memory model, exactly as the HostAlias plumbing is
    /// the VMM lanes'; every non-memory syscall still goes to the one
    /// shared dispatcher.
    ///
    /// Fails closed, never approximates:
    /// - `PROT_EXEC` content the scan+patch window pipeline cannot prove —
    ///   `MAP_FIXED` exec mmaps, anonymous exec mmaps, `mprotect(PROT_EXEC)`
    ///   outside a patched tier-D mapping — LEAVES named;
    /// - `MAP_SHARED` file mmap -> LEAVES named (a private copy would break
    ///   the sharing contract);
    /// - `mremap` is serviced ONLY inside a mapping this runner can PROVE is
    ///   plain anonymous RW (its own tracked creations, protection never
    ///   changed) — anything else LEAVES named.
    fn service_identity_memory(&self, ctx: &GuestContext) -> Option<ServiceVerdict> {
        use carrick_abi::{LinuxMmapFlags, LinuxProtFlags};
        let number = ctx.syscall_nr();
        let [a0, a1, a2, a3, a4, a5] = ctx.args();
        let unsupported = |this: &Self, what: &str| {
            this.end_process(DirectRunOutcome::Unsupported {
                syscall: number,
                outcome: what.to_string(),
            });
            Some(ServiceVerdict::Leave)
        };
        match number {
            // mmap(addr, len, prot, flags, fd, off)
            222 => {
                let prot = LinuxProtFlags::from_bits_truncate(a2);
                let flags = LinuxMmapFlags::from_bits_truncate(a3);
                if !flags.contains(LinuxMmapFlags::ANONYMOUS) {
                    if flags.contains(LinuxMmapFlags::SHARED) {
                        if prot.contains(LinuxProtFlags::EXEC) {
                            // Patching writes the private JIT copy; a SHARED
                            // exec mapping's patches would hit the file.
                            return unsupported(self, "MAP_SHARED PROT_EXEC file mmap on tier D");
                        }
                        return Some(self.service_shared_file_mmap(a0, a1, prot, flags, a4, a5));
                    }
                    if a5 % HOST_PAGE_SIZE != 0 {
                        // The identity tier's page size IS the host's
                        // (`AT_PAGESZ` says so), so a file offset must be
                        // host-page aligned to be mappable at all.
                        return Some(ServiceVerdict::Resume(
                            crate::host_to_linux_errno(libc::EINVAL).guest_retval(),
                        ));
                    }
                    if prot.contains(LinuxProtFlags::EXEC) {
                        return Some(self.service_exec_file_mmap(a0, flags, a4, a5, a1));
                    }
                    return Some(self.service_data_file_mmap(a0, a1, prot, flags, a4, a5));
                }
                if prot.contains(LinuxProtFlags::EXEC) {
                    // Fresh anonymous pages have no content to patch; a
                    // guest that wants executable memory must publish it
                    // through a PROT_EXEC flip (or is an RWX-without-flip
                    // JIT, which is tier T's by design).
                    return unsupported(
                        self,
                        "anonymous mmap(PROT_EXEC) on tier D (RWX-without-flip is tier T's)",
                    );
                }
                let mut host_flags = libc::MAP_ANON;
                host_flags |= if flags.contains(LinuxMmapFlags::SHARED) {
                    libc::MAP_SHARED
                } else {
                    libc::MAP_PRIVATE
                };
                if flags.contains(LinuxMmapFlags::FIXED) {
                    host_flags |= libc::MAP_FIXED;
                }
                // A guest that names no address gets a SPARSE-space hint so
                // later MAP_FIXED exec windows over the reservation can place
                // their island arena within `b` range (see ANON_HINT_CURSOR).
                // The address stays untyped Linux semantics: any placement is
                // a valid non-fixed mmap result.
                let request_addr = if a0 == 0 && !flags.contains(LinuxMmapFlags::FIXED) {
                    ANON_HINT_CURSOR
                        .fetch_add(a1.next_multiple_of(HOST_PAGE_SIZE), Ordering::Relaxed)
                } else {
                    a0
                };
                // SAFETY: identity tier — the guest's address space IS this
                // process's, so a host mmap is the exact semantic.
                let mapped = unsafe {
                    libc::mmap(
                        request_addr as usize as *mut libc::c_void,
                        a1 as usize,
                        host_prot(prot),
                        host_flags,
                        -1,
                        a5 as i64 as libc::off_t,
                    )
                };
                Some(if mapped == libc::MAP_FAILED {
                    host_errno_verdict()
                } else {
                    self.record_owned_mapping(mapped as u64, a1);
                    // A MAP_FIXED anon punch into a tier-D mapping (ld.so's
                    // bss tail over a window) voids patched coverage there.
                    if flags.contains(LinuxMmapFlags::FIXED)
                        && let Some(group) = active_group()
                    {
                        group.note_plain_replacement(mapped as u64, a1);
                        group.forget_dynamic_exec(mapped as u64, a1);
                    }
                    // Track plain anonymous PRIVATE RW creations — the only
                    // ranges mremap can later be proven safe on. A FIXED
                    // overwrite untracks whatever it replaced first.
                    let end = (mapped as u64).saturating_add(a1.next_multiple_of(HOST_PAGE_SIZE));
                    let mut table = lock(&self.anon_rw);
                    subtract_anon_range(&mut table, mapped as u64, end);
                    let mut none = lock(&self.anon_none);
                    subtract_anon_range(&mut none, mapped as u64, end);
                    if !flags.contains(LinuxMmapFlags::SHARED)
                        && host_prot(prot) == (libc::PROT_READ | libc::PROT_WRITE)
                    {
                        table.push(AnonRwRange {
                            base: mapped as u64,
                            end,
                        });
                    } else if !flags.contains(LinuxMmapFlags::SHARED)
                        && host_prot(prot) == libc::PROT_NONE
                    {
                        none.push(AnonRwRange {
                            base: mapped as u64,
                            end,
                        });
                    }
                    drop(table);
                    drop(none);
                    ServiceVerdict::Resume(mapped as i64)
                })
            }
            // munmap(addr, len)
            215 => {
                // A hole in a tier-D mapping is no longer patched text;
                // whatever lands there later must not inherit coverage.
                if let Some(group) = active_group() {
                    group.note_plain_replacement(a0, a1);
                    group.forget_dynamic_exec(a0, a1);
                }
                // SAFETY: as above; the guest unmaps within its own space.
                let rc = unsafe { libc::munmap(a0 as usize as *mut libc::c_void, a1 as usize) };
                Some(if rc == 0 {
                    self.forget_owned_mapping(a0, a1);
                    subtract_anon_range(
                        &mut lock(&self.anon_rw),
                        a0,
                        a0.saturating_add(a1.next_multiple_of(HOST_PAGE_SIZE)),
                    );
                    subtract_anon_range(
                        &mut lock(&self.anon_none),
                        a0,
                        a0.saturating_add(a1.next_multiple_of(HOST_PAGE_SIZE)),
                    );
                    ServiceVerdict::Resume(0)
                } else {
                    host_errno_verdict()
                })
            }
            // mprotect(addr, len, prot)
            226 => {
                let prot = LinuxProtFlags::from_bits_truncate(a2);
                if prot.contains(LinuxProtFlags::EXEC) {
                    // Inside a patched tier-D mapping the pages are ALREADY
                    // executable and their text was patched at map time, so
                    // the flip adds nothing — approving it keeps
                    // W^X-disciplined guests alive (ld.so re-mprotects
                    // libc's text R|X after relocation for BTI hardening).
                    // Anywhere else the bytes are unpatched: fail closed.
                    if active_group().is_some_and(|group| group.covers_patched_executable(a0, a1)) {
                        return Some(ServiceVerdict::Resume(0));
                    }
                    let end = a0.saturating_add(a1.next_multiple_of(HOST_PAGE_SIZE));
                    let untouched_none = lock(&self.anon_none)
                        .iter()
                        .any(|range| range.base <= a0 && end <= range.end);
                    if untouched_none
                        && prot.contains(LinuxProtFlags::READ)
                        && prot.contains(LinuxProtFlags::WRITE)
                        && let Some(group) = active_group()
                    {
                        return Some(match group.map_dynamic_exec(a0, end - a0) {
                            Ok(()) => {
                                subtract_anon_range(&mut lock(&self.anon_none), a0, end);
                                ServiceVerdict::Resume(0)
                            }
                            Err(error) => {
                                self.end_process(DirectRunOutcome::Unsupported {
                                    syscall: number,
                                    outcome: format!(
                                        "dynamic MAP_JIT publication failed for {a0:#x}..{end:#x}: {error}"
                                    ),
                                });
                                ServiceVerdict::Leave
                            }
                        });
                    }
                    return unsupported(
                        self,
                        &format!(
                            "mprotect(PROT_EXEC) outside a patched tier-D mapping \
                             (addr={a0:#x} len={a1:#x} prot={a2:#x})"
                        ),
                    );
                }
                let target = host_prot(prot);
                let end = a0.saturating_add(a1.next_multiple_of(HOST_PAGE_SIZE));
                // A pristine private-anon reservation promoted to ordinary
                // RW stays provably private anonymous. Preserve that
                // provenance across the protection split (Node worker stacks
                // have exactly this guard+RW shape).
                let promoted_from_none = target == (libc::PROT_READ | libc::PROT_WRITE)
                    && lock(&self.anon_none)
                        .iter()
                        .any(|range| range.base <= a0 && end <= range.end);
                // SAFETY: as above.
                let rc = unsafe {
                    libc::mprotect(a0 as usize as *mut libc::c_void, a1 as usize, target)
                };
                if rc != 0 {
                    // Darwin refuses EVERY mprotect on MAP_JIT pages —
                    // probed EACCES for any target protection, armed or not
                    // — and ld.so's segment-hole `mprotect(PROT_NONE)` lands
                    // exactly there. When the range is still original window
                    // pages, lower the protection change to a
                    // preserve-and-replace; anything else keeps the host's
                    // verdict.
                    let errno = std::io::Error::last_os_error().raw_os_error();
                    if errno == Some(libc::EACCES)
                        && active_group()
                            .is_some_and(|group| group.covers_patched_executable(a0, a1))
                    {
                        return Some(self.replace_jit_pages_with_protection(a0, a1, target));
                    }
                    return Some(host_errno_verdict());
                }
                // A writability flip over patched text means the guest may
                // rewrite it: void its coverage so a later EXEC flip cannot
                // bless stale patches.
                if prot.contains(LinuxProtFlags::WRITE)
                    && let Some(group) = active_group()
                {
                    group.note_plain_replacement(a0, a1);
                }
                // A protection change away from RW UNTRACKS the range for
                // mremap purposes: the proof "plain anonymous RW" no longer
                // holds there.
                if target != (libc::PROT_READ | libc::PROT_WRITE) {
                    subtract_anon_range(&mut lock(&self.anon_rw), a0, end);
                }
                subtract_anon_range(&mut lock(&self.anon_none), a0, end);
                if promoted_from_none {
                    lock(&self.anon_rw).push(AnonRwRange { base: a0, end });
                }
                Some(ServiceVerdict::Resume(0))
            }
            // brk(addr) — the FIRST syscall real ld.so makes.
            214 => Some(self.service_identity_brk(a0)),
            // mremap(old, old_size, new_size, flags, new_addr)
            216 => Some(self.service_identity_mremap(a0, a1, a2, a3)),
            // madvise(addr, len, advice)
            233 => Some(self.service_identity_madvise(a0, a1, a2)),
            _ => None,
        }
    }

    /// Linux `madvise(2)` over host-identity mappings, with provenance-specific
    /// Darwin lowerings. The arena dispatcher's VMA ledger cannot see these
    /// mappings, so sending them there false-ENOMEMs valid ranges (V8 aborts
    /// on exactly that result).
    ///
    /// The two destructive hints deliberately do not share one host advice:
    /// ordinary private-anon `MADV_DONTNEED` uses XNU `MADV_ZERO` (which zeroes
    /// resident pages and drops compressed pages without faulting holes in),
    /// followed by best-effort `MADV_FREE`. XNU refuses `MADV_ZERO` on JIT
    /// entries, so dynamic MAP_JIT pages are zeroed explicitly while the guest
    /// syscall thread is in JIT write mode, then returned to execute mode and
    /// offered to XNU with V8's own reusable-memory hint.
    fn service_identity_madvise(&self, address: u64, length: u64, advice: u64) -> ServiceVerdict {
        use carrick_abi::{
            LINUX_MADV_COLLAPSE, LINUX_MADV_DOFORK, LINUX_MADV_DONTFORK, LINUX_MADV_DONTNEED,
            LINUX_MADV_FREE, LINUX_MADV_HUGEPAGE, LINUX_MADV_NOHUGEPAGE, LINUX_MADV_NORMAL,
            LINUX_MADV_RANDOM, LINUX_MADV_SEQUENTIAL, LINUX_MADV_WILLNEED,
        };

        let einval =
            || ServiceVerdict::Resume(crate::host_to_linux_errno(libc::EINVAL).guest_retval());
        let enomem =
            || ServiceVerdict::Resume(crate::host_to_linux_errno(libc::ENOMEM).guest_retval());
        if !address.is_multiple_of(HOST_PAGE_SIZE)
            || !matches!(
                advice,
                LINUX_MADV_NORMAL
                    | LINUX_MADV_RANDOM
                    | LINUX_MADV_SEQUENTIAL
                    | LINUX_MADV_WILLNEED
                    | LINUX_MADV_DONTNEED
                    | LINUX_MADV_FREE
                    | LINUX_MADV_DONTFORK
                    | LINUX_MADV_DOFORK
                    | LINUX_MADV_HUGEPAGE
                    | LINUX_MADV_NOHUGEPAGE
                    | LINUX_MADV_COLLAPSE
            )
        {
            return einval();
        }
        if length == 0 {
            return ServiceVerdict::Resume(0);
        }
        let Some(raw_end) = address.checked_add(length) else {
            return enomem();
        };
        let Some(end) = raw_end
            .checked_add(HOST_PAGE_SIZE - 1)
            .map(|value| value & !(HOST_PAGE_SIZE - 1))
        else {
            return enomem();
        };
        let Ok(host_len) = usize::try_from(end - address) else {
            return enomem();
        };

        let rw_ranges = lock(&self.anon_rw).clone();
        let none_ranges = lock(&self.anon_none).clone();
        let plain_rw = rw_ranges
            .iter()
            .any(|range| range.base <= address && end <= range.end);
        let plain_none = !plain_rw
            && none_ranges
                .iter()
                .any(|range| range.base <= address && end <= range.end);
        let plain_mixed = !plain_rw
            && !plain_none
            && anon_range_union_covers(&rw_ranges, &none_ranges, address, end);
        let dynamic = !plain_rw
            && !plain_none
            && !plain_mixed
            && active_group()
                .is_some_and(|group| group.covers_dynamic_exec(address, end - address));
        let range = if plain_rw {
            IdentityMadviseRange::PlainAnonRw
        } else if plain_none {
            IdentityMadviseRange::PlainAnonNone
        } else if plain_mixed {
            IdentityMadviseRange::PlainAnonMixed
        } else if dynamic {
            IdentityMadviseRange::DynamicExec
        } else {
            self.end_process(DirectRunOutcome::Unsupported {
                syscall: 233,
                outcome: format!(
                    "madvise outside a proven Tier-D anonymous mapping \
                     (addr={address:#x} len={length:#x} advice={advice})"
                ),
            });
            return ServiceVerdict::Leave;
        };

        let host_madvise = |host_advice: libc::c_int| {
            // SAFETY: provenance above proves the complete host range is a
            // live mapping owned by this identity guest.
            unsafe { libc::madvise(address as usize as *mut libc::c_void, host_len, host_advice) }
        };
        let zero_plain_rw = |start: u64, finish: u64| -> Result<(), libc::c_int> {
            let len = usize::try_from(finish - start).map_err(|_| libc::ENOMEM)?;
            // SAFETY: the caller intersects only the snapshotted, proven
            // private-anonymous RW spans.
            let zero_rc =
                unsafe { libc::madvise(start as usize as *mut libc::c_void, len, libc::MADV_ZERO) };
            if zero_rc != 0 {
                // XNU rejects MADV_ZERO on a COW entry (e.g. after fork).
                // Replace only this proven RW segment at its exact address.
                let mapped = unsafe {
                    libc::mmap(
                        start as usize as *mut libc::c_void,
                        len,
                        libc::PROT_READ | libc::PROT_WRITE,
                        libc::MAP_PRIVATE | libc::MAP_ANON | libc::MAP_FIXED,
                        -1,
                        0,
                    )
                };
                if mapped == libc::MAP_FAILED || mapped as u64 != start {
                    return Err(std::io::Error::last_os_error()
                        .raw_os_error()
                        .unwrap_or(libc::EIO));
                }
            }
            // Reclamation is advisory; zeroing above is the semantic.
            let _ =
                unsafe { libc::madvise(start as usize as *mut libc::c_void, len, libc::MADV_FREE) };
            Ok(())
        };
        match advice {
            LINUX_MADV_NORMAL | LINUX_MADV_RANDOM | LINUX_MADV_SEQUENTIAL => {
                if host_madvise(advice as libc::c_int) == 0 {
                    ServiceVerdict::Resume(0)
                } else {
                    host_errno_verdict()
                }
            }
            // Advisory only. XNU's WILLNEED can fault pages and rejects some
            // PROT_NONE shapes that Linux accepts; accepting the hint without
            // eager population preserves its non-binding contract.
            LINUX_MADV_WILLNEED
            | LINUX_MADV_HUGEPAGE
            | LINUX_MADV_NOHUGEPAGE
            | LINUX_MADV_COLLAPSE => ServiceVerdict::Resume(0),
            LINUX_MADV_DONTFORK | LINUX_MADV_DOFORK => {
                const VM_INHERIT_COPY: libc::c_int = 1;
                const VM_INHERIT_NONE: libc::c_int = 2;
                unsafe extern "C" {
                    fn minherit(
                        addr: *mut libc::c_void,
                        len: libc::size_t,
                        inherit: libc::c_int,
                    ) -> libc::c_int;
                }
                let inherit = if advice == LINUX_MADV_DONTFORK {
                    VM_INHERIT_NONE
                } else {
                    VM_INHERIT_COPY
                };
                // SAFETY: complete proven host mapping; minherit changes only
                // the mapping's fork inheritance.
                if unsafe { minherit(address as usize as *mut libc::c_void, host_len, inherit) }
                    == 0
                {
                    ServiceVerdict::Resume(0)
                } else {
                    host_errno_verdict()
                }
            }
            LINUX_MADV_FREE => {
                if range == IdentityMadviseRange::PlainAnonNone {
                    return ServiceVerdict::Resume(0);
                }
                if range == IdentityMadviseRange::PlainAnonMixed {
                    for span in &rw_ranges {
                        let lo = address.max(span.base);
                        let hi = end.min(span.end);
                        if lo < hi
                            && unsafe {
                                libc::madvise(
                                    lo as usize as *mut libc::c_void,
                                    (hi - lo) as usize,
                                    libc::MADV_FREE,
                                )
                            } != 0
                        {
                            return host_errno_verdict();
                        }
                    }
                    return ServiceVerdict::Resume(0);
                }
                if host_madvise(libc::MADV_FREE) == 0 {
                    ServiceVerdict::Resume(0)
                } else {
                    host_errno_verdict()
                }
            }
            LINUX_MADV_DONTNEED => match range {
                // Fresh inaccessible anonymous pages are already the exact
                // zero-fill state Linux requires; touching them would only
                // manufacture work.
                IdentityMadviseRange::PlainAnonNone => ServiceVerdict::Resume(0),
                IdentityMadviseRange::PlainAnonRw => {
                    if let Err(errno) = zero_plain_rw(address, end) {
                        return ServiceVerdict::Resume(
                            crate::host_to_linux_errno(errno).guest_retval(),
                        );
                    }
                    ServiceVerdict::Resume(0)
                }
                IdentityMadviseRange::PlainAnonMixed => {
                    for span in &rw_ranges {
                        let lo = address.max(span.base);
                        let hi = end.min(span.end);
                        if lo < hi
                            && let Err(errno) = zero_plain_rw(lo, hi)
                        {
                            return ServiceVerdict::Resume(
                                crate::host_to_linux_errno(errno).guest_retval(),
                            );
                        }
                    }
                    ServiceVerdict::Resume(0)
                }
                IdentityMadviseRange::DynamicExec => {
                    let Some(group) = active_group() else {
                        return enomem();
                    };
                    let discard = if pristine_dynamic_exec_discard_enabled() {
                        group
                            .discard_dynamic_exec_contents(address, end - address)
                            .map(|_| ())
                    } else {
                        group.zero_dynamic_exec(address, end - address)
                    };
                    if let Err(error) = discard {
                        return ServiceVerdict::Resume(
                            crate::host_to_linux_errno(error.raw_os_error().unwrap_or(libc::EIO))
                                .guest_retval(),
                        );
                    }
                    // Contents are already Linux-exact. Reusable/DONTNEED is
                    // now only a best-effort host reclamation hint, so a host
                    // refusal cannot make this successful guest operation
                    // incorrect.
                    let rc = host_madvise(libc::MADV_FREE_REUSABLE);
                    if rc != 0 {
                        let _ = host_madvise(libc::MADV_DONTNEED);
                    }
                    ServiceVerdict::Resume(0)
                }
            },
            _ => unreachable!("supported advice matched above"),
        }
    }

    /// `mremap(2)`, identity-style, and ONLY where its semantics are
    /// provable: `[old, old+old_size)` must lie inside one mapping this
    /// runner created as plain anonymous PRIVATE RW and whose protection
    /// never changed ([`AnonRwRange`]). For such memory a shrink is a tail
    /// unmap, an in-place grow is a hint-probed adjacent anon mapping (the
    /// kernel relocating the hint proves the space was occupied — never a
    /// clobber), and a `MREMAP_MAYMOVE` move is map-copy-unmap (private
    /// anonymous contents survive a copy by definition). Everything else —
    /// untracked ranges, `MREMAP_FIXED`/`DONTUNMAP`, growth without
    /// `MAYMOVE` that cannot extend in place — fails Linux-shaped (ENOMEM)
    /// or LEAVES named, never approximates.
    fn service_identity_mremap(
        &self,
        old_addr: u64,
        old_size: u64,
        new_size: u64,
        flags: u64,
    ) -> ServiceVerdict {
        const MREMAP_MAYMOVE: u64 = 1;
        let einval =
            || ServiceVerdict::Resume(crate::host_to_linux_errno(libc::EINVAL).guest_retval());
        let enomem =
            || ServiceVerdict::Resume(crate::host_to_linux_errno(libc::ENOMEM).guest_retval());
        if flags & !MREMAP_MAYMOVE != 0 {
            // MREMAP_FIXED / MREMAP_DONTUNMAP: not modeled — fail closed.
            self.end_process(DirectRunOutcome::Unsupported {
                syscall: 216,
                outcome: format!("mremap flags {flags:#x} on tier D"),
            });
            return ServiceVerdict::Leave;
        }
        if !old_addr.is_multiple_of(HOST_PAGE_SIZE) || old_size == 0 || new_size == 0 {
            return einval();
        }
        let old_len = old_size.next_multiple_of(HOST_PAGE_SIZE);
        let new_len = new_size.next_multiple_of(HOST_PAGE_SIZE);
        let old_end = old_addr.saturating_add(old_len);
        let mut table = lock(&self.anon_rw);
        let tracked = table
            .iter()
            .any(|entry| old_addr >= entry.base && old_end <= entry.end);
        if !tracked {
            drop(table);
            self.end_process(DirectRunOutcome::Unsupported {
                syscall: 216,
                outcome: "mremap outside a provably plain anonymous RW mapping on tier D"
                    .to_string(),
            });
            return ServiceVerdict::Leave;
        }
        if new_len == old_len {
            return ServiceVerdict::Resume(old_addr as i64);
        }
        if new_len < old_len {
            // SAFETY: releasing the tail of the guest's own tracked mapping.
            let rc = unsafe {
                libc::munmap(
                    (old_addr + new_len) as usize as *mut libc::c_void,
                    (old_len - new_len) as usize,
                )
            };
            if rc != 0 {
                return host_errno_verdict();
            }
            self.forget_owned_mapping(old_addr + new_len, old_len - new_len);
            subtract_anon_range(&mut table, old_addr + new_len, old_end);
            return ServiceVerdict::Resume(old_addr as i64);
        }
        // Grow. Try in place first: a hinted (non-FIXED) anon mmap comes back
        // AT the hint iff the range was free — the probed pattern the island
        // arena placement already relies on — so success extends the mapping
        // and a relocated result is released untouched.
        let grow_len = (new_len - old_len) as usize;
        // SAFETY: hinted anonymous mapping; without MAP_FIXED the kernel
        // relocates instead of clobbering when the range is occupied.
        let grown = unsafe {
            libc::mmap(
                old_end as usize as *mut libc::c_void,
                grow_len,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_PRIVATE | libc::MAP_ANON,
                -1,
                0,
            )
        };
        if grown != libc::MAP_FAILED && grown as u64 == old_end {
            self.record_owned_mapping(old_addr, new_len);
            subtract_anon_range(
                &mut table,
                old_addr,
                old_end.saturating_add(grow_len as u64),
            );
            table.push(AnonRwRange {
                base: old_addr,
                end: old_end + grow_len as u64,
            });
            return ServiceVerdict::Resume(old_addr as i64);
        }
        if grown != libc::MAP_FAILED {
            // Occupied: give the relocated probe back.
            // SAFETY: unmapping the mapping just created above.
            unsafe { libc::munmap(grown, grow_len) };
        }
        if flags & MREMAP_MAYMOVE == 0 {
            return enomem();
        }
        // Move: fresh anon RW, copy the old contents (private anonymous
        // memory — the copy IS the semantic), release the old range.
        // SAFETY: fresh kernel-placed anonymous mapping.
        let moved = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                new_len as usize,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_PRIVATE | libc::MAP_ANON,
                -1,
                0,
            )
        };
        if moved == libc::MAP_FAILED {
            return enomem();
        }
        // SAFETY: the old range is tracked RW (readable) and the new mapping
        // was just created RW at `moved` with `new_len >= old_len`.
        unsafe {
            std::ptr::copy_nonoverlapping(
                old_addr as usize as *const u8,
                moved.cast::<u8>(),
                old_len as usize,
            );
            libc::munmap(old_addr as usize as *mut libc::c_void, old_len as usize);
        }
        self.forget_owned_mapping(old_addr, old_len);
        self.record_owned_mapping(moved as u64, new_len);
        subtract_anon_range(&mut table, old_addr, old_end);
        table.push(AnonRwRange {
            base: moved as u64,
            end: moved as u64 + new_len,
        });
        ServiceVerdict::Resume(moved as i64)
    }

    /// `mmap(PROT_EXEC, fd)`: guest-created executable memory, serviced
    /// through the load group's scan+patch window pipeline (roadmap Phase 1
    /// item 5 — this is how ld.so maps libc.so.6's text). The file content
    /// comes through the dispatcher's own fd table, so whatever backend the
    /// file lives on (VFS overlay, host dir, synthetic) feeds the same
    /// pipeline. Refusals LEAVE named — tier T owns what the scan cannot
    /// prove.
    fn service_exec_file_mmap(
        &self,
        addr: u64,
        flags: carrick_abi::LinuxMmapFlags,
        fd: u64,
        offset: u64,
        len: u64,
    ) -> ServiceVerdict {
        let leave = |this: &Self, what: String| -> ServiceVerdict {
            this.end_process(DirectRunOutcome::Unsupported {
                syscall: 222,
                outcome: what,
            });
            ServiceVerdict::Leave
        };
        let fixed = flags.contains(carrick_abi::LinuxMmapFlags::FIXED);
        // The group reference is derived from a thread-local pointer and
        // names memory separate from `self`, so it is held across the
        // `&mut self` file read below without aliasing.
        let Some(group) = active_group() else {
            return leave(
                self,
                "mmap(PROT_EXEC, fd) with no tier-D load group installed".to_string(),
            );
        };
        let file = match self.read_guest_file_all(fd) {
            Ok(file) => file,
            Err(retval) => return ServiceVerdict::Resume(retval),
        };
        let Ok(len_usize) = usize::try_from(len) else {
            return ServiceVerdict::Resume(crate::host_to_linux_errno(libc::EINVAL).guest_retval());
        };
        let result = if fixed {
            // The guest reserved this address; a MAP_FIXED exec segment must
            // land exactly there (plain-anon text + a separate island arena).
            group.map_fixed_exec_file_window(&file, offset, addr, len_usize)
        } else {
            group.map_exec_file_window(&file, offset, len_usize)
        };
        match result {
            Ok(Ok(base)) => ServiceVerdict::Resume(base as i64),
            Ok(Err(reason)) => leave(
                self,
                format!("mmap(PROT_EXEC, fd): tier D window scan refused: {reason}"),
            ),
            Err(error) => leave(self, format!("mmap(PROT_EXEC, fd): {error}")),
        }
    }

    /// A SHARED file-backed data mapping: the ONE correct lowering is a real
    /// host `mmap(MAP_SHARED)` of the same file — guest writes reach the
    /// page cache, coherent with every other opener and across fork, which
    /// is the whole MAP_SHARED contract (glibc maps locale-archive this
    /// way at every coreutils startup). Identity tier: guest VA is host VA,
    /// so the host mapping IS the guest mapping. The host fd comes from the
    /// dispatcher's fd table (`dup_host_file_fd`); anything not an ordinary
    /// host-backed file fails closed, named.
    fn service_shared_file_mmap(
        &self,
        addr: u64,
        len: u64,
        prot: carrick_abi::LinuxProtFlags,
        flags: carrick_abi::LinuxMmapFlags,
        fd: u64,
        offset: u64,
    ) -> ServiceVerdict {
        use std::os::fd::AsRawFd as _;
        if !offset.is_multiple_of(HOST_PAGE_SIZE) {
            // The identity tier's page size IS the host's (`AT_PAGESZ`).
            return ServiceVerdict::Resume(crate::host_to_linux_errno(libc::EINVAL).guest_retval());
        }
        let Ok(len_usize) = usize::try_from(len) else {
            return ServiceVerdict::Resume(crate::host_to_linux_errno(libc::EINVAL).guest_retval());
        };
        let Some(host_fd) = self.dispatcher.dup_host_file_fd(fd as i32) else {
            let fd_description = self.dispatcher.describe_fd_for_diagnostic(fd as i32);
            self.end_process(DirectRunOutcome::Unsupported {
                syscall: 222,
                outcome: format!(
                    "MAP_SHARED mmap of a non-host-file fd on tier D: fd={fd} \
                     ({fd_description}), addr={addr:#x}, len={len:#x}, prot={prot:?}, \
                     flags={flags:?}, offset={offset:#x}"
                ),
            });
            return ServiceVerdict::Leave;
        };
        let mut host_flags = libc::MAP_SHARED;
        if flags.contains(carrick_abi::LinuxMmapFlags::FIXED) {
            host_flags |= libc::MAP_FIXED;
        }
        let request_addr = if addr == 0 && !flags.contains(carrick_abi::LinuxMmapFlags::FIXED) {
            ANON_HINT_CURSOR.fetch_add(len.next_multiple_of(HOST_PAGE_SIZE), Ordering::Relaxed)
        } else {
            addr
        };
        // SAFETY: identity tier — a host MAP_SHARED mmap of the guest's own
        // file is the exact semantic; the dup'd fd is closed after mapping
        // (the mapping keeps the file referenced).
        let mapped = unsafe {
            libc::mmap(
                request_addr as usize as *mut libc::c_void,
                len_usize,
                host_prot(prot),
                host_flags,
                host_fd.as_raw_fd(),
                offset as i64 as libc::off_t,
            )
        };
        drop(host_fd);
        if mapped == libc::MAP_FAILED {
            return host_errno_verdict();
        }
        self.record_owned_mapping(mapped as u64, len);
        if flags.contains(carrick_abi::LinuxMmapFlags::FIXED) {
            if let Some(group) = active_group() {
                group.note_plain_replacement(mapped as u64, len);
            }
            subtract_anon_range(
                &mut lock(&self.anon_rw),
                mapped as u64,
                (mapped as u64).saturating_add(len.next_multiple_of(HOST_PAGE_SIZE)),
            );
        }
        ServiceVerdict::Resume(mapped as i64)
    }

    /// A PRIVATE file-backed data mapping (ld.so's `MAP_FIXED` data
    /// segments, read-only header windows): fresh anonymous pages plus a
    /// dispatcher read of the file window. MAP_PRIVATE means writes never
    /// reach the file and later file changes need not appear, so the copy IS
    /// the semantic; bytes past EOF stay zero, mmap's own rule. Content is
    /// read BEFORE any address-space mutation so an fd error fails the mmap
    /// without having clobbered guest pages.
    fn service_data_file_mmap(
        &self,
        addr: u64,
        len: u64,
        prot: carrick_abi::LinuxProtFlags,
        flags: carrick_abi::LinuxMmapFlags,
        fd: u64,
        offset: u64,
    ) -> ServiceVerdict {
        let Ok(len_usize) = usize::try_from(len) else {
            return ServiceVerdict::Resume(crate::host_to_linux_errno(libc::EINVAL).guest_retval());
        };
        let bytes = match self.read_guest_file(fd, offset, len_usize) {
            Ok(bytes) => bytes,
            Err(retval) => return ServiceVerdict::Resume(retval),
        };
        let mut host_flags = libc::MAP_ANON | libc::MAP_PRIVATE;
        if flags.contains(carrick_abi::LinuxMmapFlags::FIXED) {
            host_flags |= libc::MAP_FIXED;
        }
        // SAFETY: identity tier; a MAP_FIXED target is the guest replacing
        // its own pages (ld.so mapping data over its text reservation).
        let mapped = unsafe {
            libc::mmap(
                addr as usize as *mut libc::c_void,
                len_usize,
                libc::PROT_READ | libc::PROT_WRITE,
                host_flags,
                -1,
                0,
            )
        };
        if mapped == libc::MAP_FAILED {
            return host_errno_verdict();
        }
        self.record_owned_mapping(mapped as u64, len);
        if flags.contains(carrick_abi::LinuxMmapFlags::FIXED)
            && let Some(group) = active_group()
        {
            group.note_plain_replacement(mapped as u64, len);
        }
        // SAFETY: `bytes.len() == len_usize` and the mapping was just
        // created RW at `mapped`.
        unsafe { std::ptr::copy_nonoverlapping(bytes.as_ptr(), mapped.cast::<u8>(), len_usize) };
        let final_prot = host_prot(prot);
        if final_prot != (libc::PROT_READ | libc::PROT_WRITE) {
            // SAFETY: narrowing the mapping just created to the guest's prot.
            let rc = unsafe { libc::mprotect(mapped, len_usize, final_prot) };
            if rc != 0 {
                return host_errno_verdict();
            }
        }
        ServiceVerdict::Resume(mapped as i64)
    }

    /// Change the protection of tier-D window pages by REPLACING them:
    /// Darwin's `mprotect` refuses MAP_JIT pages outright (probed: EACCES
    /// for every target protection), so the only way to honor a guest
    /// protection change inside a window is to swap the pages for plain
    /// ones. Contents are preserved — stash the (readable) JIT bytes, map
    /// plain anon RW in place, copy back, then apply the requested
    /// protection — so the guest-visible mprotect guarantee holds even
    /// through a PROT_NONE round trip. The replaced range loses
    /// patched-executable coverage: plain pages cannot execute, and a later
    /// PROT_EXEC flip on them fails closed by the containment rule.
    ///
    /// The caller guarantees the range is still original window pages
    /// (`covers_patched_executable`), which is what makes the stash read
    /// safe: original MAP_JIT pages are always readable (no mprotect ever
    /// succeeded on them, and they were created R+W+X).
    fn replace_jit_pages_with_protection(
        &self,
        addr: u64,
        len: u64,
        target: i32,
    ) -> ServiceVerdict {
        let Ok(len_usize) = usize::try_from(len) else {
            return ServiceVerdict::Resume(crate::host_to_linux_errno(libc::EINVAL).guest_retval());
        };
        let mut stash = vec![0_u8; len_usize];
        // SAFETY: the caller proved the range lies in original (readable)
        // window pages, and the guest is parked in the handler.
        unsafe {
            std::ptr::copy_nonoverlapping(
                addr as usize as *const u8,
                stash.as_mut_ptr(),
                len_usize,
            );
        }
        // SAFETY: replacing the guest's own window pages in place.
        let mapped = unsafe {
            libc::mmap(
                addr as usize as *mut libc::c_void,
                len_usize,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_PRIVATE | libc::MAP_ANON | libc::MAP_FIXED,
                -1,
                0,
            )
        };
        if mapped == libc::MAP_FAILED {
            return host_errno_verdict();
        }
        if let Some(group) = active_group() {
            group.note_plain_replacement(addr, len);
        }
        // SAFETY: fresh RW pages at `addr`, sized `len_usize`.
        unsafe { std::ptr::copy_nonoverlapping(stash.as_ptr(), mapped.cast::<u8>(), len_usize) };
        if target != (libc::PROT_READ | libc::PROT_WRITE) {
            // SAFETY: plain pages now; any non-EXEC protection is honored.
            let rc = unsafe { libc::mprotect(mapped, len_usize, target) };
            if rc != 0 {
                return host_errno_verdict();
            }
        }
        ServiceVerdict::Resume(0)
    }

    /// Dispatch a runner-synthesized syscall (`fstat`/`pread64` for the mmap
    /// file services) through the one shared dispatcher — the same fd
    /// semantics every guest read gets. Errno outcomes come back as the
    /// guest retval to fail the surrounding mmap with; any non-value outcome
    /// is EIO (these numbers cannot fork or exit).
    fn dispatch_synthesized(&self, number: u64, args: [u64; 6]) -> Result<i64, i64> {
        let request = SyscallRequest::from_raw(carrick_hal::RawSyscall {
            number: CanonicalNr(number),
            args,
            guest_abi: LinuxGuestAbi::Aarch64,
            native_number: NativeNr(number),
        });
        let reporter = crate::compat::CompatReporter::default();
        let mut memory = self.memory;
        let linux_tid = self
            .current_linux_tid()
            .ok_or_else(|| crate::host_to_linux_errno(libc::EIO).guest_retval())?;
        let kernel = self
            .dispatcher
            .capture_kernel_context(linux_tid)
            .map_err(|_| crate::host_to_linux_errno(libc::EIO).guest_retval())?;
        match self.dispatcher.dispatch_threaded(
            &kernel,
            request,
            &mut memory,
            &reporter,
            self.current_tid(),
            &read_lock(&self.registry),
            &self.futex,
        ) {
            Ok(DispatchOutcome::Returned { value }) => Ok(value),
            Ok(DispatchOutcome::Errno { errno }) => Err(errno.guest_retval()),
            _ => Err(crate::host_to_linux_errno(libc::EIO).guest_retval()),
        }
    }

    /// The byte length of the guest file behind `fd`, via `fstat(2)`.
    fn guest_file_len(&self, fd: u64) -> Result<u64, i64> {
        use zerocopy::FromBytes as _;
        let mut stat_bytes = [0_u8; core::mem::size_of::<carrick_abi::LinuxStat>()];
        let addr = stat_bytes.as_mut_ptr() as u64;
        // fstat(fd, statbuf); the dispatcher writes the guest's aarch64
        // `struct stat` through the identity memory into our buffer.
        self.dispatch_synthesized(80, [fd, addr, 0, 0, 0, 0])?;
        let stat = carrick_abi::LinuxStat::read_from_bytes(&stat_bytes)
            .map_err(|_| crate::host_to_linux_errno(libc::EIO).guest_retval())?;
        Ok(stat.st_size.max(0) as u64)
    }

    /// Read `[offset, offset + len)` of the guest file behind `fd` via
    /// `pread64(2)` — offset-neutral, so the guest's own file position is
    /// undisturbed. A short read leaves the tail zeroed (mmap's
    /// beyond-EOF semantic).
    fn read_guest_file(&self, fd: u64, offset: u64, len: usize) -> Result<Vec<u8>, i64> {
        let mut out = vec![0_u8; len];
        let mut done = 0_usize;
        while done < len {
            let addr = out.as_mut_ptr() as u64 + done as u64;
            let n = self.dispatch_synthesized(
                67,
                [fd, addr, (len - done) as u64, offset + done as u64, 0, 0],
            )?;
            if n <= 0 {
                break;
            }
            done += n as usize;
        }
        Ok(out)
    }

    /// The whole guest file behind `fd`: `fstat` for the length, `pread64`
    /// for the bytes. The exec-window pipeline needs the full file because
    /// the section headers that place the code live at its end.
    fn read_guest_file_all(&self, fd: u64) -> Result<Vec<u8>, i64> {
        let len = self.guest_file_len(fd)?;
        let len = usize::try_from(len)
            .map_err(|_| crate::host_to_linux_errno(libc::EINVAL).guest_retval())?;
        self.read_guest_file(fd, 0, len)
    }

    /// `brk(2)`, identity-style (see [`IdentityBrk`]). Linux semantics: on
    /// any failure or out-of-range request, return the CURRENT break —
    /// `brk` never errnos.
    fn service_identity_brk(&self, addr: u64) -> ServiceVerdict {
        const PAGE: u64 = HOST_PAGE_SIZE;
        let mut brk_slot = lock(&self.brk);
        if brk_slot.is_none() {
            // SAFETY: fresh PROT_NONE reservation, kernel-chosen address.
            let base = unsafe {
                libc::mmap(
                    std::ptr::null_mut(),
                    IdentityBrk::RESERVE,
                    libc::PROT_NONE,
                    libc::MAP_PRIVATE | libc::MAP_ANON,
                    -1,
                    0,
                )
            };
            if base == libc::MAP_FAILED {
                drop(brk_slot);
                // No break exists and none can: park the run with the reason
                // named rather than inventing an address.
                self.end_process(DirectRunOutcome::Unsupported {
                    syscall: 214,
                    outcome: "brk reservation failed".to_string(),
                });
                return ServiceVerdict::Leave;
            }
            let base = base as u64;
            *brk_slot = Some(IdentityBrk {
                base,
                current: base,
            });
        }
        let Some(brk) = brk_slot.as_mut() else {
            // Populated just above; this arm keeps the no-panic gate total.
            // "No change" is brk's own failure semantic, and with no break
            // the current break is 0.
            return ServiceVerdict::Resume(0);
        };
        let (lo, hi) = (brk.base, brk.base + IdentityBrk::RESERVE as u64);
        if addr < lo || addr > hi {
            return ServiceVerdict::Resume(brk.current as i64);
        }
        let committed = (brk.current - lo).next_multiple_of(PAGE);
        let wanted = (addr - lo).next_multiple_of(PAGE);
        if wanted > committed {
            // SAFETY: committing untouched reservation pages; zero-fill on
            // first touch preserves the anonymous-memory guarantee.
            let rc = unsafe {
                libc::mprotect(
                    (lo + committed) as usize as *mut libc::c_void,
                    (wanted - committed) as usize,
                    libc::PROT_READ | libc::PROT_WRITE,
                )
            };
            if rc != 0 {
                return ServiceVerdict::Resume(brk.current as i64);
            }
        } else if wanted < committed {
            // SAFETY: replacing released break pages with a fresh PROT_NONE
            // mapping so a later regrowth re-delivers ZEROS.
            let remapped = unsafe {
                libc::mmap(
                    (lo + wanted) as usize as *mut libc::c_void,
                    (committed - wanted) as usize,
                    libc::PROT_NONE,
                    libc::MAP_PRIVATE | libc::MAP_ANON | libc::MAP_FIXED,
                    -1,
                    0,
                )
            };
            if remapped == libc::MAP_FAILED {
                return ServiceVerdict::Resume(brk.current as i64);
            }
        }
        brk.current = addr;
        ServiceVerdict::Resume(addr as i64)
    }

    /// Run the blocking half of `F_SETLKW`/`F_OFD_SETLKW` after dispatch has
    /// returned its owned outcome and released every subsystem lock.
    ///
    /// Tier-D guest threads are independent host pthreads, so blocking this
    /// calling pthread leaves a sibling able to release the conflicting lock.
    /// `EINTR` returns through the ordinary syscall boundary below, where the
    /// existing signal/restart policy applies.
    fn service_blocking_record_lock(
        &self,
        syscall: u64,
        lock: &crate::dispatch::BlockingRecordLock,
    ) -> ServiceVerdict {
        match crate::dispatch::drive_blocking_record_lock(lock) {
            DispatchOutcome::Returned { value } => ServiceVerdict::Resume(value),
            DispatchOutcome::Errno { errno } => ServiceVerdict::Resume(errno.guest_retval()),
            other => {
                self.end_process(DirectRunOutcome::Unsupported {
                    syscall,
                    outcome: format!("blocking record-lock driver returned {other:?}"),
                });
                ServiceVerdict::Leave
            }
        }
    }

    /// Run a blocking pipe write continuation after dispatch has released all
    /// subsystem locks. The owned continuation carries its partial offset, so
    /// a readiness wake resumes the INNER write loop rather than re-dispatching
    /// the original syscall and replaying its already-written prefix.
    fn service_blocking_host_write(
        &self,
        syscall: u64,
        mut write: crate::dispatch::BlockingHostWrite,
    ) -> ServiceVerdict {
        let outcome = loop {
            match crate::dispatch::drive_blocking_host_write(&mut write) {
                crate::dispatch::BlockingHostWriteStep::Done(outcome) => break outcome,
                crate::dispatch::BlockingHostWriteStep::Wait => {
                    match self.wait_on_fds(
                        write.tid(),
                        &[crate::io_wait::WaitFd::raw(write.host_fd(), libc::POLLOUT)],
                        None,
                        carrick_abi::WaitSigMask::NONE,
                        FdWaitKind::Kqueue,
                    ) {
                        TierDWait::Ready => continue,
                        // No deadline was supplied, but preserve the shared
                        // driver's defensive partial-progress result if a
                        // waiter nevertheless reports a timeout.
                        TierDWait::TimedOut => {
                            break DispatchOutcome::Returned {
                                value: write.offset() as i64,
                            };
                        }
                        TierDWait::Interrupted => {
                            break crate::vcpu_loop::partial_write_interrupt_outcome(&write);
                        }
                        TierDWait::Leave => return ServiceVerdict::Leave,
                    }
                }
            }
        };
        let outcome =
            crate::vcpu_loop::raise_sigpipe_for_blocking_write(&self.dispatcher, &write, outcome);
        match outcome {
            DispatchOutcome::Returned { value } => ServiceVerdict::Resume(value),
            DispatchOutcome::Errno { errno } => ServiceVerdict::Resume(errno.guest_retval()),
            other => {
                self.end_process(DirectRunOutcome::Unsupported {
                    syscall,
                    outcome: format!("blocking host-write driver returned {other:?}"),
                });
                ServiceVerdict::Leave
            }
        }
    }

    /// Service one syscall from a tier-D island: dispatch, then run the
    /// signal-delivery boundary — every completed syscall is a delivery
    /// point, exactly the DSR loop's `complete_dsr_syscall` contract.
    fn service(&self, ctx: &mut GuestContext) -> ServiceVerdict {
        // A child tid is registered before its host thread starts. If a fork
        // begins in that interval, the new thread must contribute to the
        // forker's live-count drain before its first guest instruction.
        self.park_for_fork_quiesce();
        if self.exiting.load(Ordering::SeqCst) {
            return ServiceVerdict::Leave;
        }
        let number = ctx.syscall_nr();
        let name = crate::syscall::lookup_aarch64(number).map_or("unknown", |syscall| syscall.name);
        let mut service = crate::native_darwin::NativeSyscallServiceSpan::open(number, name);
        let verdict = self.service_syscall(ctx, number, name);
        // The flag can rise while dispatch is in flight. Park on every
        // outcome, including ThreadExit: the forker may already have counted
        // this tid, so disappearing without a pause would strand the drain.
        self.park_for_fork_quiesce();
        let verdict = if self.exiting.load(Ordering::SeqCst)
            && matches!(verdict, ServiceVerdict::Resume(_))
        {
            ServiceVerdict::Leave
        } else {
            verdict
        };
        let service_outcome = match verdict {
            ServiceVerdict::Resume(_) => crate::probes::NativeSyscallServiceOutcome::Resume,
            // `exit`/`exit_group` complete by retiring a thread or the whole
            // group. `rt_sigreturn` likewise does not return to the syscall
            // site, but it DOES resume the guest at the restored context.
            ServiceVerdict::Leave if matches!(number, 93 | 94) => {
                crate::probes::NativeSyscallServiceOutcome::ThreadExit
            }
            ServiceVerdict::Leave if number == 139 => {
                crate::probes::NativeSyscallServiceOutcome::Resume
            }
            ServiceVerdict::Leave => crate::probes::NativeSyscallServiceOutcome::Aborted,
        };
        let closed = service.end(service_outcome);
        debug_assert!(closed, "tier-D syscall service span closed exactly once");
        match verdict {
            ServiceVerdict::Resume(value) => self.deliver_pending_at_boundary(ctx, value),
            leave => leave,
        }
    }

    /// The dispatch half of [`Self::service`].
    ///
    /// The dispatch runs in a RE-DISPATCH loop, mirroring the DSR native
    /// loop's contract for blocking outcomes: a wait that reports `Ready`
    /// re-dispatches the SAME request so the handler completes it against
    /// fresh state; `TimedOut` completes with the outcome's timeout value;
    /// an interruption is classified — process exit retires the thread, and
    /// a deliverable pending signal completes the syscall with `EINTR` so
    /// the boundary delivers its handler (or restarts, per `SA_RESTART`).
    fn service_syscall(
        &self,
        ctx: &mut GuestContext,
        number: u64,
        name: &'static str,
    ) -> ServiceVerdict {
        self.syscalls.fetch_add(1, Ordering::Relaxed);
        let identity_memory = matches!(number, 214 | 215 | 216 | 222 | 226 | 233);
        if identity_memory {
            self.reporter.record(CompatEvent::SyscallEntry {
                number,
                name: std::borrow::Cow::Borrowed(name),
                args: SyscallArgs(ctx.args()),
            });
        }
        if let Some(verdict) = self.service_identity_memory(ctx) {
            if let ServiceVerdict::Resume(value) = verdict {
                let errno = i32::try_from(-value)
                    .ok()
                    .filter(|errno| (1..=4095).contains(errno));
                self.reporter.record(CompatEvent::SyscallReturn {
                    number,
                    name: std::borrow::Cow::Borrowed(name),
                    retval: value,
                    errno,
                });
            }
            return verdict;
        }
        let request = SyscallRequest::from_raw(carrick_hal::RawSyscall {
            number: CanonicalNr(number),
            args: ctx.args(),
            // aarch64 guest on an aarch64 host: the canonical numbering IS the
            // guest's own, so there is nothing to normalize.
            guest_abi: LinuxGuestAbi::Aarch64,
            native_number: NativeNr(number),
        });
        let tid = self.current_tid();
        let mut memory = self.memory;
        // One deadline per syscall INSTANCE: re-dispatches after a Ready wake
        // must not restart a finite timeout from zero (the DSR loop's
        // `remaining_native_wait_timeout` contract).
        let mut fd_wait_deadline: Option<Instant> = None;
        // The signal-wait (`WaitOnSignals`) overall deadline, same contract.
        let mut signal_wait_deadline: Option<Instant> = None;
        let Some(linux_tid) = self.current_linux_tid() else {
            self.end_process(DirectRunOutcome::Unsupported {
                syscall: number,
                outcome: "missing explicit one-task Linux thread identity".to_string(),
            });
            return ServiceVerdict::Leave;
        };
        let kernel = match self.dispatcher.capture_kernel_context(linux_tid) {
            Ok(kernel) => kernel,
            Err(error) => {
                self.end_process(DirectRunOutcome::Unsupported {
                    syscall: number,
                    outcome: format!("capture one-task kernel context: {error}"),
                });
                return ServiceVerdict::Leave;
            }
        };
        loop {
            self.park_for_fork_quiesce();
            if self.exiting.load(Ordering::SeqCst) {
                return ServiceVerdict::Leave;
            }
            let outcome = self.dispatcher.dispatch_threaded(
                &kernel,
                request,
                &mut memory,
                &self.reporter,
                tid,
                &read_lock(&self.registry),
                &self.futex,
            );
            match outcome {
                Ok(DispatchOutcome::Returned { value }) => return ServiceVerdict::Resume(value),
                Ok(DispatchOutcome::Errno { errno }) => {
                    return ServiceVerdict::Resume(errno.guest_retval());
                }
                Ok(DispatchOutcome::Exit { code }) => {
                    self.end_process(DirectRunOutcome::Exited { code });
                    return ServiceVerdict::Leave;
                }
                // `exit(2)` from a thread that is not the last: retire THIS
                // thread only (CLEARTID write + wake is pthread_join's other
                // half), leaving the process running.
                Ok(DispatchOutcome::ThreadExit { code }) => {
                    self.finish_thread_bookkeeping(tid, code);
                    return ServiceVerdict::Leave;
                }
                // Roadmap Phase 1 item 4: a thread-creating clone spawns a
                // host thread whose guest enters tier D with its OWN
                // DirectThreadSlots (the veneers address per-thread state
                // through the proven TSD chain), parked at the parent's
                // resume site with x0 = 0.
                Ok(DispatchOutcome::CloneThread {
                    stack,
                    tls,
                    flags,
                    parent_tid_addr,
                    child_tid_addr,
                    clear_child_tid_addr,
                }) => {
                    return self.service_clone_thread(
                        ctx,
                        tid,
                        linux_tid,
                        flags,
                        stack,
                        tls,
                        parent_tid_addr,
                        child_tid_addr,
                        clear_child_tid_addr,
                    );
                }
                // Process-creating clone: a real host fork of this runner
                // process — identity memory makes the copied address space
                // the child's guest state by construction (Phase 2 item 2).
                Ok(DispatchOutcome::Fork {
                    flags: _,
                    pidfd_out,
                    clone_parent,
                    parent_tid_addr,
                    child_tid_addr,
                    exit_signal,
                    child_stack,
                    vfork,
                }) => {
                    return self.service_fork(
                        ctx,
                        tid,
                        ForkRequest {
                            pidfd_out,
                            clone_parent,
                            parent_tid_addr,
                            child_tid_addr,
                            exit_signal,
                            child_stack,
                            vfork,
                        },
                    );
                }
                // `execve(2)`: leave to the existing host self-re-exec path
                // (the capsule); the resumed process tier-decides ANEW for
                // the new image. On success the host `execve` replaces this
                // process inside the call; a pre-commit failure resumes the
                // guest with the errno, exactly as Linux's execve returns.
                Ok(DispatchOutcome::Execve { path, argv, env }) => {
                    let Some(exec) = &self.exec else {
                        self.end_process(DirectRunOutcome::Unsupported {
                            syscall: number,
                            outcome: format!(
                                "Execve {{ path: {path:?} }} without exec services \
                                 (tier D outside the shipped driver)"
                            ),
                        });
                        return ServiceVerdict::Leave;
                    };
                    if read_lock(&self.registry).live_count() > 1 {
                        // Linux execve destroys sibling threads; tier D has
                        // no sibling-teardown orchestration yet. Fail closed.
                        self.end_process(DirectRunOutcome::Unsupported {
                            syscall: number,
                            outcome: "execve with live sibling threads on tier D".to_string(),
                        });
                        return ServiceVerdict::Leave;
                    }
                    return match crate::native_darwin::tier_d_service_execve(
                        &self.dispatcher,
                        path,
                        argv,
                        env,
                        &exec.plan,
                        exec.max_traps,
                    ) {
                        crate::native_darwin::TierDExecFlow::Resume(value) => {
                            ServiceVerdict::Resume(value)
                        }
                        crate::native_darwin::TierDExecFlow::Replace(replacement) => {
                            let mut slot = lock(&self.exec_replacement);
                            if slot.is_some() {
                                drop(slot);
                                self.end_process(DirectRunOutcome::Unsupported {
                                    syscall: number,
                                    outcome: "second prepared Tier-D exec replacement".to_string(),
                                });
                                ServiceVerdict::Leave
                            } else {
                                *slot = Some(*replacement);
                                drop(slot);
                                self.end_process(DirectRunOutcome::ExecReplacement);
                                ServiceVerdict::Leave
                            }
                        }
                    };
                }
                // `rt_sigreturn(2)`: pop the frame, chain-deliver, re-enter
                // at the RESTORED pc (constant resume branches cannot).
                Ok(DispatchOutcome::SigReturn) => {
                    return self.service_sigreturn(ctx, tid);
                }
                // `tkill`/`tgkill` to a sibling guest thread: publish into
                // its pending state and wake its parks (futex notify + the
                // waiter self-pipe); the target delivers at its next
                // boundary or interrupted wait. A SELF-directed tkill is
                // delivered immediately by this syscall's own boundary
                // epilogue.
                Ok(DispatchOutcome::SignalThread {
                    tid: target,
                    signum,
                }) => {
                    let value = if read_lock(&self.registry).is_live(target) {
                        crate::native_darwin::publish_native_pending_for(target.raw(), signum);
                        0
                    } else {
                        crate::linux_abi::LINUX_ESRCH.guest_retval()
                    };
                    return ServiceVerdict::Resume(value);
                }
                // The dispatcher resolved a signal to immediate thread-group
                // death (e.g. an unblockable fatal directed at self).
                Ok(DispatchOutcome::SignalDeath { signum }) => {
                    return self.die_by_guest_signal(signum);
                }
                // Synchronous signal wait (`rt_sigtimedwait`/`rt_sigsuspend`
                // /`pause`): park until a wait-set signal is pending (Ready
                // → re-dispatch dequeues it and writes siginfo), a caught
                // signal OUTSIDE the set interrupts with EINTR (its handler
                // delivers at this syscall's boundary), or the guest timeout
                // expires (EAGAIN).
                Ok(DispatchOutcome::WaitOnSignals {
                    wait_set,
                    block_mask,
                    timeout,
                }) => {
                    use crate::native_darwin::NativeSignalWaitResult;
                    match self.wait_on_signals(
                        tid,
                        wait_set,
                        block_mask,
                        timeout,
                        &mut signal_wait_deadline,
                    ) {
                        NativeSignalWaitResult::Ready => continue,
                        NativeSignalWaitResult::Interrupted => {
                            if self.exiting.load(Ordering::SeqCst) {
                                return ServiceVerdict::Leave;
                            }
                            return ServiceVerdict::Resume(
                                crate::linux_abi::LINUX_EINTR.guest_retval(),
                            );
                        }
                        NativeSignalWaitResult::TimedOut => {
                            return ServiceVerdict::Resume(
                                crate::linux_abi::LINUX_EAGAIN.guest_retval(),
                            );
                        }
                    }
                }
                // FUTEX_WAIT whose value check passed under the dispatcher
                // lock: park on the shared table (the dispatcher's wake side
                // uses the same one). A deliverable pending signal breaks
                // the park with EINTR so the boundary delivers its handler;
                // a fork quiesce breaks it only long enough to park at the
                // barrier, then re-dispatches invisibly.
                Ok(DispatchOutcome::FutexWait { wait, timeout }) => {
                    match self
                        .futex
                        .wait_prepared_for_thread(wait, timeout, tid, &|| {
                            self.exiting.load(Ordering::SeqCst)
                                || self.deliverable_wait_signal_pending(
                                    tid,
                                    carrick_abi::WaitSigMask::NONE,
                                )
                                || crate::fork_quiesce::is_quiescing()
                                || crate::fork_quiesce::exec_replacing_other_thread(tid)
                        }) {
                        crate::thread::FutexWaitOutcome::Woken => {
                            return ServiceVerdict::Resume(0);
                        }
                        crate::thread::FutexWaitOutcome::TimedOut => {
                            return ServiceVerdict::Resume(
                                crate::linux_abi::LINUX_ETIMEDOUT.guest_retval(),
                            );
                        }
                        crate::thread::FutexWaitOutcome::Interrupted => {
                            if self.exiting.load(Ordering::SeqCst) {
                                return ServiceVerdict::Leave;
                            }
                            let real_signal = self.deliverable_wait_signal_pending(
                                tid,
                                carrick_abi::WaitSigMask::NONE,
                            );
                            if !real_signal
                                && !crate::fork_quiesce::exec_replacing_other_thread(tid)
                                && crate::fork_quiesce::is_quiescing()
                            {
                                self.park_for_fork_quiesce();
                                continue;
                            }
                            return ServiceVerdict::Resume(
                                crate::linux_abi::LINUX_EINTR.guest_retval(),
                            );
                        }
                    }
                }
                // Blocking fd waits: park on the per-thread waiter, then
                // RE-DISPATCH on readiness (the handler then finds the ready
                // fds and completes the syscall itself).
                Ok(DispatchOutcome::WaitOnFds {
                    fds,
                    timeout,
                    on_timeout,
                    sig_mask,
                }) => {
                    let Some(remaining) = remaining_wait_timeout(timeout, &mut fd_wait_deadline)
                    else {
                        return ServiceVerdict::Resume(on_timeout);
                    };
                    match self.wait_on_fds(tid, &fds, remaining, sig_mask, FdWaitKind::Kqueue) {
                        TierDWait::Ready => continue,
                        TierDWait::TimedOut => return ServiceVerdict::Resume(on_timeout),
                        TierDWait::Interrupted => {
                            return ServiceVerdict::Resume(
                                crate::linux_abi::LINUX_EINTR.guest_retval(),
                            );
                        }
                        TierDWait::Leave => return ServiceVerdict::Leave,
                    }
                }
                Ok(DispatchOutcome::WaitOnPollFds {
                    fds,
                    timeout,
                    on_timeout,
                    sig_mask,
                }) => {
                    let Some(remaining) = remaining_wait_timeout(timeout, &mut fd_wait_deadline)
                    else {
                        return ServiceVerdict::Resume(on_timeout);
                    };
                    match self.wait_on_fds(tid, &fds, remaining, sig_mask, FdWaitKind::Poll) {
                        TierDWait::Ready => continue,
                        TierDWait::TimedOut => return ServiceVerdict::Resume(on_timeout),
                        TierDWait::Interrupted => {
                            return ServiceVerdict::Resume(
                                crate::linux_abi::LINUX_EINTR.guest_retval(),
                            );
                        }
                        TierDWait::Leave => return ServiceVerdict::Leave,
                    }
                }
                Ok(DispatchOutcome::WaitOnFdsSelect {
                    fds,
                    timeout,
                    sig_mask,
                    clear_on_timeout,
                }) => {
                    let timed_out = |this: &Self| {
                        // select's timeout contract: zeroed fd-sets, retval 0.
                        let mut memory = this.memory;
                        for (addr, len) in &clear_on_timeout {
                            let _ = memory.write_bytes_raw(*addr, &vec![0_u8; *len]);
                        }
                        ServiceVerdict::Resume(0)
                    };
                    let Some(remaining) = remaining_wait_timeout(timeout, &mut fd_wait_deadline)
                    else {
                        return timed_out(self);
                    };
                    match self.wait_on_fds(tid, &fds, remaining, sig_mask, FdWaitKind::Kqueue) {
                        TierDWait::Ready => continue,
                        TierDWait::TimedOut => return timed_out(self),
                        TierDWait::Interrupted => {
                            return ServiceVerdict::Resume(
                                crate::linux_abi::LINUX_EINTR.guest_retval(),
                            );
                        }
                        TierDWait::Leave => return ServiceVerdict::Leave,
                    }
                }
                // Blocking child wait: park on the child's exit (EVFILT_PROC
                // under the per-thread waiter), then re-dispatch to reap.
                // EINTR here is the SA_RESTART-restartable case (wait4 and
                // waitid are the kernel's restartable set): the boundary
                // epilogue restarts or surfaces EINTR per the handler flags.
                Ok(DispatchOutcome::WaitOnProcExit { pid, sig_mask }) => {
                    match self.wait_on_proc_exit(tid, pid, sig_mask) {
                        TierDWait::Ready | TierDWait::TimedOut => continue,
                        TierDWait::Interrupted => {
                            return ServiceVerdict::Resume(
                                crate::linux_abi::LINUX_EINTR.guest_retval(),
                            );
                        }
                        TierDWait::Leave => return ServiceVerdict::Leave,
                    }
                }
                // Non-terminal child state (WSTOPPED/WCONTINUED): bounded
                // re-poll, the DSR arm's exact shape.
                Ok(DispatchOutcome::WaitOnProcState { pid: _, sig_mask }) => {
                    match self.wait_on_proc_state(tid, sig_mask) {
                        TierDWait::Ready | TierDWait::TimedOut => continue,
                        TierDWait::Interrupted => {
                            return ServiceVerdict::Resume(
                                crate::linux_abi::LINUX_EINTR.guest_retval(),
                            );
                        }
                        TierDWait::Leave => return ServiceVerdict::Leave,
                    }
                }
                // Relative sleep: completes with 0, or EINTR on a delivered
                // signal — writing the remaining time first, as nanosleep
                // does.
                Ok(DispatchOutcome::WaitOnSleep {
                    duration,
                    remaining,
                }) => {
                    let deadline = Instant::now() + duration;
                    match self.wait_on_sleep(tid, deadline) {
                        TierDWait::Ready | TierDWait::TimedOut => return ServiceVerdict::Resume(0),
                        TierDWait::Interrupted => {
                            let mut memory = self.memory;
                            let completed = crate::dispatch::complete_interrupted_sleep(
                                &mut memory,
                                remaining,
                                deadline.saturating_duration_since(Instant::now()),
                            );
                            return match completed {
                                DispatchOutcome::Returned { value } => {
                                    ServiceVerdict::Resume(value)
                                }
                                DispatchOutcome::Errno { errno } => {
                                    ServiceVerdict::Resume(errno.guest_retval())
                                }
                                other => {
                                    self.end_process(DirectRunOutcome::Unsupported {
                                        syscall: number,
                                        outcome: format!(
                                            "interrupted sleep completed with {other:?}"
                                        ),
                                    });
                                    ServiceVerdict::Leave
                                }
                            };
                        }
                        TierDWait::Leave => return ServiceVerdict::Leave,
                    }
                }
                Ok(DispatchOutcome::BlockingRecordLock(lock)) => {
                    return self.service_blocking_record_lock(number, &lock);
                }
                Ok(DispatchOutcome::BlockingHostWrite(write)) => {
                    return self.service_blocking_host_write(number, write);
                }
                Ok(other) => {
                    self.end_process(DirectRunOutcome::Unsupported {
                        syscall: number,
                        outcome: format!("{other:?}"),
                    });
                    return ServiceVerdict::Leave;
                }
                Err(error) => {
                    self.end_process(DirectRunOutcome::Unsupported {
                        syscall: number,
                        outcome: error.to_string(),
                    });
                    return ServiceVerdict::Leave;
                }
            }
        }
    }

    /// Spawn a guest thread for `clone(CLONE_VM|CLONE_THREAD)`.
    ///
    /// The child's [`DirectThreadSlots`] are seeded on the PARENT (so any
    /// failure surfaces as the clone's errno, never a half-started thread):
    /// full parent register file with x0 = 0 (the child's clone return
    /// value — glibc's clone.S reads fn/arg out of copied registers, so the
    /// whole file is load-bearing), SP = the caller's child stack, pc = the
    /// parent's resume site, TLS = `CLONE_SETTLS`'s value or inherited,
    /// x18 inherited. The spawned host thread installs the slots and enters
    /// through the parked-entry stub ([`DirectLoadGroup::enter_parked`]).
    #[allow(clippy::too_many_arguments)]
    fn service_clone_thread(
        &self,
        ctx: &GuestContext,
        parent_tid: ThreadId,
        parent_linux_tid: crate::kernel::LinuxTid,
        flags: u64,
        stack: u64,
        tls: Option<u64>,
        parent_tid_addr: u64,
        child_tid_addr: u64,
        clear_child_tid_addr: u64,
    ) -> ServiceVerdict {
        let Some(group) = active_group() else {
            self.end_process(DirectRunOutcome::Unsupported {
                syscall: ctx.syscall_nr(),
                outcome: "thread clone with no tier-D load group installed".to_string(),
            });
            return ServiceVerdict::Leave;
        };
        let parent_slots = current_thread_slots_ptr();
        if parent_slots.is_null() {
            self.end_process(DirectRunOutcome::Unsupported {
                syscall: ctx.syscall_nr(),
                outcome: "thread clone with no installed parent thread slots".to_string(),
            });
            return ServiceVerdict::Leave;
        }
        // SAFETY: the parent's own installed slots; its guest is parked in
        // this handler, so the values are stable.
        let (parent_tls, parent_x18) =
            unsafe { ((*parent_slots).guest_tls, (*parent_slots).guest_x18) };
        let mut slots = group.new_thread_slots();
        slots.context.x = ctx.x;
        slots.context.x[0] = 0;
        slots.context.sp = stack;
        slots.context.pc = ctx.pc;
        slots.guest_tls = tls.unwrap_or(parent_tls);
        slots.guest_x18 = parent_x18;

        let clone_plan = match crate::kernel::ClonePlan::from_flags(
            carrick_abi::LinuxCloneFlags::from_bits_retain(flags),
        ) {
            Ok(plan) => plan,
            Err(_) => {
                return ServiceVerdict::Resume(crate::linux_abi::LINUX_EINVAL.guest_retval());
            }
        };
        let parent_context = match self.dispatcher.capture_kernel_context(parent_linux_tid) {
            Ok(context) => context,
            Err(error) => {
                self.end_process(DirectRunOutcome::Unsupported {
                    syscall: ctx.syscall_nr(),
                    outcome: format!("capture tier-D clone parent Kernel context: {error}"),
                });
                return ServiceVerdict::Leave;
            }
        };
        let reservation =
            match parent_context
                .kernel()
                .reserve_thread_clone(&parent_context, clone_plan, None)
            {
                Ok(reservation) => reservation,
                Err(error) => {
                    self.end_process(DirectRunOutcome::Unsupported {
                        syscall: ctx.syscall_nr(),
                        outcome: format!("reserve tier-D Kernel thread: {error}"),
                    });
                    return ServiceVerdict::Leave;
                }
            };
        let linux_tid = reservation.tid();
        let mut memory = self.memory;
        let read_tid_output = |memory: &mut IdentityMemory, address: u64| {
            if address == 0 {
                Some(None)
            } else {
                memory
                    .read_bytes(address, std::mem::size_of::<i32>())
                    .ok()
                    .map(Some)
            }
        };
        let Some(parent_tid_original) = read_tid_output(&mut memory, parent_tid_addr) else {
            return ServiceVerdict::Resume(crate::linux_abi::LINUX_EFAULT.guest_retval());
        };
        let Some(child_tid_original) = read_tid_output(&mut memory, child_tid_addr) else {
            return ServiceVerdict::Resume(crate::linux_abi::LINUX_EFAULT.guest_retval());
        };
        let tid = read_lock(&self.registry).register_child(clear_child_tid_addr);
        let prepared_thread = match reservation.prepare(tid) {
            Ok(prepared) => prepared,
            Err(error) => {
                read_lock(&self.registry).exit(tid);
                self.end_process(DirectRunOutcome::Unsupported {
                    syscall: ctx.syscall_nr(),
                    outcome: format!("prepare tier-D Kernel thread: {error}"),
                });
                return ServiceVerdict::Leave;
            }
        };
        self.dispatcher.inherit_thread_signal_mask(parent_tid, tid);

        // A process with two guest threads must have Mach delivery on both
        // before either can publish or execute a process-global MAP_JIT range.
        // The parent is parked in this clone handler now; make the requirement
        // sticky before spawning, so the child and the parent's next entry
        // both arm their ports without a cross-thread race.
        group.require_mach_exception_handler();
        let runner_ptr = SendPtr(std::ptr::from_ref(self));
        let group_ptr = SendGroupPtr(std::ptr::from_ref(group));
        let (start_tx, start_rx) = std::sync::mpsc::sync_channel(1);
        let spawned = std::thread::Builder::new()
            .name(format!("tierd-guest-{tid}"))
            .spawn(move || {
                let (runner_ptr, group_ptr) = (runner_ptr, group_ptr);
                // SAFETY: `with_runner` joins every spawned guest thread
                // before returning, and its caller keeps the runner and the
                // group alive across it — so both pointers outlive this
                // thread.
                let (runner, group) = unsafe { (&*runner_ptr.0, &*group_ptr.0) };
                if start_rx.recv() != Ok(true) {
                    runner.finish_thread_bookkeeping(tid, 0);
                    return;
                }
                // A child that cannot ENTER is a process-level failure, not
                // a quiet thread death: the guest was told the clone
                // succeeded, so a thread that never runs its first
                // instruction is silent corruption (the pthread_join
                // "succeeds", the thread's work never happened — exactly
                // the shape a load-coupled stub-placement refusal produced,
                // 1/25 as an empty-stdout flake). Fail LOUD: name the
                // reason as the process outcome, then retire the tid so a
                // joiner still unblocks and the run can end.
                let fail_closed = |what: String| {
                    runner.end_process(DirectRunOutcome::Unsupported {
                        syscall: 220,
                        outcome: what,
                    });
                    runner.finish_thread_bookkeeping(tid, 0);
                };
                let guard = match InstalledThreadSlots::install(slots) {
                    Ok(guard) => guard,
                    Err(error) => {
                        fail_closed(format!("clone child slot install failed: {error}"));
                        return;
                    }
                };
                let _thread_ctx = install_thread_context(runner, group, tid);
                // `register_child` preceded the host spawn. A sibling fork
                // may therefore already include this tid in its drain.
                runner.park_for_fork_quiesce();
                if runner.exiting.load(Ordering::SeqCst) {
                    runner.finish_thread_bookkeeping(tid, 0);
                    drop(guard);
                    return;
                }
                // SAFETY: the parked context was seeded from the parent's
                // state at a patched svc site of this group, and the guest
                // leaves through the handler.
                if let Err(error) = unsafe { group.enter_parked() } {
                    fail_closed(format!("clone child parked entry failed: {error}"));
                } else {
                    // Delivery/sigreturn re-entries for THIS guest thread.
                    // SAFETY: the parked context was written by this thread's
                    // own delivery path from a genuine guest state.
                    unsafe { reenter_until_final(runner, group) };
                }
                drop(guard);
                runner.terminate_forked_child_from_guest_thread();
            });
        match spawned {
            Ok(handle) => {
                let restore_tid_outputs = |memory: &mut IdentityMemory| {
                    if let Some(bytes) = parent_tid_original.as_ref() {
                        let _ = memory.write_bytes_raw(parent_tid_addr, bytes);
                    }
                    if let Some(bytes) = child_tid_original.as_ref() {
                        let _ = memory.write_bytes_raw(child_tid_addr, bytes);
                    }
                };
                let tid_bytes = linux_tid.raw().to_le_bytes();
                let tid_outputs_published = (parent_tid_addr == 0
                    || memory.write_bytes_raw(parent_tid_addr, &tid_bytes).is_ok())
                    && (child_tid_addr == 0
                        || memory.write_bytes_raw(child_tid_addr, &tid_bytes).is_ok());
                if !tid_outputs_published {
                    restore_tid_outputs(&mut memory);
                    let _ = start_tx.send(false);
                    let _ = handle.join();
                    return ServiceVerdict::Resume(crate::linux_abi::LINUX_EFAULT.guest_retval());
                }
                let published = match prepared_thread.commit() {
                    Ok(published) => published,
                    Err(error) => {
                        restore_tid_outputs(&mut memory);
                        let _ = start_tx.send(false);
                        let _ = handle.join();
                        self.end_process(DirectRunOutcome::Unsupported {
                            syscall: ctx.syscall_nr(),
                            outcome: format!("publish tier-D Kernel thread: {error}"),
                        });
                        return ServiceVerdict::Leave;
                    }
                };
                if let Err(error) = published.into_context() {
                    tracing::error!(
                        linux_tid = linux_tid.raw(),
                        backend_tid = tid.raw(),
                        %error,
                        "tier-D Kernel start gate failed after publication"
                    );
                    std::process::abort();
                }
                write_lock(&self.linux_tids).insert(tid, linux_tid);
                lock(&self.threads).push(handle);
                if start_tx.send(true).is_err() {
                    std::process::abort();
                }
                ServiceVerdict::Resume(i64::from(linux_tid.raw()))
            }
            Err(_) => {
                read_lock(&self.registry).exit(tid);
                self.dispatcher.forget_thread_signal_state(tid);
                ServiceVerdict::Resume(crate::host_to_linux_errno(libc::EAGAIN).guest_retval())
            }
        }
    }

    /// Service a process-creating `clone(2)` (fork) by forking THIS host
    /// process — the identity tier's structural win: guest VA is host VA, so
    /// the kernel's CoW copy of the address space IS the child's guest state,
    /// with no snapshot, no rebuild, and no translator repair.
    ///
    /// Both sides resume through the normal island restore: the child
    /// continues from this handler with x0 = 0 on its (copied) guest stack,
    /// the parent with the child's guest-visible pid. The pre/post-fork
    /// bookkeeping mirrors the DSR lane's `handle_native_fork` — ns-pid
    /// allocation, the guest-cpu child record, the shared dispatcher
    /// fork-child reset, the child-exit watch, and the shared sibling
    /// quiesce. vfork is serviced as CoW + true parent
    /// suspension; see the vfork block below for the one documented
    /// divergence (no CLONE_VM memory sharing).
    fn service_fork(
        &self,
        ctx: &mut GuestContext,
        parent_tid: ThreadId,
        request: ForkRequest,
    ) -> ServiceVerdict {
        use carrick_dsr_aarch64::mapped_memory::NATIVE_FORKED_GUEST_CHILD;
        let eagain =
            || ServiceVerdict::Resume(crate::host_to_linux_errno(libc::EAGAIN).guest_retval());
        let unsupported = |what: &str| {
            self.end_process(DirectRunOutcome::Unsupported {
                syscall: ctx.syscall_nr(),
                outcome: what.to_string(),
            });
            ServiceVerdict::Leave
        };
        // XNU applies the pre-macOS-13 preserve-x18 compatibility policy at
        // exec signature processing, but a Darwin fork/vfork child does not
        // inherit it (qualified against current XNU and a live syscall probe).
        // Record the parent's proven policy now. The child uses it below to
        // replace inherited dynamic MAP_JIT mappings with byte-preserving DSR
        // shadow sources before any guest instruction resumes; the parent
        // retains the low-overhead physical-x18 direct path.
        let fork_child_needs_dynamic_shadow =
            carrick_native_darwin::direct::physical_x18_supported();
        if request.clone_parent {
            return unsupported("CLONE_PARENT fork on tier D");
        }
        let barrier = crate::fork_quiesce::barrier();
        if !barrier.try_begin_fork() {
            return eagain();
        }
        let live_at_fork = read_lock(&self.registry).live_count();
        let mut quiesced = false;
        if live_at_fork > 1 {
            barrier.set_quiescing();
            // Publish quiesce before waking both independent park classes.
            // Futex waiters observe the shared generation; fd/sleep/signal
            // waiters observe their private pipe. Registration precedes each
            // wait's final is_quiescing() check, so no periodic retry is needed.
            self.futex.notify_signal_pending();
            crate::host_signal::wake_all_waiters();
            if !barrier.wait_quiesced(live_at_fork - 1, Duration::from_secs(10)) {
                barrier.end_quiesce();
                barrier.end_fork();
                return eagain();
            }
            quiesced = true;
        }
        let end_fork_state = || {
            if quiesced {
                barrier.end_quiesce();
            }
            barrier.end_fork();
        };
        crate::probes::fork_pre(ctx.pc, 0, 0);
        // vfork/CLONE_VFORK: the child gets the same CoW copy an ordinary
        // fork gets — tier D's identity mappings are MAP_PRIVATE, so the
        // CLONE_VM sharing HALF of vfork cannot be honored — but the
        // SUSPENSION half is: the parent blocks here until the child execs
        // or exits, signalled by EOF on a pipe whose write end is CLOEXEC
        // in the child (the capsule self-re-exec's host execve closes it;
        // so does any exit). Within POSIX's vfork contract (the child only
        // execs or `_exit`s) this is exact; the one divergence is a guest
        // that WRITES parent-visible memory in the vfork window — glibc
        // posix_spawn's failed-exec errno write-back — which under CoW the
        // parent never sees (the spawn "succeeds" and the child exits 127).
        // Deliberate, documented approximation; full fidelity needs
        // shareable guest memory, which is the DSR lane's
        // `set_fork_inheritance` and a tier-D future lever.
        let vfork_pipe = if request.vfork.is_some() {
            let mut fds = [0 as libc::c_int; 2];
            // SAFETY: plain pipe(2) into a local array.
            if unsafe { libc::pipe(fds.as_mut_ptr()) } != 0 {
                end_fork_state();
                return eagain();
            }
            // SAFETY: just-created fd; set the WRITE end close-on-exec so
            // the child's execve releases the parent without cooperation.
            unsafe {
                libc::fcntl(fds[1], libc::F_SETFD, libc::FD_CLOEXEC);
            }
            Some((fds[0], fds[1]))
        } else {
            None
        };
        let close_pipe = |pipe: Option<(i32, i32)>| {
            if let Some((read_fd, write_fd)) = pipe {
                // SAFETY: fds owned by this function.
                unsafe {
                    libc::close(read_fd);
                    libc::close(write_fd);
                }
            }
        };
        let child_parent = std::process::id();
        let child_subreaper = self.dispatcher.subreaper_for_fork_child();
        let child_ns_pid = crate::namespace::pid::allocate_child_ns_pid_pre_fork();
        let Ok(prepared_child_record) = crate::guest_cpu::prepare_child_record_pre_fork(
            child_parent,
            child_subreaper,
            child_ns_pid.unwrap_or(0),
            false,
            0,
        ) else {
            close_pipe(vfork_pipe);
            end_fork_state();
            return eagain();
        };
        // Pin the fork-shared signal-static mutexes an auxiliary thread (the
        // child-exit watcher mid-publish) can hold, exactly as the DSR fork
        // does — a fork landing inside such a window hands the child a lock
        // held by a thread that does not exist there.
        let fork_signal_locks = crate::host_signal::hold_signal_locks_for_fork();
        // Exclude the barrier's park-window mutex across fork. Every sibling
        // is parked with no runner/dispatcher lock held, and the forking
        // thread owns this mutex in both CoW copies, so the child can reset it.
        let paused_across_fork = quiesced.then(|| barrier.lock_paused_across_fork());
        // SAFETY: every guest sibling is parked; this thread's guest state is
        // fully in `ctx` and host memory.
        let child = unsafe { libc::fork() };
        drop(fork_signal_locks);
        drop(paused_across_fork);
        if child < 0 {
            crate::guest_cpu::abort_prepared_child_record();
            close_pipe(vfork_pipe);
            end_fork_state();
            return eagain();
        }
        if child == 0 {
            end_fork_state();
            if quiesced {
                barrier.reset_paused_for_child();
            }
            // CHILD: repair inherited runtime state before the guest resumes.
            if let Some((read_fd, write_fd)) = vfork_pipe {
                // Keep the CLOEXEC write end: closing it (via exec or exit)
                // IS the vfork-completion signal. Drop the read end.
                // SAFETY: the child's own inherited fd.
                unsafe {
                    libc::close(read_fd);
                }
                self.hold_vfork_completion_fd(write_fd);
            }
            if fork_child_needs_dynamic_shadow {
                let Some(group) = active_group() else {
                    return unsupported(
                        "fork child has no tier-D load group for dynamic shadow transition",
                    );
                };
                if let Err(error) = group.enable_dynamic_shadow() {
                    return unsupported(&format!(
                        "fork child could not preserve dynamic text through the tier-D shadow transition: {error}"
                    ));
                }
            }
            if let Err(error) = carrick_native_darwin::direct::exception_handler_after_fork_child()
            {
                return unsupported(&format!(
                    "fork child could not rebind tier-D Mach exception server: {error}"
                ));
            }
            NATIVE_FORKED_GUEST_CHILD.store(true, Ordering::Release);
            self.forked_child.store(true, Ordering::Release);
            crate::probes::host_process_birth_current();
            crate::native::fork_child::dispatcher_after_fork_child(&self.dispatcher);
            let child_tid = self.reset_after_fork_child();
            self.dispatcher
                .retire_sibling_thread_signal_state(parent_tid);
            self.dispatcher
                .migrate_thread_signal_state(parent_tid, child_tid);
            crate::guest_cpu::reset();
            crate::guest_cpu::complete_child_record_post_fork_child();
            if let Err(error) = self.dispatcher.rlimit_cpu_after_fork_child() {
                return unsupported(&format!(
                    "fork child could not rearm finite RLIMIT_CPU helper: {error}"
                ));
            }
            crate::run_state::reinit_booting_after_fork();
            let self_tid = (crate::namespace::pid::self_ns_pid() as i32).to_le_bytes();
            let mut memory = self.memory;
            if let Some(addr) = request.parent_tid_addr {
                let _ = memory.write_bytes_raw(addr, &self_tid);
            }
            if let Some(addr) = request.child_tid_addr {
                let _ = memory.write_bytes_raw(addr, &self_tid);
            }
            // A clone with an explicit stack runs the CHILD on it, exactly as
            // the kernel does; the island's restore reads SP from the context.
            // (vfork carries its stack argument in the `vfork` payload.)
            if request.child_stack != 0 {
                ctx.sp = request.child_stack;
            }
            if let Some(stack) = request.vfork
                && stack != 0
            {
                ctx.sp = stack;
            }
            crate::probes::fork_post(0, ctx.pc, 0);
            return ServiceVerdict::Resume(0);
        }
        // PARENT: release siblings before a possible vfork suspension.
        end_fork_state();
        // PARENT. For vfork, SUSPEND until the child execs or exits (EOF on
        // the pipe): the guest contract, and the same order as the DSR
        // lane's vfork wait (suspend first, publish after). Single guest
        // thread is guaranteed above, so a blocking read cannot starve a
        // sibling; EINTR (a host signal against carrick) just retries.
        if let Some((read_fd, write_fd)) = vfork_pipe {
            // SAFETY: parent's copy of the write end; the child holds its own.
            unsafe {
                libc::close(write_fd);
            }
            let mut byte = [0_u8; 1];
            loop {
                // SAFETY: blocking read on the runner-owned pipe read end.
                let n = unsafe { libc::read(read_fd, byte.as_mut_ptr().cast(), 1) };
                if n > 0 {
                    continue; // contract violation tolerated: keep draining
                }
                if n == 0 {
                    break; // EOF: the child exec'd or exited
                }
                if std::io::Error::last_os_error().raw_os_error() != Some(libc::EINTR) {
                    break;
                }
            }
            // SAFETY: as above.
            unsafe {
                libc::close(read_fd);
            }
        }
        // Publish the child record and arm the exit watch.
        crate::guest_cpu::publish_prepared_child_record_parent_ref(
            prepared_child_record,
            child as u32,
        );
        crate::namespace::pid::notify_child_registered();
        crate::run_state::publish_child_booting(child as u32);
        let mut memory = self.memory;
        if let Some(addr) = request.pidfd_out {
            let fd = self.dispatcher.install_child_pidfd(child).unwrap_or(-1);
            let _ = memory.write_bytes_raw(addr, &fd.to_le_bytes());
        }
        let guest_child_pid = child_ns_pid.unwrap_or(child as u32) as i32;
        if let Some(addr) = request.parent_tid_addr {
            let _ = memory.write_bytes_raw(addr, &guest_child_pid.to_le_bytes());
        }
        crate::native_darwin::native_register_child_exit_watch(
            &self.dispatcher,
            child,
            request.exit_signal,
            parent_tid,
        );
        crate::probes::fork_post(child, ctx.pc, 0);
        ServiceVerdict::Resume(i64::from(guest_child_pid))
    }

    /// Fork-child runner reset: a fresh registry keyed to the child's pid
    /// (only the forking thread survives `fork`), abandoned sibling join
    /// handles (their pthreads do not exist here), and this thread's ACTIVE
    /// tid re-pointed at the new main. The futex table, brk and tracked-anon
    /// state are the guest's own memory bookkeeping and stay valid across
    /// the address-space copy.
    fn reset_after_fork_child(&self) -> ThreadId {
        let tid = ThreadId::main_from_host_pid();
        let registry = Arc::new(crate::thread::ThreadRegistry::new(tid));
        *write_lock(&self.registry) = Arc::clone(&registry);
        crate::thread::set_current_registry(registry);
        let context = self
            .dispatcher
            .reset_one_task_kernel_binding_for_current_process(tid)
            .unwrap_or_else(|error| {
                let message = format!("tier-D fork child Kernel reset failed: {error}\n");
                unsafe {
                    libc::write(2, message.as_ptr().cast(), message.len());
                    libc::_exit(125);
                }
            });
        *write_lock(&self.linux_tids) =
            std::collections::BTreeMap::from([(tid, context.thread().key().tid)]);
        for handle in std::mem::take(&mut *lock(&self.threads)) {
            // The copied JoinHandle names a PARENT thread; joining or
            // detaching it here would target a pthread that does not exist
            // in this process.
            std::mem::forget(handle);
        }
        self.exiting.store(false, Ordering::SeqCst);
        ACTIVE_TID.with(|slot| slot.set(tid));
        // The inherited per-thread waiter (if any) wraps a kqueue, which
        // fork does NOT inherit; drop it so the next wait builds a fresh one.
        TIER_D_WAITER.with(|cell| cell.borrow_mut().take());
        tid
    }

    /// The effective signal block mask for a blocking wait (the DSR lane's
    /// `native_wait_block_mask`).
    fn wait_block_mask(
        &self,
        tid: ThreadId,
        sig_mask: carrick_abi::WaitSigMask,
    ) -> carrick_abi::SigBlockMask {
        let effective = match sig_mask {
            carrick_abi::WaitSigMask::Replace(mask) => mask,
            carrick_abi::WaitSigMask::Additive(mask) => {
                self.dispatcher.signal_mask_for(tid).union(mask)
            }
        };
        carrick_abi::SigBlockMask::blocking_all_of(effective)
    }

    /// A deliverable pending signal for `tid` under a WAIT's mask, checked
    /// across BOTH pending stores: the dispatcher-owned pending state AND
    /// the host slot (`host_signal`) — timers and host-delivered signals
    /// publish into the latter, and the per-thread waiter's own interrupt
    /// check reads it, so a classifier that consulted only dispatcher state
    /// re-dispatched forever against a host-slot pending (the observed
    /// 100%-CPU read spin).
    fn deliverable_wait_signal_pending(
        &self,
        tid: ThreadId,
        sig_mask: carrick_abi::WaitSigMask,
    ) -> bool {
        self.dispatcher
            .has_deliverable_dispatch_pending_for_wait(tid, sig_mask)
            || crate::host_signal::has_unblocked_pending_for(
                tid.raw(),
                self.wait_block_mask(tid, sig_mask),
            )
    }

    /// Classify an interrupted wait. Process end retires the thread quietly
    /// (the outcome is already recorded). A deliverable pending signal with
    /// the wait's mask is what Linux calls an interrupted syscall: the wait
    /// completes with `EINTR` and the boundary-delivery epilogue runs the
    /// handler (or restarts the syscall, per `SA_RESTART`) — exactly the DSR
    /// lane's wait→EINTR→`complete`+`deliver_pending_signal` shape.
    fn classify_wait_interrupt(
        &self,
        tid: ThreadId,
        sig_mask: carrick_abi::WaitSigMask,
    ) -> Option<TierDWait> {
        if self.exiting.load(Ordering::SeqCst) {
            return Some(TierDWait::Leave);
        }
        if self.deliverable_wait_signal_pending(tid, sig_mask) {
            return Some(TierDWait::Interrupted);
        }
        None
    }

    /// The wait-interrupt predicate handed to the per-thread waiter: wake
    /// for process end or for a deliverable pending signal (which the caller
    /// then classifies — see [`Self::classify_wait_interrupt`]).
    fn wait_should_interrupt(&self, tid: ThreadId, sig_mask: carrick_abi::WaitSigMask) -> bool {
        self.exiting.load(Ordering::SeqCst) || self.deliverable_wait_signal_pending(tid, sig_mask)
    }

    /// Park on host-fd readiness (`WaitOnFds`/`WaitOnPollFds`/select).
    fn wait_on_fds(
        &self,
        tid: ThreadId,
        fds: &[crate::io_wait::WaitFd],
        timeout: Option<Duration>,
        sig_mask: carrick_abi::WaitSigMask,
        kind: FdWaitKind,
    ) -> TierDWait {
        let block_mask = self.wait_block_mask(tid, sig_mask);
        let result = with_thread_waiter(tid, |waiter| match kind {
            FdWaitKind::Kqueue => {
                waiter.wait_with_dispatch_pending(fds, timeout, block_mask, || {
                    self.wait_should_interrupt(tid, sig_mask)
                })
            }
            FdWaitKind::Poll => {
                waiter.wait_poll_with_dispatch_pending(fds, timeout, block_mask, || {
                    self.wait_should_interrupt(tid, sig_mask)
                })
            }
        });
        match result {
            crate::io_wait::WaitResult::Ready => TierDWait::Ready,
            crate::io_wait::WaitResult::TimedOut => TierDWait::TimedOut,
            // A spurious host wake re-dispatches (the caller re-derives the
            // remaining time from the per-syscall deadline), and a
            // wait-infrastructure errno is not a guest result — a fresh
            // dispatch takes a fresh look. Only a classified interrupt
            // (process end / deliverable signal) breaks the wait.
            crate::io_wait::WaitResult::Interrupted => self
                .classify_wait_interrupt(tid, sig_mask)
                .unwrap_or(TierDWait::Ready),
            crate::io_wait::WaitResult::Errno(_) => TierDWait::Ready,
        }
    }

    /// Park until the guest child `pid` is reapable (`WaitOnProcExit`).
    fn wait_on_proc_exit(
        &self,
        tid: ThreadId,
        pid: i32,
        sig_mask: carrick_abi::WaitSigMask,
    ) -> TierDWait {
        let block_mask = self.wait_block_mask(tid, sig_mask);
        let result = with_thread_waiter(tid, |waiter| {
            waiter.wait_proc_exit_with_dispatch_pending(pid, block_mask, || {
                self.wait_should_interrupt(tid, sig_mask)
            })
        });
        match result {
            crate::io_wait::WaitResult::Ready | crate::io_wait::WaitResult::TimedOut => {
                TierDWait::Ready
            }
            crate::io_wait::WaitResult::Interrupted => self
                .classify_wait_interrupt(tid, sig_mask)
                .unwrap_or(TierDWait::Ready),
            crate::io_wait::WaitResult::Errno(_) => TierDWait::Ready,
        }
    }

    /// Bounded re-poll for a non-terminal child state (`WaitOnProcState`).
    fn wait_on_proc_state(&self, tid: ThreadId, sig_mask: carrick_abi::WaitSigMask) -> TierDWait {
        let block_mask = self.wait_block_mask(tid, sig_mask);
        let result = with_thread_waiter(tid, |waiter| {
            waiter.wait_proc_state_with_dispatch_pending(block_mask, || {
                self.wait_should_interrupt(tid, sig_mask)
            })
        });
        match result {
            crate::io_wait::WaitResult::Ready | crate::io_wait::WaitResult::TimedOut => {
                TierDWait::Ready
            }
            crate::io_wait::WaitResult::Interrupted => self
                .classify_wait_interrupt(tid, sig_mask)
                .unwrap_or(TierDWait::Ready),
            crate::io_wait::WaitResult::Errno(_) => TierDWait::Ready,
        }
    }

    /// A relative sleep (`WaitOnSleep`), interruptible by process end or a
    /// deliverable pending signal (nanosleep's EINTR).
    fn wait_on_sleep(&self, tid: ThreadId, deadline: Instant) -> TierDWait {
        let sig_mask = carrick_abi::WaitSigMask::NONE;
        let block_mask = self.wait_block_mask(tid, sig_mask);
        loop {
            let now = Instant::now();
            if now >= deadline {
                return TierDWait::TimedOut;
            }
            // The waiter is registered before the final `exiting` predicate
            // check, and end_process stores `exiting` before broadcasting to
            // its private pipe. An unread byte survives the check-to-park race,
            // so park once against the real guest deadline.
            let park_for = deadline - now;
            let result = with_thread_waiter(tid, |waiter| {
                waiter.wait_with_dispatch_pending(&[], Some(park_for), block_mask, || {
                    self.wait_should_interrupt(tid, sig_mask)
                })
            });
            match result {
                crate::io_wait::WaitResult::TimedOut => {
                    if let Some(interrupt) = self.classify_wait_interrupt(tid, sig_mask) {
                        return interrupt;
                    }
                    if Instant::now() >= deadline {
                        return TierDWait::TimedOut;
                    }
                    // A timeout is the guest deadline; rounding can leave a
                    // sub-tick remainder, so the loop verifies the clock.
                }
                crate::io_wait::WaitResult::Ready | crate::io_wait::WaitResult::Interrupted => {
                    if let Some(interrupt) = self.classify_wait_interrupt(tid, sig_mask) {
                        return interrupt;
                    }
                    // A fork quiesce is an internal stop-the-world edge, not
                    // a guest-visible EINTR and not completion of the sleep.
                    // Park here, at the same lock-safe wait boundary, then
                    // continue against the ORIGINAL deadline after release.
                    self.park_for_fork_quiesce();
                    // Spurious: re-park for the remaining time.
                }
                crate::io_wait::WaitResult::Errno(_) => return TierDWait::TimedOut,
            }
        }
    }

    /// Park until a signal in `wait_set` is pending (`WaitOnSignals` —
    /// `rt_sigtimedwait`/`rt_sigsuspend`/`pause`), the DSR lane's
    /// `wait_native_signals` shape: park on the registered wake channel and
    /// re-run pending classification on each real publication.
    fn wait_on_signals(
        &self,
        tid: ThreadId,
        wait_set: SigSet,
        block_mask: carrick_abi::SigBlockMask,
        timeout: Option<Duration>,
        deadline: &mut Option<Instant>,
    ) -> crate::native_darwin::NativeSignalWaitResult {
        use crate::native_darwin::{NativeSignalWaitResult, native_signal_wait_pending};
        loop {
            if self.exiting.load(Ordering::SeqCst) {
                // The caller's Interrupted arm re-checks `exiting` and leaves.
                return NativeSignalWaitResult::Interrupted;
            }
            // Establish the per-syscall deadline using the shared semantics,
            // then park for the FULL remaining guest interval. Tier D has a
            // durable pending bit plus a registered pipe, so the shared VMM
            // lane's historical 50 ms service slice is unnecessary here.
            let Some(_) = crate::vcpu_loop::signal_wait_slice(deadline, timeout) else {
                return NativeSignalWaitResult::TimedOut;
            };
            let park_timeout = crate::vcpu_loop::signal_wait_remaining(*deadline, timeout);
            if let Some(result) =
                native_signal_wait_pending(&self.dispatcher, tid, wait_set, block_mask)
            {
                return result;
            }
            let result = with_thread_waiter(tid, |waiter| {
                waiter.wait_with_dispatch_pending(&[], park_timeout, block_mask, || {
                    self.exiting.load(Ordering::SeqCst)
                        || native_signal_wait_pending(&self.dispatcher, tid, wait_set, block_mask)
                            .is_some()
                })
            });
            match result {
                crate::io_wait::WaitResult::Ready | crate::io_wait::WaitResult::Interrupted => {
                    if let Some(result) =
                        native_signal_wait_pending(&self.dispatcher, tid, wait_set, block_mask)
                    {
                        return result;
                    }
                }
                crate::io_wait::WaitResult::TimedOut | crate::io_wait::WaitResult::Errno(_) => {
                    if crate::vcpu_loop::signal_wait_expired(*deadline) {
                        return NativeSignalWaitResult::TimedOut;
                    }
                }
            }
        }
    }

    /// The syscall-boundary delivery point (the DSR lane's
    /// `complete_dsr_syscall` contract), split across the leave because of a
    /// STACK constraint unique to tier D: islands call this Rust handler ON
    /// THE GUEST'S OWN STACK, so the live dispatch frames occupy exactly the
    /// bytes below the parked guest SP where a signal frame must be written.
    /// Building the frame in-handler would overwrite our own caller frames.
    /// So the boundary only CHECKS (non-destructively) for a deliverable
    /// pending signal here; when one exists it parks the COMPLETED syscall
    /// state and defers the actual `deliver_pending_signal` cycle to
    /// [`reenter_until_final`], which runs on the restored HOST stack after
    /// the island's leave leg (the guest stack is then fully parked).
    fn deliver_pending_at_boundary(&self, ctx: &mut GuestContext, value: i64) -> ServiceVerdict {
        let tid = self.current_tid();
        if !self.deliverable_signal_is_pending(tid) {
            return ServiceVerdict::Resume(value);
        }
        // Park the completed syscall state: retval visible in x0, pc already
        // the resume site. The ORIGINAL arg0 rides the deferred record — the
        // SA_RESTART path re-executes the syscall with it.
        let orig_x0 = ctx.x[0];
        ctx.set_return(value);
        defer_boundary_delivery(DeferredBoundaryDelivery {
            retval: value,
            orig_x0,
        });
        ServiceVerdict::Leave
    }

    /// Non-destructive "would `deliver_pending_signal` find work?" check, so
    /// the common no-signal syscall boundary stays leave-free. False
    /// positives cost one leave/re-enter round trip; the sources checked are
    /// exactly the ones the deferred delivery consumes (the xsig ring is
    /// DRAINED into dispatcher pending state here, which is a move between
    /// pending stores, not a delivery).
    fn deliverable_signal_is_pending(&self, tid: ThreadId) -> bool {
        self.dispatcher.drain_xsignals_process_directed();
        self.deliverable_wait_signal_pending(tid, carrick_abi::WaitSigMask::NONE)
    }

    /// The deferred half of [`Self::deliver_pending_at_boundary`], run by
    /// [`reenter_until_final`] on the HOST stack with the guest parked. Runs
    /// one `deliver_pending_signal` cycle against the parked context (frame
    /// writes below the parked guest SP are safe here — nothing lives
    /// there). Returns whether the guest should be re-entered.
    fn deliver_parked_boundary(
        &self,
        ctx: &mut GuestContext,
        group: &DirectLoadGroup,
        deferred: DeferredBoundaryDelivery,
    ) -> bool {
        let tid = self.current_tid();
        let mut trap = TierDSignalTrap::from_parked(
            ctx,
            self.memory,
            Some(ctx.syscall_nr()),
            group.sigreturn_trampoline(),
        );
        // The parked x0 is the COMPLETED retval; SA_RESTART needs the call's
        // original arg0, which the boundary stashed before completing.
        trap.orig_x0 = deferred.orig_x0;
        match crate::vcpu_loop::deliver_pending_signal(
            &mut trap,
            &self.dispatcher,
            Some(deferred.retval),
            tid,
            None,
        ) {
            Ok(action) => {
                if let Some(action) = action {
                    if let Some(signum) = action.stop_signal {
                        // Default-stop: host-stop until SIGCONT, then resume.
                        crate::exec_helpers::stop_by_signal(signum);
                    }
                    if let Some(signum) = action.term_signal {
                        self.terminate_by_guest_signal(signum);
                        return false;
                    }
                }
                // Injected: pc now names the handler entry. Not injected
                // (ignored/blocked): pc is still the resume site. Either way
                // the parked-entry stub resumes the right state.
                trap.write_back(ctx, false);
                true
            }
            Err(error) => {
                self.end_process(DirectRunOutcome::Unsupported {
                    syscall: ctx.syscall_nr(),
                    outcome: format!("signal delivery failed: {error}"),
                });
                false
            }
        }
    }

    /// `rt_sigreturn(2)`: restore the pre-signal context from the frame the
    /// handler is returning through, chain-deliver any remaining pending
    /// signal (Linux delivers every deliverable signal before returning to
    /// the interrupted context), and re-enter the guest at the RESTORED pc
    /// with the frame's FP/NZCV state armed for the parked-entry stub.
    fn service_sigreturn(&self, ctx: &mut GuestContext, tid: ThreadId) -> ServiceVerdict {
        let Some(group) = active_group() else {
            self.end_process(DirectRunOutcome::Unsupported {
                syscall: 139,
                outcome: "rt_sigreturn with no tier-D load group installed".to_string(),
            });
            return ServiceVerdict::Leave;
        };
        let mut trap =
            TierDSignalTrap::from_parked(ctx, self.memory, None, group.sigreturn_trampoline());
        let restored_sigmask = match trap.restore_from_sigframe() {
            Ok(mask) => mask,
            Err(_) => {
                // Linux force_sigsegv: an unreadable/forged frame at SP
                // terminates the thread-group by SIGSEGV, not carrick.
                return self.die_by_guest_signal(crate::linux_abi::LINUX_SIGSEGV);
            }
        };
        self.dispatcher
            .restore_signal_mask(tid, SigSet::from_raw(restored_sigmask));
        let restored_pc = trap.pc();
        match crate::vcpu_loop::deliver_pending_signal(
            &mut trap,
            &self.dispatcher,
            None,
            tid,
            Some(restored_pc),
        ) {
            Ok(action) => {
                if let Some(action) = action {
                    if let Some(signum) = action.stop_signal {
                        crate::exec_helpers::stop_by_signal(signum);
                    }
                    if let Some(signum) = action.term_signal {
                        return self.die_by_guest_signal(signum);
                    }
                }
            }
            Err(error) => {
                self.end_process(DirectRunOutcome::Unsupported {
                    syscall: 139,
                    outcome: format!("post-sigreturn delivery failed: {error}"),
                });
                return ServiceVerdict::Leave;
            }
        }
        // The frame's state (possibly with a chained handler frame on top)
        // is the guest's next state; NZCV + FP restore rides the stub.
        trap.write_back(ctx, true);
        request_reenter();
        ServiceVerdict::Leave
    }

    /// A signal whose action is termination kills the whole thread-group.
    ///
    /// Record the guest signal exactly; do not turn it into a normal
    /// `128 + signum` exit. The shipped driver re-raises the corresponding
    /// host signal only AFTER [`with_runner`] has joined every guest sibling,
    /// preserving both Linux wait status and orderly tier-D teardown.
    fn terminate_by_guest_signal(&self, signum: i32) {
        self.end_process(DirectRunOutcome::Signaled { signum });
    }

    /// [`Self::terminate_by_guest_signal`] as an island verdict.
    fn die_by_guest_signal(&self, signum: i32) -> ServiceVerdict {
        self.terminate_by_guest_signal(signum);
        ServiceVerdict::Leave
    }
}

/// A process-creating clone request (the `DispatchOutcome::Fork` payload).
struct ForkRequest {
    pidfd_out: Option<u64>,
    clone_parent: bool,
    parent_tid_addr: Option<u64>,
    child_tid_addr: Option<u64>,
    exit_signal: u32,
    child_stack: u64,
    vfork: Option<u64>,
}

/// How a blocking wait ended, from the service loop's point of view.
enum TierDWait {
    /// Re-dispatch the syscall (readiness, or a state change worth a fresh
    /// look).
    Ready,
    /// Complete the syscall with its timeout value.
    TimedOut,
    /// A deliverable pending signal interrupted the wait: complete the
    /// syscall with `EINTR` and let the boundary-delivery epilogue run the
    /// handler (or restart, per `SA_RESTART`).
    Interrupted,
    /// Leave guest execution (process end, or a named fail-closed reason
    /// already recorded via `end_process`).
    Leave,
}

/// Which waiter primitive a fd wait uses (`WaitOnFds` vs `WaitOnPollFds` —
/// the latter polls so epoll's kqueue fd is observed without consuming).
#[derive(Clone, Copy)]
enum FdWaitKind {
    Kqueue,
    Poll,
}

/// Per-syscall-instance timeout bookkeeping: `None` = the deadline passed
/// (complete with the timeout value); `Some(None)` = wait forever;
/// `Some(Some(d))` = wait at most `d`.
fn remaining_wait_timeout(
    timeout: Option<Duration>,
    deadline: &mut Option<Instant>,
) -> Option<Option<Duration>> {
    match timeout {
        Some(duration) => {
            let now = Instant::now();
            let deadline = *deadline.get_or_insert(now + duration);
            (now < deadline).then_some(Some(deadline.saturating_duration_since(now)))
        }
        None => {
            *deadline = None;
            Some(None)
        }
    }
}

thread_local! {
    /// The per-thread blocking-I/O waiter for tier-D guest threads. Lazily
    /// built (and rebuilt when the tid changes — a fork child's kqueue is
    /// not inherited).
    static TIER_D_WAITER: std::cell::RefCell<Option<crate::io_wait::ThreadWaiter>> =
        const { std::cell::RefCell::new(None) };
}

/// Run `f` with this thread's waiter, creating or re-keying it as needed.
fn with_thread_waiter<R>(
    tid: ThreadId,
    f: impl FnOnce(&mut crate::io_wait::ThreadWaiter) -> R,
) -> R {
    TIER_D_WAITER.with(|cell| {
        let mut slot = cell.borrow_mut();
        let rebuild = slot.as_ref().is_none_or(|waiter| waiter.tid() != tid);
        if rebuild {
            let mut waiter = crate::io_wait::ThreadWaiter::new(tid);
            waiter.ensure_full();
            *slot = Some(waiter);
        }
        let Some(waiter) = slot.as_mut() else {
            unreachable!("waiter installed just above");
        };
        f(waiter)
    })
}

// ---------------------------------------------------------------------------
// Signal delivery: the tier-D engine view of a parked guest thread
// ---------------------------------------------------------------------------

/// The tier-D signal engine: `carrick_hal::sigframe`'s (and
/// `vcpu_loop::deliver_pending_signal`'s) view of a PARKED tier-D guest
/// thread. GPRs/SP/PC come from the parked [`GuestContext`]; the FP/SIMD
/// file is captured LIVE from the physical registers when (and only when) a
/// frame is actually built or restored — delivery runs on the guest's own
/// host thread, so the physical file is this guest's.
///
/// Honesty note on the V registers at a syscall boundary: islands park
/// x0-x30+SP only, so by capture time the caller-saved vector registers may
/// have been clobbered by the Rust dispatch path — exactly the preservation
/// level the guest already observes across ANY tier-D syscall (the recorded
/// SIMD-across-islands approximation; the host C ABI preserves v8-v15's low
/// halves through the handler chain). The frame is SELF-CONSISTENT: what
/// `build_sigframe` captures here, `rt_sigreturn` restores verbatim
/// (including handler mutations of the frame), which is the Linux contract.
/// The same applies to PSTATE: NZCV at a tier-D syscall boundary is not
/// preserved (the Rust handler clobbers flags), so the frame records EL0t
/// with clear flags — consistent with what a resumed guest observes today.
/// Truly-async delivery (mid-guest-execution, where the interrupted host
/// mcontext carries the exact V file and flags) is the one case this cannot
/// serve; it stays fail-closed.
struct TierDSignalTrap {
    memory: IdentityMemory,
    x: [u64; 31],
    sp: u64,
    pc: u64,
    pstate: u64,
    v: [u128; 32],
    fpsr: u64,
    fpcr: u64,
    orig_x0: u64,
    last_syscall_nr: Option<u64>,
    sigreturn_trampoline: u64,
}

impl TierDSignalTrap {
    /// Build the engine view of the guest parked in `ctx`. `last_syscall_nr`
    /// feeds the SA_RESTART restartable-set check; `sigreturn_trampoline` is
    /// the group's handler-return stub (the aarch64 ABI has no
    /// `sa_restorer` in practice).
    ///
    /// The FP/SIMD file comes from the slots' resume extras, PARKED BY THE
    /// ISLAND'S LEAVE LEG — the only point where the physical vector file
    /// still carries the guest's values (any Rust frame between the leave
    /// and this constructor may have spilled a callee-saved q register for
    /// its own use, so reading the live registers here would capture that
    /// frame's temporary — observed as d8 coming back wrong).
    fn from_parked(
        ctx: &GuestContext,
        memory: IdentityMemory,
        last_syscall_nr: Option<u64>,
        sigreturn_trampoline: u64,
    ) -> Self {
        // The context IS the slots (offset 0 by `repr(C)` contract), and the
        // reference derives from the slots pointer, so the upcast keeps
        // provenance.
        let slots = std::ptr::from_ref(ctx).cast::<DirectThreadSlots>();
        // SAFETY: this thread's own installed slots; the guest is parked.
        // `parked_fp` is the leave leg's capture — NOT `resume_extras`,
        // which the runner itself arms (single-writer split).
        let parked_fp = unsafe { (*slots).parked_fp };
        Self {
            memory,
            x: ctx.x,
            sp: ctx.sp,
            pc: ctx.pc,
            // EL0t, flags clear — see the struct doc's PSTATE note.
            pstate: 0,
            v: parked_fp.v.map(u128::from_le_bytes),
            fpsr: parked_fp.fpsr,
            fpcr: parked_fp.fpcr,
            // Captured BEFORE any completion write: the parked x0 IS the
            // syscall's original arg0 (SA_RESTART re-executes with it).
            orig_x0: ctx.x[0],
            last_syscall_nr,
            sigreturn_trampoline,
        }
    }

    fn pc(&self) -> u64 {
        self.pc
    }

    /// Write the engine state back into the parked context (the state the
    /// next `enter_parked` resumes from). With `restore_extras`, also arm
    /// the parked-resume extras — NZCV + the FP/SIMD file — for the next
    /// entry (the sigreturn path, where the frame's state is authoritative).
    fn write_back(&self, ctx: &mut GuestContext, restore_extras: bool) {
        ctx.x = self.x;
        ctx.sp = self.sp;
        ctx.pc = self.pc;
        if restore_extras {
            // The context IS the slots (offset 0 by `repr(C)` contract), and
            // `ctx` was derived from the slots pointer, so casting back up
            // is provenance-preserving.
            let slots = std::ptr::from_mut(ctx).cast::<DirectThreadSlots>();
            // SAFETY: this thread's own installed slots; the guest is parked.
            unsafe {
                (*slots).resume_extras.pstate = self.pstate;
                (*slots).resume_extras.fpsr = self.fpsr;
                (*slots).resume_extras.fpcr = self.fpcr;
                for (i, value) in self.v.iter().enumerate() {
                    (*slots).resume_extras.v[i] = value.to_le_bytes();
                }
                (*slots).resume_extras.restore = 1;
            }
        }
    }
}

impl GuestMemory for TierDSignalTrap {
    fn read_bytes_raw(&self, address: u64, length: usize) -> Result<Vec<u8>, MemoryError> {
        self.memory.read_bytes_raw(address, length)
    }

    fn write_bytes_raw(&mut self, address: u64, bytes: &[u8]) -> Result<(), MemoryError> {
        let mut memory = self.memory;
        memory.write_bytes_raw(address, bytes)
    }
}

impl RegAccess for TierDSignalTrap {
    fn get_reg(&self, reg: Reg) -> Result<u64, carrick_hal::OsError> {
        Ok(match reg {
            Reg::X(index) => usize::try_from(index)
                .ok()
                .and_then(|i| self.x.get(i).copied())
                .unwrap_or(0),
            Reg::Sp => self.sp,
            Reg::Pc | Reg::ElrEl1 => self.pc,
            Reg::Pstate | Reg::SpsrEl1 => self.pstate,
            _ => 0,
        })
    }

    fn set_reg(&mut self, reg: Reg, value: u64) -> Result<(), carrick_hal::OsError> {
        match reg {
            Reg::X(index) => {
                if let Ok(i) = usize::try_from(index)
                    && let Some(slot) = self.x.get_mut(i)
                {
                    *slot = value;
                }
            }
            Reg::Sp => self.sp = value,
            Reg::Pc | Reg::ElrEl1 => self.pc = value,
            Reg::Pstate | Reg::SpsrEl1 => self.pstate = value,
            _ => {}
        }
        Ok(())
    }

    fn get_sys_reg(&self, _reg: SysReg) -> Result<u64, carrick_hal::OsError> {
        Ok(0)
    }

    fn set_sys_reg(&mut self, _reg: SysReg, _value: u64) -> Result<(), carrick_hal::OsError> {
        Ok(())
    }

    fn get_vreg(&self, n: u32) -> Result<u128, carrick_hal::OsError> {
        Ok(usize::try_from(n)
            .ok()
            .and_then(|index| self.v.get(index).copied())
            .unwrap_or(0))
    }

    fn set_vreg(&mut self, n: u32, value: u128) -> Result<(), carrick_hal::OsError> {
        if let Ok(index) = usize::try_from(n)
            && let Some(slot) = self.v.get_mut(index)
        {
            *slot = value;
        }
        Ok(())
    }

    fn get_fpcr(&self) -> Result<u64, carrick_hal::OsError> {
        Ok(self.fpcr)
    }

    fn set_fpcr(&mut self, value: u64) -> Result<(), carrick_hal::OsError> {
        self.fpcr = value;
        Ok(())
    }

    fn get_fpsr(&self) -> Result<u64, carrick_hal::OsError> {
        Ok(self.fpsr)
    }

    fn set_fpsr(&mut self, value: u64) -> Result<(), carrick_hal::OsError> {
        self.fpsr = value;
        Ok(())
    }
}

impl SyscallTrap for TierDSignalTrap {
    fn next_syscall(&mut self) -> Result<Option<carrick_hal::RawSyscall>, TrapError> {
        Err(TrapError::Hypervisor(
            "tier-D signal adapter cannot enter guest".to_string(),
        ))
    }

    fn current_pc(&self) -> Result<u64, TrapError> {
        Ok(self.pc)
    }

    fn complete_syscall(&mut self, return_value: i64) -> Result<(), TrapError> {
        self.x[0] = return_value as u64;
        Ok(())
    }

    fn fork(&mut self) -> Result<carrick_hal::ForkOutcome, TrapError> {
        Err(TrapError::Hypervisor(
            "tier-D signal adapter cannot fork".to_string(),
        ))
    }

    fn execve_into(&mut self, _new_image: &crate::memory::AddressSpace) -> Result<(), TrapError> {
        Err(TrapError::Hypervisor(
            "tier-D signal adapter cannot execve".to_string(),
        ))
    }

    fn inject_signal(
        &mut self,
        signum: i32,
        handler: u64,
        sa_restorer: u64,
        pending_syscall_retval: Option<i64>,
        interrupted_pc: Option<u64>,
        altstack: Option<(u64, u64)>,
        saved_sigmask: u64,
        fault_siginfo: Option<(i32, u64)>,
        queued_siginfo: Option<carrick_abi::LinuxSiginfo>,
        restart_syscall: bool,
    ) -> Result<(), TrapError> {
        let params = carrick_hal::sigframe::InjectParams {
            signum,
            handler,
            sa_restorer,
            pending_syscall_retval,
            interrupted_pc: interrupted_pc.or(Some(self.pc)),
            altstack,
            saved_sigmask,
            fault_siginfo,
            queued_siginfo,
            restart_syscall,
            pstate_source: self.pstate & !0xf,
            orig_x0: self.orig_x0,
            fault_esr: 0,
            fpsimd_enabled: true,
            sigreturn_trampoline_base: self.sigreturn_trampoline,
        };
        carrick_hal::sigframe::build_sigframe(self, params)?;
        Ok(())
    }

    fn last_syscall_nr(&self) -> Option<u64> {
        self.last_syscall_nr
    }

    fn restore_from_sigframe(&mut self) -> Result<u64, TrapError> {
        // The constructor baselined the FP file from the leave-parked
        // extras, so a frame WITHOUT an fpsimd record (foreign/rebuilt
        // frames) falls back to the state parked at the delivery leave
        // rather than zeros; a normal carrick frame overwrites everything.
        let restored = carrick_hal::sigframe::restore_sigframe(self, true)?;
        self.pc = restored.saved_pc;
        Ok(restored.sigmask)
    }
}

/// A syscall boundary that observed a deliverable pending signal, parked the
/// completed syscall and left — the delivery itself runs on the host stack
/// (see [`DirectRunner::deliver_pending_at_boundary`]'s stack constraint).
#[derive(Clone, Copy)]
struct DeferredBoundaryDelivery {
    /// The completed syscall's retval (already written to the parked x0).
    retval: i64,
    /// The syscall's ORIGINAL arg0, for the SA_RESTART re-execution.
    orig_x0: u64,
}

thread_local! {
    /// Set by the delivery/sigreturn paths on THIS guest thread: after the
    /// island's leave leg returns to `enter`'s caller, RE-ENTER the guest
    /// from its parked context instead of ending the run. The island's
    /// resume leg is a constant branch, so a redirected pc (handler entry,
    /// sigreturn's restored pc) can only be reached through a leave +
    /// [`DirectLoadGroup::enter_parked`] round trip — this flag is that
    /// round trip's request bit.
    static REENTER_PARKED: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
    /// A boundary-observed pending signal whose delivery cycle must run on
    /// the host stack before the next re-entry.
    static PENDING_BOUNDARY_DELIVERY: std::cell::Cell<Option<DeferredBoundaryDelivery>> =
        const { std::cell::Cell::new(None) };
}

fn request_reenter() {
    REENTER_PARKED.with(|cell| cell.set(true));
}

fn take_reenter() -> bool {
    REENTER_PARKED.with(|cell| cell.replace(false))
}

fn defer_boundary_delivery(deferred: DeferredBoundaryDelivery) {
    PENDING_BOUNDARY_DELIVERY.with(|cell| cell.set(Some(deferred)));
}

fn take_deferred_boundary_delivery() -> Option<DeferredBoundaryDelivery> {
    PENDING_BOUNDARY_DELIVERY.with(std::cell::Cell::take)
}

/// Drive the leave/re-enter loop for the guest thread running on THIS host
/// thread: run any deferred boundary delivery (now safely on the host
/// stack), then re-enter from the parked context, until the guest leaves
/// for real (exit, thread exit, termination, or a named refusal).
///
/// # Safety
/// As [`DirectLoadGroup::enter_parked`]: the parked context was written by
/// this thread's own delivery path from a genuine guest state of `group`.
unsafe fn reenter_until_final(runner: &DirectRunner, group: &DirectLoadGroup) {
    loop {
        let slots = current_thread_slots_ptr();
        let dynamic_reenter = if slots.is_null() {
            false
        } else {
            // SAFETY: this thread's own installed slots; a captured fault
            // returned to the host landing point before this read.
            let slots = unsafe { &mut *slots };
            if let Some(fault) = slots.take_fault() {
                let prepared = if group.dynamic_exec_is_shadowed(slots.context.pc) {
                    group.execute_dynamic_shadow(slots).map(|()| true)
                } else {
                    group.prepare_dynamic_fault(fault, &slots.context)
                };
                match prepared {
                    Ok(reenter) => reenter,
                    Err(reason) => {
                        runner.end_process(DirectRunOutcome::Unsupported {
                            syscall: 0,
                            outcome: format!("direct dynamic-code fault: {reason}"),
                        });
                        return;
                    }
                }
            } else {
                false
            }
        };
        if let Some(deferred) = take_deferred_boundary_delivery() {
            let slots = current_thread_slots_ptr();
            if slots.is_null() {
                runner.end_process(DirectRunOutcome::Unsupported {
                    syscall: 0,
                    outcome: "deferred signal delivery with no installed thread slots".to_string(),
                });
                return;
            }
            // SAFETY: this thread's own installed slots; the guest is parked
            // (its leave leg just returned control here).
            let ctx = unsafe { &mut (*slots).context };
            if !runner.deliver_parked_boundary(ctx, group, deferred) {
                return;
            }
        } else if !dynamic_reenter && !take_reenter() {
            return;
        }
        // SAFETY: caller contract.
        if let Err(error) = unsafe { group.enter_parked() } {
            runner.end_process(DirectRunOutcome::Unsupported {
                syscall: 0,
                outcome: format!("signal re-entry failed: {error}"),
            });
            return;
        }
    }
}

/// Raw runner pointer that crosses into a spawned guest thread; safety is
/// argued at the spawn site (join-before-return).
struct SendPtr(*const DirectRunner);
// SAFETY: see the spawn site — the pointee outlives the thread by the
// join-before-return contract, and DirectRunner's shared state is Sync.
unsafe impl Send for SendPtr {}
/// As [`SendPtr`], for the load group.
struct SendGroupPtr(*const DirectLoadGroup);
// SAFETY: as above.
unsafe impl Send for SendGroupPtr {}

/// Lower a guest protection to the host's non-executable bits. EXEC never
/// reaches here: every EXEC path is routed to the scan+patch pipeline or
/// fails closed before protection is applied.
fn host_prot(prot: carrick_abi::LinuxProtFlags) -> i32 {
    use carrick_abi::LinuxProtFlags;
    let mut host = 0;
    if prot.contains(LinuxProtFlags::READ) {
        host |= libc::PROT_READ;
    }
    if prot.contains(LinuxProtFlags::WRITE) {
        host |= libc::PROT_WRITE;
    }
    host
}

/// Resume the guest with the host's errno, translated to Linux's.
fn host_errno_verdict() -> ServiceVerdict {
    let host = std::io::Error::last_os_error()
        .raw_os_error()
        .unwrap_or(libc::EINVAL);
    ServiceVerdict::Resume(crate::host_to_linux_errno(host).guest_retval())
}

thread_local! {
    /// The runner serving the guest executing on THIS thread.
    ///
    /// A directly-executed guest runs on the host thread that entered it, so
    /// "which runner" is exactly a per-thread question — every guest thread
    /// installs the SAME runner, and its own tid alongside.
    static ACTIVE: std::cell::Cell<*const DirectRunner> =
        const { std::cell::Cell::new(std::ptr::null()) };
    /// The load group of that guest, installed alongside the runner: the
    /// identity memory services need it for the mmap(PROT_EXEC) window
    /// pipeline and the mprotect(PROT_EXEC) containment rule.
    static ACTIVE_GROUP: std::cell::Cell<*const DirectLoadGroup> =
        const { std::cell::Cell::new(std::ptr::null()) };
    /// The registry key of the guest thread running here (`ThreadId::NONE`
    /// when nothing is installed).
    static ACTIVE_TID: std::cell::Cell<ThreadId> =
        const { std::cell::Cell::new(ThreadId::NONE) };
}

/// The load group installed for the guest on this thread, if any.
fn active_group<'a>() -> Option<&'a DirectLoadGroup> {
    let group = ACTIVE_GROUP.with(std::cell::Cell::get);
    // SAFETY: `install_thread_context` installs the pointer for exactly the
    // window in which the guest can call back and clears it before the
    // thread ends, and the reference is only used inside handler-called
    // services within that window.
    unsafe { group.as_ref() }
}

/// RAII installation of the per-thread runner/group/tid context; restores
/// the previous values on drop.
struct ThreadContextGuard {
    previous_runner: *const DirectRunner,
    previous_group: *const DirectLoadGroup,
    previous_tid: ThreadId,
}

fn install_thread_context(
    runner: &DirectRunner,
    group: &DirectLoadGroup,
    tid: ThreadId,
) -> ThreadContextGuard {
    ThreadContextGuard {
        previous_runner: ACTIVE.with(|slot| slot.replace(std::ptr::from_ref(runner))),
        previous_group: ACTIVE_GROUP.with(|slot| slot.replace(std::ptr::from_ref(group))),
        previous_tid: ACTIVE_TID.with(|slot| slot.replace(tid)),
    }
}

impl Drop for ThreadContextGuard {
    fn drop(&mut self) {
        ACTIVE.with(|slot| slot.set(self.previous_runner));
        ACTIVE_GROUP.with(|slot| slot.set(self.previous_group));
        ACTIVE_TID.with(|slot| slot.set(self.previous_tid));
    }
}

/// The handler a tier-D image is built with.
extern "C" fn dispatch_from_island(ctx: *mut GuestContext) {
    let runner = ACTIVE.with(std::cell::Cell::get);
    if runner.is_null() || ctx.is_null() {
        return;
    }
    let physical_x18 = carrick_native_darwin::direct::physical_x18_supported();
    if physical_x18 {
        carrick_native_darwin::direct::enter_host_x18_abi();
    }
    // SAFETY: `install_thread_context` installs this runner for exactly the
    // window in which the guest can call back, and the island owns `ctx` for
    // this call.
    let (runner, ctx) = unsafe { (&*runner, &mut *ctx) };
    match runner.service(ctx) {
        ServiceVerdict::Resume(value) => {
            if physical_x18 && let Err(error) = carrick_native_darwin::direct::enter_guest_x18_abi()
            {
                runner.end_process(DirectRunOutcome::Unsupported {
                    syscall: ctx.syscall_nr(),
                    outcome: format!("cannot restore tier-D physical x18 ABI: {error}"),
                });
                ctx.request_leave();
                return;
            }
            ctx.set_return(value);
        }
        // The guest's own state at the syscall stays parked in the context —
        // no fabricated return value — and the island's leave leg returns
        // control to `enter`'s caller (guest-leave contract).
        ServiceVerdict::Leave => ctx.request_leave(),
    }
}

/// Synchronous `__clear_cache` publication bridge. The patched definition
/// calls this while the publishing guest thread is still in MAP_JIT write
/// mode, before its original cache-maintenance body runs. Patch every Linux
/// virtual-state word now so an already-executable sibling can never observe
/// unlowered x18/TLS/syscall code after the guest publishes it.
extern "C" fn publish_dynamic_from_guest(start: u64, end: u64) -> libc::c_int {
    let runner = ACTIVE.with(std::cell::Cell::get);
    let Some(group) = active_group() else {
        return 0;
    };
    if runner.is_null() {
        return 0;
    }
    let physical_x18 = carrick_native_darwin::direct::physical_x18_supported();
    if physical_x18 {
        carrick_native_darwin::direct::enter_host_x18_abi();
    }
    let result = match group.publish_dynamic_code(start, end) {
        Ok(()) => 1,
        Err(reason) => {
            // SAFETY: `install_thread_context` keeps the runner live for the
            // exact window in which the guest can reach this callback.
            let runner = unsafe { &*runner };
            runner.end_process(DirectRunOutcome::Unsupported {
                syscall: 0,
                outcome: format!("direct dynamic-code publication: {reason}"),
            });
            0
        }
    };
    if physical_x18 && let Err(error) = carrick_native_darwin::direct::enter_guest_x18_abi() {
        // SAFETY: as above; failure is terminal and the patched clear-cache
        // hook will take its named leave leg instead of resuming guest code.
        let runner = unsafe { &*runner };
        runner.end_process(DirectRunOutcome::Unsupported {
            syscall: 0,
            outcome: format!("cannot restore tier-D physical x18 ABI: {error}"),
        });
        return 0;
    }
    result
}

/// Build a tier-D image with this so its syscalls reach the real dispatcher.
pub fn island_handler() -> extern "C" fn(*mut GuestContext) {
    dispatch_from_island
}

/// Install the MAIN guest thread's slots and runner context, run `body` (the
/// enter call), then JOIN every guest thread the run spawned and hand back
/// the main thread's parked slots for inspection.
///
/// # Safety
/// `body` must enter an image (or runtime window) of `group`, built with
/// [`island_handler`], and the caller keeps `runner` and `group` alive until
/// this returns (spawned guest threads borrow both; the join before
/// returning is what bounds those borrows).
pub unsafe fn with_runner<R>(
    runner: &DirectRunner,
    group: &DirectLoadGroup,
    body: impl FnOnce() -> R,
) -> std::io::Result<(R, Box<DirectThreadSlots>)> {
    install_dynamic_publication_handler(publish_dynamic_from_guest)?;
    let slots = group.install_thread_slots()?;
    let context = install_thread_context(runner, group, runner.main_tid());
    let result = body();
    // Signal delivery / sigreturn park the guest and request a re-entry at a
    // redirected pc; drive those round trips until the guest leaves for real.
    // SAFETY: the parked context was written by this thread's delivery path
    // from a genuine guest state of `group` (caller contract for `body`).
    unsafe { reenter_until_final(runner, group) };
    drop(context);
    runner.join_guest_threads();
    Ok((result, slots.into_slots()))
}

#[cfg(all(test, target_os = "macos", target_arch = "aarch64"))]
mod tests {
    use super::*;
    use carrick_native_darwin::direct::DirectLoadGroup;

    #[test]
    fn tier_d_syscall_service_emits_the_native_service_window() {
        use crate::native_darwin::{
            NativeSyscallServiceProbeEvent, take_native_syscall_service_probe_events,
        };

        take_native_syscall_service_probe_events();
        let runner = DirectRunner::new(SyscallDispatcher::new(), IdentityMemory::new(0, u64::MAX));
        let mut ctx = GuestContext::default();
        ctx.x[8] = 172; // getpid

        assert!(matches!(runner.service(&mut ctx), ServiceVerdict::Resume(value) if value > 0));
        assert!(matches!(
            take_native_syscall_service_probe_events().as_slice(),
            [
                NativeSyscallServiceProbeEvent::Entry {
                    number: 172,
                    name: "getpid"
                },
                NativeSyscallServiceProbeEvent::End {
                    number: 172,
                    name: "getpid",
                    outcome: crate::probes::NativeSyscallServiceOutcome::Resume
                }
            ]
        ));

        let runner = DirectRunner::new(SyscallDispatcher::new(), IdentityMemory::new(0, u64::MAX));
        let mut ctx = GuestContext::default();
        ctx.x[0] = 7;
        ctx.x[8] = 94; // exit_group

        assert!(matches!(runner.service(&mut ctx), ServiceVerdict::Leave));
        assert!(matches!(
            take_native_syscall_service_probe_events().as_slice(),
            [
                NativeSyscallServiceProbeEvent::Entry {
                    number: 94,
                    name: "exit_group"
                },
                NativeSyscallServiceProbeEvent::End {
                    number: 94,
                    name: "exit_group",
                    outcome: crate::probes::NativeSyscallServiceOutcome::ThreadExit
                }
            ]
        ));
    }

    /// A host `execve` used to provide two hidden pieces of the Tier-D exec
    /// contract for free: it retired every mapping owned by the outgoing
    /// guest, and FD_CLOEXEC closed the private pipe that releases a vfork
    /// parent.  The in-process replacement must do both explicitly before
    /// any instruction from the new image can run.
    #[test]
    fn in_process_exec_commit_retires_identity_memory_and_releases_vfork() {
        let runner = DirectRunner::new(SyscallDispatcher::new(), IdentityMemory::new(0, u64::MAX));

        let mut pipe = [-1; 2];
        assert_eq!(unsafe { libc::pipe(pipe.as_mut_ptr()) }, 0);
        runner.hold_vfork_completion_fd(pipe[1]);

        let mut mmap = GuestContext::default();
        mmap.x[0] = 0;
        mmap.x[1] = HOST_PAGE_SIZE;
        mmap.x[2] = 3; // PROT_READ | PROT_WRITE
        mmap.x[3] = 0x22; // MAP_PRIVATE | MAP_ANONYMOUS
        mmap.x[4] = u64::MAX;
        mmap.x[8] = 222; // mmap
        let mapped = match runner
            .service_identity_memory(&mmap)
            .expect("mmap is an identity-memory syscall")
        {
            ServiceVerdict::Resume(value) if value > 0 => value as u64,
            _ => panic!("anonymous mmap did not return a mapping"),
        };
        assert_eq!(
            unsafe {
                libc::mprotect(
                    mapped as usize as *mut libc::c_void,
                    HOST_PAGE_SIZE as usize,
                    libc::PROT_READ | libc::PROT_WRITE,
                )
            },
            0,
            "the outgoing guest mapping must exist before exec commit"
        );

        runner.commit_in_process_exec();

        assert_eq!(
            unsafe {
                libc::mprotect(
                    mapped as usize as *mut libc::c_void,
                    HOST_PAGE_SIZE as usize,
                    libc::PROT_NONE,
                )
            },
            -1,
            "exec commit must retire the outgoing guest mapping"
        );
        let mut byte = 0_u8;
        assert_eq!(
            unsafe { libc::read(pipe[0], std::ptr::from_mut(&mut byte).cast(), 1) },
            0,
            "closing the child completion fd must release the vfork parent"
        );
        unsafe { libc::close(pipe[0]) };
    }

    #[test]
    fn sleeping_guest_wakes_promptly_on_durable_process_exit_publication() {
        let runner = Arc::new(DirectRunner::new(
            SyscallDispatcher::new(),
            IdentityMemory::new(0, u64::MAX),
        ));
        let tid = runner.main_tid();
        let (parked_tx, parked_rx) = std::sync::mpsc::channel();
        let child_runner = Arc::clone(&runner);
        let sleeper = std::thread::spawn(move || {
            parked_tx.send(()).expect("announce wait entry");
            child_runner.wait_on_sleep(tid, Instant::now() + Duration::from_secs(2))
        });
        parked_rx.recv().expect("sleeper reached wait path");
        std::thread::sleep(Duration::from_millis(100));

        // end_process is the publication protocol: first store the durable
        // terminal bit, then wake every registered private waiter pipe. The
        // sleeper must not inherit the guest's remaining two-second deadline.
        let start = Instant::now();
        runner.end_process(DirectRunOutcome::Exited { code: 0 });
        let result = sleeper.join().expect("join sleeper");

        assert!(matches!(result, TierDWait::Leave));
        assert!(
            start.elapsed() < Duration::from_millis(500),
            "process-exit publication must wake a sleeping guest promptly"
        );
    }

    #[test]
    fn blocking_host_write_waits_and_returns_through_the_tier_d_boundary() {
        let mut fds = [-1; 2];
        assert_eq!(unsafe { libc::pipe(fds.as_mut_ptr()) }, 0);
        let flags = unsafe { libc::fcntl(fds[1], libc::F_GETFL) };
        assert!(flags >= 0);
        assert_eq!(
            unsafe { libc::fcntl(fds[1], libc::F_SETFL, flags | libc::O_NONBLOCK) },
            0
        );

        let bytes = vec![0x5a; 4 * 1024 * 1024 + 1];
        let expected = bytes.len();
        let write = crate::dispatch::BlockingHostWrite::for_tests(
            fds[1],
            bytes,
            0,
            ThreadId::main_from_host_pid(),
            true,
        )
        .expect("pin write fd");
        assert_eq!(unsafe { libc::close(fds[1]) }, 0);

        let read_fd = fds[0];
        let reader = std::thread::spawn(move || {
            // Hold the reader back until the first nonblocking write has
            // filled the pipe and the continuation has observed EAGAIN.
            // This makes the POLLOUT park a deterministic part of the test,
            // rather than a scheduler-dependent possibility.
            std::thread::sleep(Duration::from_millis(10));
            let mut total = 0usize;
            let mut buf = [0u8; 64 * 1024];
            while total < expected {
                let n = unsafe { libc::read(read_fd, buf.as_mut_ptr().cast(), buf.len()) };
                assert!(n > 0, "pipe closed after {total}/{expected} bytes");
                total += n as usize;
            }
            assert_eq!(unsafe { libc::close(read_fd) }, 0);
            total
        });

        let runner = DirectRunner::new(SyscallDispatcher::new(), IdentityMemory::new(0, u64::MAX));
        assert!(matches!(
            runner.service_blocking_host_write(64, write),
            ServiceVerdict::Resume(value) if value == expected as i64
        ));
        assert_eq!(reader.join().expect("reader thread"), expected);
    }

    #[test]
    fn blocking_record_lock_returns_through_the_tier_d_boundary() {
        use std::os::fd::AsRawFd as _;

        let file = tempfile::tempfile().expect("temp file");
        let lock = crate::dispatch::BlockingRecordLock::new(
            file.as_raw_fd(),
            libc::F_SETLKW,
            0,
            0,
            libc::F_WRLCK,
            libc::SEEK_SET as i16,
        )
        .expect("pin lock fd");
        let runner = DirectRunner::new(SyscallDispatcher::new(), IdentityMemory::new(0, u64::MAX));

        assert!(matches!(
            runner.service_blocking_record_lock(25, &lock),
            ServiceVerdict::Resume(0)
        ));
    }

    /// The STRETCH gate: real CPython 3.12 running `print(1)` end to end on
    /// tier D. `python3.12` is a real, PIE, dynamically linked interpreter
    /// from the debian-based `python:3.12-slim` image; its real ld.so maps
    /// libc, libm, and the 6.6 MB `libpython3.12.so` through the exec-mmap
    /// window pipeline (both the whole-span and MAP_FIXED strategies), and
    /// CPython's full C runtime initializes, imports the frozen `encodings`
    /// codec from the staged stdlib, evaluates `print(1)`, and exits 0 with
    /// `1\n` on stdout — all through the one dispatcher, single-threaded.
    ///
    /// Runs from a rootfs staged on disk under `target/tierd-live/pyroot`
    /// (skips loudly when absent). Staging, from the cached OCI layers:
    /// `bin/python3.12` + `lib/libpython3.12.so.1.0` into `usr/local/{bin,
    /// lib}`, the interpreter/libc/libm into `lib`, `lib64`, `usr/lib` (the
    /// default search path, since `$ORIGIN` RUNPATH cannot resolve without a
    /// real `/proc/self/exe`), and the full `python3.12` stdlib under
    /// `usr/local/lib`.
    #[test]
    fn real_cpython_prints_through_tier_d() {
        let root = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../target/tierd-live/pyroot"
        );
        let (Ok(py), Ok(ld)) = (
            std::fs::read(format!("{root}/usr/local/bin/python3.12")),
            std::fs::read(format!("{root}/lib/ld-linux-aarch64.so.1")),
        ) else {
            eprintln!("skipping: no python rootfs under target/tierd-live/pyroot (see test doc)");
            return;
        };
        let group =
            DirectLoadGroup::load_with_interpreter(&py, |_| Ok(ld.clone()), island_handler())
                .expect("load")
                .expect("python and its ld.so are tier-D eligible");
        let interp = group.interpreter().expect("interpreter mapped");
        let stack = DirectStack::build(
            &py,
            group.main().bias(),
            Some(interp.bias()),
            &[
                b"python3".to_vec(),
                b"-I".to_vec(),
                b"-S".to_vec(),
                b"-c".to_vec(),
                b"print(1)".to_vec(),
            ],
            &[b"PYTHONHOME=/usr/local".to_vec()],
        )
        .expect("stack builds");
        let mut dispatcher = SyscallDispatcher::new();
        dispatcher.set_fs_backend(Box::new(
            crate::fs_backend::HostFsBackend::from_existing_dir(
                cap_std::fs::Dir::open_ambient_dir(root, cap_std::ambient_authority())
                    .expect("open python rootfs"),
            ),
        ));
        let runner = DirectRunner::new(dispatcher, IdentityMemory::new(0, u64::MAX));
        let entry = group.entry_pc();
        let sp = stack.sp();
        // SAFETY: patched images built with `island_handler`; the guest
        // leaves through its exit.
        unsafe { with_runner(&runner, &group, || group.enter_on_stack(entry, sp)) }
            .expect("with_runner")
            .0
            .expect("enter");
        assert_eq!(
            runner.outcome(),
            Some(DirectRunOutcome::Exited { code: 0 }),
            "CPython evaluated print(1) and exited 0 on tier D (syscalls: {}; \
             stdout: {:?}; stderr: {:?})",
            runner.syscalls(),
            String::from_utf8_lossy(&runner.dispatcher().stdout()),
            String::from_utf8_lossy(&runner.dispatcher().stderr()),
        );
        assert_eq!(
            runner.dispatcher().stdout(),
            b"1\n",
            "print(1) reached stdout through the one dispatcher"
        );
    }

    /// The MULTI-THREADED gate (roadmap Phase 1 item 4, live-verified): real
    /// CPython 3.12 creates a real `threading.Thread`. glibc's
    /// `pthread_create` issues `clone(CLONE_VM|CLONE_THREAD|CLONE_SETTLS|
    /// CLONE_CHILD_CLEARTID)`, the child enters tier D on its own host thread
    /// with PRIVATE `DirectThreadSlots` (its `CLONE_SETTLS` value in its own
    /// TLS slot — the veneers resolving per-thread state through the proven
    /// TSD chain), the GIL handoff runs on real futex wait/wake through the
    /// runner's shared table, `t.join()` parks on the CLEARTID word, and the
    /// child's `exit(2)` retires as a `ThreadExit`. The main thread then
    /// prints a value computed IN the child — proof the second thread really
    /// executed guest code — and exits 0.
    ///
    /// Deliberately WITHOUT `-I -S`: full CPython startup (site import
    /// included) runs on tier D here, so the gate is the unrestricted
    /// interpreter, not a trimmed one. glibc's realloc grows its mmapped
    /// chunks with `mremap` on this path — serviced by the identity tier's
    /// tracked-anonymous-RW lowering, which this gate therefore also covers.
    ///
    /// Same staged rootfs as [`real_cpython_prints_through_tier_d`] (loud
    /// skip when absent).
    #[test]
    fn real_cpython_runs_threads_through_tier_d() {
        let root = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../target/tierd-live/pyroot"
        );
        let (Ok(py), Ok(ld)) = (
            std::fs::read(format!("{root}/usr/local/bin/python3.12")),
            std::fs::read(format!("{root}/lib/ld-linux-aarch64.so.1")),
        ) else {
            eprintln!("skipping: no python rootfs under target/tierd-live/pyroot (see test doc)");
            return;
        };
        let group =
            DirectLoadGroup::load_with_interpreter(&py, |_| Ok(ld.clone()), island_handler())
                .expect("load")
                .expect("python and its ld.so are tier-D eligible");
        let interp = group.interpreter().expect("interpreter mapped");
        let program = b"import threading\n\
                        r = []\n\
                        t = threading.Thread(target=r.append, args=(41,))\n\
                        t.start()\n\
                        t.join()\n\
                        print(r[0] + 1)\n";
        let stack = DirectStack::build(
            &py,
            group.main().bias(),
            Some(interp.bias()),
            &[b"python3".to_vec(), b"-c".to_vec(), program.to_vec()],
            &[b"PYTHONHOME=/usr/local".to_vec()],
        )
        .expect("stack builds");
        let mut dispatcher = SyscallDispatcher::new();
        dispatcher.set_fs_backend(Box::new(
            crate::fs_backend::HostFsBackend::from_existing_dir(
                cap_std::fs::Dir::open_ambient_dir(root, cap_std::ambient_authority())
                    .expect("open python rootfs"),
            ),
        ));
        let runner = DirectRunner::new(dispatcher, IdentityMemory::new(0, u64::MAX));
        let entry = group.entry_pc();
        let sp = stack.sp();
        // SAFETY: patched images built with `island_handler`; every thread
        // leaves through the handler.
        unsafe { with_runner(&runner, &group, || group.enter_on_stack(entry, sp)) }
            .expect("with_runner")
            .0
            .expect("enter");
        assert_eq!(
            runner.outcome(),
            Some(DirectRunOutcome::Exited { code: 0 }),
            "CPython ran a threading.Thread and exited 0 on tier D \
             (syscalls: {}; stdout: {:?}; stderr: {:?})",
            runner.syscalls(),
            String::from_utf8_lossy(&runner.dispatcher().stdout()),
            String::from_utf8_lossy(&runner.dispatcher().stderr()),
        );
        assert_eq!(
            runner.dispatcher().stdout(),
            b"42\n",
            "the printed value was computed IN the spawned guest thread"
        );
    }

    const NR_WRITE: u32 = 64;
    const SVC_0: u32 = 0xd400_0001;

    const fn movz(rd: u32, imm16: u32, shift: u32) -> u32 {
        0xd280_0000 | ((shift / 16) << 21) | (imm16 << 5) | rd
    }
    const fn movk(rd: u32, imm16: u32, shift: u32) -> u32 {
        0xf280_0000 | ((shift / 16) << 21) | (imm16 << 5) | rd
    }
    const fn mov_reg(rd: u32, rm: u32) -> u32 {
        0xaa00_03e0 | (rm << 16) | rd
    }
    const fn str_pre_sp(rt: u32) -> u32 {
        0xf800_0c00 | ((0x1f0_u32 & 0x1ff) << 12) | (31 << 5) | rt
    }
    const fn mov_from_sp(rd: u32) -> u32 {
        0x9100_0000 | (31 << 5) | rd
    }
    /// `add sp, sp, #16`
    const ADD_SP_16: u32 = 0x9100_0000 | (16 << 10) | (31 << 5) | 31;

    /// `write(1, "hi\n", 3)`, then return to the host with SP BALANCED.
    ///
    /// The pop is load-bearing. A real guest never returns to Rust — it leaves
    /// through `exit` — so an unbalanced SP is harmless there. A fixture that
    /// returns via `ret` hands Rust a stack pointer 16 bytes low, and Rust then
    /// unwinds through garbage: the failure surfaces later as a branch to a
    /// stack address (EXC_BAD_ACCESS with PC on the stack), and whether it
    /// fires at all depends on what the caller does next. That fixture bug,
    /// not tier D, is what blocked this bridge.
    fn write_fixture() -> Vec<u8> {
        elf_with_code(&[
            mov_reg(20, 30),      // stash the incoming link register
            movz(9, 0x6968, 0),   // 'h','i'
            movk(9, 0x000a, 16),  // '\n'
            str_pre_sp(9),        // bytes onto the guest stack (SP -= 16)
            mov_from_sp(1),       // x1 = buf
            movz(0, 1, 0),        // x0 = fd 1
            movz(2, 3, 0),        // x2 = len
            movz(8, NR_WRITE, 0), // x8 = __NR_write
            SVC_0,
            ADD_SP_16,       // give the borrowed slot back
            mov_reg(30, 20), // restore the host's link register
            0xd65f_03c0,     // ret
        ])
    }

    /// The "one dispatcher" claim, made concrete: bytes travel from guest code
    /// executing natively on the host CPU, through a patched `svc`, into the
    /// same `SyscallDispatcher` the translated lane uses.
    #[test]
    fn guest_write_reaches_the_real_dispatcher() {
        let group = DirectLoadGroup::load(&write_fixture(), island_handler())
            .expect("load")
            .expect("eligible");
        assert_eq!(group.main().svc_sites(), 1);
        let runner = DirectRunner::new(SyscallDispatcher::new(), IdentityMemory::new(0, u64::MAX));
        let entry = group.main().entry();
        // SAFETY: the image is patched and built with `island_handler`.
        unsafe { with_runner(&runner, &group, || group.enter(entry)) }
            .expect("with_runner")
            .0
            .expect("enter");

        assert_eq!(runner.syscalls(), 1, "exactly one syscall was serviced");
        assert_eq!(
            runner.dispatcher().stdout(),
            b"hi\n",
            "the guest's own write(2) reached the real dispatcher"
        );
    }

    /// Linux/aarch64 exposes CTR_EL0 to EL0, but XNU traps the same MRS as
    /// EXC_BAD_INSTRUCTION. Tier D must answer that rare architectural query
    /// without translating the surrounding static code. The canonical value
    /// deliberately matches the translated native lane.
    #[test]
    fn direct_mach_exception_emulates_linux_ctr_el0() {
        const NR_EXIT_GROUP: u32 = 94;
        const MRS_CTR_EL0_X0: u32 = 0xd53b_0020;
        let elf = elf_with_code(&[MRS_CTR_EL0_X0, movz(8, NR_EXIT_GROUP, 0), SVC_0]);
        let group = DirectLoadGroup::load(&elf, island_handler())
            .expect("load")
            .expect("eligible");
        let runner = DirectRunner::new(SyscallDispatcher::new(), IdentityMemory::new(0, u64::MAX));
        let entry = group.main().entry();
        // SAFETY: the image is patched and the Mach handler owns the trapped
        // instruction's exact state transition before exit_group leaves.
        unsafe { with_runner(&runner, &group, || group.enter(entry)) }
            .expect("with_runner")
            .0
            .expect("enter");

        assert_eq!(
            runner.outcome(),
            Some(DirectRunOutcome::Exited {
                code: carrick_native_darwin::direct::LINUX_CTR_EL0 as i32,
            }),
            "CTR_EL0 was synthesized with the Linux-shaped native value"
        );
    }

    /// V8's Linux arm64 code-cage shape in its smallest executable form:
    /// reserve anonymous `PROT_NONE`, promote it to persistent RWX, write
    /// machine code, and call it without a second mprotect boundary. Tier D
    /// must lower that Linux RWX contract through Darwin's per-thread
    /// `MAP_JIT` write/execute modes: static guest text remains executable
    /// while the code page is writable, the first branch faults into the
    /// scan+patch publication boundary, and the dynamic function returns 42.
    ///
    /// This is red against the old fail-closed mprotect arm, which stops at
    /// syscall 226 with "outside a patched tier-D mapping".
    #[test]
    fn anonymous_rwx_code_is_published_through_dynamic_wx() {
        const NR_MMAP: u32 = 222;
        const NR_MPROTECT: u32 = 226;
        const NR_MADVISE: u32 = 233;
        const NR_EXIT_GROUP: u32 = 94;
        const MADV_DONTNEED: u32 = 4;
        const MAP_PRIVATE_ANON: u32 = 0x22;
        const HOST_PAGE: u32 = 16 * 1024;
        const STR_W9_X21: u32 = 0xb900_02a9;
        const STR_W9_X21_4: u32 = 0xb900_06a9;
        const BLR_X21: u32 = 0xd63f_02a0;
        const DYNAMIC_RET: u32 = 0xd65f_03c0;
        let dynamic_return_42 = movz(0, 42, 0);
        let expected_dynamic_bytes = u64::from(dynamic_return_42) | (u64::from(DYNAMIC_RET) << 32);
        let elf = elf_with_code(&[
            movz(0, 0, 0),
            movz(1, HOST_PAGE, 0),
            movz(2, 0, 0), // PROT_NONE
            movz(3, MAP_PRIVATE_ANON, 0),
            movz(4, 0xffff, 0),
            movk(4, 0xffff, 16),
            movk(4, 0xffff, 32),
            movk(4, 0xffff, 48), // fd = -1
            movz(5, 0, 0),
            movz(8, NR_MMAP, 0),
            SVC_0,
            mov_reg(21, 0), // dynamic page
            mov_reg(0, 21),
            movz(1, HOST_PAGE, 0),
            movz(2, 7, 0), // PROT_READ|WRITE|EXEC
            movz(8, NR_MPROTECT, 0),
            SVC_0,
            // V8 creates its code cage in exactly this order: promote the
            // pristine reservation to persistent RWX, discard the untouched
            // pages, then publish generated code. The discard must see the
            // Tier-D mapping even though it bypasses the arena dispatcher.
            mov_reg(0, 21),
            movz(1, HOST_PAGE, 0),
            movz(2, MADV_DONTNEED, 0),
            movz(8, NR_MADVISE, 0),
            SVC_0,
            cbz_rel(0, (24 - 20) * 4), // success -> publish the code
            movz(0, 77, 0),            // named discard failure
            movz(8, NR_EXIT_GROUP, 0),
            SVC_0,
            // The first store faults while the shadow source is read-only.
            // XNU zeroes physical x18 on a direct Mach exception reply, so
            // hold a sentinel across that exact boundary and fail distinctly
            // unless Carrick parks and restores the complete guest state.
            movz(18, 0x1818, 0),
            movz(9, dynamic_return_42 & 0xffff, 0),
            movk(9, dynamic_return_42 >> 16, 16),
            STR_W9_X21,
            movz(10, 0x1818, 0),
            cmp_reg(18, 10),
            b_eq_rel(4 * 4),
            movz(0, 78, 0), // shadow write reply lost physical x18
            movz(8, NR_EXIT_GROUP, 0),
            SVC_0,
            movz(9, DYNAMIC_RET & 0xffff, 0),
            movk(9, DYNAMIC_RET >> 16, 16),
            STR_W9_X21_4,
            BLR_X21,
            // V8 legitimately reads generated instructions as data. The
            // shadow route must execute from a separate cache while leaving
            // this exact eight-byte source value untouched.
            ldr_reg_imm(10, 21, 0),
            movz(11, (expected_dynamic_bytes & 0xffff) as u32, 0),
            movk(11, ((expected_dynamic_bytes >> 16) & 0xffff) as u32, 16),
            movk(11, ((expected_dynamic_bytes >> 32) & 0xffff) as u32, 32),
            movk(11, ((expected_dynamic_bytes >> 48) & 0xffff) as u32, 48),
            cmp_reg(10, 11),
            b_eq_rel(4 * 4),
            movz(0, 79, 0), // source bytes changed
            movz(8, NR_EXIT_GROUP, 0),
            SVC_0,
            movz(8, NR_EXIT_GROUP, 0),
            SVC_0,
        ]);
        let group = DirectLoadGroup::load(&elf, island_handler())
            .expect("load")
            .expect("eligible");
        group
            .enable_dynamic_shadow()
            .expect("force byte-preserving dynamic shadow route");
        let stack = DirectStack::build(
            &elf,
            group.main().bias(),
            None,
            &[b"dynamic-wx-fixture".to_vec()],
            &[],
        )
        .expect("guest stack");
        let runner = DirectRunner::new(SyscallDispatcher::new(), IdentityMemory::new(0, u64::MAX));
        let entry = group.main().entry();
        let sp = stack.sp();
        // SAFETY: the static image is patched and the dynamic target is
        // published by the runner before it is re-entered; the dedicated
        // product-shaped guest stack keeps signal recovery's host frame
        // disjoint from guest and island-handler frames.
        unsafe { with_runner(&runner, &group, || group.enter_on_stack(entry, sp)) }
            .expect("with_runner")
            .0
            .expect("enter");

        assert_eq!(
            runner.outcome(),
            Some(DirectRunOutcome::Exited { code: 42 }),
            "dynamic code survived the V8-shaped discard and returned its value"
        );
    }

    /// A later V8 discard is not necessarily over a pristine code cage: the
    /// guest may already have published bytes in the MAP_JIT mapping. Linux
    /// still requires DONTNEED to make the discarded private-anon pages read
    /// as zero. Prove both the zero and the ability to publish fresh code
    /// afterward.
    #[test]
    fn dirty_dynamic_code_discard_zeroes_then_republishes() {
        const NR_MMAP: u32 = 222;
        const NR_MPROTECT: u32 = 226;
        const NR_MADVISE: u32 = 233;
        const NR_EXIT_GROUP: u32 = 94;
        const MADV_DONTNEED: u32 = 4;
        const MAP_PRIVATE_ANON: u32 = 0x22;
        const HOST_PAGE: u32 = 16 * 1024;
        const STR_W9_X21: u32 = 0xb900_02a9;
        const STR_W9_X21_4: u32 = 0xb900_06a9;
        const BLR_X21: u32 = 0xd63f_02a0;
        const DYNAMIC_RET: u32 = 0xd65f_03c0;
        let old_return = movz(0, 99, 0);
        let new_return = movz(0, 42, 0);
        let elf = elf_with_code(&[
            movz(0, 0, 0),
            movz(1, HOST_PAGE, 0),
            movz(2, 0, 0),
            movz(3, MAP_PRIVATE_ANON, 0),
            movz(4, 0xffff, 0),
            movk(4, 0xffff, 16),
            movk(4, 0xffff, 32),
            movk(4, 0xffff, 48),
            movz(5, 0, 0),
            movz(8, NR_MMAP, 0),
            SVC_0,
            mov_reg(21, 0),
            mov_reg(0, 21),
            movz(1, HOST_PAGE, 0),
            movz(2, 7, 0),
            movz(8, NR_MPROTECT, 0),
            SVC_0,
            movz(9, old_return & 0xffff, 0),
            movk(9, old_return >> 16, 16),
            STR_W9_X21,
            movz(9, DYNAMIC_RET & 0xffff, 0),
            movk(9, DYNAMIC_RET >> 16, 16),
            STR_W9_X21_4,
            mov_reg(0, 21),
            movz(1, HOST_PAGE, 0),
            movz(2, MADV_DONTNEED, 0),
            movz(8, NR_MADVISE, 0),
            SVC_0,
            cbz_rel(0, (32 - 28) * 4),
            movz(0, 77, 0),
            movz(8, NR_EXIT_GROUP, 0),
            SVC_0,
            ldr_reg_imm(0, 21, 0),
            cbz_rel(0, (37 - 33) * 4),
            movz(0, 78, 0),
            movz(8, NR_EXIT_GROUP, 0),
            SVC_0,
            movz(9, new_return & 0xffff, 0),
            movk(9, new_return >> 16, 16),
            STR_W9_X21,
            movz(9, DYNAMIC_RET & 0xffff, 0),
            movk(9, DYNAMIC_RET >> 16, 16),
            STR_W9_X21_4,
            BLR_X21,
            movz(8, NR_EXIT_GROUP, 0),
            SVC_0,
        ]);
        let group = DirectLoadGroup::load(&elf, island_handler())
            .expect("load")
            .expect("eligible");
        group
            .enable_dynamic_shadow()
            .expect("use the shipped byte-preserving dynamic-code policy");
        let stack = DirectStack::build(
            &elf,
            group.main().bias(),
            None,
            &[b"dirty-discard-fixture".to_vec()],
            &[],
        )
        .expect("guest stack");
        let runner = DirectRunner::new(SyscallDispatcher::new(), IdentityMemory::new(0, u64::MAX));
        let entry = group.main().entry();
        let sp = stack.sp();
        // SAFETY: static code is patched; the dynamic page is published only
        // through the MAP_JIT transition protocol under test.
        unsafe { with_runner(&runner, &group, || group.enter_on_stack(entry, sp)) }
            .expect("with_runner")
            .0
            .expect("enter");

        assert_eq!(
            runner.outcome(),
            Some(DirectRunOutcome::Exited { code: 42 }),
            "dirty code was zero-discarded and fresh code republished"
        );
    }

    /// Linux `MADV_DONTNEED` on private anonymous memory discards the old
    /// contents: a later read observes zero-fill. Tier D owns the live host
    /// mapping, so the arena dispatcher's VMA ledger cannot validate or zero
    /// it. This fixture is red against that split (madvise returns ENOMEM and
    /// the old 0x5a remains) and pins both range visibility and contents.
    #[test]
    fn identity_madvise_dontneed_zeroes_private_anonymous_memory() {
        const NR_MMAP: u32 = 222;
        const NR_MADVISE: u32 = 233;
        const NR_EXIT_GROUP: u32 = 94;
        const MADV_DONTNEED: u32 = 4;
        const MAP_PRIVATE_ANON: u32 = 0x22;
        const HOST_PAGE: u32 = 16 * 1024;
        let elf = elf_with_code(&[
            movz(0, 0, 0),
            movz(1, HOST_PAGE, 0),
            movz(2, 3, 0), // PROT_READ|WRITE
            movz(3, MAP_PRIVATE_ANON, 0),
            movz(4, 0xffff, 0),
            movk(4, 0xffff, 16),
            movk(4, 0xffff, 32),
            movk(4, 0xffff, 48), // fd = -1
            movz(5, 0, 0),       // offset
            movz(8, NR_MMAP, 0),
            SVC_0,
            mov_reg(21, 0),
            movz(9, 0x5a, 0),
            str_reg_imm(9, 21, 0),
            mov_reg(0, 21),
            movz(1, HOST_PAGE, 0),
            movz(2, MADV_DONTNEED, 0),
            movz(8, NR_MADVISE, 0),
            SVC_0,
            ldr_reg_imm(0, 21, 0), // zero on success; 0x5a on the old path
            movz(8, NR_EXIT_GROUP, 0),
            SVC_0,
        ]);
        let group = DirectLoadGroup::load(&elf, island_handler())
            .expect("load")
            .expect("eligible");
        let runner = DirectRunner::new(SyscallDispatcher::new(), IdentityMemory::new(0, u64::MAX));
        let entry = group.main().entry();
        // SAFETY: patched image built with `island_handler`; exit_group leaves
        // through the direct handler.
        unsafe { with_runner(&runner, &group, || group.enter(entry)) }
            .expect("with_runner")
            .0
            .expect("enter");

        assert_eq!(
            runner.outcome(),
            Some(DirectRunOutcome::Exited { code: 0 }),
            "MADV_DONTNEED replaced the private-anon contents with zero-fill"
        );
    }

    /// Node's worker-stack teardown discards one range spanning an untouched
    /// PROT_NONE guard prefix and an interior promoted to RW. Both pieces are
    /// one private-anon mapping; Linux accepts the cross-protection madvise,
    /// leaves the guard inaccessible, and zeroes the writable contents.
    #[test]
    fn identity_madvise_spans_none_guard_and_promoted_rw_stack() {
        const NR_MMAP: u32 = 222;
        const NR_MPROTECT: u32 = 226;
        const NR_MADVISE: u32 = 233;
        const NR_EXIT_GROUP: u32 = 94;
        const MADV_DONTNEED: u32 = 4;
        const MAP_PRIVATE_ANON_STACK: u32 = 0x2_0022;
        const HOST_PAGE: u32 = 16 * 1024;
        let elf = elf_with_code(&[
            movz(0, 0, 0),
            movz(1, HOST_PAGE * 2, 0),
            movz(2, 0, 0),
            movz(3, MAP_PRIVATE_ANON_STACK & 0xffff, 0),
            movk(3, MAP_PRIVATE_ANON_STACK >> 16, 16),
            movz(4, 0xffff, 0),
            movk(4, 0xffff, 16),
            movk(4, 0xffff, 32),
            movk(4, 0xffff, 48),
            movz(5, 0, 0),
            movz(8, NR_MMAP, 0),
            SVC_0,
            mov_reg(21, 0),
            movz(22, HOST_PAGE, 0),
            add_reg(22, 21, 22),
            mov_reg(0, 22),
            movz(1, HOST_PAGE, 0),
            movz(2, 3, 0),
            movz(8, NR_MPROTECT, 0),
            SVC_0,
            movz(9, 0x5a, 0),
            str_reg_imm(9, 22, 0),
            mov_reg(0, 21),
            movz(1, HOST_PAGE * 2, 0),
            movz(2, MADV_DONTNEED, 0),
            movz(8, NR_MADVISE, 0),
            SVC_0,
            ldr_reg_imm(0, 22, 0),
            movz(8, NR_EXIT_GROUP, 0),
            SVC_0,
        ]);
        let group = DirectLoadGroup::load(&elf, island_handler())
            .expect("load")
            .expect("eligible");
        let runner = DirectRunner::new(SyscallDispatcher::new(), IdentityMemory::new(0, u64::MAX));
        let entry = group.main().entry();
        // SAFETY: patched image built with the Tier-D handler; every host
        // range touched is created by this fixture's identity mmap.
        unsafe { with_runner(&runner, &group, || group.enter(entry)) }
            .expect("with_runner")
            .0
            .expect("enter");

        assert_eq!(
            runner.outcome(),
            Some(DirectRunOutcome::Exited { code: 0 }),
            "the RW stack contents were discarded across its PROT_NONE guard"
        );
    }

    /// The guest-leave contract, enforced at the syscall that ends the run:
    /// `exit(2)` must LEAVE through the handler, not merely be recorded while
    /// the guest keeps executing whatever bytes follow the `svc`. The poison
    /// write after the exit would be serviced by a runner without an exit
    /// path, so the assertions below are red against exactly that defect.
    #[test]
    fn exit_leaves_through_the_handler_instead_of_running_past_it() {
        const NR_EXIT: u32 = 93;
        let elf = elf_with_code(&[
            mov_reg(20, 30), // stash the incoming link register
            movz(0, 7, 0),   // exit code 7
            movz(8, NR_EXIT, 0),
            SVC_0,
            // POISON: everything from here on must never execute. A runner
            // without a real exit path resumes the guest here and services
            // this write, which is the observable difference.
            movz(9, 0x4141, 0), // "AA"
            str_pre_sp(9),
            mov_from_sp(1),
            movz(0, 1, 0),
            movz(2, 2, 0),
            movz(8, NR_WRITE, 0),
            SVC_0,
            ADD_SP_16,
            mov_reg(30, 20),
            0xd65f_03c0, // ret — reached only when the exit path is broken
        ]);
        let group = DirectLoadGroup::load(&elf, island_handler())
            .expect("load")
            .expect("eligible");
        let runner = DirectRunner::new(SyscallDispatcher::new(), IdentityMemory::new(0, u64::MAX));
        let entry = group.main().entry();
        // SAFETY: the image is patched and built with `island_handler`.
        unsafe { with_runner(&runner, &group, || group.enter(entry)) }
            .expect("with_runner")
            .0
            .expect("enter");

        assert_eq!(
            runner.outcome(),
            Some(DirectRunOutcome::Exited { code: 7 }),
            "the exit was recorded"
        );
        assert_eq!(
            runner.syscalls(),
            1,
            "the guest left AT the exit; the poison write never reached the dispatcher"
        );
        assert_eq!(
            runner.dispatcher().stdout(),
            b"",
            "no poison bytes: the guest did not run past its own exit"
        );
    }

    /// `execve(2)` is the syscall the roadmap names as needing a real exit:
    /// the dispatcher resolves path/argv/envp and hands back an `Execve`
    /// outcome the RUNNER must act on, which tier D cannot yet — so the guest
    /// must leave through the handler with its full state parked in the
    /// context, not resume with a fabricated errno.
    #[test]
    fn execve_leaves_through_the_handler_with_the_guest_parked_at_the_syscall() {
        const NR_EXECVE: u32 = 221;
        const NR_EXIT: u32 = 93;
        let elf = elf_with_code(&[
            mov_reg(20, 30),
            movz(9, 0x782f, 0), // "/x" + NUL padding
            str_pre_sp(9),
            mov_from_sp(0), // x0 = pathname
            str_pre_sp(31), // NULL terminator word (str xzr)
            mov_from_sp(1), // x1 = argv (empty, NULL-terminated)
            mov_reg(2, 1),  // x2 = envp = same empty array
            movz(8, NR_EXECVE, 0),
            SVC_0,
            // POISON: a broken exit path resumes here and this exit(9)
            // overwrites the recorded outcome, which the assertion catches.
            movz(0, 9, 0),
            movz(8, NR_EXIT, 0),
            SVC_0,
            ADD_SP_16,
            ADD_SP_16,
            mov_reg(30, 20),
            0xd65f_03c0, // ret
        ]);
        let group = DirectLoadGroup::load(&elf, island_handler())
            .expect("load")
            .expect("eligible");
        let runner = DirectRunner::new(SyscallDispatcher::new(), IdentityMemory::new(0, u64::MAX));
        let entry = group.main().entry();
        // SAFETY: the image is patched and built with `island_handler`.
        unsafe { with_runner(&runner, &group, || group.enter(entry)) }
            .expect("with_runner")
            .0
            .expect("enter");

        assert!(
            matches!(
                runner.outcome(),
                Some(DirectRunOutcome::Unsupported {
                    syscall: 221,
                    ref outcome
                }) if outcome.contains("Execve")
            ),
            "the run stopped AT the execve with the outcome named: {:?}",
            runner.outcome()
        );
        assert_eq!(
            runner.syscalls(),
            1,
            "the guest left AT the execve; the poison exit never ran"
        );
    }

    /// The tier-D exec stack: a REAL Linux process begins with argc/argv/
    /// envp/auxv on its stack, and the guest must find them through nothing
    /// but SP. The fixture reads argc from `[sp]` and `argv[0]` from
    /// `[sp+8]`, writes the first bytes of `argv[0]` to stdout, and exits
    /// with argc as its code — so a wrong layout fails loudly on three
    /// independent axes. The Rust side additionally walks the built stack
    /// past envp into the auxv and checks the interpreter contract values
    /// (`AT_PHDR`/`AT_ENTRY`; `AT_BASE` belongs to the interpreter chain).
    #[test]
    fn exec_stack_hands_argv_envp_auxv_to_the_guest() {
        const NR_EXIT: u32 = 93;
        let elf = elf_with_code(&[
            ldr_sp_imm(20, 0), // x20 = argc
            ldr_sp_imm(1, 8),  // x1 = argv[0] (the string's stack address)
            movz(0, 1, 0),     // fd 1
            movz(2, 5, 0),     // len 5: "hello"
            movz(8, NR_WRITE, 0),
            SVC_0,
            mov_reg(0, 20), // exit(argc)
            movz(8, NR_EXIT, 0),
            SVC_0,
        ]);
        let group = DirectLoadGroup::load(&elf, island_handler())
            .expect("load")
            .expect("eligible");
        let stack = DirectStack::build(
            &elf,
            group.main().bias(),
            None,
            &[b"hello-stack".to_vec(), b"arg1".to_vec()],
            &[b"PATH=/usr/bin".to_vec()],
        )
        .expect("stack builds");

        // Rust-side walk BEFORE entering: sp -> argc, argv[..], NULL,
        // envp[..], NULL, auxv pairs. This proves the auxv contract without
        // trusting the guest.
        // SAFETY: the stack was just built in host memory; reading it back.
        let word = |offset_words: u64| -> u64 {
            unsafe { *((stack.sp() + offset_words * 8) as *const u64) }
        };
        assert_eq!(word(0), 2, "argc");
        let argv0 = word(1);
        // SAFETY: argv[0] points into the same stack allocation.
        let argv0_bytes = unsafe { std::slice::from_raw_parts(argv0 as *const u8, 12) };
        assert_eq!(&argv0_bytes[..11], b"hello-stack");
        assert_eq!(word(3), 0, "argv NULL terminator");
        let envp0 = word(4);
        // SAFETY: envp[0] points into the same stack allocation.
        let envp0_bytes = unsafe { std::slice::from_raw_parts(envp0 as *const u8, 13) };
        assert_eq!(envp0_bytes, b"PATH=/usr/bin");
        assert_eq!(word(5), 0, "envp NULL terminator");
        let mut auxv = std::collections::HashMap::new();
        let mut cursor = 6;
        loop {
            let (a_type, a_val) = (word(cursor), word(cursor + 1));
            if a_type == carrick_abi::LINUX_AT_NULL {
                break;
            }
            auxv.insert(a_type, a_val);
            cursor += 2;
        }
        assert_eq!(
            auxv.get(&carrick_abi::LINUX_AT_ENTRY),
            Some(&group.main().entry()),
            "AT_ENTRY is the main image's BIASED entry"
        );
        let phdr = auxv
            .get(&carrick_abi::LINUX_AT_PHDR)
            .expect("AT_PHDR present");
        assert!(
            *phdr > group.main().bias(),
            "AT_PHDR is a runtime address inside the mapped image"
        );
        assert!(
            !auxv.contains_key(&carrick_abi::LINUX_AT_BASE),
            "no interpreter, no AT_BASE (a bogus AT_BASE was a real bug)"
        );
        assert!(
            auxv.contains_key(&carrick_abi::LINUX_AT_RANDOM),
            "AT_RANDOM present (glibc stack canary init reads it)"
        );

        // Now the guest's own view.
        let runner = DirectRunner::new(SyscallDispatcher::new(), IdentityMemory::new(0, u64::MAX));
        let entry = group.main().entry();
        let sp = stack.sp();
        // SAFETY: the image is patched and built with `island_handler`; the
        // guest leaves through its exit.
        unsafe { with_runner(&runner, &group, || group.enter_on_stack(entry, sp)) }
            .expect("with_runner")
            .0
            .expect("enter");
        assert_eq!(
            runner.outcome(),
            Some(DirectRunOutcome::Exited { code: 2 }),
            "the guest read argc == 2 through its own SP"
        );
        assert_eq!(
            runner.dispatcher().stdout(),
            b"hello",
            "the guest wrote argv[0]'s bytes read via the stack"
        );
    }

    /// The interpreter chain, end to end on synthetic images: the main image
    /// declares `PT_INTERP`, the loader maps the resolved interpreter as a
    /// SECOND image in the same load group, entry goes to the INTERPRETER,
    /// and the interpreter finds the main image the only way the real ld.so
    /// can — by walking the stack past argv and envp into the auxv and
    /// branching to `AT_ENTRY`. The main image then exits through the
    /// handler. A wrong stack layout, a missing/wrong `AT_ENTRY` or
    /// `AT_BASE`, or entry at the wrong image all fail this test loudly (the
    /// interpreter exits 99 if the auxv has no `AT_ENTRY`).
    #[test]
    fn interpreter_chain_reaches_the_main_image_through_the_auxv() {
        const NR_EXIT: u32 = 93;
        // The "interpreter": skip argc/argv/envp, scan the auxv for AT_ENTRY
        // (a_type 9), `br` to its value; exit(99) at AT_NULL. Word indices in
        // the comments; branch offsets are (target - here) * 4.
        let interp_code: Vec<u32> = vec![
            ldr_sp_imm(1, 0),          //  0: x1 = argc
            add_imm(2, 31, 8),         //  1: x2 = &argv[0]
            add_lsl3(2, 2, 1),         //  2: x2 += argc * 8
            add_imm(2, 2, 8),          //  3: skip argv's NULL
            ldr_post8(3, 2),           //  4: x3 = *x2++, an envp entry
            cbnz_rel(3, -4),           //  5: while x3 != 0 goto 4
            ldr_post8(3, 2),           //  6: a_type
            ldr_post8(4, 2),           //  7: a_val
            cmp_imm(3, 9),             //  8: AT_ENTRY?
            b_eq_rel((14 - 9) * 4),    //  9: -> the br at 14
            cbnz_rel(3, (6 - 10) * 4), // 10: not AT_NULL: next pair
            movz(0, 99, 0),            // 11: AT_NULL, no AT_ENTRY
            movz(8, NR_EXIT, 0),       // 12
            SVC_0,                     // 13
            br_reg(4),                 // 14: hand control to the main image
        ];
        // The main image writes through the dispatcher and exits 42 — proof
        // it ran AFTER the interpreter handoff, with the stack intact.
        let main_code: Vec<u32> = vec![
            movz(9, 0x7964, 0),  // 'd','y'
            movk(9, 0x0a6e, 16), // 'n','\n'
            str_pre_sp(9),
            mov_from_sp(1),
            movz(0, 1, 0),
            movz(2, 4, 0),
            movz(8, NR_WRITE, 0),
            SVC_0,
            movz(0, 42, 0),
            movz(8, NR_EXIT, 0),
            SVC_0,
        ];
        let main_elf = elf_with_code_and_interp(&main_code, Some(b"/lib/fake-ld.so.1"));
        let interp_elf = elf_with_code(&interp_code);
        let group = DirectLoadGroup::load_with_interpreter(
            &main_elf,
            |path| {
                assert_eq!(path, "/lib/fake-ld.so.1", "the PT_INTERP path is resolved");
                Ok(interp_elf.clone())
            },
            island_handler(),
        )
        .expect("load")
        .expect("eligible");
        let interp = group.interpreter().expect("the interpreter was mapped");
        assert_ne!(
            interp.base(),
            group.main().base(),
            "two images, two mappings, one load group"
        );
        assert_eq!(
            group.entry_pc(),
            interp.entry(),
            "process entry is the INTERPRETER's entry"
        );

        let stack = DirectStack::build(
            &main_elf,
            group.main().bias(),
            Some(interp.bias()),
            &[b"dyn-fixture".to_vec()],
            &[],
        )
        .expect("stack builds");
        // Rust-side: AT_BASE is the interpreter's load bias — ld.so requires
        // it to find itself (a missing AT_BASE was a real carrick bug).
        // Layout for argc=1, no envp: argc(0) argv0(1) NULL(2) NULL(3) auxv(4..).
        // SAFETY: reading back the stack allocation just built.
        let word = |offset_words: u64| -> u64 {
            unsafe { *((stack.sp() + offset_words * 8) as *const u64) }
        };
        let mut auxv = std::collections::HashMap::new();
        let mut cursor = 4;
        loop {
            let (a_type, a_val) = (word(cursor), word(cursor + 1));
            if a_type == carrick_abi::LINUX_AT_NULL {
                break;
            }
            auxv.insert(a_type, a_val);
            cursor += 2;
        }
        assert_eq!(
            auxv.get(&carrick_abi::LINUX_AT_BASE),
            Some(&interp.bias()),
            "AT_BASE is the interpreter's load bias"
        );
        assert_eq!(
            auxv.get(&carrick_abi::LINUX_AT_ENTRY),
            Some(&group.main().entry()),
            "AT_ENTRY is the MAIN image's biased entry, reachable from the interpreter"
        );

        let runner = DirectRunner::new(SyscallDispatcher::new(), IdentityMemory::new(0, u64::MAX));
        let entry = group.entry_pc();
        let sp = stack.sp();
        // SAFETY: both images are patched and built with `island_handler`;
        // the guest leaves through its exit.
        unsafe { with_runner(&runner, &group, || group.enter_on_stack(entry, sp)) }
            .expect("with_runner")
            .0
            .expect("enter");
        assert_eq!(
            runner.outcome(),
            Some(DirectRunOutcome::Exited { code: 42 }),
            "the MAIN image ran and exited through the handler (99 = interpreter \
             found no AT_ENTRY; anything else = the chain broke earlier)"
        );
        assert_eq!(
            runner.dispatcher().stdout(),
            b"dyn\n",
            "the main image's write went through the dispatcher after the handoff"
        );
    }

    /// Milestone: a REAL dynamically linked binary on tier D. The fixture is
    /// cross-compiled with the host's aarch64-linux-gnu toolchain
    /// (`-nostdlib -pie` with an explicit `--dynamic-linker`), and the
    /// interpreter is the toolchain sysroot's REAL glibc ld.so — real
    /// relocation processing, real TLS setup, real syscalls through the real
    /// dispatcher, veneered tpidr/x18 and patched `svc` throughout. The run
    /// must end with the MAIN image's exit(42) leaving through the handler.
    ///
    /// Skips (loudly) when the cross toolchain is not installed; on the
    /// canonical dev host it runs (`brew install aarch64-unknown-linux-gnu`).
    #[test]
    fn real_glibc_ld_so_runs_a_dynamic_binary_on_tier_d() {
        let probe = std::process::Command::new("aarch64-linux-gnu-gcc")
            .arg("-print-sysroot")
            .output();
        let Ok(output) = probe else {
            eprintln!("skipping: aarch64-linux-gnu-gcc not on PATH");
            return;
        };
        assert!(output.status.success(), "-print-sysroot failed");
        let sysroot = String::from_utf8_lossy(&output.stdout).trim().to_string();
        let ld_path = format!("{sysroot}/lib/ld-linux-aarch64.so.1");
        let ld_bytes = std::fs::read(&ld_path).expect("sysroot ships ld.so");

        let dir = tempfile::tempdir().expect("tempdir");
        let src = dir.path().join("dyn.c");
        std::fs::write(
            &src,
            r#"
__attribute__((naked)) void _start(void) {
    __asm__ volatile(
        "mov x0, #42\n"
        "mov x8, #93\n"
        "svc #0\n");
}
"#,
        )
        .expect("write fixture source");
        let out = dir.path().join("dyn");
        let compile = std::process::Command::new("aarch64-linux-gnu-gcc")
            .args(["-nostdlib", "-pie", "-fpic", "-o"])
            .arg(&out)
            .arg(&src)
            .arg("-Wl,--dynamic-linker=/lib/ld-linux-aarch64.so.1")
            .output()
            .expect("cross gcc runs");
        assert!(
            compile.status.success(),
            "fixture compile failed: {}",
            String::from_utf8_lossy(&compile.stderr)
        );
        let main_elf = std::fs::read(&out).expect("read fixture");

        let group = DirectLoadGroup::load_with_interpreter(
            &main_elf,
            |path| {
                assert_eq!(path, "/lib/ld-linux-aarch64.so.1");
                Ok(ld_bytes.clone())
            },
            island_handler(),
        )
        .expect("load")
        .expect("real ld.so and the fixture are both tier-D eligible");
        let interp = group.interpreter().expect("interpreter mapped");
        let stack = DirectStack::build(
            &main_elf,
            group.main().bias(),
            Some(interp.bias()),
            &[b"dyn-real".to_vec()],
            &[],
        )
        .expect("stack builds");

        let runner = DirectRunner::new(SyscallDispatcher::new(), IdentityMemory::new(0, u64::MAX));
        let entry = group.entry_pc();
        let sp = stack.sp();
        // SAFETY: both images are patched and built with `island_handler`;
        // the guest leaves through its exit.
        let (entered, slots) =
            unsafe { with_runner(&runner, &group, || group.enter_on_stack(entry, sp)) }
                .expect("with_runner");
        entered.expect("enter");
        assert_eq!(
            runner.outcome(),
            Some(DirectRunOutcome::Exited { code: 42 }),
            "real ld.so ran to the main image, which exited through the \
             handler (syscalls serviced: {}; guest stdout: {:?}; guest \
             stderr: {:?})",
            runner.syscalls(),
            String::from_utf8_lossy(&runner.dispatcher().stdout()),
            String::from_utf8_lossy(&runner.dispatcher().stderr()),
        );
        assert_ne!(
            slots.guest_tls, 0,
            "real ld.so initialized TLS through the veneers into the main \
             thread's slots (glibc's TLS_INIT_TP is an `msr tpidr_el0`)"
        );
    }

    /// The former `/bin/dash` frontier, now CROSSED: a real libc-linked
    /// binary (`DT_NEEDED libc.so.6`). ld.so runs, finds the real libc.so.6
    /// through the dispatcher's VFS, maps its text with `mmap(PROT_EXEC,
    /// fd)` — the scan+patch window boundary, roadmap Phase 1 item 5 — maps
    /// its data segments `MAP_FIXED` over the reservation (guest-fd reads
    /// through the one fd table), relocates, runs glibc's full startup, and
    /// the program's `main` returns 41 out through the handler.
    ///
    /// Until item 5 landed, this test pinned the fail-closed stop at the
    /// named `mmap(PROT_EXEC, fd)` gap; its history is the red-first proof.
    #[test]
    fn dt_needed_binary_runs_through_the_exec_mmap_boundary() {
        let probe = std::process::Command::new("aarch64-linux-gnu-gcc")
            .arg("-print-sysroot")
            .output();
        let Ok(output) = probe else {
            eprintln!("skipping: aarch64-linux-gnu-gcc not on PATH");
            return;
        };
        assert!(output.status.success(), "-print-sysroot failed");
        let sysroot = String::from_utf8_lossy(&output.stdout).trim().to_string();
        let ld_bytes =
            std::fs::read(format!("{sysroot}/lib/ld-linux-aarch64.so.1")).expect("ld.so");

        let dir = tempfile::tempdir().expect("tempdir");
        let src = dir.path().join("hello.c");
        std::fs::write(&src, "int main(void) { return 41; }\n").expect("write");
        let out = dir.path().join("hello");
        // -pie -fpie explicitly: this toolchain's default is ET_EXEC at
        // 0x400000, which tier D refuses by physics (the __PAGEZERO wall).
        let compile = std::process::Command::new("aarch64-linux-gnu-gcc")
            .args(["-pie", "-fpie", "-o"])
            .arg(&out)
            .arg(&src)
            .output()
            .expect("cross gcc runs");
        assert!(
            compile.status.success(),
            "compile failed: {}",
            String::from_utf8_lossy(&compile.stderr)
        );
        let main_elf = std::fs::read(&out).expect("read fixture");

        let group = DirectLoadGroup::load_with_interpreter(
            &main_elf,
            |_| Ok(ld_bytes.clone()),
            island_handler(),
        )
        .expect("load")
        .expect("eligible");
        let interp = group.interpreter().expect("interpreter mapped");
        let stack = DirectStack::build(
            &main_elf,
            group.main().bias(),
            Some(interp.bias()),
            &[b"hello-libc".to_vec()],
            &[],
        )
        .expect("stack builds");

        // A rootfs whose /lib64 holds the sysroot's REAL libc.so.6 — /lib64
        // because that is this toolchain's system search path, read from
        // ld.so's own `LD_DEBUG=libs` trace through the dispatcher — so the
        // search SUCCEEDS through the VFS and the run reaches the file mmap
        // itself instead of dying on the lookup.
        use crate::fs_backend::FsBackend as _;
        let libc_bytes = std::fs::read(format!("{sysroot}/lib/libc.so.6")).expect("sysroot libc");
        let scratch = tempfile::tempdir().expect("scratch rootfs");
        let dir = cap_std::fs::Dir::open_ambient_dir(scratch.path(), cap_std::ambient_authority())
            .expect("open scratch");
        let backend = crate::fs_backend::HostFsBackend::from_existing_dir(dir);
        backend.make_dir("/lib64").expect("mkdir /lib64");
        backend
            .set_file_contents("/lib64/libc.so.6", libc_bytes)
            .expect("place libc");
        let mut dispatcher = SyscallDispatcher::new();
        dispatcher.set_fs_backend(Box::new(backend));
        let runner = DirectRunner::new(dispatcher, IdentityMemory::new(0, u64::MAX));
        let entry = group.entry_pc();
        let sp = stack.sp();
        // SAFETY: patched images built with `island_handler`; the guest
        // leaves through its exit.
        unsafe { with_runner(&runner, &group, || group.enter_on_stack(entry, sp)) }
            .expect("with_runner")
            .0
            .expect("enter");
        assert_eq!(
            runner.outcome(),
            Some(DirectRunOutcome::Exited { code: 41 }),
            "real ld.so mapped libc through the exec-mmap window and main \
             returned 41 (syscalls: {}; stderr: {:?})",
            runner.syscalls(),
            String::from_utf8_lossy(&runner.dispatcher().stderr()),
        );
    }

    /// THE GATE: `/bin/dash -c 'echo hi'` end to end on tier D — a real,
    /// stripped, PIE `/bin/dash` from a debian arm64 image, its real
    /// ld-linux-aarch64.so.1 as the interpreter, its real libc.so.6 found
    /// through the dispatcher's VFS and mapped through the exec-mmap window
    /// pipeline. `echo` is a dash builtin, so the whole run is one process:
    /// ld.so relocation, glibc startup, dash's parser, the builtin's
    /// write(2), and exit(0) through the handler.
    ///
    /// Binary sources (loud skip when absent): extracted from the cached
    /// debian OCI layer into `target/tierd-live` —
    /// `cd target/tierd-live && tar -xzf ~/.carrick/blobs/sha256/<debian
    /// stable layer digest> usr/bin/dash usr/lib/aarch64-linux-gnu/libc.so.6
    /// usr/lib/aarch64-linux-gnu/ld-linux-aarch64.so.1`.
    #[test]
    fn real_dash_echoes_through_tier_d() {
        let live = concat!(env!("CARGO_MANIFEST_DIR"), "/../../target/tierd-live");
        let read = |name: &str| std::fs::read(format!("{live}/{name}"));
        let (Ok(dash_elf), Ok(ld_bytes), Ok(libc_bytes)) = (
            read("usr/bin/dash"),
            read("usr/lib/aarch64-linux-gnu/ld-linux-aarch64.so.1"),
            read("usr/lib/aarch64-linux-gnu/libc.so.6"),
        ) else {
            eprintln!("skipping: no debian binaries under target/tierd-live (see test doc)");
            return;
        };

        let group = DirectLoadGroup::load_with_interpreter(
            &dash_elf,
            |path| {
                assert_eq!(path, "/lib/ld-linux-aarch64.so.1");
                Ok(ld_bytes.clone())
            },
            island_handler(),
        )
        .expect("load")
        .expect("dash and its ld.so are tier-D eligible");
        let interp = group.interpreter().expect("interpreter mapped");
        let stack = DirectStack::build(
            &dash_elf,
            group.main().bias(),
            Some(interp.bias()),
            &[b"dash".to_vec(), b"-c".to_vec(), b"echo hi".to_vec()],
            &[b"PATH=/usr/bin:/bin".to_vec()],
        )
        .expect("stack builds");

        // A rootfs carrying libc at every stop of debian ld.so's built-in
        // search list, so the lookup succeeds wherever this ld looks.
        use crate::fs_backend::FsBackend as _;
        let scratch = tempfile::tempdir().expect("scratch rootfs");
        let dir = cap_std::fs::Dir::open_ambient_dir(scratch.path(), cap_std::ambient_authority())
            .expect("open scratch");
        let backend = crate::fs_backend::HostFsBackend::from_existing_dir(dir);
        for parent in [
            "/lib",
            "/lib/aarch64-linux-gnu",
            "/lib64",
            "/usr",
            "/usr/lib",
        ] {
            backend.make_dir(parent).expect("mkdir");
        }
        for path in [
            "/lib/aarch64-linux-gnu/libc.so.6",
            "/lib64/libc.so.6",
            "/lib/libc.so.6",
        ] {
            backend
                .set_file_contents(path, libc_bytes.clone())
                .expect("place libc");
        }
        let mut dispatcher = SyscallDispatcher::new();
        dispatcher.set_fs_backend(Box::new(backend));
        let runner = DirectRunner::new(dispatcher, IdentityMemory::new(0, u64::MAX));
        let entry = group.entry_pc();
        let sp = stack.sp();
        // SAFETY: patched images built with `island_handler`; the guest
        // leaves through its exit.
        unsafe { with_runner(&runner, &group, || group.enter_on_stack(entry, sp)) }
            .expect("with_runner")
            .0
            .expect("enter");
        assert_eq!(
            runner.outcome(),
            Some(DirectRunOutcome::Exited { code: 0 }),
            "dash -c 'echo hi' ran end to end on tier D (syscalls: {}; \
             stdout: {:?}; stderr: {:?})",
            runner.syscalls(),
            String::from_utf8_lossy(&runner.dispatcher().stdout()),
            String::from_utf8_lossy(&runner.dispatcher().stderr()),
        );
        assert_eq!(
            runner.dispatcher().stdout(),
            b"hi\n",
            "the builtin echo's bytes came through the one dispatcher"
        );
    }

    /// Phase 2 item 2, the FORK half: a guest `fork(2)` on tier D host-forks
    /// the runner process. The CHILD resumes from this handler with x0 = 0
    /// in the kernel's CoW copy of the identity address space (no snapshot,
    /// no rebuild — the structural win of guest VA == host VA); the PARENT
    /// resumes with the child's pid and REAPS it through the blocking-wait
    /// path (`WaitOnProcExit` → the per-thread waiter → re-dispatched
    /// wait4). The script uses only dash BUILTINS (no execve): the subshell
    /// echoes into a file on the host-dir backend — durable, fork-coherent
    /// state — which the parent then reads back and echoes, so one stdout
    /// assertion proves the child EXECUTED (file content), the parent
    /// resumed and REAPED (`;` sequencing needs wait4), and both exited.
    ///
    /// Red against the pre-fork runner: the run leaves
    /// `Unsupported {{ syscall: 220 }}` at the clone and stdout is empty.
    /// The child-process epilogue detects the forked copy by host PID (no
    /// new-API dependence, so the red run compiles) and `_exit`s so the
    /// harness never continues in the child.
    #[test]
    fn tier_d_guest_fork_runs_both_sides_and_the_parent_reaps() {
        let live = concat!(env!("CARGO_MANIFEST_DIR"), "/../../target/tierd-live");
        let read = |name: &str| std::fs::read(format!("{live}/{name}"));
        let (Ok(dash_elf), Ok(ld_bytes), Ok(libc_bytes)) = (
            read("usr/bin/dash"),
            read("usr/lib/aarch64-linux-gnu/ld-linux-aarch64.so.1"),
            read("usr/lib/aarch64-linux-gnu/libc.so.6"),
        ) else {
            eprintln!("skipping: no debian binaries under target/tierd-live (see test doc)");
            return;
        };
        let group = DirectLoadGroup::load_with_interpreter(
            &dash_elf,
            |path| {
                assert_eq!(path, "/lib/ld-linux-aarch64.so.1");
                Ok(ld_bytes.clone())
            },
            island_handler(),
        )
        .expect("load")
        .expect("dash and its ld.so are tier-D eligible");
        let interp = group.interpreter().expect("interpreter mapped");
        let stack = DirectStack::build(
            &dash_elf,
            group.main().bias(),
            Some(interp.bias()),
            &[
                b"dash".to_vec(),
                b"-c".to_vec(),
                b"( echo 42 > /work/out ); read v < /work/out; echo \"got $v\"".to_vec(),
            ],
            &[b"PATH=/usr/bin:/bin".to_vec()],
        )
        .expect("stack builds");

        use crate::fs_backend::FsBackend as _;
        let scratch = tempfile::tempdir().expect("scratch rootfs");
        let dir = cap_std::fs::Dir::open_ambient_dir(scratch.path(), cap_std::ambient_authority())
            .expect("open scratch");
        let backend = crate::fs_backend::HostFsBackend::from_existing_dir(dir);
        for parent in [
            "/lib",
            "/lib/aarch64-linux-gnu",
            "/lib64",
            "/usr",
            "/usr/lib",
            "/work",
        ] {
            backend.make_dir(parent).expect("mkdir");
        }
        for path in [
            "/lib/aarch64-linux-gnu/libc.so.6",
            "/lib64/libc.so.6",
            "/lib/libc.so.6",
        ] {
            backend
                .set_file_contents(path, libc_bytes.clone())
                .expect("place libc");
        }
        let mut dispatcher = SyscallDispatcher::new();
        dispatcher.set_fs_backend(Box::new(backend));
        let runner = DirectRunner::new(dispatcher, IdentityMemory::new(0, u64::MAX));
        let entry = group.entry_pc();
        let sp = stack.sp();
        let host_pid_before = unsafe { libc::getpid() };
        // SAFETY: patched images built with `island_handler`; the guest
        // leaves through its exit (both sides of the fork).
        unsafe { with_runner(&runner, &group, || group.enter_on_stack(entry, sp)) }
            .expect("with_runner")
            .0
            .expect("enter");
        if unsafe { libc::getpid() } != host_pid_before {
            // We are the guest's fork CHILD: this host process's exit status
            // IS the child guest's outcome, and the harness must not
            // continue here (it would re-report the suite from the copy).
            let code = match runner.outcome() {
                Some(DirectRunOutcome::Exited { code }) => code,
                _ => 111,
            };
            unsafe { libc::_exit(code) };
        }
        assert_eq!(
            runner.outcome(),
            Some(DirectRunOutcome::Exited { code: 0 }),
            "fork + subshell + wait ran end to end on tier D (syscalls: {}; \
             stdout: {:?}; stderr: {:?})",
            runner.syscalls(),
            String::from_utf8_lossy(&runner.dispatcher().stdout()),
            String::from_utf8_lossy(&runner.dispatcher().stderr()),
        );
        assert_eq!(
            runner.dispatcher().stdout(),
            b"got 42\n",
            "the subshell's file write survived the fork and the parent read it back"
        );
    }

    /// Phase 2 item 2, the VFORK half, up to the exec boundary: dash spawns
    /// an external command via `vfork` (CLONE_VM|CLONE_VFORK). Tier D
    /// services it as CoW + TRUE parent suspension (the sharing half cannot
    /// be honored on private identity mappings — documented divergence);
    /// the child runs its pre-exec work and reaches `execve(2)`, which
    /// WITHOUT exec services leaves named (`Unsupported {{ syscall: 221 }}`)
    /// and the child `_exit`s through the test epilogue with 111. That EOF
    /// releases the suspended parent, whose wait4 reaps 111, and dash's `;`
    /// continues to the builtin echo — so `done` on stdout + exit 0 proves
    /// the whole vfork choreography (suspend, child pre-exec, release,
    /// reap) with the exec boundary itself pinned by the shipped-binary
    /// gate.
    #[test]
    fn tier_d_vfork_child_reaches_the_exec_boundary() {
        let live = concat!(env!("CARGO_MANIFEST_DIR"), "/../../target/tierd-live");
        let read = |name: &str| std::fs::read(format!("{live}/{name}"));
        let (Ok(dash_elf), Ok(ld_bytes), Ok(libc_bytes)) = (
            read("usr/bin/dash"),
            read("usr/lib/aarch64-linux-gnu/ld-linux-aarch64.so.1"),
            read("usr/lib/aarch64-linux-gnu/libc.so.6"),
        ) else {
            eprintln!("skipping: no debian binaries under target/tierd-live (see test doc)");
            return;
        };
        let group = DirectLoadGroup::load_with_interpreter(
            &dash_elf,
            |path| {
                assert_eq!(path, "/lib/ld-linux-aarch64.so.1");
                Ok(ld_bytes.clone())
            },
            island_handler(),
        )
        .expect("load")
        .expect("dash and its ld.so are tier-D eligible");
        let interp = group.interpreter().expect("interpreter mapped");
        let stack = DirectStack::build(
            &dash_elf,
            group.main().bias(),
            Some(interp.bias()),
            &[
                b"dash".to_vec(),
                b"-c".to_vec(),
                b"/bin/true; echo done".to_vec(),
            ],
            &[b"PATH=/usr/bin:/bin".to_vec()],
        )
        .expect("stack builds");

        use crate::fs_backend::FsBackend as _;
        let scratch = tempfile::tempdir().expect("scratch rootfs");
        let dir = cap_std::fs::Dir::open_ambient_dir(scratch.path(), cap_std::ambient_authority())
            .expect("open scratch");
        let backend = crate::fs_backend::HostFsBackend::from_existing_dir(dir);
        for parent in [
            "/bin",
            "/lib",
            "/lib/aarch64-linux-gnu",
            "/lib64",
            "/usr",
            "/usr/lib",
        ] {
            backend.make_dir(parent).expect("mkdir");
        }
        for path in [
            "/lib/aarch64-linux-gnu/libc.so.6",
            "/lib64/libc.so.6",
            "/lib/libc.so.6",
        ] {
            backend
                .set_file_contents(path, libc_bytes.clone())
                .expect("place libc");
        }
        // A real executable at /bin/true so dash's PATH search and the
        // dispatcher's exec resolution both succeed (dash itself works).
        backend
            .set_file_contents("/bin/true", dash_elf.clone())
            .expect("place /bin/true");
        let mut dispatcher = SyscallDispatcher::new();
        dispatcher.set_fs_backend(Box::new(backend));
        let runner = DirectRunner::new(dispatcher, IdentityMemory::new(0, u64::MAX));
        let entry = group.entry_pc();
        let sp = stack.sp();
        let host_pid_before = unsafe { libc::getpid() };
        // SAFETY: patched images built with `island_handler`; the guest
        // leaves through its exit (both sides of the vfork).
        unsafe { with_runner(&runner, &group, || group.enter_on_stack(entry, sp)) }
            .expect("with_runner")
            .0
            .expect("enter");
        if unsafe { libc::getpid() } != host_pid_before {
            // The vfork CHILD: without exec services its execve leaves
            // named; exit 111 tells the parent's reap apart from a crash.
            let code = match runner.outcome() {
                Some(DirectRunOutcome::Exited { code }) => code,
                _ => 111,
            };
            unsafe { libc::_exit(code) };
        }
        assert_eq!(
            runner.outcome(),
            Some(DirectRunOutcome::Exited { code: 0 }),
            "vfork + suspended parent + reap ran end to end (syscalls: {}; \
             stdout: {:?}; stderr: {:?})",
            runner.syscalls(),
            String::from_utf8_lossy(&runner.dispatcher().stdout()),
            String::from_utf8_lossy(&runner.dispatcher().stderr()),
        );
        assert_eq!(
            runner.dispatcher().stdout(),
            b"done\n",
            "the parent resumed after the vfork child left at the exec boundary"
        );
    }

    /// Roadmap Phase 1 item 4, FLIPPED: the formerly pinned fail-closed
    /// boundary (`thread_creating_clone_leaves_at_the_per_thread_boundary`,
    /// `5a6422cb`) is gone — a `pthread_create`-shaped clone now RUNS. The
    /// fixture is the raw pthread_join shape end to end: the parent mmaps a
    /// child stack, clones with `CLONE_CHILD_SETTID|CLONE_CHILD_CLEARTID`
    /// targeting a word on its own stack, and spins until the runner's
    /// thread-exit bookkeeping CLEARS that word (Linux's CLEARTID contract);
    /// the child — full parent register file, x0 = 0, its own stack — writes
    /// through the shared dispatcher and leaves via `exit(2)` as a
    /// `ThreadExit` (not process exit). Against the pre-item-4 runner this
    /// test is red at the clone (the run left `Unsupported`); the SETTID
    /// word doubles as proof the parent observed the child's tid.
    #[test]
    fn thread_creating_clone_runs_the_child_on_private_slots() {
        const NR_MMAP: u32 = 222;
        const NR_CLONE: u32 = 220;
        const NR_WRITE_C: u32 = 64;
        const NR_EXIT_THREAD: u32 = 93;
        const NR_EXIT_GROUP: u32 = 94;
        // CLONE_VM|CLONE_FS|CLONE_FILES|CLONE_SIGHAND|CLONE_THREAD
        // |CLONE_CHILD_CLEARTID|CLONE_CHILD_SETTID.
        const FLAGS: u32 = 0x100 | 0x200 | 0x400 | 0x800 | 0x1_0000 | 0x0020_0000 | 0x0100_0000;
        /// `add xd, xn, xm`
        const fn add_reg(rd: u32, rn: u32, rm: u32) -> u32 {
            0x8b00_0000 | (rm << 16) | (rn << 5) | rd
        }
        /// `cbz xt, <pc + offset>`
        const fn cbz_rel(rt: u32, offset: i32) -> u32 {
            0xb400_0000 | (((offset as u32 >> 2) & 0x7ffff) << 5) | rt
        }
        let elf = elf_with_code(&[
            //  0: parent — mmap a 128 KiB child stack.
            movz(0, 0, 0),
            movz(1, 0x2, 16), // len 0x20000
            movz(2, 3, 0),    // PROT_READ|WRITE
            movz(3, 0x22, 0), // MAP_PRIVATE|MAP_ANONYMOUS
            movz(4, 0, 0),    // fd (ignored for anon)
            movz(5, 0, 0),    // offset
            movz(8, NR_MMAP, 0),
            SVC_0,            //  7: x0 = stack base
            movz(9, 0x2, 16), //  8
            add_reg(9, 0, 9), //  9: x9 = stack TOP
            str_pre_sp(31),   // 10: ctid word = 0 at [sp] (str xzr)
            mov_from_sp(4),   // 11: x4 = &ctid (SETTID + CLEARTID target)
            movz(0, FLAGS & 0xffff, 0),
            movk(0, FLAGS >> 16, 16), // 13: x0 = flags
            mov_reg(1, 9),            // 14: x1 = child stack top
            movz(2, 0, 0),            // 15: ptid unused
            movz(3, 0, 0),            // 16: no CLONE_SETTLS
            movz(8, NR_CLONE, 0),
            SVC_0,                     // 18: parent: x0 = tid; child: x0 = 0
            cbz_rel(0, (25 - 19) * 4), // 19: child -> its own leg
            // parent join: SETTID stamped a nonzero tid BEFORE the clone
            // returned, so the spin only ends when the child's exit CLEARS it.
            ldr_sp_imm(9, 0),          // 20
            cbnz_rel(9, -4),           // 21: while ctid != 0
            movz(0, 5, 0),             // 22
            movz(8, NR_EXIT_GROUP, 0), // 23
            SVC_0,                     // 24: process exit 5
            // child leg: write "c\n" from ITS OWN stack, exit(7) as a THREAD.
            movz(9, 0x0a63, 0), // 25: 'c','\n'
            str_pre_sp(9),      // 26
            mov_from_sp(1),     // 27
            movz(0, 1, 0),      // 28
            movz(2, 2, 0),      // 29
            movz(8, NR_WRITE_C, 0),
            SVC_0,         // 31
            movz(0, 7, 0), // 32
            movz(8, NR_EXIT_THREAD, 0),
            SVC_0, // 34: ThreadExit -> CLEARTID wake
        ]);
        let group = DirectLoadGroup::load(&elf, island_handler())
            .expect("load")
            .expect("eligible");
        let runner = DirectRunner::new(SyscallDispatcher::new(), IdentityMemory::new(0, u64::MAX));
        let entry = group.main().entry();
        // SAFETY: patched image built with `island_handler`; both threads
        // leave through the handler (exit / exit_group).
        unsafe { with_runner(&runner, &group, || group.enter(entry)) }
            .expect("with_runner")
            .0
            .expect("enter");
        assert_eq!(
            runner.outcome(),
            Some(DirectRunOutcome::Exited { code: 5 }),
            "the parent joined its thread and exit_grouped (syscalls: {})",
            runner.syscalls(),
        );
        assert_eq!(
            runner.dispatcher().stdout(),
            b"c\n",
            "the CHILD THREAD's write reached the one shared dispatcher"
        );
        assert!(
            runner.syscalls() >= 5,
            "mmap + clone + child write + child exit + exit_group all serviced \
             (got {})",
            runner.syscalls()
        );
    }

    /// The multithreaded-fork boundary: a live guest sibling loops through
    /// syscall boundaries while the main guest thread creates a PROCESS
    /// child. The forker must quiesce that sibling, fork with the shared
    /// runtime locks in a coherent state, reset the child copy, and release
    /// the parent sibling. Both process sides then exit and the parent reaps
    /// the child; `exit_group` retires the still-live sibling before
    /// [`with_runner`] joins it.
    ///
    /// Red against the pre-quiesce runner: syscall 220 left named as
    /// `multithreaded fork on tier D (no sibling quiesce)`.
    #[test]
    fn multithreaded_fork_quiesces_the_live_guest_sibling() {
        const NR_MMAP: u32 = 222;
        const NR_CLONE: u32 = 220;
        const NR_NANOSLEEP: u32 = 101;
        const NR_WAIT4: u32 = 260;
        const NR_EXIT_GROUP: u32 = 94;
        // CLONE_VM|CLONE_FS|CLONE_FILES|CLONE_SIGHAND|CLONE_THREAD
        // |CLONE_CHILD_CLEARTID|CLONE_CHILD_SETTID.
        const THREAD_FLAGS: u32 =
            0x100 | 0x200 | 0x400 | 0x800 | 0x1_0000 | 0x0020_0000 | 0x0100_0000;
        let elf = elf_with_code(&[
            //  0: reserve the sibling's 128 KiB stack.
            movz(0, 0, 0),
            movz(1, 0x2, 16),
            movz(2, 3, 0),
            movz(3, 0x22, 0),
            movz(4, 0, 0),
            movz(5, 0, 0),
            movz(8, NR_MMAP, 0),
            SVC_0,
            movz(9, 0x2, 16),
            add_reg(9, 0, 9),
            str_pre_sp(31), // ctid word
            mov_from_sp(4),
            str_pre_sp(31), // sibling-started word
            mov_from_sp(20),
            movz(0, THREAD_FLAGS & 0xffff, 0),
            movk(0, THREAD_FLAGS >> 16, 16),
            mov_reg(1, 9),
            movz(2, 0, 0),
            movz(3, 0, 0),
            movz(8, NR_CLONE, 0),
            SVC_0,
            cbz_rel(0, (51 - 21) * 4), // sibling -> long sleep
            // Wait until the sibling has executed guest code, so the fork
            // cannot win solely against the pre-entry startup check.
            ldr_reg_imm(9, 20, 0),
            cbz_rel(9, -4),
            // 24: process-creating clone(SIGCHLD), stack = NULL.
            movz(0, 17, 0),
            movz(1, 0, 0),
            movz(2, 0, 0),
            movz(3, 0, 0),
            movz(4, 0, 0),
            movz(8, NR_CLONE, 0),
            SVC_0,
            cbz_rel(0, (61 - 31) * 4), // process child -> exit 23
            mov_reg(19, 0),            // parent: preserve child pid
            str_pre_sp(31),            // wait status word
            mov_reg(0, 19),
            mov_from_sp(1),
            movz(2, 0, 0),
            movz(3, 0, 0),
            movz(8, NR_WAIT4, 0),
            SVC_0,
            // Give the released sibling 100 ms to enter its 60-second host
            // wait. The later exit_group must wake it; otherwise the test
            // blocks for roughly a minute in join_guest_threads.
            str_pre_sp(31),
            movz(9, 0xe100, 0),
            movk(9, 0x05f5, 16), // 100,000,000 ns
            str_sp(9, 8),
            mov_from_sp(0),
            movz(1, 0, 0),
            movz(8, NR_NANOSLEEP, 0),
            SVC_0,
            movz(0, 5, 0),
            movz(8, NR_EXIT_GROUP, 0),
            SVC_0,
            // 51: sibling publishes that it ran, then blocks in a 60-second
            // nanosleep. Fork quiesce must
            // wake+park it without completing the guest sleep; the parent's
            // later exit_group must wake it again and retire it promptly.
            movz(9, 1, 0),
            str_reg_imm(9, 20, 0),
            movz(9, 60, 0),
            str_pre_sp(9),
            str_sp(31, 8),
            mov_from_sp(0),
            movz(1, 0, 0),
            movz(8, NR_NANOSLEEP, 0),
            SVC_0,
            b_rel((53 - 60) * 4),
            // 61: only the forking thread exists in the process child.
            movz(0, 23, 0),
            movz(8, NR_EXIT_GROUP, 0),
            SVC_0,
        ]);
        let group = DirectLoadGroup::load(&elf, island_handler())
            .expect("load")
            .expect("eligible");
        let stack = DirectStack::build(
            &elf,
            group.main().bias(),
            None,
            &[b"mt-fork-fixture".to_vec()],
            &[],
        )
        .expect("stack");
        let runner = DirectRunner::new(SyscallDispatcher::new(), IdentityMemory::new(0, u64::MAX));
        let host_pid_before = unsafe { libc::getpid() };
        // SAFETY: patched image built with `island_handler`; every surviving
        // guest thread leaves through exit_group.
        unsafe {
            with_runner(&runner, &group, || {
                group.enter_on_stack(group.main().entry(), stack.sp())
            })
        }
        .expect("with_runner")
        .0
        .expect("enter");
        if unsafe { libc::getpid() } != host_pid_before {
            let code = match runner.outcome() {
                Some(DirectRunOutcome::Exited { code }) => code,
                _ => 111,
            };
            unsafe { libc::_exit(code) };
        }
        assert_eq!(
            runner.outcome(),
            Some(DirectRunOutcome::Exited { code: 5 }),
            "the parent resumed, reaped its process child, and retired the sibling"
        );
    }

    /// `ldr xt, [sp, #imm]`
    const fn ldr_sp_imm(rt: u32, byte_offset: u32) -> u32 {
        0xf940_0000 | ((byte_offset / 8) << 10) | (31 << 5) | rt
    }
    /// `ldr xt, [xn, #imm]` / `str xt, [xn, #imm]`.
    const fn ldr_reg_imm(rt: u32, rn: u32, byte_offset: u32) -> u32 {
        0xf940_0000 | ((byte_offset / 8) << 10) | (rn << 5) | rt
    }
    const fn str_reg_imm(rt: u32, rn: u32, byte_offset: u32) -> u32 {
        0xf900_0000 | ((byte_offset / 8) << 10) | (rn << 5) | rt
    }
    /// `add xd, xn, #imm` (rn = 31 reads SP)
    const fn add_imm(rd: u32, rn: u32, imm12: u32) -> u32 {
        0x9100_0000 | (imm12 << 10) | (rn << 5) | rd
    }
    /// `add xd, xn, xm`.
    const fn add_reg(rd: u32, rn: u32, rm: u32) -> u32 {
        0x8b00_0000 | (rm << 16) | (rn << 5) | rd
    }
    /// `add xd, xn, xm, lsl #3`
    const fn add_lsl3(rd: u32, rn: u32, rm: u32) -> u32 {
        0x8b00_0000 | (rm << 16) | (3 << 10) | (rn << 5) | rd
    }
    /// `ldr xt, [xn], #8`
    const fn ldr_post8(rt: u32, rn: u32) -> u32 {
        0xf840_0400 | (8 << 12) | (rn << 5) | rt
    }
    /// `cbnz xt, <pc + offset>`
    const fn cbnz_rel(rt: u32, offset: i32) -> u32 {
        0xb500_0000 | (((offset as u32 >> 2) & 0x7ffff) << 5) | rt
    }
    /// `cbz xt, <pc + offset>`.
    const fn cbz_rel(rt: u32, offset: i32) -> u32 {
        0xb400_0000 | (((offset as u32 >> 2) & 0x7ffff) << 5) | rt
    }
    /// `b <pc + offset>`.
    const fn b_rel(offset: i32) -> u32 {
        0x1400_0000 | ((offset as u32 >> 2) & 0x03ff_ffff)
    }
    /// `cmp xn, #imm` (SUBS XZR)
    const fn cmp_imm(rn: u32, imm12: u32) -> u32 {
        0xf100_0000 | (imm12 << 10) | (rn << 5) | 31
    }
    /// `cmp xn, xm` (SUBS XZR, Xn, Xm).
    const fn cmp_reg(rn: u32, rm: u32) -> u32 {
        0xeb00_001f | (rm << 16) | (rn << 5)
    }
    /// `b.eq <pc + offset>`
    const fn b_eq_rel(offset: i32) -> u32 {
        0x5400_0000 | (((offset as u32 >> 2) & 0x7ffff) << 5)
    }
    /// `br xn`
    const fn br_reg(rn: u32) -> u32 {
        0xd61f_0000 | (rn << 5)
    }

    /// Minimal ET_DYN wrapper with a section header table, which tier D's
    /// eligibility scan requires (it walks SHF_EXECINSTR sections).
    ///
    /// Real-binary shape where it matters for the exec stack: the FIRST
    /// `PT_LOAD` covers the ELF header and program headers at vaddr 0 (every
    /// real toolchain binary does this), which is what lets the load planner
    /// derive `AT_PHDR` — a fixture whose phdrs sit outside every segment
    /// would rightly get no `AT_PHDR` at all.
    fn elf_with_code(code: &[u32]) -> Vec<u8> {
        elf_with_code_and_interp(code, None)
    }

    /// As [`elf_with_code`], plus an optional `PT_INTERP` naming the given
    /// interpreter path — the shape of every real dynamically linked binary.
    fn elf_with_code_and_interp(code: &[u32], interp: Option<&[u8]>) -> Vec<u8> {
        let code_bytes: Vec<u8> = code.iter().flat_map(|w| w.to_le_bytes()).collect();
        let entry: u64 = 0x1000;
        let phnum: u64 = if interp.is_some() { 3 } else { 2 };
        let headers_len: u64 = 0x40 + phnum * 56;
        let mut elf = vec![0_u8; headers_len as usize];
        elf[..4].copy_from_slice(b"\x7fELF");
        elf[4] = 2;
        elf[5] = 1;
        elf[6] = 1;
        elf[0x10..0x12].copy_from_slice(&3_u16.to_le_bytes());
        elf[0x12..0x14].copy_from_slice(&183_u16.to_le_bytes());
        elf[0x18..0x20].copy_from_slice(&entry.to_le_bytes());
        elf[0x20..0x28].copy_from_slice(&0x40_u64.to_le_bytes());
        elf[0x36..0x38].copy_from_slice(&56_u16.to_le_bytes());
        elf[0x38..0x3a].copy_from_slice(&(phnum as u16).to_le_bytes());
        // PT_LOAD [0]: the headers, read-only at vaddr 0.
        let ph = 0x40;
        elf[ph..ph + 4].copy_from_slice(&1_u32.to_le_bytes());
        elf[ph + 4..ph + 8].copy_from_slice(&4_u32.to_le_bytes()); // PF_R
        elf[ph + 0x20..ph + 0x28].copy_from_slice(&headers_len.to_le_bytes());
        elf[ph + 0x28..ph + 0x30].copy_from_slice(&headers_len.to_le_bytes());
        // PT_LOAD [1]: the code.
        let ph = 0x40 + 56;
        elf[ph..ph + 4].copy_from_slice(&1_u32.to_le_bytes());
        elf[ph + 4..ph + 8].copy_from_slice(&5_u32.to_le_bytes());
        elf[ph + 0x08..ph + 0x10].copy_from_slice(&entry.to_le_bytes());
        elf[ph + 0x10..ph + 0x18].copy_from_slice(&entry.to_le_bytes());
        elf[ph + 0x20..ph + 0x28].copy_from_slice(&(code_bytes.len() as u64).to_le_bytes());
        elf[ph + 0x28..ph + 0x30].copy_from_slice(&(code_bytes.len() as u64).to_le_bytes());
        elf.resize(entry as usize, 0);
        elf.extend_from_slice(&code_bytes);
        let shoff = elf.len();
        let mut shdrs = vec![0_u8; 64 * 2];
        let text = 64;
        shdrs[text + 0x04..text + 0x08].copy_from_slice(&1_u32.to_le_bytes());
        shdrs[text + 0x08..text + 0x10].copy_from_slice(&0x6_u64.to_le_bytes());
        shdrs[text + 0x10..text + 0x18].copy_from_slice(&entry.to_le_bytes());
        shdrs[text + 0x18..text + 0x20].copy_from_slice(&entry.to_le_bytes());
        shdrs[text + 0x20..text + 0x28].copy_from_slice(&(code_bytes.len() as u64).to_le_bytes());
        elf.extend_from_slice(&shdrs);
        elf[0x28..0x30].copy_from_slice(&(shoff as u64).to_le_bytes());
        elf[0x3a..0x3c].copy_from_slice(&64_u16.to_le_bytes());
        elf[0x3c..0x3e].copy_from_slice(&2_u16.to_le_bytes());
        // PT_INTERP [2]: path bytes appended past the section headers
        // (nothing after them reads by offset), NUL-terminated.
        if let Some(path) = interp {
            let interp_off = elf.len();
            elf.extend_from_slice(path);
            elf.push(0);
            let ph = 0x40 + 2 * 56;
            elf[ph..ph + 4].copy_from_slice(&3_u32.to_le_bytes());
            elf[ph + 0x08..ph + 0x10].copy_from_slice(&(interp_off as u64).to_le_bytes());
            elf[ph + 0x20..ph + 0x28].copy_from_slice(&((path.len() + 1) as u64).to_le_bytes());
        }
        elf
    }

    // ==== tier-D signal gates (transplantable block for the red proof) ====

    /// Two-pass fixture assembler: emit words, mark labels, fix up the
    /// pc-relative forms (`adr`/`cbnz`/`b.ne`) once every index is known —
    /// hand-counted branch offsets are exactly the bug shape this avoids.
    #[derive(Default)]
    struct Asm {
        words: Vec<u32>,
        fixups: Vec<(usize, AsmFix)>,
        labels: std::collections::HashMap<&'static str, usize>,
    }

    enum AsmFix {
        Adr { rd: u32, label: &'static str },
        Cbnz { rt: u32, label: &'static str },
        Bne { label: &'static str },
    }

    impl Asm {
        fn put(&mut self, word: u32) -> &mut Self {
            self.words.push(word);
            self
        }
        fn label(&mut self, name: &'static str) -> &mut Self {
            self.labels.insert(name, self.words.len());
            self
        }
        fn adr(&mut self, rd: u32, label: &'static str) -> &mut Self {
            self.fixups
                .push((self.words.len(), AsmFix::Adr { rd, label }));
            self.words.push(0);
            self
        }
        fn cbnz(&mut self, rt: u32, label: &'static str) -> &mut Self {
            self.fixups
                .push((self.words.len(), AsmFix::Cbnz { rt, label }));
            self.words.push(0);
            self
        }
        fn b_ne(&mut self, label: &'static str) -> &mut Self {
            self.fixups.push((self.words.len(), AsmFix::Bne { label }));
            self.words.push(0);
            self
        }
        /// `write(1, &byte, 1)` through the guest stack (8 words).
        fn write_stdout(&mut self, byte: u8) -> &mut Self {
            self.put(movz(9, u32::from(byte), 0))
                .put(str_pre_sp(9))
                .put(mov_from_sp(1))
                .put(movz(0, 1, 0))
                .put(movz(2, 1, 0))
                .put(movz(8, NR_WRITE, 0))
                .put(SVC_0)
                .put(ADD_SP_16)
        }
        /// `exit_group(code)` (3 words).
        fn exit_group(&mut self, code: u32) -> &mut Self {
            self.put(movz(0, code, 0)).put(movz(8, 94, 0)).put(SVC_0)
        }
        /// Install a SIGALRM handler at `label` via `rt_sigaction` — flags,
        /// restorer and mask all zero, the aarch64 glibc shape (no
        /// `sa_restorer`: the handler returns through carrick's trampoline).
        /// Branches to `fail` on a nonzero retval. (16 words)
        fn sigaction_sigalrm(&mut self, handler: &'static str, fail: &'static str) -> &mut Self {
            self.adr(1, handler)
                .put(sub_sp(32))
                .put(str_sp(1, 0)) // sa_handler
                .put(str_sp(31, 8)) // sa_flags = 0
                .put(str_sp(31, 16)) // sa_restorer = 0
                .put(str_sp(31, 24)) // sa_mask = 0
                .put(movz(0, 14, 0)) // SIGALRM
                .put(mov_from_sp(1))
                .put(movz(2, 0, 0))
                .put(movz(3, 8, 0))
                .put(movz(8, 134, 0)) // rt_sigaction
                .put(SVC_0)
                .put(add_sp(32))
                .cbnz(0, fail)
        }
        /// One-shot `setitimer(ITIMER_REAL, {0, 0, 0, usec})`, branching to
        /// `fail` on a nonzero retval. (13 words)
        fn setitimer_oneshot(&mut self, usec: u32, fail: &'static str) -> &mut Self {
            self.put(sub_sp(32))
                .put(str_sp(31, 0)) // interval.sec = 0
                .put(str_sp(31, 8)) // interval.usec = 0
                .put(str_sp(31, 16)) // value.sec = 0
                .put(movz(1, usec, 0))
                .put(str_sp(1, 24)) // value.usec
                .put(movz(0, 0, 0)) // ITIMER_REAL
                .put(mov_from_sp(1))
                .put(movz(2, 0, 0))
                .put(movz(8, 103, 0)) // setitimer
                .put(SVC_0)
                .put(add_sp(32))
                .cbnz(0, fail)
        }
        // Test-only assembler; a bad label is a fixture bug (clippy's
        // in-tests allowance does not see through the module's cfg(all(...))).
        #[allow(clippy::panic)]
        fn assemble(&mut self) -> Vec<u8> {
            for (at, fix) in &self.fixups {
                let target = |name: &&'static str| {
                    *self
                        .labels
                        .get(*name)
                        .unwrap_or_else(|| panic!("undefined label {name}"))
                };
                let word = match fix {
                    AsmFix::Adr { rd, label } => {
                        let imm = ((target(label) as i64 - *at as i64) * 4) as u32;
                        0x1000_0000 | ((imm & 3) << 29) | (((imm >> 2) & 0x7_ffff) << 5) | rd
                    }
                    AsmFix::Cbnz { rt, label } => {
                        let off = (target(label) as i64 - *at as i64) * 4;
                        0xb500_0000 | ((((off >> 2) as u32) & 0x7_ffff) << 5) | rt
                    }
                    AsmFix::Bne { label } => {
                        let off = (target(label) as i64 - *at as i64) * 4;
                        0x5400_0000 | ((((off >> 2) as u32) & 0x7_ffff) << 5) | 0x1
                    }
                };
                self.words[*at] = word;
            }
            elf_with_code(&self.words)
        }
    }

    /// `sub sp, sp, #imm` / `add sp, sp, #imm`.
    const fn sub_sp(imm: u32) -> u32 {
        0xd100_0000 | (imm << 10) | (31 << 5) | 31
    }
    const fn add_sp(imm: u32) -> u32 {
        0x9100_0000 | (imm << 10) | (31 << 5) | 31
    }
    /// `str xt, [sp, #off]` (rt = 31 stores xzr).
    const fn str_sp(rt: u32, off: u32) -> u32 {
        0xf900_0000 | ((off / 8) << 10) | (31 << 5) | rt
    }
    /// `ldr wt, [sp, #off]`.
    const fn ldr_w_sp(rt: u32, off: u32) -> u32 {
        0xb940_0000 | ((off / 4) << 10) | (31 << 5) | rt
    }
    /// `add xd, sp, #imm`.
    const fn add_x_sp(rd: u32, imm: u32) -> u32 {
        0x9100_0000 | (imm << 10) | (31 << 5) | rd
    }
    /// `cmn xn, #imm` (ADDS xzr) — `cmn x0, #4` is the `retval == -EINTR`
    /// check.
    const fn cmn_imm(rn: u32, imm: u32) -> u32 {
        0xb100_0000 | (imm << 10) | (rn << 5) | 31
    }
    /// `fmov dd, xn` / `fmov xd, dn`.
    const fn fmov_d_x(d: u32, x: u32) -> u32 {
        0x9e67_0000 | (x << 5) | d
    }
    const fn fmov_x_d(x: u32, d: u32) -> u32 {
        0x9e66_0000 | (d << 5) | x
    }
    const RET_WORD: u32 = 0xd65f_03c0;

    /// Run an assembled fixture on tier D with a REAL exec stack (signal
    /// frames are written below the parked guest SP, so the guest must run
    /// on its own stack, never the host thread's — exactly the shipped
    /// driver's shape) and hand back the runner for assertions.
    // Test-only harness (clippy's in-tests allowance does not see through
    // the module's cfg(all(...))).
    #[allow(clippy::expect_used)]
    fn run_signal_fixture(elf: &[u8], dispatcher: SyscallDispatcher) -> DirectRunner {
        let group = DirectLoadGroup::load(elf, island_handler())
            .expect("load")
            .expect("eligible");
        let stack = DirectStack::build(elf, group.main().bias(), None, &[b"fixture".to_vec()], &[])
            .expect("stack");
        let runner = DirectRunner::new(dispatcher, IdentityMemory::new(0, u64::MAX));
        let entry = group.main().entry();
        let sp = stack.sp();
        // SAFETY: patched image built with `island_handler`; the guest
        // leaves through the handler (exit_group in every path).
        unsafe { with_runner(&runner, &group, || group.enter_on_stack(entry, sp)) }
            .expect("with_runner")
            .0
            .expect("enter");
        runner
    }

    /// The island-boundary delivery gate: a self-directed `kill(SIGALRM)`
    /// with a registered handler must run the handler AT the kill's own
    /// syscall boundary and `rt_sigreturn` back — through carrick's
    /// trampoline (no `sa_restorer`, the aarch64 reality) — restoring the
    /// exact pre-signal state: the kill's retval in x0, a callee register
    /// the handler deliberately trashed, and a V register the handler
    /// deliberately trashed (the frame's fpsimd record, restored by the
    /// parked-entry stub's extras block).
    ///
    /// Red against the pre-delivery runner: the pending signal was silently
    /// dropped — stdout read "M" (no handler) instead of "HM".
    #[test]
    fn sigalrm_delivers_at_the_kill_boundary_and_sigreturns_exactly() {
        let mut asm = Asm::default();
        asm.sigaction_sigalrm("handler", "fail")
            // Markers the handler will trash and sigreturn must restore.
            .put(movz(21, 0x77, 0))
            .put(movz(9, 0x99, 0))
            .put(fmov_d_x(8, 9))
            // kill(getpid(), SIGALRM)
            .put(movz(8, 172, 0)) // getpid
            .put(SVC_0)
            .put(movz(1, 14, 0))
            .put(movz(8, 129, 0)) // kill
            .put(SVC_0)
            // Post-handler: the frame restored x0 = kill's retval (0).
            .cbnz(0, "fail_x0")
            .put(cmp_imm(21, 0x77))
            .b_ne("fail_x21")
            .put(fmov_x_d(9, 8))
            .put(cmp_imm(9, 0x99))
            .b_ne("fail_d8")
            .write_stdout(b'M')
            .exit_group(42)
            .label("fail")
            .exit_group(1)
            .label("fail_x0")
            .exit_group(3)
            .label("fail_x21")
            .exit_group(4)
            .label("fail_d8")
            .exit_group(5)
            .label("handler")
            .put(movz(21, 0x11, 0)) // trash x21 (frame must restore)
            .put(movz(9, 0x55, 0))
            .put(fmov_d_x(8, 9)) // trash d8 (frame must restore)
            .write_stdout(b'H')
            .put(RET_WORD); // x30 = the tier-D sigreturn trampoline
        let runner = run_signal_fixture(&asm.assemble(), SyscallDispatcher::new());
        assert_eq!(
            runner.outcome(),
            Some(DirectRunOutcome::Exited { code: 42 }),
            "handler ran and sigreturn restored the exact pre-signal state \
             (stdout: {:?})",
            String::from_utf8_lossy(&runner.dispatcher().stdout()),
        );
        assert_eq!(
            runner.dispatcher().stdout(),
            b"HM",
            "the handler wrote FIRST (delivery at the kill boundary), then \
             the interrupted flow resumed"
        );
    }

    /// The `timeout(1)` shape (the smoke's dominant tier-D failure class):
    /// park in `rt_sigsuspend`, receive the one-shot `ITIMER_REAL` SIGALRM,
    /// run the handler, and return -EINTR from sigsuspend.
    ///
    /// Red against the pre-delivery runner: `WaitOnSignals` was an
    /// unimplemented outcome — the run left named and stdout stayed empty.
    #[test]
    fn sigsuspend_wakes_for_the_itimer_sigalrm_and_eintrs() {
        let mut asm = Asm::default();
        asm.sigaction_sigalrm("handler", "fail")
            .setitimer_oneshot(50_000, "fail")
            // rt_sigsuspend(&empty_mask, 8)
            .put(sub_sp(16))
            .put(str_sp(31, 0))
            .put(mov_from_sp(0))
            .put(movz(1, 8, 0))
            .put(movz(8, 133, 0)) // rt_sigsuspend
            .put(SVC_0)
            .put(add_sp(16))
            .put(cmn_imm(0, 4)) // retval must be -EINTR
            .b_ne("fail")
            .write_stdout(b'M')
            .exit_group(42)
            .label("fail")
            .exit_group(1)
            .label("handler")
            .write_stdout(b'H')
            .put(RET_WORD);
        let runner = run_signal_fixture(&asm.assemble(), SyscallDispatcher::new());
        assert_eq!(
            runner.outcome(),
            Some(DirectRunOutcome::Exited { code: 42 }),
            "sigsuspend was interrupted by the delivered SIGALRM \
             (stdout: {:?})",
            String::from_utf8_lossy(&runner.dispatcher().stdout()),
        );
        assert_eq!(runner.dispatcher().stdout(), b"HM");
    }

    /// A blocking fd wait (`read(2)` on an empty pipe) interrupted by a
    /// delivered handler must complete with EINTR (the handler has no
    /// SA_RESTART, and read is not in the kernel's restartable set anyway).
    ///
    /// Red against the pre-delivery runner: the run left named at the wait
    /// ("deliverable pending signal during a blocking wait").
    #[test]
    fn blocked_pipe_read_eintrs_when_the_itimer_handler_fires() {
        let mut asm = Asm::default();
        asm.sigaction_sigalrm("handler", "fail")
            .setitimer_oneshot(50_000, "fail")
            // pipe2(&fds, 0), then read(fds[0], buf, 1) — blocks until the
            // SIGALRM interrupts it.
            .put(sub_sp(16))
            .put(mov_from_sp(0))
            .put(movz(1, 0, 0))
            .put(movz(8, 59, 0)) // pipe2
            .put(SVC_0)
            .cbnz(0, "fail")
            .put(ldr_w_sp(0, 0)) // read end
            .put(add_x_sp(1, 8)) // buf
            .put(movz(2, 1, 0))
            .put(movz(8, 63, 0)) // read
            .put(SVC_0)
            .put(add_sp(16))
            .put(cmn_imm(0, 4)) // retval must be -EINTR
            .b_ne("fail")
            .write_stdout(b'M')
            .exit_group(42)
            .label("fail")
            .exit_group(1)
            .label("handler")
            .write_stdout(b'H')
            .put(RET_WORD);
        let runner = run_signal_fixture(&asm.assemble(), SyscallDispatcher::new());
        assert_eq!(
            runner.outcome(),
            Some(DirectRunOutcome::Exited { code: 42 }),
            "the blocked read was interrupted with EINTR after the handler \
             (stdout: {:?})",
            String::from_utf8_lossy(&runner.dispatcher().stdout()),
        );
        assert_eq!(runner.dispatcher().stdout(), b"HM");
    }

    /// A self-directed fatal signal with NO handler takes the default
    /// action: the whole run records a signal death, and nothing after the
    /// kill executes. The shipped driver turns this into a real host signal
    /// death after all guest siblings have retired.
    ///
    /// Red against the pre-delivery runner: the signal was dropped and the
    /// poison write ran.
    #[test]
    fn unhandled_fatal_signal_ends_the_process_with_its_signal() {
        let mut asm = Asm::default();
        asm.put(movz(8, 172, 0)) // getpid
            .put(SVC_0)
            .put(movz(1, 10, 0)) // SIGUSR1, no handler
            .put(movz(8, 129, 0)) // kill
            .put(SVC_0)
            // POISON: default-terminate must end the run at the kill.
            .write_stdout(b'P')
            .exit_group(0);
        let runner = run_signal_fixture(&asm.assemble(), SyscallDispatcher::new());
        assert_eq!(
            runner.outcome(),
            Some(DirectRunOutcome::Signaled { signum: 10 }),
            "SIGUSR1's default action terminated the run (stdout: {:?})",
            String::from_utf8_lossy(&runner.dispatcher().stdout()),
        );
        assert_eq!(
            runner.dispatcher().stdout(),
            b"",
            "no poison bytes: the guest did not run past its own death"
        );
    }

    // ==== end tier-D signal gates ====
}
