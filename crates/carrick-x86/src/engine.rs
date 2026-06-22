//! `X86EngineCore<V>` — the generic x86 trap engine (design §2.2).
//!
//! Implements the five `carrick-hal` engine traits ONCE over the thin
//! [`X86Vmm`]/[`X86Vcpu`] trait pair, replacing each per-VMM copy of the trap
//! loop, the register walk, the guest-memory access, the sigframe glue, and the
//! threaded lifecycle. A backend that implements the pair gets
//! `SyscallTrap + RegAccess + GuestMemory + SegmentBaseRegs + ThreadedEngine`
//! for free.
//!
//! ## The pending-syscall state lives HERE (§2.1)
//!
//! Collapsing each backend's `PendingInout {rip, inst_length}` into the single
//! `X86Exit::Syscall { resume_pc }` moves the "which doorbell is pending"
//! bookkeeping into the engine: `next_syscall` stashes `resume_pc`,
//! `complete_syscall` writes RAX and resumes at it. The backend's `run()` is
//! stateless w.r.t. the pending syscall.

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Once, OnceLock};

use carrick_guest_mem::{GuestMemory, MemoryError};
use carrick_hal::guest_arch::GuestArch as _;
use carrick_hal::x8664_arch::{SegmentBaseRegs, SyscallNorm, X8664GuestArch, service_arch_prctl};
use carrick_hal::{
    ForkOutcome, GuestEntryRegs, OsError, RawSyscall, Reg, SysReg, SyscallTrap, ThreadedEngine,
    TrapError,
};
use carrick_mem::memory::{AddressSpace, LINUX_NULL_GUARD_END};

use crate::bringup_fns::{self, BringupLayout, X86VcpuSnapshot};
use crate::vmm::{X86Exit, X86FaultKind, X86Reg, X86Vcpu, X86Vmm};

/// fxsave-area byte offsets (Intel SDM vol. 1 §10.5.1 "FXSAVE Area"):
///   MXCSR at +24, XMM0 at +160 (16 bytes each).
const FXSAVE_MXCSR_OFF: usize = 24;
const FXSAVE_XMM0_OFF: usize = 160;
const X86_PFEC_PRESENT: u64 = 1 << 0;
const X86_TRAMPOLINE_SYSRET_OFFSET: u64 = 2;
const X86_SYSCALL_STAT_SLOTS: usize = 512;
const X86_SYSCALL_STAT_PRINT_LIMIT: usize = 32;

static X86_SYSCALL_STATS_PRINTED: AtomicBool = AtomicBool::new(false);
static X86_SYSCALL_STATS: [AtomicU64; X86_SYSCALL_STAT_SLOTS] =
    [const { AtomicU64::new(0) }; X86_SYSCALL_STAT_SLOTS];
static X86_SYSCALL_STATS_OVERFLOW: AtomicU64 = AtomicU64::new(0);

fn x86_syscall_stats_enabled() -> bool {
    static ENABLED: OnceLock<bool> = OnceLock::new();
    *ENABLED.get_or_init(|| std::env::var_os("CARRICK_X86_SYSCALL_STATS").is_some())
}

fn x86_efault_trace_enabled() -> bool {
    static ENABLED: OnceLock<bool> = OnceLock::new();
    *ENABLED.get_or_init(|| std::env::var_os("CARRICK_X86_EFAULT_TRACE").is_some())
}

fn trace_x86_efault(op: &str, address: u64, length: usize) {
    if x86_efault_trace_enabled() {
        eprintln!("[X86-EFAULT] op={op} va=0x{address:x} len=0x{length:x}");
    }
}

fn install_x86_syscall_stats_atexit() {
    static INSTALL: Once = Once::new();
    INSTALL.call_once(|| {
        // SAFETY: register a process-exit diagnostic printer. The function
        // captures no stack state and remains valid until process exit.
        unsafe {
            let _ = libc::atexit(print_x86_syscall_stats_at_exit);
        }
    });
}

extern "C" fn print_x86_syscall_stats_at_exit() {
    print_x86_syscall_stats_once("atexit");
}

#[inline]
fn record_x86_syscall_stat(number: u64) {
    if !x86_syscall_stats_enabled() {
        return;
    }
    install_x86_syscall_stats_atexit();
    match usize::try_from(number) {
        Ok(idx) if idx < X86_SYSCALL_STAT_SLOTS => {
            X86_SYSCALL_STATS[idx].fetch_add(1, Ordering::Relaxed);
        }
        _ => {
            X86_SYSCALL_STATS_OVERFLOW.fetch_add(1, Ordering::Relaxed);
        }
    }
}

fn reset_x86_syscall_stats_for_fork_child() {
    if !x86_syscall_stats_enabled() {
        return;
    }
    X86_SYSCALL_STATS_PRINTED.store(false, Ordering::Relaxed);
    X86_SYSCALL_STATS_OVERFLOW.store(0, Ordering::Relaxed);
    for counter in &X86_SYSCALL_STATS {
        counter.store(0, Ordering::Relaxed);
    }
}

fn print_x86_syscall_stats_once(reason: &str) {
    if !x86_syscall_stats_enabled() || X86_SYSCALL_STATS_PRINTED.swap(true, Ordering::Relaxed) {
        return;
    }
    let mut total = X86_SYSCALL_STATS_OVERFLOW.load(Ordering::Relaxed);
    let mut entries = Vec::new();
    for (number, counter) in X86_SYSCALL_STATS.iter().enumerate() {
        let count = counter.load(Ordering::Relaxed);
        total = total.saturating_add(count);
        if count != 0 {
            entries.push((number, count));
        }
    }
    entries.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
    eprintln!(
        "[carrick-x86-syscall-stats pid={} reason={reason}] total={} overflow={} unique={} top={}",
        std::process::id(),
        total,
        X86_SYSCALL_STATS_OVERFLOW.load(Ordering::Relaxed),
        entries.len(),
        X86_SYSCALL_STAT_PRINT_LIMIT,
    );
    for (number, count) in entries.into_iter().take(X86_SYSCALL_STAT_PRINT_LIMIT) {
        let name =
            <<X8664GuestArch as carrick_hal::GuestArch>::Table as carrick_hal::SyscallTable>::name(
                number as u64,
            )
            .unwrap_or("<unknown>");
        eprintln!(
            "[carrick-x86-syscall-stat pid={} nr={} name={} count={}]",
            std::process::id(),
            number,
            name,
            count,
        );
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct SysretResume {
    user_pc: u64,
    user_rflags: u64,
}

fn x86_fault_signal(kind: X86FaultKind, error_code: u64) -> Option<(i32, i32)> {
    const SIGSEGV: i32 = libc::SIGSEGV;
    const SIGBUS: i32 = libc::SIGBUS;
    const SIGFPE: i32 = libc::SIGFPE;
    const SIGILL: i32 = libc::SIGILL;
    const SEGV_MAPERR: i32 = 1;
    const SEGV_ACCERR: i32 = 2;
    const SI_KERNEL: i32 = 128;
    const BUS_ADRALN: i32 = 1;
    const FPE_INTDIV: i32 = 1;
    const ILL_ILLOPN: i32 = 2;
    match kind {
        X86FaultKind::PageFault => {
            let si_code = if error_code & X86_PFEC_PRESENT != 0 {
                SEGV_ACCERR
            } else {
                SEGV_MAPERR
            };
            Some((SIGSEGV, si_code))
        }
        X86FaultKind::DivideError => Some((SIGFPE, FPE_INTDIV)),
        X86FaultKind::InvalidOpcode => Some((SIGILL, ILL_ILLOPN)),
        X86FaultKind::GeneralProtection => Some((SIGSEGV, SI_KERNEL)),
        X86FaultKind::AlignmentCheck => Some((SIGBUS, BUS_ADRALN)),
        X86FaultKind::Other => None,
    }
}

/// The generic x86 trap engine. Owns the VM, the (one) vCPU, the pending-syscall
/// resume PC, and the SA_RESTART syscall-number stash. Per-backend behaviour is
/// reached only through the [`X86Vmm`]/[`X86Vcpu`] trait pair.
pub struct X86EngineCore<V: X86Vmm> {
    vm: V,
    vcpu: V::Vcpu,
    /// The kernel-window GPA layout this engine was brought up with (trampoline /
    /// GDT / PML4). Carried so fork/clone re-seed and re-apply MSRs with the same
    /// LSTAR/CR3.
    layout: BringupLayout,
    /// The RIP to resume at after the pending syscall completes (the `SYSRETQ`
    /// after the LSTAR doorbell). `Some` between `next_syscall` and
    /// `complete_syscall`.
    pending_resume_pc: Option<u64>,
    /// RAX (the syscall NUMBER) captured at the trap, before `complete_syscall`
    /// overwrites RAX with the retval. SA_RESTART restores it so a restarted
    /// syscall re-executes with its number intact.
    last_orig_rax: u64,
    /// CANONICAL syscall number of the most recent trapped `syscall`, tracked so
    /// `SyscallTrap::last_syscall_nr` can feed the run loop's SA_RESTART decision
    /// (`is_restartable_syscall` matches CANONICAL numbers like waitid=95/wait4=260,
    /// NOT the raw x86 rax — wait4=61/waitid=247). Without this override the engine
    /// inherited the `None` default and SA_RESTART was dead on the whole x86 lane.
    last_syscall_canonical: Option<u64>,
    /// User-mode state saved by SYSCALL while the live RIP is parked on the
    /// trampoline SYSRET.
    sysret_resume: Option<SysretResume>,
    /// `true` on the child side of a guest `fork(2)`.
    is_forked_child: bool,
    /// Process-wide PROT_NONE set: the SHARED host-side EFAULT gate every x86
    /// backend (KVM/bhyve/NVMM) inherits via `GuestMemory::read_bytes`/
    /// `write_bytes`. Held as `Arc` so `clone(CLONE_THREAD)` siblings share ONE
    /// set (a sibling's `mprotect` is seen by all); `fork(2)` gets an independent
    /// COW copy; `execve` starts fresh. bhyve/NVMM need zero code for this — the
    /// engine owns it.
    protections: std::sync::Arc<carrick_guest_mem::protections::MemoryProtections>,
}

impl<V: X86Vmm> X86EngineCore<V> {
    /// Build an engine around an already-constructed VM + vCPU (the backend's
    /// bring-up produces these). `layout` is the GPA layout the bring-up used.
    pub fn from_parts(vm: V, vcpu: V::Vcpu, layout: BringupLayout) -> Self {
        // A freshly brought-up (or execve'd, or fork-child) engine starts with no
        // PROT_NONE ranges. Siblings instead SHARE the spawning thread's set via
        // `from_parts_with_protections` (see `materialize_sibling`).
        Self::from_parts_with_protections(
            vm,
            vcpu,
            layout,
            std::sync::Arc::new(carrick_guest_mem::protections::MemoryProtections::default()),
        )
    }

    /// Like [`from_parts`](Self::from_parts) but adopts an existing PROT_NONE set
    /// — used to make a `clone(CLONE_THREAD)` sibling SHARE its parent's gate.
    pub fn from_parts_with_protections(
        vm: V,
        vcpu: V::Vcpu,
        layout: BringupLayout,
        protections: std::sync::Arc<carrick_guest_mem::protections::MemoryProtections>,
    ) -> Self {
        // Calibrate the x86 vDSO clock page once, here in the shared construction
        // path, so EVERY backend gets the userspace clock fast path with no
        // per-backend bring-up code. Best-effort: a no-op until the vvar page is
        // mapped (so unit-test backends and pre-memory construction are safe).
        let _ = crate::vdso::populate_vdso_vvar(&vm, &vcpu);
        Self {
            vm,
            vcpu,
            layout,
            pending_resume_pc: None,
            last_orig_rax: 0,
            last_syscall_canonical: None,
            sysret_resume: None,
            is_forked_child: false,
            protections,
        }
    }

    fn sysret_pc(&self) -> u64 {
        self.layout.trampoline_base + X86_TRAMPOLINE_SYSRET_OFFSET
    }

    fn is_syscall_trampoline_pc(&self, pc: u64) -> bool {
        pc == self.layout.trampoline_base || pc == self.sysret_pc()
    }

    fn sysret_resume_at(&self, live_rip: u64) -> Option<SysretResume> {
        self.is_syscall_trampoline_pc(live_rip)
            .then_some(self.sysret_resume)
            .flatten()
    }

    fn interrupted_rflags(&self) -> Result<u64, TrapError> {
        let live_rip = self.vcpu.get_gpr(X86Reg::Rip)?;
        if let Some(resume) = self.sysret_resume_at(live_rip) {
            return Ok(resume.user_rflags);
        }
        self.vcpu.get_gpr(X86Reg::Rflags)
    }

    /// The GPA a syscall buffer at guest VA `address` resolves to. Identity
    /// (`address`) for every ordinary pointer — NO page-table walk on the hot
    /// path. Only a `repoint_private` overlay over a shared-aperture VA
    /// ([`carrick_mem::memory::needs_stage1_translation`]) walks the live page
    /// tables to find the per-process overlay GPA whose backing the guest's OWN
    /// accesses hit (the identity GPA still resolves to the STALE shared
    /// aperture). High VAs (the alias arena) are EXCLUDED by
    /// `needs_stage1_translation`: their window is keyed at the VA, so identity
    /// is correct there. A walk miss falls back to `address` (identity),
    /// preserving prior behaviour for an unmapped VA. Mirrors the aarch64
    /// engine's `syscall_buffer_ipa`.
    fn syscall_buffer_gpa(&self, address: u64, len: usize) -> u64 {
        if !carrick_mem::memory::needs_stage1_translation(address, len as u64) {
            return address;
        }
        self.vm.translate_va(address).unwrap_or(address)
    }

    fn flush_current_tlb(&mut self) -> Result<(), MemoryError> {
        let cr3 = self
            .vcpu
            .get_gpr(X86Reg::Cr3)
            .map_err(|e| MemoryError::HostMap(format!("x86: read CR3 for TLB flush: {e}")))?;
        self.vcpu
            .set_gpr(X86Reg::Cr3, cr3)
            .map_err(|e| MemoryError::HostMap(format!("x86: reload CR3 for TLB flush: {e}")))
    }

    /// Immutable access to the underlying VM (sibling-spec construction, fork).
    pub fn vm(&self) -> &V {
        &self.vm
    }

    /// Mutable access to the underlying vCPU (rarely needed; the traits cover the
    /// hot paths).
    pub fn vcpu_mut(&mut self) -> &mut V::Vcpu {
        &mut self.vcpu
    }
}

// ─── SegmentBaseRegs (arch_prctl FS/GS base) ─────────────────────────────────

impl<V: X86Vmm> SegmentBaseRegs for X86EngineCore<V> {
    fn seg_set_fs_base(&mut self, addr: u64) -> Result<(), TrapError> {
        self.vcpu.set_fs_base(addr)
    }
    fn seg_get_fs_base(&self) -> Result<u64, TrapError> {
        self.vcpu.get_fs_base()
    }
    fn seg_set_gs_base(&mut self, addr: u64) -> Result<(), TrapError> {
        self.vcpu.set_gs_base(addr)
    }
    fn seg_get_gs_base(&self) -> Result<u64, TrapError> {
        self.vcpu.get_gs_base()
    }
}

// ─── GuestMemory ─────────────────────────────────────────────────────────────

/// Largest `n` in `1..=max` such that `[addr, addr+n)` lies within a single host
/// window (so one `host_ptr` copy is valid); `0` if even the first byte is
/// unmapped. Probes with `host_ptr` and binary-searches the run.
///
/// A syscall buffer can straddle two ADJACENT but NON-contiguous guest windows:
/// the Go amd64 runtime commits its `0xc0..` heap arena in separate `mmap`
/// pieces, each backed by an independent host alias window, so a bulk syscall
/// copy (e.g. a 40 MiB `getrandom`) crossing a window boundary cannot be served
/// by one `host_ptr`. Callers copy window-by-window using this run length.
fn host_run_len<V: X86Vmm>(vm: &V, addr: u64, max: usize) -> usize {
    if max == 0 {
        return 0;
    }
    if vm.host_ptr(addr, max).is_some() {
        return max; // fast path: whole span in one window
    }
    if vm.host_ptr(addr, 1).is_none() {
        return 0; // first byte unmapped
    }
    let (mut lo, mut hi) = (1usize, max); // lo maps, hi does not
    while hi - lo > 1 {
        let mid = lo + (hi - lo) / 2;
        if vm.host_ptr(addr, mid).is_some() {
            lo = mid;
        } else {
            hi = mid;
        }
    }
    lo
}

impl<V: X86Vmm> GuestMemory for X86EngineCore<V> {
    /// The engine-owned PROT_NONE set, shared by every x86 backend (KVM, bhyve,
    /// NVMM) — the default `read_bytes`/`write_bytes` run it before the raw copy
    /// below, so bhyve/NVMM get the EFAULT gate with zero backend code.
    fn protections(&self) -> Option<&carrick_guest_mem::protections::MemoryProtections> {
        Some(&*self.protections)
    }

    /// Record/clear a guest PROT_NONE range (guest `mprotect(PROT_NONE)`/`munmap`).
    /// Closes the x86 `set_no_access` no-op gap: without this the engine's
    /// `protections()` set stays empty and the gate never fires.
    fn set_no_access(&mut self, address: u64, len: usize, no_access: bool) {
        self.protections.set_no_access(address, len, no_access);
    }

    /// Resolve a guest futex VA to the host address of its `MAP_SHARED` backing
    /// (the boot aperture OR a runtime file-backed alias), so a cross-process
    /// futex routes through the bare-`SYS_futex` shared path instead of the
    /// per-process parking lot. Translate the VA to the GPA the guest's own
    /// access hits (identity for ordinary pointers, the stage-1 mapping for an
    /// aliased VA at/above the 40-bit IPA cap), then ask the VMM whether that GPA
    /// lies in a fork-coherent shared window. `None` (private/anon word) keeps the
    /// futex in-process. Without this override the engine inherited the default
    /// `None`, so EVERY x86 cross-process futex fell to the per-process parking
    /// lot — a forked child's `FUTEX_WAKE` never reached a parent parked in
    /// `FUTEX_WAIT` on the same `/dev/shm` page (`ltpcheckpoint` reverse direction).
    fn shared_futex_host_addr(&self, guest_addr: u64) -> Option<usize> {
        // A futex word is a 4-byte u32.
        let gpa = self.syscall_buffer_gpa(guest_addr, 4);
        self.vm.shared_futex_host_addr(gpa, 4)
    }

    /// x86-specific WRITE gate (the analog of HVF's `validate_guest_write_range`):
    /// a syscall write faults if the buffer is PROT_NONE (any access) OR read-only
    /// (`no_write`). Reads from a read-only mapping are fine (handled by the shared
    /// default `read_bytes`, which gates only PROT_NONE). Carrick-internal writes
    /// (`write_bytes_unchecked` -> `write_bytes_raw`) bypass both. `no_write` is
    /// x86-only, so this lives here, not in the shared default.
    fn write_bytes(&mut self, address: u64, bytes: &[u8]) -> Result<(), MemoryError> {
        if !bytes.is_empty() {
            if self.protections.range_no_access(address, bytes.len()) {
                trace_x86_efault("write-na", address, bytes.len());
                return Err(MemoryError::OutOfBounds {
                    address,
                    length: bytes.len(),
                });
            }
            if self.protections.range_no_write(address, bytes.len()) {
                trace_x86_efault("write-ro", address, bytes.len());
                return Err(MemoryError::OutOfBounds {
                    address,
                    length: bytes.len(),
                });
            }
        }
        self.write_bytes_raw(address, bytes)
    }

    fn read_bytes_raw(&self, address: u64, length: usize) -> Result<Vec<u8>, MemoryError> {
        // A guest pointer in the NULL guard region [0, 0x10000) is unmapped on
        // Linux; the aarch64 path faults it (safe_access_translated). The x86
        // host_ptr path has no VA guard — the low identity window backs GPA 0 —
        // so without this a syscall copy of a NULL/low pointer would silently
        // read zeros instead of EFAULT (memfdcreate/iovecedge). Zero-length is
        // exempt (read(fd, NULL, 0) == 0).
        if length > 0 && address < LINUX_NULL_GUARD_END {
            trace_x86_efault("read", address, length);
            return Err(MemoryError::OutOfBounds { address, length });
        }
        // Resolve the GPA the guest's OWN access hits: identity for ordinary
        // pointers, the per-process overlay GPA for a `repoint_private` VA over
        // the shared aperture (the identity GPA still backs the STALE shared
        // page). The overlay slot is contiguous, so translating the base and
        // adding the offset addresses the whole buffer.
        let gpa_base = self.syscall_buffer_gpa(address, length);
        let mut out = vec![0u8; length];
        let mut off = 0usize;
        while off < length {
            let addr = gpa_base + off as u64;
            let run = host_run_len(&self.vm, addr, length - off);
            if run == 0 {
                // A reserved-but-uncommitted page (a lazily-zeroed anonymous
                // mmap/brk page the guest never touched — e.g. a calloc/
                // alloc_zeroed buffer): the kernel reads it as zeros, so skip it
                // (`out` is already zero-filled) instead of faulting. Only a VA
                // that is NOT a reservation is a genuine EFAULT.
                if self.vm.is_guest_reserved(addr) {
                    let page_rem = (0x1000 - (addr as usize & 0xfff)).min(length - off);
                    off += page_rem;
                    continue;
                }
                trace_x86_efault("read", addr, length - off);
                return Err(MemoryError::OutOfBounds { address, length });
            }
            let host = self
                .vm
                .host_ptr(addr, run)
                .ok_or(MemoryError::OutOfBounds { address, length })?;
            // SAFETY: `host_run_len`/`host_ptr` proved [host, host+run) is within
            // a live window; the destination slice is disjoint.
            unsafe { std::ptr::copy_nonoverlapping(host, out.as_mut_ptr().add(off), run) };
            off += run;
        }
        Ok(out)
    }

    fn write_bytes_raw(&mut self, address: u64, bytes: &[u8]) -> Result<(), MemoryError> {
        let length = bytes.len();
        // NULL-guard, mirroring read_bytes (and the aarch64 path): a write
        // through a NULL/low guest pointer must EFAULT, not silently hit the
        // GPA-0-backed low window.
        if length > 0 && address < LINUX_NULL_GUARD_END {
            trace_x86_efault("write", address, length);
            return Err(MemoryError::OutOfBounds { address, length });
        }
        // Resolve the GPA the guest's OWN access hits (see `read_bytes_raw`): for
        // a `repoint_private` overlay VA this lands the syscall write in the
        // PRIVATE overlay backing the guest reads, not the stale shared aperture.
        let gpa_base = self.syscall_buffer_gpa(address, length);
        let mut off = 0usize;
        while off < length {
            let addr = gpa_base + off as u64;
            // Let a lazy/sparse backend materialize the range before we probe
            // run lengths: `host_run_len` uses the immutable `host_ptr`, which
            // reads 0 for a not-yet-backed reservation, so a host-side write into
            // one (file-backed mmap content, stack/auxv) would wrongly EFAULT.
            // On eager backends `host_ptr_mut` defaults to `host_ptr` → no-op.
            let _ = self.vm.host_ptr_mut(addr, length - off);
            let run = host_run_len(&self.vm, addr, length - off);
            if run == 0 {
                trace_x86_efault("write", addr, length - off);
                return Err(MemoryError::OutOfBounds { address, length });
            }
            let host = self
                .vm
                .host_ptr_mut(addr, run)
                .ok_or(MemoryError::OutOfBounds { address, length })?;
            // SAFETY: `host_run_len`/`host_ptr_mut` proved [host, host+run) is
            // within a live window; the source slice is disjoint.
            unsafe { std::ptr::copy_nonoverlapping(bytes.as_ptr().add(off), host, run) };
            off += run;
        }
        Ok(())
    }

    fn protect_range(&mut self, address: u64, len: usize, prot: u64) -> Result<(), MemoryError> {
        // A non-PROT_NONE MAP_FIXED|MAP_PRIVATE|MAP_ANON landing OUTSIDE the eager
        // mmap arena / image regions (a guest placing a mapping at a high identity
        // VA) needs a host backing slot before the guest can touch it. The aarch64
        // backend has a broad 0..1 TiB identity stage-1 + backing, so such a VA is
        // already live; the x86 PML4 only maps the arena/aperture/stack windows.
        // Back it on demand: allocate a fresh identity-GPA slot + install the leaf,
        // so the guest's own access hits real backing instead of a SIGSEGV. The
        // slot can be absent two ways, BOTH caught by `host_ptr(address,1).is_none()`:
        //   (1) no page-table leaf at all (`vm.protect_range` errors — a VA the PML4
        //       never mapped); or
        //   (2) a leaf exists but points at a GPA with no memory slot.
        // An in-arena / aperture VA always resolves (its MAP_NORESERVE slot exists
        // even before the pages are resident), so this only fires for a genuinely
        // unbacked MAP_FIXED. PROT_NONE (prot==0) needs no backing — an unmapped VA
        // must keep faulting, exactly as Linux wants.
        let protect_err = self.vm.protect_range(address, len, prot).err();
        if prot != 0 && self.vm.host_ptr(address, 1).is_none() {
            let writable = prot & carrick_abi::LINUX_PROT_WRITE != 0;
            self.vm.back_fixed_anon(address, len, writable)?;
        } else if let Some(e) = protect_err {
            return Err(e);
        }
        // Syscall-path WRITE gate: a PROT_READ (no PROT_WRITE) mapping is read-only,
        // so a kernel write into it must EFAULT (the x86 analog of HVF's
        // validate_guest_write_range; reads from it are still fine). A writable prot
        // clears it; PROT_NONE is covered by the no_access set. The dispatcher calls
        // protect_range with the prot for BOTH mmap and mprotect, so this one hook
        // covers a region read-only from creation AND a later mprotect(PROT_READ).
        let read_only = prot != 0 && prot & carrick_abi::LINUX_PROT_WRITE == 0;
        self.protections.set_no_write(address, len, read_only);
        self.flush_current_tlb()
    }

    fn repoint_private(
        &mut self,
        va: u64,
        overlay_gpa: u64,
        len: usize,
        content: &[u8],
    ) -> Result<(), MemoryError> {
        // Seed the overlay backing + repoint the leaf on the backend (it seeds
        // `host_ptr(overlay_gpa)` FIRST, while `va` still maps to the stale shared
        // aperture, then edits the live PML4 leaf), then flush the current vCPU's
        // TLB so an already-touched overlay VA picks up the new mapping. Mirrors
        // the aarch64 engine's `repoint_private` (pt edit + EL1-maintenance TLBI).
        self.vm.repoint_private(va, overlay_gpa, len, content)?;
        self.flush_current_tlb()
    }

    fn unmap_range(&mut self, address: u64, len: usize) -> Result<(), MemoryError> {
        self.vm.unmap_range(address, len)?;
        self.flush_current_tlb()
    }

    fn unmap_alias_range(&mut self, address: u64, len: usize) -> Result<(), MemoryError> {
        self.vm.unmap_alias_range(address, len)?;
        self.flush_current_tlb()
    }
}

// ─── RegAccess ───────────────────────────────────────────────────────────────
//
// The Reg→X86Reg walk + FP/SIMD access served from the backend's fxsave area
// (`get_fp`/`set_fp`). KVM/NVMM have a native getter (`get_fp() == Some`); a
// no-FP-getter backend (bhyve) drives the ring-3 stub, after which `get_fp`
// returns the captured area, so this path is uniform.

fn reg_to_x86(r: Reg) -> Option<X86Reg> {
    Some(match r {
        Reg::Rax => X86Reg::Rax,
        Reg::Rbx => X86Reg::Rbx,
        Reg::Rcx => X86Reg::Rcx,
        Reg::Rdx => X86Reg::Rdx,
        Reg::Rsi => X86Reg::Rsi,
        Reg::Rdi => X86Reg::Rdi,
        Reg::Rbp => X86Reg::Rbp,
        Reg::Rsp => X86Reg::Rsp,
        Reg::R8 => X86Reg::R8,
        Reg::R9 => X86Reg::R9,
        Reg::R10 => X86Reg::R10,
        Reg::R11 => X86Reg::R11,
        Reg::R12 => X86Reg::R12,
        Reg::R13 => X86Reg::R13,
        Reg::R14 => X86Reg::R14,
        Reg::R15 => X86Reg::R15,
        Reg::Rip => X86Reg::Rip,
        Reg::Rflags => X86Reg::Rflags,
        _ => return None,
    })
}

impl<V: X86Vmm> carrick_hal::RegAccess for X86EngineCore<V> {
    fn get_reg(&self, r: Reg) -> Result<u64, OsError> {
        let xr = reg_to_x86(r).ok_or_else(|| OsError::from_raw(libc::EINVAL))?;
        self.vcpu
            .get_gpr(xr)
            .map_err(|_| OsError::from_raw(libc::EIO))
    }

    fn set_reg(&mut self, r: Reg, v: u64) -> Result<(), OsError> {
        let xr = reg_to_x86(r).ok_or_else(|| OsError::from_raw(libc::EINVAL))?;
        self.vcpu
            .set_gpr(xr, v)
            .map_err(|_| OsError::from_raw(libc::EIO))
    }

    fn get_sys_reg(&self, r: SysReg) -> Result<u64, OsError> {
        match r {
            SysReg::FsBase => self
                .vcpu
                .get_fs_base()
                .map_err(|_| OsError::from_raw(libc::EIO)),
            SysReg::GsBase => self
                .vcpu
                .get_gs_base()
                .map_err(|_| OsError::from_raw(libc::EIO)),
            _ => Err(OsError::from_raw(libc::EINVAL)),
        }
    }

    fn set_sys_reg(&mut self, r: SysReg, v: u64) -> Result<(), OsError> {
        match r {
            SysReg::FsBase => self
                .vcpu
                .set_fs_base(v)
                .map_err(|_| OsError::from_raw(libc::EIO)),
            SysReg::GsBase => self
                .vcpu
                .set_gs_base(v)
                .map_err(|_| OsError::from_raw(libc::EIO)),
            _ => Err(OsError::from_raw(libc::EINVAL)),
        }
    }

    fn get_vreg(&self, n: u32) -> Result<u128, OsError> {
        if n >= 16 {
            return Err(OsError::from_raw(libc::EINVAL));
        }
        let fx = self
            .vcpu
            .get_fp()
            .map_err(|_| OsError::from_raw(libc::EIO))?
            .ok_or_else(|| OsError::from_raw(libc::EIO))?;
        let off = FXSAVE_XMM0_OFF + (n as usize) * 16;
        let mut b = [0u8; 16];
        b.copy_from_slice(&fx[off..off + 16]);
        Ok(u128::from_le_bytes(b))
    }

    fn set_vreg(&mut self, n: u32, v: u128) -> Result<(), OsError> {
        if n >= 16 {
            return Err(OsError::from_raw(libc::EINVAL));
        }
        let mut fx = self
            .vcpu
            .get_fp()
            .map_err(|_| OsError::from_raw(libc::EIO))?
            .ok_or_else(|| OsError::from_raw(libc::EIO))?;
        let off = FXSAVE_XMM0_OFF + (n as usize) * 16;
        fx[off..off + 16].copy_from_slice(&v.to_le_bytes());
        self.vcpu
            .set_fp(&fx)
            .map(|_| ())
            .map_err(|_| OsError::from_raw(libc::EIO))
    }

    fn get_ymm_hi(&self, n: u32) -> Result<u128, OsError> {
        if n >= 16 {
            return Err(OsError::from_raw(libc::EINVAL));
        }
        // YMM upper halves live in the XSAVE AVX component (offset 576), NOT the
        // FXSAVE area get_vreg reads. A backend whose get_xsave is the FXSAVE-pad
        // default returns 0 here (no AVX) — correct, that guest never set YMM.
        let xs = self
            .vcpu
            .get_xsave()
            .map_err(|_| OsError::from_raw(libc::EIO))?
            .ok_or_else(|| OsError::from_raw(libc::EIO))?;
        let off = crate::vmm::XSAVE_AVX_OFFSET + (n as usize) * 16;
        let mut b = [0u8; 16];
        b.copy_from_slice(&xs[off..off + 16]);
        Ok(u128::from_le_bytes(b))
    }

    fn set_ymm_hi(&mut self, n: u32, v: u128) -> Result<(), OsError> {
        if n >= 16 {
            return Err(OsError::from_raw(libc::EINVAL));
        }
        let mut xs = self
            .vcpu
            .get_xsave()
            .map_err(|_| OsError::from_raw(libc::EIO))?
            .ok_or_else(|| OsError::from_raw(libc::EIO))?;
        let off = crate::vmm::XSAVE_AVX_OFFSET + (n as usize) * 16;
        xs[off..off + 16].copy_from_slice(&v.to_le_bytes());
        // Advertise AVX in xstate_bv (bit 2) so the setter restores the YMM_Hi
        // component rather than treating it as "in init state" (zeroed).
        xs[512] |= 0x04;
        self.vcpu
            .set_xsave(&xs)
            .map(|_| ())
            .map_err(|_| OsError::from_raw(libc::EIO))
    }

    /// Batched signal-frame FP save: ONE `KVM_GET_XSAVE` yields MXCSR + XMM0–15
    /// (legacy FXSAVE region) AND the AVX `YMM_Hi` (extended region) — replacing
    /// the per-register default's ~33 ioctls per signal delivery (the
    /// `test_stress_delivery_simultaneous` throughput cliff).
    fn save_fpsimd_frame(&mut self) -> Result<(u32, [u32; 64], [u8; 256]), OsError> {
        let xs = self
            .vcpu
            .get_xsave()
            .map_err(|_| OsError::from_raw(libc::EIO))?
            .ok_or_else(|| OsError::from_raw(libc::EIO))?;
        let mxcsr = u32::from_le_bytes(
            xs[FXSAVE_MXCSR_OFF..FXSAVE_MXCSR_OFF + 4]
                .try_into()
                .unwrap_or([0u8; 4]),
        );
        let mut xmm = [0u32; 64];
        for (i, word) in xmm.iter_mut().enumerate() {
            let o = FXSAVE_XMM0_OFF + i * 4;
            *word = u32::from_le_bytes(xs[o..o + 4].try_into().unwrap_or([0u8; 4]));
        }
        let mut ymm_hi = [0u8; 256];
        let avx = crate::vmm::XSAVE_AVX_OFFSET;
        ymm_hi.copy_from_slice(&xs[avx..avx + 256]);
        Ok((mxcsr, xmm, ymm_hi))
    }

    /// Batched signal-frame FP restore: ONE `KVM_GET_XSAVE` + ONE `KVM_SET_XSAVE`
    /// for MXCSR + all 16 XMM + all 16 YMM_Hi — replacing the per-register
    /// default's ~80 ioctls per signal return.
    fn restore_fpsimd_frame(
        &mut self,
        mxcsr: u32,
        xmm: &[u32; 64],
        ymm_hi: &[u8; 256],
    ) -> Result<(), OsError> {
        let mut xs = self
            .vcpu
            .get_xsave()
            .map_err(|_| OsError::from_raw(libc::EIO))?
            .ok_or_else(|| OsError::from_raw(libc::EIO))?;
        xs[FXSAVE_MXCSR_OFF..FXSAVE_MXCSR_OFF + 4].copy_from_slice(&mxcsr.to_le_bytes());
        for (i, word) in xmm.iter().enumerate() {
            let o = FXSAVE_XMM0_OFF + i * 4;
            xs[o..o + 4].copy_from_slice(&word.to_le_bytes());
        }
        let avx = crate::vmm::XSAVE_AVX_OFFSET;
        xs[avx..avx + 256].copy_from_slice(ymm_hi);
        // Advertise SSE (bit 1, for MXCSR+XMM) and AVX (bit 2, for YMM_Hi) so the
        // setter restores those components instead of treating them as init zeros.
        xs[512] |= 0x06;
        self.vcpu
            .set_xsave(&xs)
            .map(|_| ())
            .map_err(|_| OsError::from_raw(libc::EIO))
    }

    fn get_fpcr(&self) -> Result<u64, OsError> {
        // x86 has no FPCR; MXCSR is the nearest control word.
        let fx = self
            .vcpu
            .get_fp()
            .map_err(|_| OsError::from_raw(libc::EIO))?
            .ok_or_else(|| OsError::from_raw(libc::EIO))?;
        let mut b = [0u8; 4];
        b.copy_from_slice(&fx[FXSAVE_MXCSR_OFF..FXSAVE_MXCSR_OFF + 4]);
        Ok(u64::from(u32::from_le_bytes(b)))
    }

    fn set_fpcr(&mut self, v: u64) -> Result<(), OsError> {
        let mut fx = self
            .vcpu
            .get_fp()
            .map_err(|_| OsError::from_raw(libc::EIO))?
            .ok_or_else(|| OsError::from_raw(libc::EIO))?;
        fx[FXSAVE_MXCSR_OFF..FXSAVE_MXCSR_OFF + 4].copy_from_slice(&(v as u32).to_le_bytes());
        self.vcpu
            .set_fp(&fx)
            .map(|_| ())
            .map_err(|_| OsError::from_raw(libc::EIO))
    }

    fn get_fpsr(&self) -> Result<u64, OsError> {
        // No distinct x86 status word in this model (unused on the x86 sigframe path).
        Ok(0)
    }

    fn set_fpsr(&mut self, _v: u64) -> Result<(), OsError> {
        Ok(())
    }
}

// ─── SyscallTrap ─────────────────────────────────────────────────────────────

impl<V: X86Vmm> SyscallTrap for X86EngineCore<V> {
    fn next_syscall(&mut self) -> Result<Option<RawSyscall>, TrapError> {
        loop {
            // Account the guest's CPU time (wall time inside the backend's guest
            // run) into this thread's guest_cpu slot so getrusage(RUSAGE_SELF) /
            // times / `/proc` see it — the bhyve/NVMM backends' `run()` does not
            // add to the host thread's rusage. Mirrors the KVM (KvmTrapEngine) and
            // HVF trap loops, but lives HERE so every backend on this shared engine
            // gets it for free.
            let run_result = carrick_host::guest_cpu::timed_run(|| self.vcpu.run());
            match run_result? {
                X86Exit::Syscall { frame, resume_pc } => {
                    self.sysret_resume = None;
                    record_x86_syscall_stat(frame.rax);
                    // The engine — not the backend — owns the pending state.
                    self.pending_resume_pc = Some(resume_pc);
                    self.last_orig_rax = frame.rax;

                    match X8664GuestArch::normalize_syscall(&frame) {
                        SyscallNorm::ArchPrctl { code, addr } => {
                            let ret = service_arch_prctl(self, code, addr)?;
                            self.complete_syscall(ret)?;
                            continue;
                        }
                        SyscallNorm::Plain(raw) => {
                            // Track the CANONICAL number for SA_RESTART (see
                            // `last_syscall_canonical` / `last_syscall_nr`).
                            self.last_syscall_canonical = Some(raw.number);
                            return Ok(Some(raw));
                        }
                    }
                }
                X86Exit::Halt => {
                    self.sysret_resume = None;
                    return Ok(None);
                }
                // A cross-thread kick forced the vCPU out of the guest with no
                // syscall pending. Return `Ok(None)` so the run loop's kick path
                // delivers any pending async signal at the interrupted PC, then
                // re-enters (vcpu_loop.rs `Ok(None)` arm). Returning here (rather
                // than `continue`) is REQUIRED for async host→guest signal
                // delivery to a vCPU spinning in a syscall-free loop — a spurious
                // (un-requested) kick is harmless: the loop finds no pending
                // signal and resumes. (The backend already distinguishes a
                // requested kick from a spurious VT-x re-entry before surfacing
                // `Kicked`.)
                X86Exit::Kicked => return Ok(None),
                X86Exit::FpDoorbell => {
                    self.sysret_resume = None;
                    // The FP doorbell is only meaningful while `run_fp_stub` is
                    // driving the stub (it consumes the exit itself); reaching it
                    // here is a spurious re-entry — re-run the guest.
                    continue;
                }
                X86Exit::Memory { gpa } => {
                    self.sysret_resume = None;
                    if self.vm.handle_memory_exit(gpa)? {
                        continue;
                    }
                    return Err(TrapError::Hypervisor(format!(
                        "x86 backend did not handle memory exit for gpa=0x{gpa:x}"
                    )));
                }
                X86Exit::Fault {
                    kind,
                    fault_addr,
                    error_code,
                } => {
                    self.sysret_resume = None;
                    // Demand-paging: a NOT-PRESENT (#PF MAPERR) fault at a VA the
                    // backend lazily reserved (e.g. Go's PROT_NONE page-summary
                    // arena, which bhyve does not back eagerly) is committed on
                    // first touch — the backend allocates a page + maps the leaf,
                    // we flush the TLB, and `continue` re-runs the faulting
                    // instruction (the #PF did NOT advance RIP). Eager backends
                    // (KVM/NVMM/HVF) keep the `Ok(false)` default → genuine fault.
                    if kind == X86FaultKind::PageFault
                        && error_code & X86_PFEC_PRESENT == 0
                        && self
                            .vm
                            .demand_commit(fault_addr)
                            .map_err(|e| TrapError::Hypervisor(format!("demand_commit: {e:?}")))?
                    {
                        self.flush_current_tlb().map_err(|e| {
                            TrapError::Hypervisor(format!("demand-page TLB flush: {e:?}"))
                        })?;
                        continue;
                    }
                    // Deliver as an ISA-neutral guest fault. For #PF, PFEC.P
                    // selects MAPERR vs ACCERR exactly like Linux; other x86
                    // vectors use the backend-resolved Linux si_addr.
                    let (signum, si_code) =
                        x86_fault_signal(kind, error_code).ok_or_else(|| {
                            TrapError::Hypervisor(format!("unsupported x86 fault kind {kind:?}"))
                        })?;
                    return Err(TrapError::GuestFault {
                        signum,
                        si_code,
                        fault_addr,
                    });
                }
            }
        }
    }

    fn current_pc(&self) -> Result<u64, TrapError> {
        let live_rip = self.vcpu.get_gpr(X86Reg::Rip)?;
        Ok(self
            .sysret_resume_at(live_rip)
            .map_or(live_rip, |resume| resume.user_pc))
    }

    /// The CANONICAL number of the most recent trapped syscall, tracked in
    /// `next_syscall`. Without this override X86EngineCore inherited the `None`
    /// default, so the run loop's `last_syscall_nr().is_some_and(is_restartable…)`
    /// gate was always false and SA_RESTART never fired on the x86 lane.
    fn last_syscall_nr(&self) -> Option<u64> {
        self.last_syscall_canonical
    }

    fn process_exit_cleanup(&mut self) {
        // Delegate to the backend (§2.5c): a HOOK, not Drop — the forked child
        // `_exit`s skipping Drops. Default is a no-op (KVM/NVMM RAM is released by
        // the OS on `_exit`); bhyve overrides it to tear down its `/dev/vmm` node
        // (and skip a vfork-shared/borrowed VM).
        print_x86_syscall_stats_once("process-exit");
        self.vm.process_exit_cleanup();
    }

    fn complete_syscall(&mut self, return_value: i64) -> Result<(), TrapError> {
        // Write RAX = return value and resume inside the stashed syscall
        // trampoline. KVM reports the native current RIP (observed as the OUT
        // address); bhyve reports `rip + inst_length` (the SYSRETQ). Either way
        // the engine owns the user PC/RFLAGS to expose if a kick lands before
        // SYSRET gets back to ring 3.
        self.sysret_resume = None;
        if let Some(pc) = self.pending_resume_pc.take() {
            if self.is_syscall_trampoline_pc(pc) {
                let (user_pc, user_rflags) =
                    self.vcpu.complete_sysret(self.layout, return_value, pc)?;
                self.sysret_resume = Some(SysretResume {
                    user_pc,
                    user_rflags,
                });
            } else {
                self.vcpu.set_gpr(X86Reg::Rax, return_value as u64)?;
                self.vcpu.set_gpr(X86Reg::Rip, pc)?;
            }
        } else {
            self.vcpu.set_gpr(X86Reg::Rax, return_value as u64)?;
        }
        Ok(())
    }

    fn is_forked_child(&self) -> bool {
        self.is_forked_child
    }

    fn fork(&mut self) -> Result<ForkOutcome, TrapError> {
        crate::engine::fork_x86(self)
    }

    fn execve_into(&mut self, new_image: &AddressSpace) -> Result<(), TrapError> {
        // Delegate the image replacement to the backend (it rebuilds a fresh VM
        // from `new_image` and re-points the live vCPU). The default
        // `X86Vmm::execve_rebuild` is NYI (KVM/NVMM Phase-2 hello do not execve);
        // bhyve overrides it. Clear the pending-syscall state — the fresh image
        // resumes at its own entry, not the old doorbell resume.
        self.vm.execve_rebuild(&mut self.vcpu, new_image)?;
        // The fresh image has its own RAM; re-calibrate the vDSO clock page
        // (shared, so no backend re-implements it).
        let _ = crate::vdso::populate_vdso_vvar(&self.vm, &self.vcpu);
        self.pending_resume_pc = None;
        self.last_syscall_canonical = None;
        self.sysret_resume = None;
        // execve replaces the whole address space — the old image's PROT_NONE
        // ranges are gone, so the gate must start fresh (else a new mapping at an
        // old PROT_NONE VA would wrongly EFAULT).
        self.protections =
            std::sync::Arc::new(carrick_guest_mem::protections::MemoryProtections::default());
        Ok(())
    }

    fn map_host_alias(
        &mut self,
        va: u64,
        ipa: u64,
        len: u64,
        payload: &[u8],
        file: Option<(libc::c_int, libc::off_t, libc::c_int)>,
    ) -> Result<(), TrapError> {
        // The third element of `file` is the HOST libc::PROT_* mask the dispatcher
        // computed for this file-backed alias. A PROT_READ-only alias is backed by
        // a host mmap WITHOUT PROT_WRITE, so a syscall-path write into it would take
        // a fatal host SIGBUS (the guest-reachable crash the `rosharedbus` probe
        // catches). Register the range in the syscall WRITE gate so such a write
        // surfaces as a clean EFAULT instead — mirroring HVF's
        // validate_guest_write_range. Reads stay allowed; a writable alias clears it.
        let read_only = file.is_some_and(|(_, _, prot)| prot & libc::PROT_WRITE == 0);
        self.vm.map_host_alias(va, ipa, len, payload, file)?;
        if let Ok(len_usize) = usize::try_from(len) {
            self.protections.set_no_write(va, len_usize, read_only);
        }
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
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
        // The interrupted RFLAGS, saved into the frame's eflags and restored
        // verbatim by rt_sigreturn (x86 has no privilege-latched SPSR analogue).
        let pstate_source = self
            .interrupted_rflags()
            .map_err(|e| TrapError::Hypervisor(e.to_string()))?;
        let params = carrick_hal::sigframe::InjectParams {
            signum,
            handler,
            sa_restorer,
            pending_syscall_retval,
            interrupted_pc,
            altstack,
            saved_sigmask,
            fault_siginfo,
            queued_siginfo,
            restart_syscall,
            pstate_source,
            // x86 reinterpretation: `orig_x0` carries the original RAX (the
            // syscall NUMBER) so SA_RESTART can restore it.
            orig_x0: self.last_orig_rax,
            // x86 has no ESR; the faulting address rides in sigcontext.cr2/si_addr.
            fault_esr: 0,
            fpsimd_enabled: true,
            // x86-64 MANDATES sa_restorer (no kernel vDSO sigreturn trampoline).
            sigreturn_trampoline_base: 0,
        };
        <Self as ThreadedEngine>::Arch::build_sigframe(self, params)?;
        self.sysret_resume = None;
        bringup_fns::program_user_segments(&mut self.vcpu)?;
        Ok(())
    }

    fn restore_from_sigframe(&mut self) -> Result<u64, TrapError> {
        let restored = <Self as ThreadedEngine>::Arch::restore_sigframe(self, true)?;
        self.sysret_resume = None;
        bringup_fns::program_user_segments(&mut self.vcpu)?;
        Ok(restored.sigmask)
    }
}

/// Shared `fork(2)` sequencing (design §2.5b). Snapshots the parent vCPU, does the
/// host `libc::fork`, and on the child side rebuilds the guest per
/// `fork_ram_strategy`:
///   - `Cow` (KVM/NVMM): the child inherits RAM via COW; the backend's
///     `rebuild_child_after_fork` may still replace VMM objects whose fds are not
///     valid in the fork child (KVM), then the generic engine re-seeds the vCPU.
///   - `EagerCopy` (bhyve): freeze the segment, rebuild a fresh named child VM
///     from it (`freeze_ram` / `rebuild_child_vm`), then re-seed.
fn fork_x86<V: X86Vmm>(engine: &mut X86EngineCore<V>) -> Result<ForkOutcome, TrapError> {
    use crate::vmm::ForkRamStrategy;

    // Snapshot the parent vCPU BEFORE forking (suspended at the trap — atomic).
    let snap = bringup_fns::snapshot(&engine.vcpu)?;
    let strategy = engine.vm.fork_ram_strategy();

    // For EagerCopy backends, freeze the whole segment pre-fork (the parent does
    // this so the child can rebuild from a coherent image).
    let frozen = match strategy {
        ForkRamStrategy::EagerCopy => engine.vm.freeze_ram()?,
        ForkRamStrategy::Cow => Vec::new(),
    };

    // Real host fork. The run loop quiesces other threads around a guest fork;
    // the calling thread is the only active one here.
    let pid = unsafe { libc::fork() };
    if pid < 0 {
        return Err(TrapError::ForkFailed(
            std::io::Error::last_os_error().to_string(),
        ));
    }
    if pid > 0 {
        return Ok(ForkOutcome::Parent { child_pid: pid });
    }

    // CHILD.
    reset_x86_syscall_stats_for_fork_child();
    // `engine.protections` needs NO re-snapshot: `libc::fork()` already COW-copied
    // the Arc's `Vec` into the child's address space, so the child's PROT_NONE set
    // is an independent copy of the parent's at fork time (the shared-Arc contract
    // only matters for CLONE_THREAD siblings inside ONE process). Do NOT "fix" this
    // by re-snapshotting — that would double-copy.
    engine
        .vm
        .rebuild_child_after_fork(&mut engine.vcpu, &frozen)?;
    let layout = engine.layout;
    let child_snap = bringup_fns::seed_entry(&snap, GuestEntryRegs::default());
    engine
        .vm
        .restore_vcpu(&mut engine.vcpu, layout, &child_snap)?;
    // The child's RAM diverged from the parent (COW / eager copy), so the
    // inherited vvar realtime_off no longer matches this process — re-calibrate
    // the vDSO clock page (shared, no per-backend code).
    let _ = crate::vdso::populate_vdso_vvar(&engine.vm, &engine.vcpu);
    // Runtime still completes the clone syscall once this returns. The child has
    // already been restored at the syscall-return point, so completion must only
    // write RAX=0 and must not reuse the parent's pending resume PC.
    engine.pending_resume_pc = None;
    engine.last_syscall_canonical = None;
    engine.sysret_resume = None;
    engine.is_forked_child = true;
    Ok(ForkOutcome::Child)
}

// ─── ThreadedEngine ──────────────────────────────────────────────────────────

/// The `Send` payload `build_sibling_spec` hands to a freshly spawned host thread,
/// which `materialize_sibling` turns into a sibling engine. Backend-parameterized:
/// the backend supplies how to build a sibling VM/vCPU from this.
pub struct X86SiblingSpec<V: X86Vmm> {
    pub builder: V::SiblingBuilder,
    pub snapshot: X86VcpuSnapshot,
    pub layout: BringupLayout,
    /// The spawning thread's PROT_NONE set — the sibling SHARES it (same VM /
    /// address space), so an `mprotect` by any thread is seen by all.
    pub protections: std::sync::Arc<carrick_guest_mem::protections::MemoryProtections>,
}

// SAFETY: the snapshot is POD and the layout is `Copy`; the builder is the
// backend's own `Send` payload (bounded `Send` on the trait); the protections
// `Arc<MemoryProtections>` is `Send + Sync`.
unsafe impl<V: X86Vmm> Send for X86SiblingSpec<V> where V::SiblingBuilder: Send {}

impl<V: X86Vmm> ThreadedEngine for X86EngineCore<V> {
    type Arch = X8664GuestArch;
    type KickHandle = V::KickHandle;
    type SiblingSpec = X86SiblingSpec<V>;

    fn kick_handle(&self) -> Self::KickHandle {
        self.vm.kick_handle()
    }

    fn wait_for_vcpu_slot() {
        V::wait_for_vcpu_slot();
    }

    fn vcpu_budget() -> usize {
        V::vcpu_budget()
    }

    fn reclaims(&self) -> bool {
        self.vm.reclaims()
    }

    fn save_guest_state(&mut self) -> Vec<u8> {
        self.vm.save_guest_state()
    }

    fn rebind_to_slot(&mut self, slot: carrick_hal::SlotId, state: &[u8]) -> Result<(), TrapError> {
        self.vm.rebind_to_slot(slot, state)
    }

    fn fork_vfork(&mut self) -> Result<ForkOutcome, TrapError> {
        crate::engine::fork_x86(self)
    }

    fn build_sibling_spec(&self, entry: GuestEntryRegs) -> Result<Self::SiblingSpec, TrapError> {
        let parent = bringup_fns::snapshot(&self.vcpu)?;
        let snapshot = bringup_fns::seed_entry(&parent, entry);
        let builder = self.vm.build_sibling_builder()?;
        Ok(X86SiblingSpec {
            builder,
            snapshot,
            layout: self.layout,
            protections: std::sync::Arc::clone(&self.protections),
        })
    }

    fn materialize_sibling(spec: Self::SiblingSpec) -> Result<Self, TrapError> {
        let (vm, mut vcpu) = V::materialize_sibling(spec.builder)?;
        vm.restore_vcpu(&mut vcpu, spec.layout, &spec.snapshot)?;
        // SHARE the spawning thread's PROT_NONE set (same address space).
        Ok(Self::from_parts_with_protections(
            vm,
            vcpu,
            spec.layout,
            spec.protections,
        ))
    }

    fn program_counter(&self) -> Result<u64, TrapError> {
        self.current_pc()
    }

    fn set_guest_sp_el0(&self, sp: u64) -> Result<(), TrapError> {
        self.vm.set_guest_sp(&self.vcpu, sp)
    }

    fn set_guest_thread_id(&self, _tid: u64) -> Result<(), TrapError> {
        // No in-guest gettid fast path on the x86 backends (no syscall shim);
        // the dispatcher services gettid. Mirrors the aarch64 no-shim path.
        Ok(())
    }

    fn fresh_fork_kicker(&self) -> std::sync::Arc<dyn carrick_hal::VcpuRegistry> {
        self.vm.fresh_fork_kicker()
    }
}

/// `X86EngineCore` is `Send` when the backend pair is: the VM/vCPU hold the host
/// VMM fds (Send) and raw window pointers valid in every thread.
//
// SAFETY: `V`/`V::Vcpu` carry only host VMM fds + raw window pointers that are
// valid in every thread of the process (threads share the address space). The
// engine is moved to its owning sibling/vCPU thread before use.
unsafe impl<V: X86Vmm> Send for X86EngineCore<V> {}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    use carrick_hal::threaded::{GenericVcpuRegistry, VcpuKick, VcpuRegistry};

    use crate::vmm::{ForkRamStrategy, MsrInstall, WindowPlan, X86Seg};

    #[derive(Clone)]
    struct TestKick;

    impl VcpuKick for TestKick {
        fn kick(&self) {}
    }

    #[derive(Default)]
    struct TestVmm;

    #[derive(Default)]
    struct TestVcpu {
        rcx: u64,
        r11: u64,
        rip: u64,
        rflags: u64,
        prepared_sysret: bool,
        get_gprs_calls: std::cell::Cell<u32>,
        set_gprs_calls: u32,
    }

    impl X86Vmm for TestVmm {
        type KickHandle = TestKick;
        type SiblingBuilder = ();
        type Vcpu = TestVcpu;

        fn setup_memory(&mut self, _plan: &WindowPlan) -> Result<(), TrapError> {
            Ok(())
        }

        fn write_gpa(&self, _gpa: u64, _bytes: &[u8]) -> Result<(), TrapError> {
            Ok(())
        }

        fn host_ptr(&self, _gpa: u64, _len: usize) -> Option<*mut u8> {
            None
        }

        fn add_vcpu(&mut self) -> Result<Self::Vcpu, TrapError> {
            Ok(TestVcpu::default())
        }

        fn fork_ram_strategy(&self) -> ForkRamStrategy {
            ForkRamStrategy::Cow
        }

        fn kick_handle(&self) -> Self::KickHandle {
            TestKick
        }

        fn build_sibling_builder(&self) -> Result<Self::SiblingBuilder, TrapError> {
            Ok(())
        }

        fn materialize_sibling(
            _builder: Self::SiblingBuilder,
        ) -> Result<(Self, Self::Vcpu), TrapError> {
            Ok((Self, TestVcpu::default()))
        }

        fn set_guest_sp(&self, _vcpu: &Self::Vcpu, _sp: u64) -> Result<(), TrapError> {
            Ok(())
        }

        fn fresh_fork_kicker(&self) -> Arc<dyn VcpuRegistry> {
            Arc::new(GenericVcpuRegistry::default())
        }
    }

    impl X86Vcpu for TestVcpu {
        fn get_gpr(&self, reg: X86Reg) -> Result<u64, TrapError> {
            Ok(match reg {
                X86Reg::Rcx => self.rcx,
                X86Reg::R11 => self.r11,
                X86Reg::Rip => self.rip,
                X86Reg::Rflags => self.rflags,
                _ => 0,
            })
        }

        fn set_gpr(&mut self, reg: X86Reg, v: u64) -> Result<(), TrapError> {
            match reg {
                X86Reg::Rcx => self.rcx = v,
                X86Reg::R11 => self.r11 = v,
                X86Reg::Rip => self.rip = v,
                X86Reg::Rflags => self.rflags = v,
                _ => {}
            }
            Ok(())
        }

        fn get_gprs(&self, regs: &[X86Reg], out: &mut [u64]) -> Result<(), TrapError> {
            self.get_gprs_calls.set(self.get_gprs_calls.get() + 1);
            for (slot, reg) in out.iter_mut().zip(regs) {
                *slot = self.get_gpr(*reg)?;
            }
            Ok(())
        }

        fn set_gprs(&mut self, writes: &[(X86Reg, u64)]) -> Result<(), TrapError> {
            self.set_gprs_calls += 1;
            for (reg, v) in writes {
                self.set_gpr(*reg, *v)?;
            }
            Ok(())
        }

        fn prepare_sysret_resume(&mut self, _layout: BringupLayout) -> Result<(), TrapError> {
            self.prepared_sysret = true;
            Ok(())
        }

        fn set_segment(
            &mut self,
            _seg: X86Seg,
            _base: u64,
            _limit: u32,
            _ar: u32,
        ) -> Result<(), TrapError> {
            Ok(())
        }

        fn get_fs_base(&self) -> Result<u64, TrapError> {
            Ok(0)
        }

        fn set_fs_base(&mut self, _v: u64) -> Result<(), TrapError> {
            Ok(())
        }

        fn get_gs_base(&self) -> Result<u64, TrapError> {
            Ok(0)
        }

        fn set_gs_base(&mut self, _v: u64) -> Result<(), TrapError> {
            Ok(())
        }

        fn set_syscall_msrs(
            &mut self,
            _lstar: u64,
            _star: u64,
            _sfmask: u64,
        ) -> Result<MsrInstall, TrapError> {
            Ok(MsrInstall::Direct)
        }

        fn get_fp(&self) -> Result<Option<[u8; 512]>, TrapError> {
            Ok(Some([0; 512]))
        }

        fn set_fp(&mut self, _fx: &[u8; 512]) -> Result<bool, TrapError> {
            Ok(true)
        }

        fn run(&mut self) -> Result<X86Exit, TrapError> {
            Ok(X86Exit::Halt)
        }

        fn enable_halt_exit(&mut self) -> Result<(), TrapError> {
            Ok(())
        }
    }

    fn test_layout() -> BringupLayout {
        BringupLayout {
            trampoline_base: 0x1000_0000,
            gdt_base: 0x1000_1000,
            pml4_base: 0x1000_2000,
        }
    }

    #[test]
    fn x86_page_fault_present_bit_selects_accerr() {
        assert_eq!(
            x86_fault_signal(X86FaultKind::PageFault, 0),
            Some((libc::SIGSEGV, 1)),
            "non-present #PF is SEGV_MAPERR"
        );
        assert_eq!(
            x86_fault_signal(X86FaultKind::PageFault, X86_PFEC_PRESENT),
            Some((libc::SIGSEGV, 2)),
            "present-page protection #PF is SEGV_ACCERR"
        );
    }

    #[test]
    fn x86_non_page_fault_vectors_match_linux_oracle() {
        assert_eq!(
            x86_fault_signal(X86FaultKind::InvalidOpcode, 0),
            Some((libc::SIGILL, 2)),
            "UD2 is SIGILL/ILL_ILLOPN on Docker linux/amd64"
        );
        assert_eq!(
            x86_fault_signal(X86FaultKind::DivideError, 0),
            Some((libc::SIGFPE, 1)),
            "integer divide error is SIGFPE/FPE_INTDIV on Docker linux/amd64"
        );
        assert_eq!(
            x86_fault_signal(X86FaultKind::GeneralProtection, 0),
            Some((libc::SIGSEGV, 128)),
            "user CLI #GP is SIGSEGV/SI_KERNEL on Docker linux/amd64"
        );
    }

    #[test]
    fn current_pc_reports_user_rcx_while_parked_at_sysret() {
        let layout = test_layout();
        let vcpu = TestVcpu {
            rcx: 0x0040_1234,
            r11: 0x246,
            rip: layout.trampoline_base + 2,
            rflags: 0x2,
            ..Default::default()
        };
        let mut engine = X86EngineCore::from_parts(TestVmm, vcpu, layout);
        engine.pending_resume_pc = Some(layout.trampoline_base + 2);

        engine.complete_syscall(0).expect("complete syscall");

        assert_eq!(engine.current_pc().expect("current pc"), 0x0040_1234);
        assert!(
            engine.vcpu.prepared_sysret,
            "backend must prepare hidden segment state for SYSRET"
        );
    }

    #[test]
    fn x86_set_no_access_records_and_default_gate_efaults() {
        // Regression for the x86 PROT_NONE gap (Review-P1): the engine OWNS the
        // PROT_NONE set, `set_no_access` records into it (closing the old no-op),
        // and the shared default `read_bytes`/`write_bytes` EFAULT a buffer in a
        // protected range BEFORE touching backing — so KVM/bhyve/NVMM inherit the
        // gate with no backend code. The end-to-end proof is the `protnonesyscall`
        // reducer (OK on KVM+bhyve, was READ-NOT-GATED).
        let layout = test_layout();
        let mut engine = X86EngineCore::from_parts(TestVmm, TestVcpu::default(), layout);
        let addr = 0x4000_0000u64;

        // mprotect(PROT_NONE) -> set_no_access records the range.
        engine.set_no_access(addr, 0x1000, true);
        let prot = engine
            .protections()
            .expect("x86 engine surfaces its PROT_NONE set");
        assert!(prot.range_no_access(addr, 0x10), "the range is recorded");
        assert!(
            !prot.range_no_access(addr + 0x2000, 0x10),
            "outside the range stays clear"
        );

        // The default gate faults syscall buffers in the range (TestVmm's None
        // host_ptr is never reached — the gate returns first).
        assert!(matches!(
            engine.read_bytes(addr, 8),
            Err(MemoryError::OutOfBounds { .. })
        ));
        assert!(matches!(
            engine.write_bytes(addr, &[0u8; 8]),
            Err(MemoryError::OutOfBounds { .. })
        ));

        // Clearing (mprotect back to accessible) removes the gate.
        engine.set_no_access(addr, 0x1000, false);
        assert!(
            !engine.protections().unwrap().range_no_access(addr, 0x10),
            "set_no_access(false) clears the range"
        );
    }

    #[test]
    fn current_pc_reports_user_rcx_after_kvm_trampoline_base_resume() {
        let layout = test_layout();
        let vcpu = TestVcpu {
            rcx: 0x0040_5678,
            r11: 0x246,
            rip: layout.trampoline_base,
            rflags: 0x2,
            ..Default::default()
        };
        let mut engine = X86EngineCore::from_parts(TestVmm, vcpu, layout);
        engine.pending_resume_pc = Some(layout.trampoline_base);

        engine.complete_syscall(0).expect("complete syscall");
        engine.vcpu.rip = layout.trampoline_base + 2;

        assert_eq!(engine.current_pc().expect("current pc"), 0x0040_5678);
    }

    #[test]
    fn current_pc_does_not_rewrite_plain_user_rip_at_trampoline_address() {
        let layout = test_layout();
        let vcpu = TestVcpu {
            rcx: 0x0040_1234,
            r11: 0x246,
            rip: layout.trampoline_base + 2,
            rflags: 0x2,
            ..Default::default()
        };
        let engine = X86EngineCore::from_parts(TestVmm, vcpu, layout);

        assert_eq!(
            engine.current_pc().expect("current pc"),
            layout.trampoline_base + 2
        );
    }

    #[test]
    fn complete_sysret_batches_rcx_r11_into_one_get_gprs() {
        let layout = test_layout();
        let vcpu = TestVcpu {
            rcx: 0x0040_1234,
            r11: 0x246,
            rip: layout.trampoline_base + 2,
            rflags: 0x2,
            ..Default::default()
        };
        let mut engine = X86EngineCore::from_parts(TestVmm, vcpu, layout);
        engine.pending_resume_pc = Some(layout.trampoline_base + 2);

        engine.complete_syscall(0).expect("complete syscall");

        // The user RCX/R11 must be fetched via a SINGLE batched get_gprs so a
        // whole-register-file backend issues one ioctl, not two.
        assert_eq!(
            engine.vcpu.get_gprs_calls.get(),
            1,
            "complete_sysret must batch the RCX/R11 read into one get_gprs"
        );
        // Behavior preserved: parked user PC = RCX, user RFLAGS = R11 | 0x2.
        assert_eq!(engine.current_pc().expect("pc"), 0x0040_1234);
        assert_eq!(engine.interrupted_rflags().expect("rflags"), 0x246);
    }

    #[test]
    fn complete_sysret_batches_rax_rip_into_one_set_gprs() {
        let layout = test_layout();
        let vcpu = TestVcpu {
            rcx: 0x0040_1234,
            r11: 0x246,
            rip: layout.trampoline_base + 2,
            rflags: 0x2,
            ..Default::default()
        };
        let mut engine = X86EngineCore::from_parts(TestVmm, vcpu, layout);
        engine.pending_resume_pc = Some(layout.trampoline_base + 2);

        engine.complete_syscall(0).expect("complete syscall");

        // RAX (return value) and RIP (resume) must be written via a SINGLE
        // batched set_gprs so a whole-register-file backend issues one ioctl.
        assert_eq!(
            engine.vcpu.set_gprs_calls, 1,
            "complete_sysret must batch the RAX+RIP write into one set_gprs"
        );
        // Behavior preserved.
        assert_eq!(engine.current_pc().expect("pc"), 0x0040_1234);
        assert_eq!(engine.interrupted_rflags().expect("rflags"), 0x246);
    }

    #[test]
    fn interrupted_rflags_reports_user_r11_while_parked_at_sysret() {
        let layout = test_layout();
        let vcpu = TestVcpu {
            rcx: 0x0040_1234,
            r11: 0x646,
            rip: layout.trampoline_base + 2,
            rflags: 0x2,
            ..Default::default()
        };
        let mut engine = X86EngineCore::from_parts(TestVmm, vcpu, layout);
        engine.pending_resume_pc = Some(layout.trampoline_base + 2);

        engine.complete_syscall(0).expect("complete syscall");

        assert_eq!(engine.interrupted_rflags().expect("rflags"), 0x646);
    }
}
