//! KvmVm / KvmVcpu: the `carrick-hal` raw-hypervisor layer (HvVm/HvVcpu) on
//! Linux/KVM, aarch64. /dev/kvm -> KVM_CREATE_VM -> KVM_CREATE_VCPU ->
//! KVM_ARM_PREFERRED_TARGET + KVM_ARM_VCPU_INIT; guest RAM via
//! KVM_SET_USER_MEMORY_REGION over a host mmap; registers via
//! KVM_GET/SET_ONE_REG; run via KVM_RUN. kick() is a signal-based vCPU exit.
use std::sync::{Arc, Mutex};
use std::sync::atomic::{AtomicI64, AtomicU32, AtomicU64, Ordering};

use carrick_hal::{HvVcpu, HvVm, MemPerms, OsError, Reg, SysReg, VcpuExit};
use carrick_mem::memory::AddressSpace;
use kvm_bindings::{KVM_ARM_VCPU_PSCI_0_2, KVM_MEM_LOG_DIRTY_PAGES, kvm_userspace_memory_region};
use kvm_ioctls::{Kvm, VcpuExit as KvmExit, VcpuFd, VmFd};
use libc;

use crate::fork::VcpuSnapshot;

fn os_err(context: &str, e: impl std::fmt::Display) -> OsError {
    OsError::new(format!("kvm: {context}: {e}"))
}

/// Process-global count of live KVM vCPUs (created-or-in-flight minus
/// dropped) — the Linux implementation of the `crate::trap::VCPU_LIVE` drain
/// contract the shared threaded run loop relies on (carrick-runtime
/// re-exports this under `platform-linux`; HVF has its own identical counter
/// in carrick-hvf's trap module). LOAD-BEARING, not a diagnostic:
/// `terminate_siblings_for_exec` spin-waits for this to reach 1 after kicking
/// sibling vCPU threads, so the execing thread cannot delete the VM's
/// memslots / munmap the old `GuestRam` while a just-kicked sibling is still
/// mid-dispatch holding raw pointers into those mmaps (host use-after-free)
/// or mid-`map_host_alias` (`next_slot` racing `reset_slot_counter`).
/// Measured without the drain: 60/60 multithreaded-execv iterations spewed
/// sibling `KVM_RUN: Bad address` after the slot teardown.
///
/// Incremented at OWNED vcpu construction (`add_vcpu`: boot + the fork-child
/// rebuild) or at sibling-spec creation ([`VcpuLiveTicket`] — see its doc for
/// the in-flight window), decremented in [`KvmVcpu::drop`] — which runs at
/// the end of a sibling's `run_vcpu_until_exit`, AFTER its last guest-RAM
/// access. A fork CHILD inherits the parent's value (plain static, copied by
/// `libc::fork`) but owns exactly one vCPU; the fork child path re-stores 1.
pub static VCPU_LIVE: AtomicI64 = AtomicI64::new(0);

/// A reserved slot in [`VCPU_LIVE`] for a sibling that is IN FLIGHT — its
/// guest `clone()` has returned but its host thread has not yet constructed
/// its vCPU. Without this, the execve drain has a blind window: the parent's
/// `build_sibling_spec` runs synchronously with the trapped clone, the guest
/// proceeds to execve, `terminate_siblings_for_exec` reads `VCPU_LIVE <= 1`
/// (the sibling's vCPU doesn't exist yet) and tears the address space down —
/// then the sibling materializes onto deleted memslots (measured: 9/60
/// multithreaded-execv iterations still EFAULT'd with construction-time
/// counting alone).
///
/// Ownership of the +1: acquired at `build_sibling_spec`, TRANSFERRED to the
/// sibling's `KvmVcpu` at construction (`consume` — the vcpu's `Drop` then
/// owns the decrement), or released by this ticket's own `Drop` if the
/// sibling never materializes (host spawn failure, spec dropped).
pub(crate) struct VcpuLiveTicket(());

impl VcpuLiveTicket {
    pub(crate) fn acquire() -> Self {
        VCPU_LIVE.fetch_add(1, Ordering::SeqCst);
        Self(())
    }

    /// Transfer the +1 to a just-constructed sibling `KvmVcpu` (whose creation
    /// path deliberately does NOT increment — see `add_sibling_vcpu`).
    pub(crate) fn consume(self) {
        std::mem::forget(self);
    }
}

impl Drop for VcpuLiveTicket {
    fn drop(&mut self) {
        VCPU_LIVE.fetch_sub(1, Ordering::SeqCst);
    }
}

/// Host `CLOCK_MONOTONIC_RAW` "now", expressed in generic-timer TICKS — the
/// epoch+unit the guest counter must match so the shared dispatcher's
/// absolute-deadline math holds (see `align`/`lock` callers).
fn host_monotonic_ticks() -> Result<u64, OsError> {
    // The host's CNTFRQ_EL0 (unprivileged `mrs`) — KVM passes the host timer
    // frequency through to the guest unchanged, and KVM does NOT expose CNTFRQ
    // via GET_ONE_REG (ENOENT), so the host read is both correct and the only
    // option. Same source the vvar realtime calibration uses.
    let freq = crate::guest_setup::host_cntfrq_el0();
    let mut ts = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    // SAFETY: plain clock read into a stack-local timespec.
    if unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC_RAW, &mut ts) } != 0 {
        return Err(os_err(
            "clock_gettime(CLOCK_MONOTONIC_RAW)",
            std::io::Error::last_os_error(),
        ));
    }
    let ns = ts.tv_sec as u128 * 1_000_000_000 + ts.tv_nsec as u128;
    Ok((ns * freq as u128 / 1_000_000_000) as u64)
}

/// The host's own virtual counter (`CNTVCT_EL0`, unprivileged `mrs` — the
/// same EL0 access the vDSO uses). The KVM guest's counter is this value
/// minus the VM's counter offset.
fn host_cntvct_el0() -> u64 {
    let cnt: u64;
    // SAFETY: `cntvct_el0` is an unprivileged read on aarch64 Linux (enabled
    // by the kernel for the vDSO clock).
    unsafe {
        core::arch::asm!("isb; mrs {}, cntvct_el0", out(reg) cnt, options(nomem, nostack));
    }
    cnt
}

/// `KVM_ARM_SET_COUNTER_OFFSET` (`_IOW(KVMIO=0xAE, 0xb5,
/// struct kvm_arm_counter_offset[16])` = 0x4010AEB5): set the VM-WIDE counter
/// offset so `guest CNTVCT == host CNTVCT - offset`. Unlike a TIMER_CNT
/// register write, the userspace-owned VM offset sets the kernel's VM-offset
/// flag, after which vcpu CREATION no longer re-zeroes the VM-wide CNTVOFF
/// (`kvm_timer_vcpu_init` zeroes it per NEW vcpu while the flag is unset) —
/// without the pin, the guest clock snapped back by the whole epoch the
/// moment a sibling thread's vCPU was created (measured: one
/// `threading.Thread` sent guest CLOCK_MONOTONIC back 317,858 s and every
/// absolute futex deadline with it). kvm-ioctls has no wrapper; raw ioctl on
/// the `VmFd`. Kernel 6.4+ (lima guest is 6.12).
fn set_vm_counter_offset_to_host_monotonic(vm: &VmFd) -> Result<(), OsError> {
    use std::os::unix::io::AsRawFd;
    const KVM_ARM_SET_COUNTER_OFFSET: libc::c_ulong = 0x4010_AEB5;
    let offs = kvm_bindings::kvm_arm_counter_offset {
        // guest = host_cntvct - offset, and we want guest == host monotonic
        // ticks: offset = host_cntvct_now - host_monotonic_ticks_now. The two
        // reads are µs apart at worst — far inside timer-test tolerances.
        counter_offset: host_cntvct_el0().wrapping_sub(host_monotonic_ticks()?),
        reserved: 0,
    };
    // SAFETY: `vm` is a live KVM VM fd; the ioctl only reads the 16-byte
    // struct we pass by reference.
    let rc = unsafe { libc::ioctl(vm.as_raw_fd(), KVM_ARM_SET_COUNTER_OFFSET, &offs) };
    if rc != 0 {
        return Err(os_err(
            "KVM_ARM_SET_COUNTER_OFFSET",
            std::io::Error::last_os_error(),
        ));
    }
    Ok(())
}

/// FALLBACK alignment for kernels without `KVM_ARM_SET_COUNTER_OFFSET`:
/// program the guest virtual counter to host CLOCK_MONOTONIC_RAW via a
/// `KVM_REG_ARM_TIMER_CNT` write (`ARM64_SYS_REG(3,3,14,3,2)` — adjusts the
/// VM-wide CNTVOFF). Without the pinned VM offset, every NEW vcpu's creation
/// re-zeroes that offset (`kvm_timer_vcpu_init` with the VM-offset flag
/// unset), so this runs after EVERY vcpu init (recycled ones included — the
/// re-write is harmless there) and concurrent vcpus see a brief zero-epoch
/// window between a sibling's create and its re-align — the VM ioctl above
/// is the primary path for a reason.
fn align_counter_to_host_monotonic(fd: &VcpuFd) -> Result<(), OsError> {
    let ticks = host_monotonic_ticks()?;
    fd.set_one_reg(sysreg_id(3, 3, 14, 3, 2), &ticks.to_le_bytes())
        .map_err(|e| os_err("KVM_SET_ONE_REG(TIMER_CNT)", e))?;
    Ok(())
}

// KVM aarch64 register-id field layout (Linux arch/arm64/include/uapi/asm/kvm.h):
//   KVM_REG_ARM64           = 0x6000... (bits 60-61: arch tag)
//   KVM_REG_SIZE_U64        = 0x0030... (bits 52-55: size, shift 52)
//   KVM_REG_ARM_COPROC_SHIFT = 16  -> the coprocessor field is bits 16-27
//   KVM_REG_ARM_CORE        = 0x0010 << 16  (the core register file)
//   KVM_REG_ARM64_SYSREG    = 0x0013 << 16  (the sysreg demux)
const KVM_REG_ARM64: u64 = 0x6000_0000_0000_0000;
const KVM_REG_SIZE_U64: u64 = 0x0030_0000_0000_0000;
const KVM_REG_SIZE_U128: u64 = 0x0040_0000_0000_0000;
const KVM_REG_SIZE_U32: u64 = 0x0020_0000_0000_0000;
const KVM_REG_ARM_COPROC_SHIFT: u64 = 16;
const KVM_REG_ARM_CORE: u64 = 0x0010 << KVM_REG_ARM_COPROC_SHIFT;
const KVM_REG_ARM64_SYSREG: u64 = 0x0013 << KVM_REG_ARM_COPROC_SHIFT;

/// Core-reg id for a `struct kvm_regs` field at `byte_offset`. The low bits of
/// a KVM_REG_ARM_CORE id are `offsetof(kvm_regs, field) / sizeof(__u32)`.
fn core_reg_id(byte_offset: u64) -> u64 {
    KVM_REG_ARM64 | KVM_REG_SIZE_U64 | KVM_REG_ARM_CORE | (byte_offset / 4)
}

// Byte offsets into `struct kvm_regs`:
//   struct user_pt_regs regs;   // 0:  regs[31] (0..248), sp@248, pc@256, pstate@264 -> 272 bytes
//   __u64 sp_el1;               // 272
//   __u64 elr_el1;              // 280
//   __u64 spsr[KVM_NR_SPSR];    // 288 (spsr[0] == SPSR_EL1)
// `user_pt_regs.sp` is SP_EL0 (the EL0/user stack).
const USER_PT_REGS_SP_EL0: u64 = 31 * 8; // 248
const USER_PT_REGS_PC: u64 = USER_PT_REGS_SP_EL0 + 8; // 256
const USER_PT_REGS_PSTATE: u64 = USER_PT_REGS_PC + 8; // 264
const KVM_REGS_SP_EL1: u64 = 272;
const KVM_REGS_ELR_EL1: u64 = 280;
const KVM_REGS_SPSR_EL1: u64 = 288;
// `struct user_fpsimd_state fp_regs` is the trailing field of `struct kvm_regs`,
// after `spsr[KVM_NR_SPSR]` (288 + 5*8 = 328). Its first member `vregs[32]` is
// 16-byte aligned, so fp_regs is padded to offset 336. Within it: vregs[n]@16*n,
// fpsr@512, fpcr@516.
const KVM_REGS_FP_REGS: u64 = 336;
const KVM_REGS_FP_FPSR: u64 = KVM_REGS_FP_REGS + 512; // 848
const KVM_REGS_FP_FPCR: u64 = KVM_REGS_FP_REGS + 516; // 852

// KVM_REG_ARM64_SYSREG: id = base | (op0<<14)|(op1<<11)|(crn<<7)|(crm<<3)|op2
fn sysreg_id(op0: u64, op1: u64, crn: u64, crm: u64, op2: u64) -> u64 {
    KVM_REG_ARM64
        | KVM_REG_SIZE_U64
        | KVM_REG_ARM64_SYSREG
        | (op0 << 14)
        | (op1 << 11)
        | (crn << 7)
        | (crm << 3)
        | op2
}

/// Core-reg id for the 128-bit SIMD/FP vector register V`n` (n in 0..32). The
/// FP/SIMD regs live in `fp_regs`, the trailing CORE field of `struct kvm_regs`,
/// so they are addressed by byte-offset just like `core_reg_id`.
fn vreg_id(n: u32) -> u64 {
    assert!(n < 32, "vreg index {n} out of range");
    KVM_REG_ARM64
        | KVM_REG_SIZE_U128
        | KVM_REG_ARM_CORE
        | ((KVM_REGS_FP_REGS + u64::from(n) * 16) / 4)
}
fn fpsr_id() -> u64 {
    KVM_REG_ARM64 | KVM_REG_SIZE_U32 | KVM_REG_ARM_CORE | (KVM_REGS_FP_FPSR / 4)
}
fn fpcr_id() -> u64 {
    KVM_REG_ARM64 | KVM_REG_SIZE_U32 | KVM_REG_ARM_CORE | (KVM_REGS_FP_FPCR / 4)
}

fn reg_to_id(r: Reg) -> u64 {
    // All of these live in the CORE register file (`struct kvm_regs`), NOT the
    // sysreg demux — including ELR_EL1 / SPSR_EL1 / SP_EL1 (see SysReg vs Reg).
    match r {
        Reg::X(n) => core_reg_id(u64::from(n) * 8), // offsetof(kvm_regs, regs.regs[n]) == n*8
        Reg::Sp => core_reg_id(USER_PT_REGS_SP_EL0), // == SP_EL0
        Reg::Pc => core_reg_id(USER_PT_REGS_PC),
        Reg::Pstate => core_reg_id(USER_PT_REGS_PSTATE),
        Reg::SpEl1 => core_reg_id(KVM_REGS_SP_EL1),
        Reg::ElrEl1 => core_reg_id(KVM_REGS_ELR_EL1),
        Reg::SpsrEl1 => core_reg_id(KVM_REGS_SPSR_EL1),
    }
}
fn sysreg_to_id(r: SysReg) -> u64 {
    // Architectural (op0,op1,CRn,CRm,op2) encodings (ARM ARM, AArch64-sysreg).
    match r {
        SysReg::Sctlr => sysreg_id(3, 0, 1, 0, 0),     // SCTLR_EL1
        SysReg::Ttbr0 => sysreg_id(3, 0, 2, 0, 0),     // TTBR0_EL1
        SysReg::Ttbr1 => sysreg_id(3, 0, 2, 0, 1),     // TTBR1_EL1
        SysReg::Tcr => sysreg_id(3, 0, 2, 0, 2),       // TCR_EL1
        SysReg::Mair => sysreg_id(3, 0, 10, 2, 0),     // MAIR_EL1
        SysReg::Vbar => sysreg_id(3, 0, 12, 0, 0),     // VBAR_EL1
        SysReg::Cpacr => sysreg_id(3, 0, 1, 0, 2),     // CPACR_EL1
        SysReg::TpidrEl0 => sysreg_id(3, 3, 13, 0, 2), // TPIDR_EL0 (EL0 thread pointer)
    }
}

pub struct KvmVm {
    /// `Some` for a VM this engine OWNS (it opened `/dev/kvm` itself, via
    /// [`Self::create_empty`]); `None` for a SIBLING vCPU's VM handle, which
    /// shares the parent's already-open `/dev/kvm` through `vm: Arc<VmFd>` and
    /// must NOT carry a second `Kvm` (`fork`'s child rebuilds a fresh VM; a
    /// `clone(CLONE_THREAD)` sibling re-uses the SAME `VmFd`). The field keeps
    /// the owner's `/dev/kvm` fd alive for the VM's lifetime.
    _kvm: Option<Kvm>,
    /// The VM fd, `Arc`-shared so a `clone(CLONE_THREAD)` sibling can create a
    /// NEW vCPU (`KVM_CREATE_VCPU`) on the SAME VM — `kvm_ioctls::VmFd` is
    /// `Send + Sync` (its fields are `File` + `usize`) and `create_vcpu` /
    /// `set_user_memory_region` / `get_preferred_target` all take `&self`, so a
    /// shared `&VmFd` suffices for both vCPU creation and (fork-child) memory
    /// registration. See Task 5 unknown #1.
    vm: Arc<VmFd>,
    /// The next `KVM_CREATE_VCPU` vcpu_id to hand out, shared across every
    /// `KvmVm` handle that targets the SAME VM (the main engine + all
    /// `clone(CLONE_THREAD)` siblings). `KVM_CREATE_VCPU` REQUIRES a unique
    /// vcpu_id per VM — creating a second vCPU with the same id returns
    /// `EEXIST`, which is exactly what deadlocked the threaded loop (every
    /// sibling tried id 0, the main vCPU's id, so no sibling ever ran). The
    /// owning VM starts this at 0 (the main vCPU takes 0); each sibling
    /// fetch-adds to get 1, 2, 3, … . A fork CHILD rebuilds a fresh VM via
    /// `create_empty`, which starts its own counter at 0 (correct — the child's
    /// VM has only the one vCPU until it spawns its own threads).
    next_vcpu_id: Arc<AtomicU64>,
    /// The next `KVM_SET_USER_MEMORY_REGION` slot id, shared across every
    /// `KvmVm` handle that targets the SAME VM — exactly like `next_vcpu_id`.
    /// Slot ids are a per-VM namespace: a `clone(CLONE_THREAD)` sibling that
    /// registers a NEW slot (post-spawn `map_host_alias`, e.g. a guest
    /// `mmap(MAP_SHARED, fd)` on a Go runtime thread) must draw from the same
    /// allocator as the main engine, or it re-issues slot 0 — the main RAM
    /// slot — and KVM returns EINVAL (changing an existing slot's
    /// `userspace_addr` is not permitted). A fork CHILD rebuilds a fresh VM
    /// via `create_empty`, which starts its own counter at 0 (correct — new
    /// VM, new slot namespace).
    next_slot: Arc<AtomicU32>,
    /// Parked vcpus of EXITED sibling threads, shared across every handle to
    /// the same VM, for REUSE by later siblings (see [`KvmVcpu::fd`] — vcpu
    /// ids are a finite per-VM resource and cannot be freed, only recycled).
    vcpu_pool: Arc<Mutex<Vec<VcpuFd>>>,
    /// `true` when `KVM_ARM_SET_COUNTER_OFFSET` pinned the VM-wide counter
    /// offset at VM creation (the offset then SURVIVES every vcpu init).
    /// `false` on kernels without the ioctl — then EVERY vcpu init must
    /// re-align the counter via the `TIMER_CNT` fallback (vcpu init zeroes
    /// the VM-wide CNTVOFF). Set once at `create_empty`; immutable after.
    counter_locked: bool,
}

/// A `Send`-safe handle to the SHARED VM state a `clone(CLONE_THREAD)` sibling
/// needs to add its own vCPU: the `VmFd` (vCPU creation + memory ops are
/// `&self`) AND the shared vcpu-id allocator (so the sibling gets a UNIQUE
/// `KVM_CREATE_VCPU` id, not a duplicate of the main vCPU's id 0).
#[derive(Clone)]
pub(crate) struct SharedVmHandle {
    vm: Arc<VmFd>,
    next_vcpu_id: Arc<AtomicU64>,
    /// Shared slot allocator (see [`KvmVm::next_slot`]) — a sibling that
    /// registers a post-spawn alias slot must draw a unique id, not slot 0.
    next_slot: Arc<AtomicU32>,
    /// Shared parked-vcpu pool (see [`KvmVcpu::fd`]) — exited siblings park
    /// their vcpu here for reuse; ids are a finite per-VM resource.
    vcpu_pool: Arc<Mutex<Vec<VcpuFd>>>,
    /// Whether the VM-wide counter offset is pinned (see [`KvmVm::counter_locked`]).
    counter_locked: bool,
}
pub struct KvmVcpu {
    /// `Some` until drop. On drop the fd is PARKED into `recycle` instead of
    /// closed: KVM vcpu ids are a FINITE per-VM resource (KVM_CAP_MAX_VCPUS,
    /// ~512) and a created vcpu persists until VM teardown — there is no
    /// KVM_DESTROY_VCPU, and closing the fd does not free the id. A
    /// thread-churny guest (cpython's test_threading spawns thousands of
    /// short-lived threads, each a sibling vCPU) exhausts the id space and
    /// later KVM_CREATE_VCPUs fail with EINVAL unless exited siblings' vcpus
    /// are REUSED. `create_vcpu_on_shared_vm` pops a parked vcpu and
    /// re-initializes it (KVM_ARM_VCPU_INIT is a full architectural reset)
    /// before handing it out — same UNPROGRAMMED contract as a fresh vcpu.
    fd: Option<VcpuFd>,
    recycle: Option<Arc<Mutex<Vec<VcpuFd>>>>,
}

impl KvmVcpu {
    /// The live vcpu fd. Present from construction to drop (the `Option` only
    /// exists so `Drop` can move the fd into the recycle pool); the None arm
    /// is unreachable, kept abort-deterministic per the crate's no-panic idiom.
    fn fd(&self) -> &VcpuFd {
        self.fd.as_ref().unwrap_or_else(|| {
            eprintln!("carrick: KvmVcpu fd accessed after drop-park (unreachable)");
            std::process::abort()
        })
    }

    /// Mutable access for the one fd method that needs it (`VcpuFd::run`).
    fn fd_mut(&mut self) -> &mut VcpuFd {
        self.fd.as_mut().unwrap_or_else(|| {
            eprintln!("carrick: KvmVcpu fd accessed after drop-park (unreachable)");
            std::process::abort()
        })
    }
}

impl Drop for KvmVcpu {
    fn drop(&mut self) {
        if let (Some(fd), Some(pool)) = (self.fd.take(), self.recycle.as_deref())
            && let Ok(mut parked) = pool.lock()
        {
            parked.push(fd);
        }
        // No pool (or a poisoned lock): the fd just closes — correct for VM
        // teardown, merely forgoing reuse.
        //
        // Decrement LAST: once the execve drain (`terminate_siblings_for_exec`)
        // observes VCPU_LIVE <= 1 it tears down the guest RAM, so everything
        // this vCPU's thread does after the decrement must be RAM-free (it is:
        // only registry/kicker bookkeeping follows the engine drop).
        VCPU_LIVE.fetch_sub(1, Ordering::SeqCst);
    }
}

impl KvmVm {
    /// Open `/dev/kvm` and `KVM_CREATE_VM` with no address space — the child
    /// side of `fork(2)` rebuilds its VM over the parent's already-built
    /// `GuestRam` windows, so there is no `AddressSpace` to thread through.
    /// (`HvVm::create` ignores its `&AddressSpace` argument; this is the same
    /// bring-up without the unused parameter.)
    pub(crate) fn create_empty() -> Result<Self, OsError> {
        let kvm = Kvm::new().map_err(|e| os_err("open /dev/kvm", e))?;
        let vm = kvm.create_vm().map_err(|e| os_err("KVM_CREATE_VM", e))?;
        // EPOCH INVARIANT: the shared dispatcher (clock_nanosleep TIMER_ABSTIME,
        // absolute FUTEX_WAIT_BITSET deadlines, timer/timerfd ABSTIME) compares
        // guest CLOCK_MONOTONIC deadlines against the HOST's monotonic clock
        // (`carrick_portable::CLOCK_UPTIME_RAW` == Linux CLOCK_MONOTONIC_RAW) —
        // an invariant HVF satisfies by construction (the macOS guest counter
        // is already host-uptime-based, carrick-hvf trap.rs
        // populate_vdso_data_page) but a fresh KVM VM does NOT: KVM zeroes the
        // virtual counter at VM creation, so the guest's vDSO MONOTONIC sat
        // ~316,000 s behind the host and every absolute deadline looked
        // already-past (cpython `time.sleep(30)` returned instantly). Pin the
        // VM-wide offset BEFORE any vcpu exists; fall back to per-vcpu-init
        // TIMER_CNT alignment on kernels without the ioctl. Fork children
        // rebuild a fresh VM through this same path, which also keeps guest
        // monotonic from jumping across fork. FATAL only if BOTH mechanisms
        // are unavailable — a silent miss is a wrong-timeout machine.
        let counter_locked = match set_vm_counter_offset_to_host_monotonic(&vm) {
            Ok(()) => true,
            Err(e) => {
                // Pre-6.4 kernel (no KVM_ARM_SET_COUNTER_OFFSET): fall back to
                // per-vcpu-init TIMER_CNT re-alignment. Loudly — the fallback
                // has a documented transient zero-epoch window per vcpu init.
                eprintln!(
                    "carrick: KVM_ARM_SET_COUNTER_OFFSET unavailable ({e}); falling back \
                     to per-vcpu-init TIMER_CNT counter alignment"
                );
                false
            }
        };
        Ok(Self {
            _kvm: Some(kvm),
            vm: Arc::new(vm),
            // The owning VM's main vCPU takes id 0; siblings fetch-add from here.
            next_vcpu_id: Arc::new(AtomicU64::new(0)),
            next_slot: Arc::new(AtomicU32::new(0)),
            vcpu_pool: Arc::new(Mutex::new(Vec::new())),
            counter_locked,
        })
    }

    /// A cloneable handle to the SAME underlying VM (the `VmFd` AND the shared
    /// vcpu-id allocator), for a `clone(CLONE_THREAD)` sibling vCPU. The
    /// sibling's [`KvmVm`] is built from this via [`Self::from_shared_vm`] and
    /// creates a NEW vCPU on it with a UNIQUE id — siblings share every memory
    /// slot by construction (same VM), so there is NO re-registration. `Send`
    /// because `VmFd` is `Send + Sync` and `Arc<AtomicU64>` is `Send + Sync`.
    pub(crate) fn vm_handle(&self) -> SharedVmHandle {
        SharedVmHandle {
            vm: Arc::clone(&self.vm),
            next_vcpu_id: Arc::clone(&self.next_vcpu_id),
            next_slot: Arc::clone(&self.next_slot),
            vcpu_pool: Arc::clone(&self.vcpu_pool),
            counter_locked: self.counter_locked,
        }
    }

    /// Build a sibling [`KvmVm`] that SHARES the parent's VM (a
    /// `clone(CLONE_THREAD)` thread). It owns no `Kvm` handle (the parent keeps
    /// `/dev/kvm` open) and registers no memory AT SPAWN (the slots already
    /// exist on the shared VM) — but it SHARES both per-VM allocators: the
    /// `next_vcpu_id` allocator so its `KVM_CREATE_VCPU` draws a unique id
    /// (1, 2, 3, …, never colliding with the main vCPU's 0), AND the
    /// `next_slot` allocator so a POST-SPAWN registration (`map_host_alias`
    /// from a guest `mmap(MAP_SHARED, fd)` on this thread) draws a unique slot
    /// id instead of re-issuing slot 0 — the main RAM slot — which KVM rejects
    /// with EINVAL (`userspace_addr` of an existing slot cannot change).
    pub(crate) fn from_shared_vm(handle: SharedVmHandle) -> Self {
        Self {
            _kvm: None,
            vm: handle.vm,
            next_vcpu_id: handle.next_vcpu_id,
            next_slot: handle.next_slot,
            vcpu_pool: handle.vcpu_pool,
            counter_locked: handle.counter_locked,
        }
    }

    /// Create a NEW vCPU on this (shared) VM. Used by `materialize_sibling`:
    /// a `clone(CLONE_THREAD)` sibling adds a vCPU to the SAME VM the parent
    /// runs on. Delegates to [`HvVm::add_vcpu`] (`KVM_CREATE_VCPU` + preferred-
    /// target init); the vCPU is returned UNPROGRAMMED for the caller to restore
    /// the seeded [`VcpuSnapshot`] onto.
    pub(crate) fn add_sibling_vcpu(&self) -> Result<KvmVcpu, OsError> {
        // Deliberately NOT counted into VCPU_LIVE here: the sibling's +1 was
        // taken at `build_sibling_spec` time ([`VcpuLiveTicket`]) to cover the
        // clone-returned-but-not-yet-materialized window; the caller consumes
        // the ticket right after this returns, transferring that +1 to the
        // vcpu (whose Drop decrements).
        self.create_vcpu_on_shared_vm()
    }

    /// `KVM_CREATE_VCPU` + preferred-target init on the shared `VmFd` (`&self`
    /// — no `next_slot` mutation, unlike [`HvVm::add_vcpu`]). Factored so both
    /// the owning and sibling paths share one vCPU-init sequence.
    fn create_vcpu_on_shared_vm(&self) -> Result<KvmVcpu, OsError> {
        // REUSE a parked vcpu of an exited sibling when one is available: vcpu
        // ids are a finite per-VM resource (KVM_CAP_MAX_VCPUS) that KVM never
        // frees, so a thread-churny guest exhausts KVM_CREATE_VCPU (EINVAL once
        // the id space is spent) unless vcpus are recycled. The vcpu_init below
        // fully resets a recycled vcpu — same UNPROGRAMMED contract either way.
        let parked = self.vcpu_pool.lock().ok().and_then(|mut p| p.pop());
        let fd = match parked {
            Some(mut fd) => {
                // A parked fd was dropped while its OLD guest thread sat at a
                // trapped syscall — i.e. mid `KVM_EXIT_MMIO` on the sentinel
                // store (thread exit parks exactly there). The in-kernel
                // completion state survives both the park and the
                // `KVM_ARM_VCPU_INIT` below (`vcpu->mmio_needed` = 1 and
                // `run->exit_reason` = `KVM_EXIT_MMIO` are GENERIC vcpu state,
                // not reset by the ARM init ioctl). The NEXT `KVM_RUN` would
                // then "complete" that stale MMIO first: `kvm_handle_mmio_return`
                // → `kvm_incr_pc` → PC advances 4 bytes — AFTER the caller has
                // restored the new sibling's seeded snapshot, so the new guest
                // thread SKIPS ITS FIRST INSTRUCTION. For a clone child seeded
                // at `__clone`'s post-svc `cmp x0, #0`, the skip makes the
                // following `b.eq thread_start` read the PARENT's stale PSTATE
                // flags: the child `ret`s down the parent path of __clone and
                // runs create_thread's tail on the child stack — the go-os
                // TestProgWideChdir `*** stack smashing detected ***` abort.
                // FLUSH the stale completion now: with `immediate_exit` set,
                // `KVM_RUN` consumes the pending MMIO (bumping the soon-to-be-
                // overwritten OLD PC) and returns EINTR before ever entering
                // the guest. The caller's snapshot restore then programs the
                // real entry state onto a clean vcpu.
                fd.set_kvm_immediate_exit(1);
                let _ = fd.run(); // -EINTR; consumes any stale MMIO completion
                fd.set_kvm_immediate_exit(0);
                fd
            }
            None => {
                // Draw a UNIQUE vcpu_id from the shared allocator. The owning
                // VM's main vCPU gets 0; every `clone(CLONE_THREAD)` sibling
                // gets the next id (1, 2, 3, …). `KVM_CREATE_VCPU` REQUIRES
                // distinct ids per VM — reusing id 0 returns EEXIST, the bug
                // that deadlocked the threaded loop (no sibling ever
                // materialised, so `pthread_join`'s futex never woke).
                let vcpu_id = self.next_vcpu_id.fetch_add(1, Ordering::SeqCst);
                self.vm
                    .create_vcpu(vcpu_id)
                    .map_err(|e| os_err("KVM_CREATE_VCPU", e))?
            }
        };
        let mut kvi = kvm_bindings::kvm_vcpu_init::default();
        self.vm
            .get_preferred_target(&mut kvi)
            .map_err(|e| os_err("KVM_ARM_PREFERRED_TARGET", e))?;
        kvi.features[0] |= 1 << KVM_ARM_VCPU_PSCI_0_2;
        fd.vcpu_init(&kvi)
            .map_err(|e| os_err("KVM_ARM_VCPU_INIT", e))?;
        // Enable EL0 reads of CNTVCT_EL0/CNTFRQ_EL0 (CNTKCTL_EL1.EL0VCTEN|EL0PCTEN)
        // so the vDSO clock fast path (`mrs cntvct_el0`) does NOT trap at EL0 (EC
        // 0x18 — which alpine/musl `ls` hit via the vDSO clock and died on). MUST
        // be on EVERY vCPU; this is the single shared create path (initial +
        // clone-siblings + fork-child rebuild via add_vcpu). Mirrors HVF's
        // `enable_el0_counter_access`. CNTKCTL_EL1 = S3_0_C14_C1_0. Best-effort
        // (like HVF): if a kernel rejects the write the vDSO clock just traps and
        // we lose the fast path — never a reason to fail vCPU creation.
        let _ = fd.set_one_reg(sysreg_id(3, 0, 14, 1, 0), &0x3u64.to_le_bytes());
        // EPOCH INVARIANT (see `create_empty`): when the VM-wide counter offset
        // could NOT be pinned at VM creation (no KVM_ARM_SET_COUNTER_OFFSET),
        // a FRESH vcpu's creation just re-zeroed the VM-wide CNTVOFF
        // (kvm_timer_vcpu_init with the VM-offset flag unset), so re-align the
        // guest counter to the host monotonic clock — unconditionally, every
        // create (recycled vcpus don't re-zero, but re-writing the correct
        // value is harmless and keeps this path branch-free). FATAL on
        // failure: silently missing the alignment is a wrong-timeout machine
        // (guest absolute deadlines land ~the host uptime away from where the
        // dispatcher evaluates them).
        if !self.counter_locked {
            align_counter_to_host_monotonic(&fd)?;
        }
        Ok(KvmVcpu {
            fd: Some(fd),
            recycle: Some(Arc::clone(&self.vcpu_pool)),
        })
    }

    /// Unregister a previously-mapped memory slot by re-issuing
    /// `KVM_SET_USER_MEMORY_REGION` with `memory_size = 0` — KVM's idiom for
    /// deleting a slot. Used by
    /// [`crate::trap_engine::KvmTrapEngine::execve_into`] to tear down the old
    /// image's slots on the LIVE VM before re-registering the new image's
    /// windows (in-place remap, no VM teardown).
    ///
    /// Does NOT touch `next_slot`; the execve path unmaps all old slots, then
    /// [`Self::reset_slot_counter`]s and re-registers the new windows from slot 0.
    pub(crate) fn unmap_memory_slot(&mut self, slot: u32) -> Result<(), OsError> {
        let region = kvm_userspace_memory_region {
            slot,
            guest_phys_addr: 0,
            memory_size: 0, // size 0 => KVM deletes this slot
            userspace_addr: 0,
            flags: 0,
        };
        // SAFETY: deleting a slot references no host memory (memory_size = 0);
        // KVM only validates the slot id and tears down its bookkeeping.
        unsafe {
            match self.vm.set_user_memory_region(region) {
                Ok(()) => {}
                // Deleting a NONEXISTENT slot returns EINVAL (kernel
                // __kvm_set_memory_region: `if (!old || !old->npages)`).
                // Treat it as idempotent success: a slot id can be a hole when
                // a registration burned its fetch_add'd id by failing (a
                // sibling map_host_alias error is contained as thread-death,
                // not process-death), and execve's `0..slot_count()` teardown
                // must not abort MID-DESTRUCTION over a hole — slots 0..k are
                // already gone, so failing here would strand the "surviving"
                // old image with no RAM.
                Err(e) if e.errno() == libc::EINVAL => {}
                Err(e) => return Err(os_err("KVM_SET_USER_MEMORY_REGION(delete)", e)),
            }
        }
        Ok(())
    }

    /// Reset the slot allocator to 0 so the next [`HvVm::map_memory`] calls
    /// re-register from slot 0. Called by `execve_into` after unmapping every
    /// old slot, so the new image's windows reuse the same slot ids/order the
    /// fresh VM would have used.
    pub(crate) fn reset_slot_counter(&mut self) {
        self.next_slot.store(0, Ordering::SeqCst);
    }

    /// How many slot ids have been drawn on this VM (across ALL handles — the
    /// allocator is shared). Ids are never recycled, so `0..slot_count()` is a
    /// SUPERSET of the live slots: a failed registration burns its id (and a
    /// sibling's map_host_alias failure is contained as thread-death, so the
    /// process can live on with a hole). `unmap_memory_slot` treats deleting a
    /// nonexistent slot as idempotent success, so execve's `0..slot_count()`
    /// teardown sweep is safe across holes.
    pub(crate) fn slot_count(&self) -> u32 {
        self.next_slot.load(Ordering::SeqCst)
    }
}

impl HvVm for KvmVm {
    type Vcpu = KvmVcpu;

    fn create(_mem: &AddressSpace) -> Result<Self, OsError> {
        Self::create_empty()
    }

    fn map_memory(
        &mut self,
        gpa: u64,
        host: *mut u8,
        len: usize,
        _perms: MemPerms,
    ) -> Result<(), OsError> {
        // Draw a UNIQUE slot id from the shared per-VM allocator BEFORE the
        // ioctl: two sibling threads registering aliases concurrently must not
        // observe the same id (KVM serializes the memslot update itself, but
        // the id must be ours alone). A failed registration burns its id —
        // harmless, since every caller treats map_memory failure as fatal.
        let slot = self.next_slot.fetch_add(1, Ordering::SeqCst);
        let region = kvm_userspace_memory_region {
            slot,
            guest_phys_addr: gpa,
            memory_size: len as u64,
            userspace_addr: host as u64,
            flags: 0, // not KVM_MEM_LOG_DIRTY_PAGES; W^X enforced in stage-1
        };
        // SAFETY: `host`..`host+len` is a live mmap owned by guest_setup for the
        // lifetime of the VM; KVM only accesses it while the vCPU runs.
        unsafe {
            self.vm.set_user_memory_region(region).map_err(|e| {
                // Rich diagnostic: a bare "Bad address" (EFAULT) hides WHICH slot
                // KVM rejected. EFAULT here is `access_ok(userspace_addr,
                // memory_size)` failing in the kernel; EINVAL is usually a
                // misaligned gpa/size or a slot-count/overlap problem. Capture the
                // full region so the failure is actionable.
                os_err(
                    &format!(
                        "KVM_SET_USER_MEMORY_REGION(slot={slot} gpa=0x{gpa:x} \
                         userspace_addr=0x{:x} size=0x{len:x})",
                        host as u64
                    ),
                    e,
                )
            })?;
        }
        let _ = KVM_MEM_LOG_DIRTY_PAGES; // keep import meaningful; unused in MVP
        Ok(())
    }

    fn add_vcpu(&mut self) -> Result<Self::Vcpu, OsError> {
        // aarch64: KVM_CREATE_VCPU + preferred-target init. Shared with the
        // sibling path ([`Self::add_sibling_vcpu`]) so the feature bits
        // (PSCI 0.2) cannot drift between bring-up and clone(CLONE_THREAD).
        let vcpu = self.create_vcpu_on_shared_vm()?;
        // OWNED vcpu (boot / fork-child rebuild): count it at construction.
        // (The sibling path counts at spec creation instead — VcpuLiveTicket.)
        VCPU_LIVE.fetch_add(1, Ordering::SeqCst);
        Ok(vcpu)
    }

    fn destroy(self) -> Result<(), OsError> {
        // VmFd/Kvm own their fds; dropping closes them (KVM tears down the VM).
        Ok(())
    }
}

impl HvVcpu for KvmVcpu {
    fn run(&mut self) -> Result<VcpuExit, OsError> {
        // EINTR from the ioctl means a signal (KICK_SIGNAL via pthread_kill) interrupted
        // KVM_RUN before any guest exit — this is the cross-thread kick path.
        let exit = match self.fd_mut().run() {
            Ok(e) => e,
            Err(e) if e.errno() == libc::EINTR => return Ok(VcpuExit::Kicked),
            Err(e) => return Err(os_err("KVM_RUN", e)),
        };
        match exit {
            KvmExit::MmioWrite(gpa, data) => {
                // KVM hands us the bytes written and the length via the slice.
                let len = data.len() as u8;
                let mut buf = [0u8; 8];
                buf[..data.len()].copy_from_slice(data);
                Ok(VcpuExit::MmioWrite {
                    gpa,
                    data: u64::from_le_bytes(buf),
                    len,
                })
            }
            KvmExit::SystemEvent(_, _) => Ok(VcpuExit::Halt),
            KvmExit::Shutdown | KvmExit::Hlt => Ok(VcpuExit::Halt),
            KvmExit::Intr => Ok(VcpuExit::Kicked),
            other => Err(os_err("unexpected KVM_RUN exit", format!("{other:?}"))),
        }
    }

    fn reg(&self, r: Reg) -> Result<u64, OsError> {
        let mut bytes = [0u8; 8];
        self.fd()
            .get_one_reg(reg_to_id(r), &mut bytes)
            .map_err(|e| os_err("KVM_GET_ONE_REG", e))?;
        Ok(u64::from_le_bytes(bytes))
    }
    fn set_reg(&mut self, r: Reg, v: u64) -> Result<(), OsError> {
        let bytes = v.to_le_bytes();
        self.fd()
            .set_one_reg(reg_to_id(r), &bytes)
            .map_err(|e| os_err("KVM_SET_ONE_REG", e))?;
        Ok(())
    }
    fn set_sys_reg(&mut self, r: SysReg, v: u64) -> Result<(), OsError> {
        let bytes = v.to_le_bytes();
        self.fd()
            .set_one_reg(sysreg_to_id(r), &bytes)
            .map_err(|e| os_err("KVM_SET_ONE_REG(sysreg)", e))?;
        Ok(())
    }

    fn kick(&self) -> Result<(), OsError> {
        // A signal delivered to the vCPU thread makes KVM_RUN return EINTR
        // (-> VcpuExit::Intr -> VcpuExit::Kicked). The MVP is single-threaded
        // (write+exit, no cross-thread wakeups), so this is exercised only by
        // the full backend; provide the mechanism, not a thread registry.
        Ok(())
    }
}

impl KvmVcpu {
    /// Read `ESR_EL1` (the syndrome of the most recent EL1 synchronous exception)
    /// via the sysreg demux (op0=3,op1=0,CRn=5,CRm=2,op2=0). Used to capture an
    /// EL0 fault after it vectors to the EL1 sentinel: the FAULT_SENTINEL store
    /// that surfaces the fault to the host is a stage-2 MMIO abort, which does NOT
    /// take an EL1 exception, so `ESR_EL1` still holds the ORIGINAL EL0-fault
    /// syndrome. Kept KVM-local (not a `carrick_hal::SysReg` variant) because only
    /// the KVM fault-capture path needs it — no cross-backend enum churn.
    pub fn get_esr_el1(&self) -> Result<u64, OsError> {
        let mut bytes = [0u8; 8];
        self.fd()
            .get_one_reg(sysreg_id(3, 0, 5, 2, 0), &mut bytes)
            .map_err(|e| os_err("KVM_GET_ONE_REG(ESR_EL1)", e))?;
        Ok(u64::from_le_bytes(bytes))
    }

    /// Read `FAR_EL1` (the faulting virtual address of the most recent EL1 sync
    /// exception) via the sysreg demux (op0=3,op1=0,CRn=6,CRm=0,op2=0). Same
    /// survival argument as [`Self::get_esr_el1`]: it retains the EL0 fault VA
    /// across the FAULT_SENTINEL store, so the delivered `SIGSEGV`/`SIGBUS`
    /// carries the correct `si_addr`.
    pub fn get_far_el1(&self) -> Result<u64, OsError> {
        let mut bytes = [0u8; 8];
        self.fd()
            .get_one_reg(sysreg_id(3, 0, 6, 0, 0), &mut bytes)
            .map_err(|e| os_err("KVM_GET_ONE_REG(FAR_EL1)", e))?;
        Ok(u64::from_le_bytes(bytes))
    }

    /// Read the guest's virtual counter — `KVM_REG_ARM_TIMER_CNT` (encoded as
    /// `ARM64_SYS_REG(3,3,14,3,2)`), the SAME value the vDSO clock reads as
    /// `CNTVCT_EL0` at EL0. Used once at boot/execve to calibrate the vvar
    /// realtime offset (`realtime_off = unix_ns - cnt/freq*1e9`).
    pub fn get_timer_cnt(&self) -> Result<u64, OsError> {
        let mut bytes = [0u8; 8];
        self.fd()
            .get_one_reg(sysreg_id(3, 3, 14, 3, 2), &mut bytes)
            .map_err(|e| os_err("KVM_GET_ONE_REG(TIMER_CNT)", e))?;
        Ok(u64::from_le_bytes(bytes))
    }

    /// Read `TPIDR_EL1` (op0=3,op1=0,CRn=13,CRm=0,op2=4 — `S3_0_C13_C0_4`), the
    /// per-vCPU EL1 thread pointer. carrick does NOT use it for thread state on
    /// KVM (the guest runs at EL0 with TPIDR_EL0 for TLS), so the EL1 sentinel
    /// vector borrows it to STASH the guest's x9 before clobbering x9 as the
    /// sentinel-store scratch; `complete_syscall` reads it back to restore x9 (the
    /// Linux syscall ABI preserves x1..x30). Kept KVM-local like
    /// [`Self::get_esr_el1`] — no `carrick_hal::SysReg` variant churn.
    pub fn get_tpidr_el1(&self) -> Result<u64, OsError> {
        let mut bytes = [0u8; 8];
        self.fd()
            .get_one_reg(sysreg_id(3, 0, 13, 0, 4), &mut bytes)
            .map_err(|e| os_err("KVM_GET_ONE_REG(TPIDR_EL1)", e))?;
        Ok(u64::from_le_bytes(bytes))
    }

    /// Write a core register through `&self` (not `&mut self`). `KVM_SET_ONE_REG`
    /// is a `&self` ioctl on `VcpuFd`, so this needs no exclusive borrow — used
    /// by the `&self` [`carrick_hal::ThreadedEngine::set_guest_sp_el0`] (a clone
    /// child's `child_stack` write) where the shared loop holds only `&E`.
    pub fn set_reg_shared(&self, r: Reg, v: u64) -> Result<(), OsError> {
        let bytes = v.to_le_bytes();
        self.fd()
            .set_one_reg(reg_to_id(r), &bytes)
            .map_err(|e| os_err("KVM_SET_ONE_REG", e))?;
        Ok(())
    }

    /// Write a system register through `&self` (see [`Self::set_reg_shared`]).
    pub fn set_sys_reg_shared(&self, r: SysReg, v: u64) -> Result<(), OsError> {
        let bytes = v.to_le_bytes();
        self.fd()
            .set_one_reg(sysreg_to_id(r), &bytes)
            .map_err(|e| os_err("KVM_SET_ONE_REG(sysreg)", e))?;
        Ok(())
    }

    /// Read a system register through `KVM_GET_ONE_REG` + the sysreg demux
    /// (`sysreg_to_id`). Symmetric to [`HvVcpu::set_sys_reg`]; used by
    /// [`Self::snapshot`] to capture the stage-1 MMU + thread-pointer registers
    /// across `fork(2)`.
    pub fn get_sys_reg(&self, r: SysReg) -> Result<u64, OsError> {
        let mut bytes = [0u8; 8];
        self.fd()
            .get_one_reg(sysreg_to_id(r), &mut bytes)
            .map_err(|e| os_err("KVM_GET_ONE_REG(sysreg)", e))?;
        Ok(u64::from_le_bytes(bytes))
    }

    /// Read the 128-bit SIMD/FP vector register V`n` (n in 0..32) via
    /// `KVM_GET_ONE_REG`. Little-endian; a non-16-byte slice yields EINVAL.
    pub fn get_vreg(&self, n: u32) -> Result<u128, OsError> {
        let mut bytes = [0u8; 16];
        self.fd()
            .get_one_reg(vreg_id(n), &mut bytes)
            .map_err(|e| os_err("KVM_GET_ONE_REG(vreg)", e))?;
        Ok(u128::from_le_bytes(bytes))
    }
    pub fn set_vreg(&mut self, n: u32, v: u128) -> Result<(), OsError> {
        let bytes = v.to_le_bytes();
        self.fd()
            .set_one_reg(vreg_id(n), &bytes)
            .map_err(|e| os_err("KVM_SET_ONE_REG(vreg)", e))?;
        Ok(())
    }
    pub fn get_fpsr(&self) -> Result<u32, OsError> {
        let mut bytes = [0u8; 4];
        self.fd()
            .get_one_reg(fpsr_id(), &mut bytes)
            .map_err(|e| os_err("KVM_GET_ONE_REG(fpsr)", e))?;
        Ok(u32::from_le_bytes(bytes))
    }
    pub fn set_fpsr(&mut self, v: u32) -> Result<(), OsError> {
        let bytes = v.to_le_bytes();
        self.fd()
            .set_one_reg(fpsr_id(), &bytes)
            .map_err(|e| os_err("KVM_SET_ONE_REG(fpsr)", e))?;
        Ok(())
    }
    pub fn get_fpcr(&self) -> Result<u32, OsError> {
        let mut bytes = [0u8; 4];
        self.fd()
            .get_one_reg(fpcr_id(), &mut bytes)
            .map_err(|e| os_err("KVM_GET_ONE_REG(fpcr)", e))?;
        Ok(u32::from_le_bytes(bytes))
    }
    pub fn set_fpcr(&mut self, v: u32) -> Result<(), OsError> {
        let bytes = v.to_le_bytes();
        self.fd()
            .set_one_reg(fpcr_id(), &bytes)
            .map_err(|e| os_err("KVM_SET_ONE_REG(fpcr)", e))?;
        Ok(())
    }

    /// Capture the parent vCPU's architectural register file before `fork(2)`
    /// so the rebuilt child vCPU can resume exactly where the parent left off
    /// (inside the trapped `clone`/`fork` syscall).
    ///
    /// Captures all GPRs, special EL1 registers, system registers, and the full
    /// FP/SIMD state (`vregs`/`fpsr`/`fpcr`) so fork-children and execve inherit
    /// correct floating-point context (Phase 4).
    pub fn snapshot(&self) -> Result<VcpuSnapshot, OsError> {
        let mut gprs = [0u64; 31];
        for (n, g) in gprs.iter_mut().enumerate() {
            *g = self.reg(Reg::X(n as u32))?;
        }
        Ok(VcpuSnapshot {
            gprs,
            pc: self.reg(Reg::Pc)?,
            pstate: self.reg(Reg::Pstate)?,
            sp_el0: self.reg(Reg::Sp)?, // user_pt_regs.sp == SP_EL0
            sp_el1: self.reg(Reg::SpEl1)?,
            elr_el1: self.reg(Reg::ElrEl1)?,
            spsr_el1: self.reg(Reg::SpsrEl1)?,
            ttbr0: self.get_sys_reg(SysReg::Ttbr0)?,
            ttbr1: self.get_sys_reg(SysReg::Ttbr1)?,
            tcr: self.get_sys_reg(SysReg::Tcr)?,
            sctlr: self.get_sys_reg(SysReg::Sctlr)?,
            mair: self.get_sys_reg(SysReg::Mair)?,
            vbar: self.get_sys_reg(SysReg::Vbar)?,
            cpacr: self.get_sys_reg(SysReg::Cpacr)?,
            tpidr_el0: self.get_sys_reg(SysReg::TpidrEl0)?,
            // Real FP/SIMD capture via the inherent accessors (Phase 4).
            vregs: {
                let mut v = [0u128; 32];
                for (n, slot) in v.iter_mut().enumerate() {
                    *slot = self.get_vreg(n as u32)?;
                }
                v
            },
            fpsr: self.get_fpsr()?,
            fpcr: self.get_fpcr()?,
        })
    }

    /// Restore a [`VcpuSnapshot`] onto this (freshly created) vCPU. The mirror of
    /// [`Self::snapshot`]; restores GPRs, EL1/system registers, and the full
    /// FP/SIMD state (`vregs`/`fpsr`/`fpcr`) so fork-children and execve inherit
    /// correct floating-point context (Phase 4).
    pub fn restore(&mut self, snap: &VcpuSnapshot) -> Result<(), OsError> {
        for (n, g) in snap.gprs.iter().enumerate() {
            self.set_reg(Reg::X(n as u32), *g)?;
        }
        self.set_reg(Reg::Pc, snap.pc)?;
        self.set_reg(Reg::Pstate, snap.pstate)?;
        self.set_reg(Reg::Sp, snap.sp_el0)?; // SP_EL0
        self.set_reg(Reg::SpEl1, snap.sp_el1)?;
        self.set_reg(Reg::ElrEl1, snap.elr_el1)?;
        self.set_reg(Reg::SpsrEl1, snap.spsr_el1)?;
        self.set_sys_reg(SysReg::Ttbr0, snap.ttbr0)?;
        self.set_sys_reg(SysReg::Ttbr1, snap.ttbr1)?;
        self.set_sys_reg(SysReg::Tcr, snap.tcr)?;
        self.set_sys_reg(SysReg::Sctlr, snap.sctlr)?;
        self.set_sys_reg(SysReg::Mair, snap.mair)?;
        self.set_sys_reg(SysReg::Vbar, snap.vbar)?;
        self.set_sys_reg(SysReg::Cpacr, snap.cpacr)?;
        self.set_sys_reg(SysReg::TpidrEl0, snap.tpidr_el0)?;
        for (n, v) in snap.vregs.iter().enumerate() {
            self.set_vreg(n as u32, *v)?;
        }
        self.set_fpsr(snap.fpsr)?;
        self.set_fpcr(snap.fpcr)?;
        Ok(())
    }
}

#[cfg(test)]
mod fp_reg_id_tests {
    use super::*;

    #[test]
    fn vreg_id_encodes_per_kernel_abi() {
        // fp_regs @ offset 336 in struct kvm_regs; vregs[0] index = 336/4 = 0x54.
        assert_eq!(vreg_id(0), 0x6040_0000_0010_0054);
        // vregs[31] @ 336 + 31*16 = 832; index = 832/4 = 0xD0.
        assert_eq!(vreg_id(31), 0x6040_0000_0010_00D0);
        // fpsr @ 848; index = 0xD4 (U32-sized). fpcr @ 852; index = 0xD5.
        assert_eq!(fpsr_id(), 0x6020_0000_0010_00D4);
        assert_eq!(fpcr_id(), 0x6020_0000_0010_00D5);
    }

    #[test]
    #[should_panic]
    fn vreg_id_rejects_out_of_range() {
        let _ = vreg_id(32);
    }
}
