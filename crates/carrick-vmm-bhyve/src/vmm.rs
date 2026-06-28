//! `BhyveVm` / `BhyveVcpu`: the raw-hypervisor layer on FreeBSD/bhyve via the
//! userspace **libvmmapi** (`/usr/lib/libvmmapi.so`). The KVM analog is
//! `carrick-vmm-kvm::kvm`.
//!
//! Arch split: the opaque handles, VM/vCPU lifecycle, guest-RAM calls
//! (`vm_setup_memory`/`vm_mmap_memseg`/`vm_map_gpa`), and the extern block are
//! arch-neutral and live here unconditionally. The aarch64 story (aarch64
//! `enum vm_reg_name`/`enum vm_exitcode` ordinals, the aarch64 `struct vm_exit`
//! guess, and the `HvVm`/`HvVcpu` impls whose `Reg`/`SysReg` enums are
//! aarch64-named) is gated `#[cfg(target_arch = "aarch64")]`. The amd64 model
//! (x86 `vm_exit`/`vm_inout`, amd64 register/exitcode constants, inherent
//! raw-register access) lives in `vmm_x86.rs` — on x86_64 the carrick-hal
//! `HvVm`/`HvVcpu` traits are deliberately NOT implemented (Phase 2 decision;
//! the x86 backend uses the inherent surface instead).
//!
//! Bring-up status: the aarch64 interfaces are transcribed from FreeBSD 15.1
//! `/usr/include/vmmapi.h`, `machine/vmm_dev.h`, and `sys/arm64/include/vmm.h`
//! (releng/15.1) and remain compile-verified only (bhyve runs same-arch guests;
//! the development box is amd64).
use std::ffi::{CString, c_char, c_int, c_uint, c_void};
use std::sync::Arc;
use std::sync::atomic::{AtomicI32, AtomicU64, Ordering};

use carrick_hal::OsError;
#[cfg(target_arch = "aarch64")]
use carrick_hal::{HvVcpu, HvVm, MemPerms, Reg, SysReg, VcpuExit};
#[cfg(target_arch = "aarch64")]
use carrick_mem::memory::AddressSpace;

// Opaque libvmmapi handles.
#[repr(C)]
pub struct Vmctx {
    _opaque: [u8; 0],
}
#[repr(C)]
pub struct Vcpu {
    _opaque: [u8; 0],
}

// enum vm_mmap_style (vmmapi.h:55-59 on the box: NONE=0, ALL=1, SPARSE=2).
// 15.1's vm_setup_memory_domains supports ONLY VM_MMAP_ALL — it asserts
// `vms == VM_MMAP_ALL` (lib/libvmmapi/vmmapi.c:497, releng/15.1) — so that is
// what carrick passes. (The scaffold's earlier VM_MMAP_SPARSE pick predated
// reading the implementation; even with NDEBUG asserts off, the style
// argument is otherwise unused and the function behaves as ALL.)
const VM_MMAP_ALL: c_int = 1;
// vm_openf flags
const VMMAPI_OPEN_CREATE: c_int = 0x01;

// aarch64 `enum vm_reg_name` (sys/arm64/include/vmm.h, releng/15.1).
// X0..X29 = 0..29; LR(X30)=30; SP=31; PC=32; CPSR=33; then the MMU sysregs.
// These ordinals are unverified on an aarch64 bhyve host (the development box
// is amd64); they may need confirmation when that path runs.
#[cfg(target_arch = "aarch64")]
const VM_REG_GUEST_X0: c_int = 0; // X0..X30 = 0..30 (LR is X30)
#[cfg(target_arch = "aarch64")]
const VM_REG_GUEST_SP: c_int = 31;
#[cfg(target_arch = "aarch64")]
const VM_REG_GUEST_PC: c_int = 32;
#[cfg(target_arch = "aarch64")]
const VM_REG_GUEST_CPSR: c_int = 33;
#[cfg(target_arch = "aarch64")]
const VM_REG_GUEST_SCTLR_EL1: c_int = 34;
#[cfg(target_arch = "aarch64")]
const VM_REG_GUEST_TTBR0_EL1: c_int = 35;
#[cfg(target_arch = "aarch64")]
const VM_REG_GUEST_TTBR1_EL1: c_int = 36;
#[cfg(target_arch = "aarch64")]
const VM_REG_GUEST_TCR_EL1: c_int = 37;

// aarch64 `enum vm_exitcode` (order from sys/arm64/include/vmm.h).
#[cfg(target_arch = "aarch64")]
const VM_EXITCODE_BOGUS: c_int = 0;
#[cfg(target_arch = "aarch64")]
const VM_EXITCODE_INST_EMUL: c_int = 1;
#[cfg(target_arch = "aarch64")]
const VM_EXITCODE_HVC: c_int = 3;
#[cfg(target_arch = "aarch64")]
const VM_EXITCODE_SUSPENDED: c_int = 4;
#[cfg(target_arch = "aarch64")]
const VM_EXITCODE_WFI: c_int = 6;
#[cfg(target_arch = "aarch64")]
const VM_EXITCODE_PAGING: c_int = 7;
#[cfg(target_arch = "aarch64")]
const VM_EXITCODE_SMCCC: c_int = 8;

/// aarch64 `struct vm_exit` (sys/arm64/include/vmm.h): common prefix `{ enum
/// vm_exitcode; int inst_length; uint64_t pc; }` then an arch union. The
/// union's first member is the faulting `gpa` for PAGING/INST_EMUL (the
/// MMIO-sentinel decode), so we model the union as a `u64` word array and read
/// `u[0]`. CONFIRM the union layout on the aarch64 target. (The amd64
/// `struct vm_exit` is modeled separately in `vmm_x86.rs`.)
#[cfg(target_arch = "aarch64")]
#[repr(C)]
struct VmExit {
    exitcode: c_int,
    inst_length: c_int,
    pc: u64,
    u: [u64; 8],
}

/// `struct vm_run` (machine/vmm_dev.h:84-89): the caller provides per-arch
/// `struct vm_exit` storage; `vm_run()` fills it. The exit pointer is typed
/// `*mut c_void` here because the pointee is the per-arch `vm_exit` model
/// (aarch64's above; amd64's in `vmm_x86.rs`).
#[repr(C)]
pub(crate) struct VmRun {
    pub(crate) cpuid: c_int,
    pub(crate) cpuset: *mut c_void,
    pub(crate) cpusetsize: usize,
    pub(crate) vm_exit: *mut c_void,
}

#[link(name = "vmmapi")]
unsafe extern "C" {
    fn vm_create(name: *const c_char) -> c_int;
    fn vm_openf(name: *const c_char, flags: c_int) -> *mut Vmctx;
    fn vm_destroy(ctx: *mut Vmctx);
    fn vm_setup_memory(ctx: *mut Vmctx, len: usize, s: c_int) -> c_int;
    fn vm_map_gpa(ctx: *mut Vmctx, gaddr: u64, len: usize) -> *mut c_void;
    fn vm_mmap_memseg(
        ctx: *mut Vmctx,
        gpa: u64,
        segid: c_int,
        segoff: i64,
        len: usize,
        prot: c_int,
    ) -> c_int;
    fn vm_vcpu_open(ctx: *mut Vmctx, vcpuid: c_int) -> *mut Vcpu;
    fn vm_activate_cpu(vcpu: *mut Vcpu) -> c_int;
    fn vcpu_reset(vcpu: *mut Vcpu) -> c_int;
    pub(crate) fn vm_set_register(vcpu: *mut Vcpu, reg: c_int, val: u64) -> c_int;
    pub(crate) fn vm_get_register(vcpu: *mut Vcpu, reg: c_int, retval: *mut u64) -> c_int;
    pub(crate) fn vm_run(vcpu: *mut Vcpu, vmrun: *mut VmRun) -> c_int;
    // --- Phase 2 additions, transcribed from the box's /usr/include/vmmapi.h
    // (FreeBSD 15.1-RC3 amd64). NOTE: the plan sketch cited vm_get_register_set
    // at vmmapi.h:156 — on the box :156 is vm_set_register_set; the GET variant
    // is :158. Same signature either way; the header wins.
    /// vmmapi.h:158-159: `int vm_get_register_set(struct vcpu *vcpu,
    /// unsigned int count, const int *regnums, uint64_t *regvals);`
    pub(crate) fn vm_get_register_set(
        vcpu: *mut Vcpu,
        count: c_uint,
        regnums: *const c_int,
        regvals: *mut u64,
    ) -> c_int;
    /// vmmapi.h:156-157: `int vm_set_register_set(struct vcpu *vcpu,
    /// unsigned int count, const int *regnums, uint64_t *regvals);` — the write
    /// twin of `vm_get_register_set` (one ioctl for a batch of registers).
    pub(crate) fn vm_set_register_set(
        vcpu: *mut Vcpu,
        count: c_uint,
        regnums: *const c_int,
        regvals: *const u64,
    ) -> c_int;
    /// vmmapi.h:148-149 (inside `#ifdef __amd64__`, vmmapi.h:147 — amd64-only
    /// in the header, hence the cfg): `int vm_set_desc(struct vcpu *vcpu,
    /// int reg, uint64_t base, uint32_t limit, uint32_t access);`
    #[cfg(target_arch = "x86_64")]
    pub(crate) fn vm_set_desc(
        vcpu: *mut Vcpu,
        reg: c_int,
        base: u64,
        limit: u32,
        access: u32,
    ) -> c_int;
    /// vmmapi.h:150-151 (same `#ifdef __amd64__` block): `int vm_get_desc(
    /// struct vcpu *vcpu, int reg, uint64_t *base, uint32_t *limit,
    /// uint32_t *access);`
    #[cfg(target_arch = "x86_64")]
    pub(crate) fn vm_get_desc(
        vcpu: *mut Vcpu,
        reg: c_int,
        base: *mut u64,
        limit: *mut u32,
        access: *mut u32,
    ) -> c_int;
    /// vmmapi.h:201-202: `int vm_set_capability(struct vcpu *vcpu,
    /// enum vm_cap_type cap, int val);` (C enum == int here).
    pub(crate) fn vm_set_capability(vcpu: *mut Vcpu, cap: c_int, val: c_int) -> c_int;
    /// vmmapi.h:268: `int vm_restart_instruction(struct vcpu *vcpu);`
    pub(crate) fn vm_restart_instruction(vcpu: *mut Vcpu) -> c_int;
    /// vmmapi.h:279-281 ("FreeBSD specific APIs"; unconditional in the header):
    /// `int vm_setup_freebsd_registers(struct vcpu *vcpu, uint64_t rip,
    /// uint64_t cr3, uint64_t gdtbase, uint64_t rsp);`
    pub(crate) fn vm_setup_freebsd_registers(
        vcpu: *mut Vcpu,
        rip: u64,
        cr3: u64,
        gdtbase: u64,
        rsp: u64,
    ) -> c_int;
}

pub(crate) fn os_err(context: &str, rc: c_int) -> OsError {
    OsError::new(format!("bhyve: {context} failed (rc={rc})"))
}

/// The bhyve register id for a carrick-hal `Reg`, or `Err` for the registers
/// bhyve's aarch64 vmmapi does NOT expose (`SP_EL1`/`ELR_EL1`/`SPSR_EL1`) — those
/// are programmed by the guest-side EL1 init stub, not the host (see the crate
/// docs). `Reg::Sp` is SP_EL0; bhyve exposes the active `SP`, which at EL1 is
/// SP_EL1 — the init stub sets SP_EL0 for EL0 before the `eret`.
#[cfg(target_arch = "aarch64")]
fn reg_id(r: Reg) -> Result<c_int, OsError> {
    Ok(match r {
        Reg::X(n) => VM_REG_GUEST_X0 + n as c_int, // X0..X30
        Reg::Sp => VM_REG_GUEST_SP,
        Reg::Pc => VM_REG_GUEST_PC,
        Reg::Pstate => VM_REG_GUEST_CPSR,
        Reg::SpEl1 | Reg::ElrEl1 | Reg::SpsrEl1 => {
            return Err(OsError::new(format!(
                "bhyve: {r:?} is not exposed by the aarch64 vmmapi; the guest-side \
                 EL1 init stub programs it (ELR/SPSR for the eret to EL0)"
            )));
        }
        // The x86_64 Reg variants are a disjoint ISA view; the shared x86 bhyve
        // backend uses its own register access, not this aarch64 path.
        _ => {
            return Err(OsError::new(format!(
                "bhyve: {r:?} is an x86_64 register, not valid on the aarch64 lane"
            )));
        }
    })
}

/// The bhyve register id for a carrick-hal `SysReg`. bhyve exposes the MMU
/// regs (SCTLR/TTBR0/TTBR1/TCR) but NOT `MAIR_EL1`/`VBAR_EL1`/`CPACR_EL1`/
/// `TPIDR_EL0`; those are set by the guest-side EL1 init stub (memory attrs /
/// vector base / FP) or handled elsewhere.
#[cfg(target_arch = "aarch64")]
fn sysreg_id(r: SysReg) -> Result<c_int, OsError> {
    Ok(match r {
        SysReg::Sctlr => VM_REG_GUEST_SCTLR_EL1,
        SysReg::Ttbr0 => VM_REG_GUEST_TTBR0_EL1,
        SysReg::Ttbr1 => VM_REG_GUEST_TTBR1_EL1,
        SysReg::Tcr => VM_REG_GUEST_TCR_EL1,
        SysReg::Mair | SysReg::Vbar | SysReg::Cpacr | SysReg::TpidrEl0 => {
            return Err(OsError::new(format!(
                "bhyve: {r:?} is not exposed by the aarch64 vmmapi; the guest-side \
                 EL1 init stub programs it"
            )));
        }
        // x86_64 FsBase/GsBase are a disjoint ISA view (the shared x86 backend's path).
        _ => {
            return Err(OsError::new(format!(
                "bhyve: {r:?} is an x86_64 sysreg, not valid on the aarch64 lane"
            )));
        }
    })
}

/// The shared inner state backing one VM across all its vCPU threads. The ctx is
/// a kernel-owned handle valid for the VM's whole lifetime; bhyve's SMP model
/// runs DISTINCT vcpus of one ctx concurrently on separate host threads
/// (bhyverun.c fbsdrun_addcpu/vm_loop). vm_destroy runs once, when the last
/// Arc holder (main engine + all siblings) drops — but ONLY if this inner OWNS
/// the node (`owns`).
///
/// `owns` is the load-bearing, robust-by-construction ownership backstop. It
/// lives HERE (not on `BhyveVm`) so that `Drop` itself is gated: a BORROWED
/// inner (`owns == false`) is STRUCTURALLY incapable of `vm_destroy` on ANY drop
/// path — normal drop, a panic-unwind drop, an early-return drop — regardless of
/// what the caller does. A borrowed handle (e.g. a vfork child's view of the
/// parent's shared VM) is built over a DISTINCT non-owning inner whose `drop` is
/// a guaranteed no-op, so the parent's `/dev/vmm` node can never be torn down by
/// the borrower. (Previously `owns` lived on `BhyveVm` while `BhyveVmInner::drop`
/// destroyed unconditionally — a borrowed `BhyveVm` that happened to be the last
/// in-process Arc holder would still destroy the parent's VM. Moving the flag
/// into the inner removes that footgun by construction.)
struct BhyveVmInner {
    ctx: *mut Vmctx,
    next_vcpu: AtomicI32,
    /// Bitset of activated vCPU ids (bit i = id i has been `vm_activate_cpu`d).
    /// Init `1` (bit 0 set) because the MAIN vCPU is id 0. A sibling vCPU id granted
    /// by the M:N scheduler is activated at most once for the VM's life; a recycled
    /// id (a prior thread exited) is re-opened + re-seeded, never re-activated
    /// (safe: `BhyveVcpu` has no `Drop`, so the kernel vCPU persists). Ids ≥ 64 fall
    /// back to always-activate (N = hw.vmm.maxcpu is ≤ that on supported hosts).
    activated: AtomicU64,
    /// `true` for an OWNING inner (`create`'s fresh VM, an execve's fresh VM, a
    /// fork child's fresh VM): its `Drop`/`destroy_in_place` run `vm_destroy`.
    /// `false` for a BORROWED inner (a vfork child's non-owning view of the
    /// parent's shared VM): its `Drop`/`destroy_in_place` are no-ops.
    owns: bool,
}

// SAFETY: ctx is a kernel handle usable from any thread; only DISTINCT vcpus
// run concurrently (the same vcpu is never touched from two threads). vcpu-id
// allocation is atomic. The pointer is never mutated after create.
unsafe impl Send for BhyveVmInner {}
unsafe impl Sync for BhyveVmInner {}

impl Drop for BhyveVmInner {
    /// Tear down `/dev/vmm/<name>`. This runs exactly once, when the last `Arc`
    /// holder drops (refcount hit 0) — i.e. after the main engine AND every
    /// sibling engine that cloned the handle have all been dropped. With the
    /// per-create unique name (see `BhyveVm::create`) each VM owns a distinct
    /// node, so `vm_destroy` here is unambiguous (no shared-ctx EINVAL).
    ///
    /// Gated on `owns` (robust-by-construction): a BORROWED inner never destroys
    /// the node on ANY drop path. A vfork child's borrowed view of the parent's
    /// shared VM is a distinct `owns == false` inner, so the parent's node is
    /// structurally safe from the borrower's drops (normal, panic, or early).
    fn drop(&mut self) {
        if self.owns && !self.ctx.is_null() {
            // SAFETY: an OWNING, live, not-yet-destroyed vmctx; this is the LAST
            // holder (Arc refcount hit 0), so vm_destroy is unambiguous + single.
            unsafe { vm_destroy(self.ctx) };
        }
    }
}

/// Tear down a reaped forked child's leaked `/dev/vmm/carrick-<host_pid>-*`
/// node(s). Installed as the carrick-hal reap-child-VM hook; the PARENT calls it
/// from its `wait4`/`waitid` reap, where the child host process is already DEAD.
/// Opening the orphaned node (flags 0 = open, no create) and `vm_destroy`-ing it
/// is the sole, final teardown — it cannot race a live in-process holder, so
/// (unlike the in-child `process_exit_cleanup`, which the engine's surviving
/// `BhyveSharedVm` clone keeps referenced and would HANG to destroy) it never
/// hangs. The child may have superseded earlier VMs (seq 0,1 destroyed on the
/// child's own Drop as it rebuilt); only the final live node leaks, but matching
/// the whole `carrick-<pid>-` prefix reaps any stragglers too.
pub fn reap_leaked_child_vm(host_pid: u32) {
    let prefix = format!("carrick-{host_pid}-");
    let Ok(rd) = std::fs::read_dir("/dev/vmm") else {
        return;
    };
    for ent in rd.flatten() {
        let fname = ent.file_name();
        let Some(name) = fname.to_str() else {
            continue;
        };
        if !name.starts_with(&prefix) {
            continue;
        }
        let Ok(cname) = CString::new(name) else {
            continue;
        };
        // SAFETY: open the orphaned node (no create) to get its ctx, then destroy
        // it. The owning process is dead, so this is the single, final vm_destroy.
        unsafe {
            let ctx = vm_openf(cname.as_ptr(), 0);
            if !ctx.is_null() {
                vm_destroy(ctx);
            }
        }
    }
}

/// Startup sweep: reap leaked `/dev/vmm/carrick-<pid>-*` nodes whose owning pid is
/// DEAD — the bhyve analog of the host-fs dead-flock scratch sweeper
/// (`fs_backend::sweep_orphans`). The wait4 reap hook ([`reap_leaked_child_vm`])
/// only covers a child reaped by its GUEST parent; a guest SIGKILL'd by the
/// orchestrator or the conformance babysit is orphaned and its node leaks. Since
/// each conformance suite spawns a fresh carrick process, sweeping on the first VM
/// create per process reclaims prior suites' orphaned nodes, keeping `/dev/vmm`
/// bounded across a long gate — else they pile up until the host OOMs (measured
/// live VMs 3→259 in 10 min on a 16G box during a full LTP run).
fn sweep_dead_vm_nodes() {
    let Ok(rd) = std::fs::read_dir("/dev/vmm") else {
        return;
    };
    for ent in rd.flatten() {
        let fname = ent.file_name();
        let Some(name) = fname.to_str() else {
            continue;
        };
        // Node name is `carrick-<pid>-<seq>`; pull the owning pid.
        let Some(pid) = name
            .strip_prefix("carrick-")
            .and_then(|rest| rest.split('-').next())
            .and_then(|p| p.parse::<i32>().ok())
        else {
            continue;
        };
        // Alive if kill(pid, 0) succeeds or fails EPERM; dead only on ESRCH.
        // SAFETY: signal 0 only probes existence, it never delivers a signal.
        let alive = unsafe { libc::kill(pid, 0) } == 0
            || std::io::Error::last_os_error().raw_os_error() == Some(libc::EPERM);
        if alive {
            continue;
        }
        let Ok(cname) = CString::new(name) else {
            continue;
        };
        // SAFETY: open the orphaned (dead-owner) node, then destroy it. No live
        // holder remains, so this is the final teardown and cannot hang.
        unsafe {
            let ctx = vm_openf(cname.as_ptr(), 0);
            if !ctx.is_null() {
                vm_destroy(ctx);
            }
        }
    }
}

pub struct BhyveVm {
    /// The shared inner carries the `owns` flag (robust-by-construction): a
    /// borrowed handle is a DISTINCT non-owning inner over the same `ctx`, so its
    /// `Drop`/`destroy_in_place` are structurally no-ops (see `from_borrowed`).
    /// Ownership is therefore per-INNER, not per-handle: every `BhyveVm` and
    /// `BhyveSharedVm` clone over one inner shares that inner's ownership verdict,
    /// and the `Arc` refcount governs WHEN the (gated) `vm_destroy` fires (the
    /// last owning holder's drop). Across `libc::fork` the inherited owning inner
    /// must NOT be the one a borrower drops — so the vfork child builds a fresh
    /// `owns == false` inner via `from_borrowed` rather than inheriting the
    /// owning one.
    inner: Arc<BhyveVmInner>,
}

/// A cloneable, Send+Sync handle to a shared VM, carried in a sibling spec to a
/// new thread which opens its own vCPU via `add_sibling_vcpu`. Each clone holds
/// an `Arc` to the same `BhyveVmInner`, keeping the VM (and its `vm_destroy`)
/// alive until every holder drops.
#[derive(Clone)]
pub struct BhyveSharedVm(Arc<BhyveVmInner>);

pub struct BhyveVcpu {
    pub(crate) vcpu: *mut Vcpu,
}

#[cfg(target_arch = "aarch64")]
impl HvVm for BhyveVm {
    type Vcpu = BhyveVcpu;

    fn create(_mem: &AddressSpace) -> Result<Self, OsError> {
        BhyveVm::create()
    }

    /// bhyve owns the guest RAM (allocated by `vm_setup_memory` / mapped at GPAs
    /// by `vm_mmap_memseg`), and the host reads/writes it via `vm_map_gpa` — the
    /// inverse of KVM, where we hand KVM our own host mmap. So this records the
    /// requested region; the bhyve guest_setup (a later slice) performs the
    /// real `vm_setup_memory` + `vm_mmap_memseg` and resolves host pointers with
    /// `vm_map_gpa`. The `host` argument (a host pointer) does not apply.
    fn map_memory(
        &mut self,
        _gpa: u64,
        _host: *mut u8,
        _len: usize,
        _perms: MemPerms,
    ) -> Result<(), OsError> {
        Err(OsError::new(
            "bhyve: map_memory does not apply (bhyve owns guest RAM via \
             vm_setup_memory/vm_map_gpa); use the bhyve guest_setup path"
                .to_string(),
        ))
    }

    fn add_vcpu(&mut self) -> Result<Self::Vcpu, OsError> {
        BhyveVm::add_vcpu(self)
    }

    fn destroy(self) -> Result<(), OsError> {
        BhyveVm::destroy(self)
    }
}

impl BhyveVm {
    /// Create + open the VM device. The name `carrick-{pid}-{seq}` is unique per
    /// `create` call: the pid keeps concurrent PROCESSES distinct (incl. a
    /// forked guest child), and the process-global `seq` keeps multiple VMs in
    /// ONE process distinct (e.g. two live tests in a cargo binary, or future
    /// per-call runs). A bare `carrick-{pid}` collided when one process built
    /// two VMs: the second `vm_setup_memory`/`vm_activate_cpu` hit the SAME
    /// already-configured `/dev/vmm` node (ENOMEM/ENXIO), and Drop's
    /// `vm_destroy` of the shared ctx then failed EINVAL on the duplicate.
    pub fn create() -> Result<Self, OsError> {
        use std::sync::atomic::AtomicU32;
        // Install the reap-child-VM hook once per process: a bhyve VM is a named
        // /dev/vmm node that leaks when a forked guest child `_exit`s past Drop,
        // so the PARENT tears it down from its wait4/waitid reap (the child is
        // dead → no live holder → no hang). Idempotent; the fn address is the
        // same in every forked process, so this registration is fork-inherited.
        static REGISTER_REAP: std::sync::Once = std::sync::Once::new();
        REGISTER_REAP.call_once(|| {
            carrick_hal::vm_backend::set_reap_child_vm_hook(reap_leaked_child_vm);
            // Reclaim any /dev/vmm node orphaned by a prior SIGKILL'd guest (the
            // reap hook only covers guest-parent-reaped children). Per-process, so
            // each conformance suite's fresh carrick sweeps the prior suites'
            // leaks, keeping /dev/vmm bounded across a long gate.
            sweep_dead_vm_nodes();
        });
        // Process-global VM sequence — distinct name per create() in this process.
        static VM_SEQ: AtomicU32 = AtomicU32::new(0);
        let seq = VM_SEQ.fetch_add(1, Ordering::Relaxed);
        let name = CString::new(format!("carrick-{}-{}", std::process::id(), seq))
            .map_err(|_| OsError::new("bhyve: VM name has a NUL".to_string()))?;
        // SAFETY: `name` is a valid NUL-terminated C string for the call's life.
        let ctx = unsafe {
            let rc = vm_create(name.as_ptr());
            // vm_create returns -1 and sets errno on failure (NOT the errno as
            // rc). Tolerate an already-existing node — we open it below; error
            // on anything else.
            if rc != 0 && std::io::Error::last_os_error().raw_os_error() != Some(libc::EEXIST) {
                return Err(os_err("vm_create", rc));
            }
            vm_openf(name.as_ptr(), VMMAPI_OPEN_CREATE)
        };
        if ctx.is_null() {
            return Err(OsError::new("bhyve: vm_openf returned NULL".to_string()));
        }
        Ok(Self {
            inner: Arc::new(BhyveVmInner {
                ctx,
                next_vcpu: AtomicI32::new(0),
                activated: AtomicU64::new(1), // bit 0 = the main vCPU (id 0)
                // A freshly-created VM is OWNED: its `Drop`/`destroy_in_place`
                // run `vm_destroy`.
                owns: true,
            }),
        })
    }

    /// Open + activate the next vCPU.
    pub fn add_vcpu(&mut self) -> Result<BhyveVcpu, OsError> {
        let id = self.inner.next_vcpu.fetch_add(1, Ordering::SeqCst);
        // SAFETY: `self.inner.ctx` is a live vmctx for the VM's lifetime.
        let vcpu = unsafe { vm_vcpu_open(self.inner.ctx, id) };
        if vcpu.is_null() {
            return Err(OsError::new(format!("bhyve: vm_vcpu_open({id}) NULL")));
        }
        // SAFETY: `vcpu` is the just-opened vcpu handle.
        let rc = unsafe { vm_activate_cpu(vcpu) };
        if rc != 0 {
            return Err(os_err("vm_activate_cpu", rc));
        }
        let _ = unsafe { vcpu_reset(vcpu) };
        Ok(BhyveVcpu { vcpu })
    }

    /// A cloneable handle to this VM's shared inner state, to hand to a sibling
    /// vCPU thread. The clone holds its own `Arc`, so the VM stays alive (and
    /// `vm_destroy` is deferred) until every holder — this `BhyveVm` and all
    /// handles derived from it — has dropped.
    pub fn shared_handle(&self) -> BhyveSharedVm {
        BhyveSharedVm(Arc::clone(&self.inner))
    }

    /// Rebuild a `BhyveVm` from a shared handle: a sibling's engine holds its
    /// own `Arc` clone, keeping the VM alive while it runs. Dropping the
    /// resulting `BhyveVm` only drops that one `Arc` clone — `vm_destroy` runs
    /// when the LAST holder drops, never before.
    pub fn from_shared(shared: BhyveSharedVm) -> BhyveVm {
        // A sibling-in-one-process handle: it clones the SAME owning inner, so
        // within the process the `Arc` refcount keeps the VM alive and the LAST
        // holder's `Drop` runs `vm_destroy` (the inner is `owns == true` — it was
        // built by `create`). The inner's ownership verdict is shared verbatim;
        // `from_shared` introduces no new inner.
        BhyveVm { inner: shared.0 }
    }

    /// Build a NON-owning [`BhyveVm`] view over a shared VM that is owned by
    /// ANOTHER process or handle — a BORROWED handle.
    ///
    /// Robust-by-construction: this does NOT clone the shared (owning) inner.
    /// It builds a FRESH, DISTINCT `BhyveVmInner { ctx, next_vcpu, owns: false }`
    /// over the SAME `ctx`. Because the new inner is `owns == false`, its
    /// `Drop` AND its `destroy_in_place` are guaranteed no-ops on EVERY path
    /// (normal drop, panic-unwind, early return) — the borrowed handle can NEVER
    /// `vm_destroy` the node. The owner (the parent process / the owning inner)
    /// is the only thing that can tear it down. This makes the safety property
    /// structural rather than resting on the caller's `mem::forget` discipline.
    ///
    /// `next_vcpu` decision (option ii — correct + minimal for vfork): the
    /// borrowed inner gets a FRESH `AtomicI32::new(1)`, NOT a clone of the
    /// owner's atomic. This is sound precisely because `from_borrowed` is used by
    /// the vfork child, which is a SEPARATE PROCESS (post-`libc::fork`) whose
    /// parent is SUSPENDED on the vfork pipe for the whole window — the parent
    /// allocates no vcpu ids concurrently, so the child can safely allocate
    /// sibling ids starting at a non-colliding base (1; id 0 is the parent's main
    /// vCPU, which the child does not reuse — it opens its OWN sibling vCPU). The
    /// owner's atomic is in the OTHER process's address space anyway; sharing it
    /// across `libc::fork` would only give the child a private post-fork copy, so
    /// a fresh base-1 atomic is both simpler and equivalent.
    ///
    /// Distinct from [`from_shared`](Self::from_shared) (sibling-in-one-process, which clones the
    /// owning inner and relies on the per-process `Arc` refcount): across
    /// `libc::fork` the `Arc` refcount is per-process and wrong for ownership, so
    /// a forked child that shares the parent's VM uses this fresh non-owning
    /// inner instead.
    pub fn from_borrowed(shared: BhyveSharedVm) -> BhyveVm {
        BhyveVm {
            inner: Arc::new(BhyveVmInner {
                ctx: shared.0.ctx,
                next_vcpu: AtomicI32::new(1),
                // Borrowed view of the parent's SHARED VM: its vCPUs are already
                // activated, so treat every id as activated → always re-open + re-
                // seed, never re-activate.
                activated: AtomicU64::new(u64::MAX),
                owns: false,
            }),
        }
    }

    /// Whether this handle's inner OWNS the `/dev/vmm` node (its drop/teardown
    /// runs `vm_destroy`). `false` for a borrowed view (see `from_borrowed`).
    pub fn owns(&self) -> bool {
        self.inner.owns
    }

    /// Tear down the VM (and `/dev/vmm/<name>`). With `Arc`-based ownership this
    /// is just dropping `self`: the `Arc` refcount decrements, and when it hits
    /// zero (this was the LAST holder — the main engine plus every sibling that
    /// cloned a handle have all dropped) `BhyveVmInner::drop` runs `vm_destroy`
    /// exactly once. If siblings still hold clones, the ctx survives this drop
    /// and is destroyed later, avoiding a use-after-free of a still-live ctx.
    pub fn destroy(self) -> Result<(), OsError> {
        drop(self);
        Ok(())
    }

    /// Host pointer into guest-physical `[gpa, gpa+len)` (bhyve owns the
    /// backing). Used by the bhyve GuestMemory to read/write syscall buffers —
    /// the analog of carrick-vmm-kvm's host mmap. `None` if the GPA is unmapped.
    pub fn map_gpa(&self, gpa: u64, len: usize) -> Option<*mut u8> {
        // SAFETY: `self.inner.ctx` is live; vm_map_gpa returns NULL for an unmapped GPA.
        let p = unsafe { vm_map_gpa(self.inner.ctx, gpa, len) };
        if p.is_null() {
            None
        } else {
            Some(p.cast::<u8>())
        }
    }

    /// Allocate `len` bytes of guest RAM. In 15.1 `vm_setup_memory` does
    /// three things itself (lib/libvmmapi/vmmapi.c:486-605, releng/15.1):
    /// creates the `VM_SYSMEM` segment, maps it into the guest at GPA
    /// `[0, len)` (for `len` ≤ 3 GiB; larger sizes split across the
    /// 3 GiB/4 GiB lowmem/highmem boundary), and host-mmaps the region so
    /// `vm_map_gpa` can resolve pointers into it. `VM_MMAP_ALL` is the only
    /// style the implementation accepts (it asserts).
    pub fn setup_memory(&self, len: usize) -> Result<(), OsError> {
        // SAFETY: `self.inner.ctx` is a live vmctx.
        let rc = unsafe { vm_setup_memory(self.inner.ctx, len, VM_MMAP_ALL) };
        if rc != 0 {
            return Err(os_err("vm_setup_memory", rc));
        }
        Ok(())
    }

    /// Destroy the VM in place (for a forked-child `_exit`, which skips `Drop`).
    ///
    /// bhyve VMs are NAME-bound `/dev/vmm/<name>` nodes that persist until
    /// `vm_destroy` — they are NOT released by fd-close (unlike KVM). A forked
    /// guest child `_exit`s without running `Drop`, so the engine calls this from
    /// `process_exit_cleanup` to tear the child VM down and avoid leaking the
    /// node. The forked child is the SOLE holder of its freshly-created child VM
    /// (no siblings cloned the handle), so `Arc::get_mut` succeeds; we run
    /// `vm_destroy` exactly once and NULL the ctx so the later `BhyveVmInner::drop`
    /// (if it ever runs) is a no-op — guarding against a double-destroy. If
    /// somehow another `Arc` holder existed (it should not for a child VM), we
    /// leave the ctx alone and let the last holder's `Drop` destroy it.
    pub fn destroy_in_place(&mut self) {
        // A BORROWED handle (a vfork child's view of the parent's shared VM)
        // never tears down the node — the owner (the parent process) resumes on
        // it. The `owns` flag lives on the inner precisely because the `Arc`
        // refcount is per-process-wrong across `libc::fork`, and a borrowed
        // handle is a distinct non-owning inner (see `from_borrowed`). This guard
        // plus the gated `BhyveVmInner::drop` make a borrowed node structurally
        // safe from teardown on every path.
        if !self.inner.owns {
            return;
        }
        if let Some(inner) = Arc::get_mut(&mut self.inner)
            && !inner.ctx.is_null()
        {
            // SAFETY: a live, not-yet-destroyed vmctx; this is the sole Arc
            // holder (Arc::get_mut succeeded), so vm_destroy is unambiguous.
            unsafe { vm_destroy(inner.ctx) };
            inner.ctx = std::ptr::null_mut();
        }
        // NOTE: for a forked child the engine holds the VM as a `BhyveSharedVm`
        // clone (a 2nd Arc holder), so `Arc::get_mut` fails here and this in-child
        // path CANNOT tear the node down — a naive "destroy via the shared ctx
        // anyway" HANGS the run (a live holder — sibling vCPU / pump / shared-alias
        // flush — is still using the node). The leak is instead reclaimed by the
        // PARENT from its wait4/waitid reap: `reap_leaked_child_vm` (installed via
        // the carrick-hal reap-child-VM hook) destroys the orphaned node once the
        // child host process is DEAD, where there is no live holder to race.
    }

    /// Map memory segment `segid` into the guest at `[gpa, gpa+len)`.
    pub fn mmap_memseg(&self, gpa: u64, segid: i32, len: usize, prot: i32) -> Result<(), OsError> {
        // SAFETY: `self.inner.ctx` is a live vmctx.
        let rc = unsafe { vm_mmap_memseg(self.inner.ctx, gpa, segid, 0, len, prot) };
        if rc != 0 {
            return Err(os_err("vm_mmap_memseg", rc));
        }
        Ok(())
    }
}

impl BhyveSharedVm {
    /// Open + activate a sibling vCPU on the shared ctx. Mirrors
    /// `BhyveVm::add_vcpu`, but takes `&self` and draws the vcpu id from the
    /// SHARED `AtomicI32` so concurrent siblings each get a DISTINCT id —
    /// bhyve's SMP model runs distinct vcpus of one ctx on separate threads.
    ///
    /// Returns the opened vCPU AND its allocated id: the long-mode sibling
    /// bring-up (Tier 2 `materialize_sibling`) carves a per-sibling ring-0 MSR
    /// blob + scratch-stack slot from the post-boot-free init-blob page by id, so
    /// the caller needs the id (sibling ids start at 1; id 0 is the main vCPU).
    pub fn add_sibling_vcpu(&self) -> Result<(BhyveVcpu, c_int), OsError> {
        // Use the M:N scheduler's granted slot id (0..N, RECYCLED across guest
        // threads) instead of a monotonic counter that would exhaust hw.vmm.maxcpu
        // (the #10 vm_activate_cpu EINVAL bug). Fall back to the counter only if no
        // lease is set (e.g. a Noop-scheduler backend that never reaches here).
        let id = carrick_hal::vcpu_sched::current_slot()
            .map(|s| s as c_int)
            .unwrap_or_else(|| self.0.next_vcpu.fetch_add(1, Ordering::SeqCst));
        // SAFETY: `self.0.ctx` is a live vmctx for the VM's lifetime.
        let vcpu = unsafe { vm_vcpu_open(self.0.ctx, id) };
        if vcpu.is_null() {
            return Err(OsError::new(format!("bhyve: vm_vcpu_open({id}) NULL")));
        }
        // Activate each id at most once for the VM's life (a recycled id is
        // re-opened + re-seeded, never re-activated — BhyveVcpu has no Drop, so the
        // kernel vCPU persists). Ids >= 64 fall back to always-activate.
        let bit = if id < 64 { 1u64 << id } else { 0 };
        let already = bit != 0 && (self.0.activated.fetch_or(bit, Ordering::SeqCst) & bit) != 0;
        if !already {
            // SAFETY: `vcpu` is the just-opened vcpu handle.
            let rc = unsafe { vm_activate_cpu(vcpu) };
            if rc != 0 {
                self.0.activated.fetch_and(!bit, Ordering::SeqCst);
                return Err(os_err("vm_activate_cpu", rc));
            }
        }
        let _ = unsafe { vcpu_reset(vcpu) };
        Ok((BhyveVcpu { vcpu }, id))
    }

    /// Re-open an ALREADY-activated vCPU id for the M:N reclaim re-bind: just the
    /// handle — NO `vm_activate_cpu` (the id persists for the VM's life) and NO
    /// `vcpu_reset` (a recycled vCPU keeps its long-mode control regs; the caller
    /// restores only the per-thread GPRs/RSP/RFLAGS/FS-GS-base it saved).
    pub fn reopen_vcpu(&self, id: c_int) -> Result<BhyveVcpu, OsError> {
        let vcpu = unsafe { vm_vcpu_open(self.0.ctx, id) };
        if vcpu.is_null() {
            return Err(OsError::new(format!(
                "bhyve: reopen vm_vcpu_open({id}) NULL"
            )));
        }
        Ok(BhyveVcpu { vcpu })
    }
}

#[cfg(target_arch = "aarch64")]
impl HvVcpu for BhyveVcpu {
    fn run(&mut self) -> Result<VcpuExit, OsError> {
        let mut exit = VmExit {
            exitcode: 0,
            inst_length: 0,
            pc: 0,
            u: [0; 8],
        };
        let mut run = VmRun {
            cpuid: 0,
            cpuset: std::ptr::null_mut(),
            cpusetsize: 0,
            vm_exit: std::ptr::from_mut(&mut exit).cast::<c_void>(),
        };
        // SAFETY: `self.vcpu` is live; `run`/`exit` outlive the call.
        let rc = unsafe { vm_run(self.vcpu, &mut run) };
        if rc != 0 {
            return Err(os_err("vm_run", rc));
        }
        Ok(match exit.exitcode {
            // The MMIO-sentinel store faults to stage-2 as a paging/inst-emul
            // exit; `u[0]` is the faulting gpa. The run loop reads the syscall
            // frame from registers, so the data/len are placeholders here.
            VM_EXITCODE_PAGING | VM_EXITCODE_INST_EMUL => VcpuExit::MmioWrite {
                gpa: exit.u[0],
                data: 0,
                len: 0,
            },
            // Alternative trap vehicle: an `hvc`/SMCCC from the EL1 vector.
            VM_EXITCODE_HVC | VM_EXITCODE_SMCCC => VcpuExit::MmioWrite {
                gpa: exit.u[0],
                data: exit.u[1],
                len: 0,
            },
            VM_EXITCODE_WFI | VM_EXITCODE_SUSPENDED => VcpuExit::Halt,
            VM_EXITCODE_BOGUS => VcpuExit::Kicked,
            other => VcpuExit::Exception {
                syndrome: other as u64,
                far: exit.pc,
            },
        })
    }

    fn reg(&self, r: Reg) -> Result<u64, OsError> {
        let id = reg_id(r)?;
        let mut val = 0u64;
        // SAFETY: `self.vcpu` is live; `val` is a valid out-pointer.
        let rc = unsafe { vm_get_register(self.vcpu, id, &mut val) };
        if rc != 0 {
            return Err(os_err("vm_get_register", rc));
        }
        Ok(val)
    }

    fn set_reg(&mut self, r: Reg, v: u64) -> Result<(), OsError> {
        let id = reg_id(r)?;
        // SAFETY: `self.vcpu` is live.
        let rc = unsafe { vm_set_register(self.vcpu, id, v) };
        if rc != 0 {
            return Err(os_err("vm_set_register", rc));
        }
        Ok(())
    }

    fn set_sys_reg(&mut self, r: SysReg, v: u64) -> Result<(), OsError> {
        let id = sysreg_id(r)?;
        // SAFETY: `self.vcpu` is live.
        let rc = unsafe { vm_set_register(self.vcpu, id, v) };
        if rc != 0 {
            return Err(os_err("vm_set_register(sysreg)", rc));
        }
        Ok(())
    }

    fn kick(&self) -> Result<(), OsError> {
        // Single-threaded scaffold: no cross-thread kick yet (matches the KVM
        // backend). bhyve's analog is vm_suspend_cpu / a directed signal.
        Ok(())
    }
}
