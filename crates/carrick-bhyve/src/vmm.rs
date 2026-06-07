//! `BhyveVm` / `BhyveVcpu`: the `carrick-hal` raw-hypervisor layer (`HvVm`/
//! `HvVcpu`) on FreeBSD/bhyve, aarch64, via the userspace **libvmmapi**
//! (`/usr/lib/libvmmapi.so`). The KVM analog is `carrick-linux::kvm`.
//!
//! SCAFFOLD (see `docs/superpowers/adr/2026-06-06-bhyve-backend-design.md`):
//! compile-verified on an amd64 FreeBSD host; the aarch64 register-enum values,
//! the `struct vm_exit` union layout, and the guest bring-up are confirmed on an
//! aarch64 FreeBSD host (bhyve runs same-arch guests only). Interfaces below are
//! transcribed from FreeBSD 15.1 `/usr/include/vmmapi.h`, `machine/vmm_dev.h`,
//! and `sys/arm64/include/vmm.h` (releng/15.1).
use std::ffi::{CString, c_char, c_int, c_void};

use carrick_hal::{HvVcpu, HvVm, MemPerms, OsError, Reg, SysReg, VcpuExit};
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

// enum vm_mmap_style
const VM_MMAP_SPARSE: c_int = 2;
// vm_openf flags
const VMMAPI_OPEN_CREATE: c_int = 0x01;

// aarch64 `enum vm_reg_name` (sys/arm64/include/vmm.h, releng/15.1).
// X0..X29 = 0..29; LR(X30)=30; SP=31; PC=32; CPSR=33; then the MMU sysregs.
// CONFIRM these ordinals on the aarch64 target.
const VM_REG_GUEST_X0: c_int = 0; // X0..X30 = 0..30 (LR is X30)
const VM_REG_GUEST_SP: c_int = 31;
const VM_REG_GUEST_PC: c_int = 32;
const VM_REG_GUEST_CPSR: c_int = 33;
const VM_REG_GUEST_SCTLR_EL1: c_int = 34;
const VM_REG_GUEST_TTBR0_EL1: c_int = 35;
const VM_REG_GUEST_TTBR1_EL1: c_int = 36;
const VM_REG_GUEST_TCR_EL1: c_int = 37;

// aarch64 `enum vm_exitcode` (order from sys/arm64/include/vmm.h).
const VM_EXITCODE_BOGUS: c_int = 0;
const VM_EXITCODE_INST_EMUL: c_int = 1;
const VM_EXITCODE_HVC: c_int = 3;
const VM_EXITCODE_SUSPENDED: c_int = 4;
const VM_EXITCODE_WFI: c_int = 6;
const VM_EXITCODE_PAGING: c_int = 7;
const VM_EXITCODE_SMCCC: c_int = 8;

/// `struct vm_exit` (machine/vmm.h): common prefix `{ enum vm_exitcode; int
/// inst_length; uint64_t pc; }` then an arch union. The union's first member is
/// the faulting `gpa` for PAGING/INST_EMUL (the MMIO-sentinel decode), so we
/// model the union as a `u64` word array and read `u[0]`. CONFIRM the union
/// layout on the aarch64 target.
#[repr(C)]
struct VmExit {
    exitcode: c_int,
    inst_length: c_int,
    pc: u64,
    u: [u64; 8],
}

/// `struct vm_run` (machine/vmm_dev.h): the caller provides `vm_exit` storage;
/// `vm_run()` fills it.
#[repr(C)]
struct VmRun {
    cpuid: c_int,
    cpuset: *mut c_void,
    cpusetsize: usize,
    vm_exit: *mut VmExit,
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
    fn vm_set_register(vcpu: *mut Vcpu, reg: c_int, val: u64) -> c_int;
    fn vm_get_register(vcpu: *mut Vcpu, reg: c_int, retval: *mut u64) -> c_int;
    fn vm_run(vcpu: *mut Vcpu, vmrun: *mut VmRun) -> c_int;
}

fn os_err(context: &str, rc: c_int) -> OsError {
    OsError::new(format!("bhyve: {context} failed (rc={rc})"))
}

/// The bhyve register id for a carrick-hal `Reg`, or `Err` for the registers
/// bhyve's aarch64 vmmapi does NOT expose (`SP_EL1`/`ELR_EL1`/`SPSR_EL1`) — those
/// are programmed by the guest-side EL1 init stub, not the host (see the crate
/// docs). `Reg::Sp` is SP_EL0; bhyve exposes the active `SP`, which at EL1 is
/// SP_EL1 — the init stub sets SP_EL0 for EL0 before the `eret`.
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
    })
}

/// The bhyve register id for a carrick-hal `SysReg`. bhyve exposes the MMU
/// regs (SCTLR/TTBR0/TTBR1/TCR) but NOT `MAIR_EL1`/`VBAR_EL1`/`CPACR_EL1`; those
/// are set by the guest-side EL1 init stub (memory attrs / vector base / FP).
fn sysreg_id(r: SysReg) -> Result<c_int, OsError> {
    Ok(match r {
        SysReg::Sctlr => VM_REG_GUEST_SCTLR_EL1,
        SysReg::Ttbr0 => VM_REG_GUEST_TTBR0_EL1,
        SysReg::Ttbr1 => VM_REG_GUEST_TTBR1_EL1,
        SysReg::Tcr => VM_REG_GUEST_TCR_EL1,
        SysReg::Mair | SysReg::Vbar | SysReg::Cpacr => {
            return Err(OsError::new(format!(
                "bhyve: {r:?} is not exposed by the aarch64 vmmapi; the guest-side \
                 EL1 init stub programs it"
            )));
        }
    })
}

pub struct BhyveVm {
    ctx: *mut Vmctx,
    next_vcpu: c_int,
}

pub struct BhyveVcpu {
    vcpu: *mut Vcpu,
}

impl HvVm for BhyveVm {
    type Vcpu = BhyveVcpu;

    fn create(_mem: &AddressSpace) -> Result<Self, OsError> {
        // A unique VM name; the device node is /dev/vmm/<name>. (A pid-based
        // name keeps concurrent runs distinct; refine when the run entry lands.)
        let name = CString::new(format!("carrick-{}", std::process::id()))
            .map_err(|_| OsError::new("bhyve: VM name has a NUL".to_string()))?;
        // SAFETY: `name` is a valid NUL-terminated C string for the call's life.
        let ctx = unsafe {
            let rc = vm_create(name.as_ptr());
            if rc != 0 && rc != libc::EEXIST {
                return Err(os_err("vm_create", rc));
            }
            vm_openf(name.as_ptr(), VMMAPI_OPEN_CREATE)
        };
        if ctx.is_null() {
            return Err(OsError::new("bhyve: vm_openf returned NULL".to_string()));
        }
        Ok(Self { ctx, next_vcpu: 0 })
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
        let id = self.next_vcpu;
        // SAFETY: `self.ctx` is a live vmctx for the VM's lifetime.
        let vcpu = unsafe { vm_vcpu_open(self.ctx, id) };
        if vcpu.is_null() {
            return Err(OsError::new(format!("bhyve: vm_vcpu_open({id}) NULL")));
        }
        // SAFETY: `vcpu` is the just-opened vcpu handle.
        let rc = unsafe { vm_activate_cpu(vcpu) };
        if rc != 0 {
            return Err(os_err("vm_activate_cpu", rc));
        }
        let _ = unsafe { vcpu_reset(vcpu) };
        self.next_vcpu += 1;
        Ok(BhyveVcpu { vcpu })
    }

    fn destroy(self) -> Result<(), OsError> {
        // SAFETY: `self.ctx` is a live vmctx; destroying it tears down /dev/vmm/<name>.
        unsafe { vm_destroy(self.ctx) };
        Ok(())
    }
}

impl BhyveVm {
    /// Host pointer into guest-physical `[gpa, gpa+len)` (bhyve owns the
    /// backing). Used by the bhyve GuestMemory to read/write syscall buffers —
    /// the analog of carrick-linux's host mmap. `None` if the GPA is unmapped.
    pub fn map_gpa(&self, gpa: u64, len: usize) -> Option<*mut u8> {
        // SAFETY: `self.ctx` is live; vm_map_gpa returns NULL for an unmapped GPA.
        let p = unsafe { vm_map_gpa(self.ctx, gpa, len) };
        if p.is_null() {
            None
        } else {
            Some(p.cast::<u8>())
        }
    }

    /// Allocate `len` bytes of sparse guest RAM (the carrick layout is mostly
    /// holes). The bhyve guest_setup maps regions at their GPAs with
    /// `vm_mmap_memseg`; exposed here for that path.
    pub fn setup_memory(&self, len: usize) -> Result<(), OsError> {
        // SAFETY: `self.ctx` is a live vmctx.
        let rc = unsafe { vm_setup_memory(self.ctx, len, VM_MMAP_SPARSE) };
        if rc != 0 {
            return Err(os_err("vm_setup_memory", rc));
        }
        Ok(())
    }

    /// Map memory segment `segid` into the guest at `[gpa, gpa+len)`.
    pub fn mmap_memseg(&self, gpa: u64, segid: i32, len: usize, prot: i32) -> Result<(), OsError> {
        // SAFETY: `self.ctx` is a live vmctx.
        let rc = unsafe { vm_mmap_memseg(self.ctx, gpa, segid, 0, len, prot) };
        if rc != 0 {
            return Err(os_err("vm_mmap_memseg", rc));
        }
        Ok(())
    }
}

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
            vm_exit: &mut exit,
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
