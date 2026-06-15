//! `NvmmMachine` / `NvmmVcpu`: the raw-hypervisor layer on NetBSD/NVMM via the
//! userspace **libnvmm** (`/usr/lib/libnvmm.so`). The KVM analog is
//! `carrick-linux::kvm`; the bhyve analog is `carrick-vmm-bhyve::vmm`.
//!
//! Layouts are transcribed from the on-box headers (confirmed via a C
//! `offsetof`/`sizeof` probe on VM 201, NetBSD 10.1 amd64):
//!
//! * `struct nvmm_machine` = 24 bytes: `machid:u32` @0, `pages:ptr` @8,
//!   `areas:ptr` @16.
//! * `struct nvmm_vcpu` = 56 bytes: `cpuid:u32` @0, `cbs` (2 ptrs) @8,
//!   `state:*mut nvmm_x64_state` @24, `event:ptr` @32, `exit:*mut nvmm_x86_exit`
//!   @40, `stop:ptr` @48. The `state`/`exit` pointers reference the per-vCPU
//!   comm page that libnvmm mmaps in `nvmm_vcpu_create`.
//! * `struct nvmm_x64_state` = 1008 bytes: `segs[10]` @0, `gprs[18]` @160,
//!   `crs[6]` @304, `drs[6]` @352, `msrs[11]` @400, `intr` @488, `fpu` (fxsave,
//!   512B) @496.
//! * `struct nvmm_x64_state_seg` = 16 bytes: `selector:u16` @0, `attrib:u16`
//!   @2 (bitfield), `limit:u32` @4, `base:u64` @8.
//! * `struct nvmm_x86_exit` = 64 bytes: `reason:u64` @0, union `u` @8,
//!   `exitstate` @40.
//! * `struct nvmm_x86_exit_io` = 24 bytes: `in:bool` @0, `port:u16` @2,
//!   `seg:i8` @4, `address_size:u8` @5, `operand_size:u8` @6, `rep:bool` @7,
//!   `str:bool` @8, `npc:u64` @16. **`npc` is the next-PC** delivered on the IO
//!   exit (the M1 RIP-advance answer: resume at `npc`, no manual +inst_len).

use std::io;
use std::ptr;

use libc::{c_int, c_void};

// ---------------------------------------------------------------------------
// Constants (from dev/nvmm/x86/nvmm_x86.h + nvmm.h, confirmed on-box).
// ---------------------------------------------------------------------------

/// `nvmm_gpa_map` protection bits.
pub const NVMM_PROT_READ: c_int = 0x01;
pub const NVMM_PROT_WRITE: c_int = 0x02;
pub const NVMM_PROT_EXEC: c_int = 0x04;

/// VCPU state sub-area flags (`NVMM_X64_STATE_*`).
pub const NVMM_X64_STATE_SEGS: u64 = 0x01;
pub const NVMM_X64_STATE_GPRS: u64 = 0x02;
pub const NVMM_X64_STATE_CRS: u64 = 0x04;
pub const NVMM_X64_STATE_DRS: u64 = 0x08;
pub const NVMM_X64_STATE_MSRS: u64 = 0x10;
pub const NVMM_X64_STATE_INTR: u64 = 0x20;
pub const NVMM_X64_STATE_FPU: u64 = 0x40;

/// GPR indices into `nvmm_x64_state.gprs`.
pub const NVMM_X64_GPR_RAX: usize = 0;
pub const NVMM_X64_GPR_RCX: usize = 1;
pub const NVMM_X64_GPR_RDX: usize = 2;
pub const NVMM_X64_GPR_RBX: usize = 3;
pub const NVMM_X64_GPR_RSP: usize = 4;
pub const NVMM_X64_GPR_RBP: usize = 5;
pub const NVMM_X64_GPR_RSI: usize = 6;
pub const NVMM_X64_GPR_RDI: usize = 7;
pub const NVMM_X64_GPR_R8: usize = 8;
pub const NVMM_X64_GPR_R9: usize = 9;
pub const NVMM_X64_GPR_R10: usize = 10;
pub const NVMM_X64_GPR_R11: usize = 11;
pub const NVMM_X64_GPR_R12: usize = 12;
pub const NVMM_X64_GPR_R13: usize = 13;
pub const NVMM_X64_GPR_R14: usize = 14;
pub const NVMM_X64_GPR_R15: usize = 15;
pub const NVMM_X64_GPR_RIP: usize = 16;
pub const NVMM_X64_GPR_RFLAGS: usize = 17;
pub const NVMM_X64_NGPR: usize = 18;

/// Segment indices into `nvmm_x64_state.segs`.
pub const NVMM_X64_SEG_ES: usize = 0;
pub const NVMM_X64_SEG_CS: usize = 1;
pub const NVMM_X64_SEG_SS: usize = 2;
pub const NVMM_X64_SEG_DS: usize = 3;
pub const NVMM_X64_SEG_FS: usize = 4;
pub const NVMM_X64_SEG_GS: usize = 5;
pub const NVMM_X64_SEG_GDT: usize = 6;
pub const NVMM_X64_SEG_IDT: usize = 7;
pub const NVMM_X64_SEG_LDT: usize = 8;
pub const NVMM_X64_SEG_TR: usize = 9;
pub const NVMM_X64_NSEG: usize = 10;

/// Control-register indices into `nvmm_x64_state.crs`.
pub const NVMM_X64_CR_CR0: usize = 0;
pub const NVMM_X64_CR_CR2: usize = 1;
pub const NVMM_X64_CR_CR3: usize = 2;
pub const NVMM_X64_CR_CR4: usize = 3;
pub const NVMM_X64_CR_CR8: usize = 4;
pub const NVMM_X64_CR_XCR0: usize = 5;
pub const NVMM_X64_NCR: usize = 6;

pub const NVMM_X64_NDR: usize = 6;

/// MSR indices into `nvmm_x64_state.msrs`.
pub const NVMM_X64_MSR_EFER: usize = 0;
pub const NVMM_X64_MSR_STAR: usize = 1;
pub const NVMM_X64_MSR_LSTAR: usize = 2;
pub const NVMM_X64_MSR_CSTAR: usize = 3;
pub const NVMM_X64_MSR_SFMASK: usize = 4;
pub const NVMM_X64_MSR_KERNELGSBASE: usize = 5;
pub const NVMM_X64_NMSR: usize = 11;

/// Exit reasons (`nvmm_x86_exit.reason`).
pub const NVMM_VCPU_EXIT_NONE: u64 = 0x0000_0000_0000_0000;
pub const NVMM_VCPU_EXIT_MEMORY: u64 = 0x0000_0000_0000_0001;
pub const NVMM_VCPU_EXIT_IO: u64 = 0x0000_0000_0000_0002;
pub const NVMM_VCPU_EXIT_SHUTDOWN: u64 = 0x0000_0000_0000_1000;
pub const NVMM_VCPU_EXIT_HALTED: u64 = 0x0000_0000_0000_1003;
pub const NVMM_VCPU_EXIT_INVALID: u64 = 0xFFFF_FFFF_FFFF_FFFF;

// ---------------------------------------------------------------------------
// Opaque/value FFI structs (sizes/offsets verified on-box).
// ---------------------------------------------------------------------------

/// `struct nvmm_machine` (24 bytes). libnvmm fills/uses all fields; we only
/// read `machid`. The trailing pointers are managed internally by libnvmm.
#[repr(C)]
pub struct NvmmMachineRaw {
    pub machid: u32,
    _pad: u32,
    pages: *mut c_void,
    areas: *mut c_void,
}

impl NvmmMachineRaw {
    fn zeroed() -> Self {
        NvmmMachineRaw {
            machid: 0,
            _pad: 0,
            pages: ptr::null_mut(),
            areas: ptr::null_mut(),
        }
    }
}

/// `struct nvmm_assist_callbacks` (2 fn pointers). Unused in M0 (no io/mem
/// assist); kept NULL.
#[repr(C)]
struct NvmmAssistCallbacks {
    io: *mut c_void,
    mem: *mut c_void,
}

/// `struct nvmm_vcpu` (56 bytes). The `state`/`event`/`exit` pointers are
/// initialized by libnvmm in `nvmm_vcpu_create` to point at the per-vCPU comm
/// page; emulator software reads/writes through them (do NOT overwrite the
/// pointers themselves).
#[repr(C)]
pub struct NvmmVcpuRaw {
    pub cpuid: u32,
    _pad: u32,
    cbs: NvmmAssistCallbacks,
    pub state: *mut NvmmX64State,
    event: *mut c_void,
    pub exit: *mut NvmmX86Exit,
    stop: *mut c_int,
}

impl NvmmVcpuRaw {
    fn zeroed() -> Self {
        NvmmVcpuRaw {
            cpuid: 0,
            _pad: 0,
            cbs: NvmmAssistCallbacks {
                io: ptr::null_mut(),
                mem: ptr::null_mut(),
            },
            state: ptr::null_mut(),
            event: ptr::null_mut(),
            exit: ptr::null_mut(),
            stop: ptr::null_mut(),
        }
    }
}

/// `struct nvmm_x64_state_seg` (16 bytes). `attrib` is a packed bitfield
/// (`type:4, s:1, dpl:2, p:1, avl:1, l:1, def:1, g:1, rsvd:4`); we model it as
/// a raw `u16` and provide a small builder for the bits M1 will need.
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct NvmmX64StateSeg {
    pub selector: u16,
    pub attrib: u16,
    pub limit: u32,
    pub base: u64,
}

/// `struct nvmm_x64_state_intr` (8 bytes; a bitfield word). Opaque here.
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct NvmmX64StateIntr {
    pub bits: u64,
}

/// `struct fxsave` (512 bytes) — the legacy FXSAVE area. Opaque byte blob for
/// M0 (FP programming is M2).
#[repr(C)]
#[derive(Clone, Copy)]
pub struct Fxsave {
    pub bytes: [u8; 512],
}

impl Default for Fxsave {
    fn default() -> Self {
        Fxsave { bytes: [0u8; 512] }
    }
}

/// `struct nvmm_x64_state` (1008 bytes). This is the comm-page state area
/// reached via `vcpu.state`. `nvmm_vcpu_getstate`/`setstate` move the
/// requested sub-areas between kernel and this struct.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct NvmmX64State {
    pub segs: [NvmmX64StateSeg; NVMM_X64_NSEG],
    pub gprs: [u64; NVMM_X64_NGPR],
    pub crs: [u64; NVMM_X64_NCR],
    pub drs: [u64; NVMM_X64_NDR],
    pub msrs: [u64; NVMM_X64_NMSR],
    pub intr: NvmmX64StateIntr,
    pub fpu: Fxsave,
}

/// `struct nvmm_x86_exit_io` (24 bytes). `npc` is the next-PC (resume RIP).
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct NvmmX86ExitIo {
    pub in_: bool,
    _pad0: u8,
    pub port: u16,
    pub seg: i8,
    pub address_size: u8,
    pub operand_size: u8,
    pub rep: bool,
    pub str_: bool,
    _pad1: [u8; 7],
    pub npc: u64,
}

/// `struct nvmm_x86_exit` (64 bytes). The union `u` (32 bytes — the largest
/// member is `nvmm_x86_exit_memory`) starts at offset 8; `exitstate` at 40.
/// We model the union as a fixed byte blob and reinterpret it per `reason`.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct NvmmX86Exit {
    pub reason: u64,
    pub u: [u8; 32],
    pub exitstate: [u8; 24],
}

impl NvmmX86Exit {
    /// Reinterpret the union as the IO exit member. Only valid when
    /// `reason == NVMM_VCPU_EXIT_IO`.
    pub fn io(&self) -> NvmmX86ExitIo {
        // SAFETY: `nvmm_x86_exit_io` (24 bytes) fits in the 32-byte union blob
        // and shares the union's start offset; only call when reason == IO.
        unsafe { ptr::read_unaligned(self.u.as_ptr() as *const NvmmX86ExitIo) }
    }
}

/// `struct nvmm_capability` (104 bytes) — only the leading scalar fields are
/// modeled (the `arch` tail is opaque for M0).
#[repr(C)]
pub struct NvmmCapabilityRaw {
    pub version: u32,
    pub state_size: u32,
    pub max_machines: u32,
    pub max_vcpus: u32,
    pub max_ram: u64,
    _arch: [u8; 80],
}

impl NvmmCapabilityRaw {
    fn zeroed() -> Self {
        NvmmCapabilityRaw {
            version: 0,
            state_size: 0,
            max_machines: 0,
            max_vcpus: 0,
            max_ram: 0,
            _arch: [0u8; 80],
        }
    }
}

/// A safe snapshot of the libnvmm capability scalars.
#[derive(Debug, Clone, Copy)]
pub struct NvmmCapability {
    pub version: u32,
    pub state_size: u32,
    pub max_machines: u32,
    pub max_vcpus: u32,
    pub max_ram: u64,
}

// ---------------------------------------------------------------------------
// FFI (libnvmm). Bind only what M0 needs.
// ---------------------------------------------------------------------------

#[link(name = "nvmm")]
unsafe extern "C" {
    fn nvmm_init() -> c_int;
    fn nvmm_capability(cap: *mut NvmmCapabilityRaw) -> c_int;
    fn nvmm_machine_create(mach: *mut NvmmMachineRaw) -> c_int;
    fn nvmm_machine_destroy(mach: *mut NvmmMachineRaw) -> c_int;
    fn nvmm_vcpu_create(mach: *mut NvmmMachineRaw, cpuid: u32, vcpu: *mut NvmmVcpuRaw) -> c_int;
    fn nvmm_vcpu_destroy(mach: *mut NvmmMachineRaw, vcpu: *mut NvmmVcpuRaw) -> c_int;
    fn nvmm_vcpu_getstate(mach: *mut NvmmMachineRaw, vcpu: *mut NvmmVcpuRaw, flags: u64) -> c_int;
    fn nvmm_vcpu_setstate(mach: *mut NvmmMachineRaw, vcpu: *mut NvmmVcpuRaw, flags: u64) -> c_int;
    fn nvmm_vcpu_run(mach: *mut NvmmMachineRaw, vcpu: *mut NvmmVcpuRaw) -> c_int;
    fn nvmm_hva_map(mach: *mut NvmmMachineRaw, hva: usize, size: usize) -> c_int;
    fn nvmm_hva_unmap(mach: *mut NvmmMachineRaw, hva: usize, size: usize) -> c_int;
    fn nvmm_gpa_map(
        mach: *mut NvmmMachineRaw,
        hva: usize,
        gpa: u64,
        size: usize,
        prot: c_int,
    ) -> c_int;
}

// ---------------------------------------------------------------------------
// Safe wrappers.
// ---------------------------------------------------------------------------

pub type NvmmResult<T> = Result<T, NvmmError>;

/// An NVMM operation failed; carries the failing call name + the OS errno.
#[derive(Debug)]
pub struct NvmmError {
    pub op: &'static str,
    pub errno: io::Error,
}

impl std::fmt::Display for NvmmError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} failed: {}", self.op, self.errno)
    }
}

impl std::error::Error for NvmmError {}

fn check(op: &'static str, rc: c_int) -> NvmmResult<()> {
    if rc == 0 {
        Ok(())
    } else {
        Err(NvmmError {
            op,
            errno: io::Error::last_os_error(),
        })
    }
}

/// Initialize NVMM (opens `/dev/nvmm`). Must be called once before any other
/// NVMM op. If this returns ENXIO ("Device not configured"), `modload nvmm`.
pub fn init() -> NvmmResult<()> {
    // SAFETY: no arguments; libnvmm performs the device open.
    check("nvmm_init", unsafe { nvmm_init() })
}

/// Query the NVMM capability scalars.
pub fn capability() -> NvmmResult<NvmmCapability> {
    let mut raw = NvmmCapabilityRaw::zeroed();
    // SAFETY: `raw` is a valid, sized output buffer.
    check("nvmm_capability", unsafe { nvmm_capability(&mut raw) })?;
    Ok(NvmmCapability {
        version: raw.version,
        state_size: raw.state_size,
        max_machines: raw.max_machines,
        max_vcpus: raw.max_vcpus,
        max_ram: raw.max_ram,
    })
}

/// An NVMM virtual machine (RAII: `nvmm_machine_destroy` on drop).
pub struct NvmmMachine {
    raw: Box<NvmmMachineRaw>,
}

impl NvmmMachine {
    /// Create a fresh machine.
    pub fn create() -> NvmmResult<Self> {
        let mut raw = Box::new(NvmmMachineRaw::zeroed());
        // SAFETY: `raw` is a valid, owned, sized machine struct; libnvmm
        // initializes its fields.
        check("nvmm_machine_create", unsafe {
            nvmm_machine_create(raw.as_mut())
        })?;
        Ok(NvmmMachine { raw })
    }

    pub fn machid(&self) -> u32 {
        self.raw.machid
    }

    fn raw_mut(&mut self) -> *mut NvmmMachineRaw {
        self.raw.as_mut()
    }

    /// `mmap` an anonymous region, register it as a shareable HVA via
    /// `nvmm_hva_map`, then link it into the guest physical space at `gpa` via
    /// `nvmm_gpa_map`. Returns the host pointer to the region (the HVA), which
    /// the caller may read/write directly to populate/observe guest RAM.
    ///
    /// `size` must be page-multiple. The region is leaked for the machine's
    /// lifetime (M0 simplicity; M1+ will track it for COW fork).
    pub fn map_guest_ram(&mut self, gpa: u64, size: usize, prot: c_int) -> NvmmResult<*mut u8> {
        // SAFETY: standard anonymous mmap; checked for MAP_FAILED below.
        let hva = unsafe {
            libc::mmap(
                ptr::null_mut(),
                size,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_ANON | libc::MAP_PRIVATE,
                -1,
                0,
            )
        };
        if hva == libc::MAP_FAILED {
            return Err(NvmmError {
                op: "mmap",
                errno: io::Error::last_os_error(),
            });
        }
        let hva_addr = hva as usize;
        let m = self.raw_mut();
        // SAFETY: `hva_addr`/`size` describe the region just mmaped; `m` is a
        // live machine. nvmm_hva_map makes the area shareable (rw, not exec).
        if let Err(e) = check("nvmm_hva_map", unsafe { nvmm_hva_map(m, hva_addr, size) }) {
            // SAFETY: unmap the region we just created on the error path.
            unsafe {
                libc::munmap(hva, size);
            }
            return Err(e);
        }
        // SAFETY: `hva_addr` was registered via nvmm_hva_map above; this links
        // it into the guest physical space at `gpa` with the given prot.
        if let Err(e) = check("nvmm_gpa_map", unsafe {
            nvmm_gpa_map(m, hva_addr, gpa, size, prot)
        }) {
            // SAFETY: best-effort teardown; ignore errors on the failure path.
            unsafe {
                nvmm_hva_unmap(m, hva_addr, size);
                libc::munmap(hva, size);
            }
            return Err(e);
        }
        Ok(hva as *mut u8)
    }

    /// Create vCPU 0 (or `cpuid`) in this machine.
    pub fn create_vcpu(&mut self, cpuid: u32) -> NvmmResult<NvmmVcpu> {
        let mut raw = Box::new(NvmmVcpuRaw::zeroed());
        let m = self.raw_mut();
        // SAFETY: `m` is a live machine; `raw` is a valid, owned vCPU struct
        // that libnvmm initializes (incl mapping the comm page + filling the
        // state/exit pointers).
        check("nvmm_vcpu_create", unsafe {
            nvmm_vcpu_create(m, cpuid, raw.as_mut())
        })?;
        Ok(NvmmVcpu {
            mach: m,
            raw,
            destroyed: false,
        })
    }
}

impl Drop for NvmmMachine {
    fn drop(&mut self) {
        // SAFETY: `raw` is a live machine owned by this struct; destroy it.
        unsafe {
            nvmm_machine_destroy(self.raw.as_mut());
        }
    }
}

/// An NVMM virtual CPU (RAII: `nvmm_vcpu_destroy` on drop).
///
/// Holds a raw pointer back to the owning machine's struct so getstate/setstate
/// /run/destroy can be issued. The `NvmmMachine` must outlive the `NvmmVcpu`
/// (enforced by usage: the vCPU is created from and used alongside the machine).
pub struct NvmmVcpu {
    mach: *mut NvmmMachineRaw,
    raw: Box<NvmmVcpuRaw>,
    destroyed: bool,
}

impl NvmmVcpu {
    /// Fetch the requested state sub-areas from the kernel into the comm page,
    /// then return a copy of the full state struct.
    ///
    /// Takes `&self` (the idiomatic FFI-handle pattern): `nvmm_vcpu_getstate`
    /// mutates only the kernel-owned comm page reached through the interior
    /// `raw.state` pointer — it does not mutate any Rust-visible field of
    /// `NvmmVcpuRaw` that a concurrent `&self` reader would observe. This lets
    /// the `&self` register getters on the `carrick_x86::X86Vcpu` impl read state
    /// without an unsound `&self`→`&mut` transmute. (libnvmm is not thread-safe
    /// per-vCPU, but a single vCPU is only ever driven from its owning thread.)
    pub fn get_state(&self, flags: u64) -> NvmmResult<NvmmX64State> {
        // SAFETY: the C API takes `*mut nvmm_vcpu`; the boxed `raw` is a valid,
        // owned vCPU struct and the call mutates only the kernel comm page.
        let raw = self.raw.as_ref() as *const NvmmVcpuRaw as *mut NvmmVcpuRaw;
        // SAFETY: `mach`/`raw` are live; getstate fills the comm-page state.
        check("nvmm_vcpu_getstate", unsafe {
            nvmm_vcpu_getstate(self.mach, raw, flags)
        })?;
        let state_ptr = self.raw.state;
        debug_assert!(!state_ptr.is_null(), "comm-page state pointer is NULL");
        // SAFETY: libnvmm initialized `state` to the comm page in
        // nvmm_vcpu_create; it is a valid, aligned NvmmX64State.
        Ok(unsafe { *state_ptr })
    }

    /// Write `state` into the comm page and push the requested sub-areas into
    /// the kernel via `nvmm_vcpu_setstate`.
    pub fn set_state(&mut self, state: &NvmmX64State, flags: u64) -> NvmmResult<()> {
        let state_ptr = self.raw.state;
        debug_assert!(!state_ptr.is_null(), "comm-page state pointer is NULL");
        // SAFETY: copy the caller's state into the comm page, then push.
        unsafe {
            *state_ptr = *state;
        }
        // SAFETY: `mach`/`raw` are live; setstate reads the comm-page state.
        check("nvmm_vcpu_setstate", unsafe {
            nvmm_vcpu_setstate(self.mach, self.raw.as_mut(), flags)
        })
    }

    /// Run the vCPU until a VM exit. The exit info is filled into the comm-page
    /// exit struct; a copy is returned. (Named `run_until_exit` to avoid clashing
    /// with the `carrick_x86::X86Vcpu::run` trait method that wraps it.)
    pub fn run_until_exit(&mut self) -> NvmmResult<NvmmX86Exit> {
        // SAFETY: `mach`/`raw` are live; run fills the comm-page exit struct.
        check("nvmm_vcpu_run", unsafe {
            nvmm_vcpu_run(self.mach, self.raw.as_mut())
        })?;
        let exit_ptr = self.raw.exit;
        debug_assert!(!exit_ptr.is_null(), "comm-page exit pointer is NULL");
        // SAFETY: libnvmm initialized `exit` to the comm page; valid+aligned.
        Ok(unsafe { *exit_ptr })
    }

    pub fn cpuid(&self) -> u32 {
        self.raw.cpuid
    }
}

impl Drop for NvmmVcpu {
    fn drop(&mut self) {
        if !self.destroyed {
            // SAFETY: `mach`/`raw` are live and not yet destroyed.
            unsafe {
                nvmm_vcpu_destroy(self.mach, self.raw.as_mut());
            }
        }
    }
}
