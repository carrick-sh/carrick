//! `NvmmMachine` / `NvmmVcpu`: the raw-hypervisor layer on NetBSD/NVMM via the
//! userspace **libnvmm** (`/usr/lib/libnvmm.so`). The KVM analog is
//! `carrick-vmm-kvm::kvm`; the bhyve analog is `carrick-vmm-bhyve::vmm`.
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

use std::cell::UnsafeCell;
use std::io;
use std::ptr;
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicBool, AtomicU32, Ordering},
};

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
        let mut bytes = [0u8; 512];
        bytes[0..2].copy_from_slice(&0x037f_u16.to_le_bytes());
        bytes[24..28].copy_from_slice(&0x1f80_u32.to_le_bytes());
        bytes[28..32].copy_from_slice(&0xffbf_u32.to_le_bytes());
        Fxsave { bytes }
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

/// `struct nvmm_x86_exit_memory` (32 bytes).
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct NvmmX86ExitMemory {
    pub prot: c_int,
    _pad0: u32,
    pub gpa: u64,
    pub inst_len: u8,
    pub inst_bytes: [u8; 15],
}

const _: () = assert!(std::mem::size_of::<NvmmX86ExitMemory>() == 32);

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
    /// Reinterpret the union as the memory-exit member. Only valid when
    /// `reason == NVMM_VCPU_EXIT_MEMORY`.
    pub fn mem(&self) -> NvmmX86ExitMemory {
        // SAFETY: `nvmm_x86_exit_memory` exactly matches the 32-byte union blob
        // and shares the union's start offset; only call when reason == MEMORY.
        unsafe { ptr::read_unaligned(self.u.as_ptr() as *const NvmmX86ExitMemory) }
    }

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
    if rc == 0 { Ok(()) } else { Err(last_error(op)) }
}

fn last_error(op: &'static str) -> NvmmError {
    NvmmError {
        op,
        errno: io::Error::last_os_error(),
    }
}

fn invalid_error(op: &'static str) -> NvmmError {
    NvmmError {
        op,
        errno: io::Error::from_raw_os_error(libc::EINVAL),
    }
}

/// Host backing policy for an NVMM guest RAM region.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NvmmRamBacking {
    /// Per-process anonymous COW backing.
    Private,
    /// Fork-shared file-backed mapping. NetBSD `__futex` does not rendezvous
    /// across `MAP_SHARED|MAP_ANON`, so shared guest futex pages need this.
    Shared,
}

fn map_private_host_ram(size: usize) -> NvmmResult<*mut c_void> {
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
        Err(last_error("mmap"))
    } else {
        Ok(hva)
    }
}

fn map_shared_host_ram(size: usize) -> NvmmResult<*mut c_void> {
    let Ok(file_len) = libc::off_t::try_from(size) else {
        return Err(invalid_error("ftruncate"));
    };

    let mut template = *b"/tmp/carrick-nvmm-ram.XXXXXX\0";
    // SAFETY: mkstemp mutates the template in place and returns an owned fd.
    let fd = unsafe { libc::mkstemp(template.as_mut_ptr().cast::<libc::c_char>()) };
    if fd < 0 {
        return Err(last_error("mkstemp"));
    }

    // SAFETY: unlink the just-created path; the fd keeps the object alive.
    if unsafe { libc::unlink(template.as_ptr().cast::<libc::c_char>()) } != 0 {
        let err = last_error("unlink");
        // SAFETY: best-effort cleanup for the owned fd.
        unsafe {
            libc::close(fd);
        }
        return Err(err);
    }
    // SAFETY: size the temporary backing file before mmap.
    if unsafe { libc::ftruncate(fd, file_len) } != 0 {
        let err = last_error("ftruncate");
        // SAFETY: best-effort cleanup for the owned fd.
        unsafe {
            libc::close(fd);
        }
        return Err(err);
    }

    // SAFETY: map the unlinked temporary file; checked for MAP_FAILED below.
    let hva = unsafe {
        libc::mmap(
            ptr::null_mut(),
            size,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_SHARED,
            fd,
            0,
        )
    };
    if hva == libc::MAP_FAILED {
        let err = last_error("mmap");
        // SAFETY: best-effort cleanup for the owned fd.
        unsafe {
            libc::close(fd);
        }
        return Err(err);
    }

    // SAFETY: the mmap now owns a reference to the file object; close the fd.
    if unsafe { libc::close(fd) } != 0 {
        let err = last_error("close");
        // SAFETY: unmap the region on the error path.
        unsafe {
            libc::munmap(hva, size);
        }
        return Err(err);
    }

    Ok(hva)
}

fn map_host_ram(size: usize, backing: NvmmRamBacking) -> NvmmResult<*mut c_void> {
    match backing {
        NvmmRamBacking::Private => map_private_host_ram(size),
        NvmmRamBacking::Shared => map_shared_host_ram(size),
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

struct NvmmMachineInner {
    raw: UnsafeCell<NvmmMachineRaw>,
    destroyed: AtomicBool,
    next_cpuid: AtomicU32,
    op_lock: Mutex<()>,
}

// SAFETY: `raw` is a libnvmm handle for a process-owned VM. Mutating libnvmm
// metadata calls (`vcpu_create/destroy`, `hva_map`, `gpa_map`, destroy) take
// `op_lock`; concurrent vCPU getstate/run calls use distinct comm pages.
unsafe impl Send for NvmmMachineInner {}
unsafe impl Sync for NvmmMachineInner {}

impl NvmmMachineInner {
    fn raw_ptr(&self) -> *mut NvmmMachineRaw {
        self.raw.get()
    }

    fn destroy_in_place(&self) {
        if self.destroyed.swap(true, Ordering::AcqRel) {
            return;
        }
        let _guard = self.op_lock.lock().unwrap_or_else(|e| e.into_inner());
        // SAFETY: `raw` is the live machine for this handle and destruction is
        // one-shot via `destroyed`.
        unsafe {
            nvmm_machine_destroy(self.raw_ptr());
        }
    }

    fn bump_next_cpuid_past(&self, cpuid: u32) {
        let target = cpuid.saturating_add(1);
        let mut current = self.next_cpuid.load(Ordering::Relaxed);
        while current < target {
            match self.next_cpuid.compare_exchange_weak(
                current,
                target,
                Ordering::Relaxed,
                Ordering::Relaxed,
            ) {
                Ok(_) => break,
                Err(next) => current = next,
            }
        }
    }
}

impl Drop for NvmmMachineInner {
    fn drop(&mut self) {
        self.destroy_in_place();
    }
}

/// An NVMM virtual machine (RAII: `nvmm_machine_destroy` when the last VM/vCPU
/// handle drops).
#[derive(Clone)]
pub struct NvmmMachine {
    inner: Arc<NvmmMachineInner>,
}

impl NvmmMachine {
    /// Create a fresh machine.
    pub fn create() -> NvmmResult<Self> {
        let mut raw = NvmmMachineRaw::zeroed();
        // SAFETY: `raw` is a valid, owned, sized machine struct; libnvmm
        // initializes its fields.
        check("nvmm_machine_create", unsafe {
            nvmm_machine_create(&mut raw)
        })?;
        Ok(NvmmMachine {
            inner: Arc::new(NvmmMachineInner {
                raw: UnsafeCell::new(raw),
                destroyed: AtomicBool::new(false),
                next_cpuid: AtomicU32::new(0),
                op_lock: Mutex::new(()),
            }),
        })
    }

    pub fn machid(&self) -> u32 {
        // SAFETY: `machid` is immutable after `nvmm_machine_create`.
        unsafe { (*self.inner.raw_ptr()).machid }
    }

    /// Prevent Drop from destroying this machine. Used in a `fork(2)` child for
    /// inherited parent handles: the child owns duplicated userspace structs, but
    /// `nvmm_machine_destroy` addresses the parent-visible kernel machine.
    pub(crate) fn disarm_destroy(&mut self) {
        self.inner.destroyed.store(true, Ordering::Release);
    }

    /// Destroy the machine now and make later Drop a no-op.
    pub(crate) fn destroy_in_place(&mut self) {
        self.inner.destroy_in_place();
    }

    /// `mmap` a private anonymous region, register it as a shareable HVA via
    /// `nvmm_hva_map`, then link it into the guest physical space at `gpa` via
    /// `nvmm_gpa_map`. Returns the host pointer to the region (the HVA), which
    /// the caller may read/write directly to populate/observe guest RAM.
    ///
    /// `size` must be page-multiple. The region is leaked for the machine's
    /// lifetime (M0 simplicity; M1+ will track it for COW fork).
    pub fn map_guest_ram(&mut self, gpa: u64, size: usize, prot: c_int) -> NvmmResult<*mut u8> {
        self.map_guest_ram_with_backing(gpa, size, prot, NvmmRamBacking::Private)
    }

    /// Variant of [`Self::map_guest_ram`] that preserves shared/private host
    /// backing intent from the generic x86 window plan.
    pub fn map_guest_ram_with_backing(
        &mut self,
        gpa: u64,
        size: usize,
        prot: c_int,
        backing: NvmmRamBacking,
    ) -> NvmmResult<*mut u8> {
        let hva = map_host_ram(size, backing)?;
        let hva_addr = hva as usize;
        let _guard = self.inner.op_lock.lock().unwrap_or_else(|e| e.into_inner());
        let m = self.inner.raw_ptr();
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

    /// Register a host RAM arena with NVMM without mapping it to guest physical
    /// memory yet. Later `nvmm_gpa_map` calls may target page-aligned subranges
    /// of this HVA; NetBSD's NVMM resolves those subranges back to the arena's
    /// one host-mapping slot.
    pub(crate) fn map_registered_ram_arena(
        &mut self,
        size: usize,
        backing: NvmmRamBacking,
    ) -> NvmmResult<*mut u8> {
        let hva = map_host_ram(size, backing)?;
        let hva_addr = hva as usize;
        let _guard = self.inner.op_lock.lock().unwrap_or_else(|e| e.into_inner());
        let m = self.inner.raw_ptr();
        if let Err(e) = check("nvmm_hva_map", unsafe { nvmm_hva_map(m, hva_addr, size) }) {
            // SAFETY: unmap the region we just created on the error path.
            unsafe {
                libc::munmap(hva, size);
            }
            return Err(e);
        }
        Ok(hva.cast::<u8>())
    }

    /// Link a page-aligned range from a previously registered HVA arena into
    /// guest physical memory.
    pub(crate) fn map_registered_host_ram(
        &mut self,
        hva: *mut u8,
        gpa: u64,
        size: usize,
        prot: c_int,
    ) -> NvmmResult<()> {
        let hva_addr = hva as usize;
        let _guard = self.inner.op_lock.lock().unwrap_or_else(|e| e.into_inner());
        let m = self.inner.raw_ptr();
        check("nvmm_gpa_map", unsafe {
            nvmm_gpa_map(m, hva_addr, gpa, size, prot)
        })
    }

    /// Register an already-mapped host RAM window with this fresh machine and
    /// link it into guest physical space at `gpa`. The caller retains ownership
    /// of the HVA mapping; failures only unregister from NVMM, never `munmap`.
    pub(crate) fn map_existing_host_ram(
        &mut self,
        hva: *mut u8,
        gpa: u64,
        size: usize,
        prot: c_int,
    ) -> NvmmResult<()> {
        let hva_addr = hva as usize;
        let _guard = self.inner.op_lock.lock().unwrap_or_else(|e| e.into_inner());
        let m = self.inner.raw_ptr();
        // SAFETY: `hva_addr`/`size` describe a live inherited host mapping; `m`
        // is a live fresh machine.
        if let Err(e) = check("nvmm_hva_map", unsafe { nvmm_hva_map(m, hva_addr, size) }) {
            return Err(e);
        }
        // SAFETY: `hva_addr` was registered with this machine above.
        if let Err(e) = check("nvmm_gpa_map", unsafe {
            nvmm_gpa_map(m, hva_addr, gpa, size, prot)
        }) {
            // SAFETY: best-effort teardown of this machine's HVA registration.
            unsafe {
                nvmm_hva_unmap(m, hva_addr, size);
            }
            return Err(e);
        }
        Ok(())
    }

    /// Create vCPU 0 (or `cpuid`) in this machine.
    pub fn create_vcpu(&self, cpuid: u32) -> NvmmResult<NvmmVcpu> {
        let mut raw = Box::new(NvmmVcpuRaw::zeroed());
        let _guard = self.inner.op_lock.lock().unwrap_or_else(|e| e.into_inner());
        let m = self.inner.raw_ptr();
        // SAFETY: `m` is a live machine; `raw` is a valid, owned vCPU struct
        // that libnvmm initializes (incl mapping the comm page + filling the
        // state/exit pointers).
        check("nvmm_vcpu_create", unsafe {
            nvmm_vcpu_create(m, cpuid, raw.as_mut())
        })?;
        self.inner.bump_next_cpuid_past(cpuid);
        Ok(NvmmVcpu {
            mach: Arc::clone(&self.inner),
            raw,
            destroyed: false,
        })
    }

    /// Create a fresh sibling vCPU on this same machine with a unique cpuid.
    pub fn create_sibling_vcpu(&self) -> NvmmResult<NvmmVcpu> {
        let cpuid = self.inner.next_cpuid.fetch_add(1, Ordering::SeqCst);
        self.create_vcpu(cpuid)
    }
}

#[cfg(test)]
mod tests {
    use super::{Fxsave, NvmmRamBacking, map_host_ram};
    use std::sync::atomic::{AtomicU32, Ordering};

    const SYS___FUTEX: libc::c_int = 166;

    #[test]
    fn fxsave_default_matches_x86_reset_masks() {
        let fx = Fxsave::default();
        let fcw = u16::from_le_bytes([fx.bytes[0], fx.bytes[1]]);
        let mxcsr = u32::from_le_bytes([fx.bytes[24], fx.bytes[25], fx.bytes[26], fx.bytes[27]]);
        let mxcsr_mask =
            u32::from_le_bytes([fx.bytes[28], fx.bytes[29], fx.bytes[30], fx.bytes[31]]);

        assert_eq!(fcw, 0x037f, "x87 control word should mask exceptions");
        assert_eq!(mxcsr, 0x1f80, "MXCSR should mask SIMD FP exceptions");
        assert_eq!(
            mxcsr_mask, 0xffbf,
            "MXCSR_MASK must preserve the initial mask bits through NVMM"
        );
    }

    fn futex_wait(host_addr: usize, value: u32) -> i64 {
        let ts = libc::timespec {
            tv_sec: 2,
            tv_nsec: 0,
        };
        // SAFETY: raw NetBSD __futex wait on a live 4-byte shared word.
        let rc = unsafe {
            libc::syscall(
                SYS___FUTEX,
                host_addr as *mut libc::c_int,
                libc::FUTEX_WAIT,
                value as libc::c_int,
                &ts as *const libc::timespec,
                std::ptr::null_mut::<libc::c_int>(),
                0 as libc::c_int,
                0 as libc::c_int,
            )
        };
        if rc < 0 {
            let e = std::io::Error::last_os_error()
                .raw_os_error()
                .unwrap_or(libc::EINVAL);
            -i64::from(e)
        } else {
            rc as i64
        }
    }

    fn futex_wake(host_addr: usize) -> i64 {
        // SAFETY: raw NetBSD __futex wake on a live 4-byte shared word.
        let rc = unsafe {
            libc::syscall(
                SYS___FUTEX,
                host_addr as *mut libc::c_int,
                libc::FUTEX_WAKE,
                1 as libc::c_int,
                std::ptr::null::<libc::timespec>(),
                std::ptr::null_mut::<libc::c_int>(),
                0 as libc::c_int,
                0 as libc::c_int,
            )
        };
        if rc < 0 {
            let e = std::io::Error::last_os_error()
                .raw_os_error()
                .unwrap_or(libc::EINVAL);
            -i64::from(e)
        } else {
            rc as i64
        }
    }

    #[test]
    fn shared_host_ram_mapping_wakes_across_fork_with_netbsd_futex() {
        let page = map_host_ram(4096, NvmmRamBacking::Shared).expect("shared host RAM");
        let word = unsafe { &*(page as *const AtomicU32) };
        word.store(0, Ordering::SeqCst);
        let addr = page as usize;

        let pid = unsafe { libc::fork() };
        assert!(pid >= 0, "fork failed");
        if pid == 0 {
            std::thread::sleep(std::time::Duration::from_millis(50));
            word.store(1, Ordering::SeqCst);
            let rc = futex_wake(addr);
            unsafe { libc::_exit(if rc == 1 { 0 } else { 10 }) };
        }

        let rc = futex_wait(addr, 0);
        let observed = word.load(Ordering::SeqCst);
        let mut status = 0;
        unsafe {
            libc::waitpid(pid, &mut status, 0);
            libc::munmap(page, 4096);
        }

        assert_eq!(rc, 0, "parent wait should be woken");
        assert_eq!(status, 0, "child wake should report one waiter");
        assert_eq!(observed, 1);
    }
}

/// An NVMM virtual CPU (RAII: `nvmm_vcpu_destroy` on drop).
///
/// Holds a raw pointer back to the owning machine's struct so getstate/setstate
/// /run/destroy can be issued. The `NvmmMachine` must outlive the `NvmmVcpu`
/// (enforced by usage: the vCPU is created from and used alongside the machine).
pub struct NvmmVcpu {
    mach: Arc<NvmmMachineInner>,
    raw: Box<NvmmVcpuRaw>,
    destroyed: bool,
}

impl NvmmVcpu {
    /// Prevent Drop from destroying this vCPU. Used in a `fork(2)` child for an
    /// inherited parent vCPU whose kernel object still belongs to the parent.
    pub(crate) fn disarm_destroy(&mut self) {
        self.destroyed = true;
    }

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
            nvmm_vcpu_getstate(self.mach.raw_ptr(), raw, flags)
        })?;
        let state_ptr = self.raw.state;
        debug_assert!(!state_ptr.is_null(), "comm-page state pointer is NULL");
        // SAFETY: libnvmm initialized `state` to the comm page in
        // nvmm_vcpu_create; it is a valid, aligned NvmmX64State.
        Ok(unsafe { *state_ptr })
    }

    /// Write `state` into the comm page and push the requested sub-areas into
    /// the kernel via `nvmm_vcpu_setstate`.
    pub fn set_state(&self, state: &NvmmX64State, flags: u64) -> NvmmResult<()> {
        let state_ptr = self.raw.state;
        debug_assert!(!state_ptr.is_null(), "comm-page state pointer is NULL");
        // SAFETY: copy the caller's state into the comm page, then push.
        unsafe {
            *state_ptr = *state;
        }
        let raw = self.raw.as_ref() as *const NvmmVcpuRaw as *mut NvmmVcpuRaw;
        // SAFETY: `mach`/`raw` are live; setstate reads the comm-page state.
        check("nvmm_vcpu_setstate", unsafe {
            nvmm_vcpu_setstate(self.mach.raw_ptr(), raw, flags)
        })
    }

    /// Run the vCPU until a VM exit. The exit info is filled into the comm-page
    /// exit struct; a copy is returned. (Named `run_until_exit` to avoid clashing
    /// with the `carrick_x86::X86Vcpu::run` trait method that wraps it.)
    pub fn run_until_exit(&mut self) -> NvmmResult<NvmmX86Exit> {
        // SAFETY: `mach`/`raw` are live; run fills the comm-page exit struct.
        check("nvmm_vcpu_run", unsafe {
            nvmm_vcpu_run(self.mach.raw_ptr(), self.raw.as_mut())
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
            let _guard = self.mach.op_lock.lock().unwrap_or_else(|e| e.into_inner());
            if !self.mach.destroyed.load(Ordering::Acquire) {
                // SAFETY: `mach`/`raw` are live and not yet destroyed.
                unsafe {
                    nvmm_vcpu_destroy(self.mach.raw_ptr(), self.raw.as_mut());
                }
            }
            self.destroyed = true;
        }
    }
}
