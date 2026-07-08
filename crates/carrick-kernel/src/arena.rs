//! The kernel arena: one file-backed `MAP_SHARED` region per run, mapped
//! before the first guest fork and inherited by every descendant. Fixed
//! `#[repr(C)]` layout; version-stamped header published magic-last; all
//! cross-process access is atomics plus robust locks for multi-record sections.

use std::os::unix::ffi::OsStrExt;
use std::path::Path;
use std::sync::OnceLock;
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};

use crate::domains::{HostPid, ProcessGeneration};
use crate::process::ProcessSection;

pub const ARENA_MAGIC: u32 = 0x434b_4131;
pub const ARENA_VERSION: u32 = 3;
pub const ARENA_PATH_ENV: &str = "CARRICK_KERNEL_ARENA";

/// Permit-section constants. These must stay byte-identical to the landed
/// `SharedPermitTable` in `carrick-vmm-hvf/src/trap.rs`: magic "CRP1",
/// version 1, 128 slots. A later task swaps the trap code onto this section.
pub const PERMIT_MAGIC: u32 = 0x4352_5031;
pub const PERMIT_VERSION: u32 = 1;
pub const PERMIT_MAX_SLOTS: usize = 128;
static ARENA_FILE_COUNTER: AtomicU64 = AtomicU64::new(0);

#[repr(C)]
pub struct ArenaHeader {
    pub magic: AtomicU32,
    pub version: AtomicU32,
    pub next_generation: AtomicU32,
    _pad: AtomicU32,
    pub run_token: AtomicU64,
}

#[repr(C)]
pub struct PermitSection {
    pub magic: AtomicU32,
    pub version: AtomicU32,
    pub next_generation: AtomicU32,
    pub slots: [AtomicU64; PERMIT_MAX_SLOTS],
}

#[repr(C)]
pub struct ArenaLayout {
    pub header: ArenaHeader,
    pub permits: PermitSection,
    pub processes: ProcessSection,
    /// Resident-VM slot table: one generation-stamped slot per LIVE HVF VM
    /// (claimed on `hv_vm_create`, freed on `hv_vm_destroy`, death-reclaimed
    /// by the vcpu-permit reaper). Same byte layout and slot protocol as
    /// `permits`; consumed by `carrick-vmm-hvf/src/trap.rs::vm_residency_region`.
    /// Exists because vCPU-admission permits UNDER-REPORT residency: a
    /// vCPU-only park frees its permit while keeping its VM
    /// (docs/2026-07-09-mt-residency-lease-evidence.md, Next Track 1).
    pub vm_slots: PermitSection,
}

#[derive(Debug)]
pub enum ArenaError {
    /// A fixed-capacity section is full. There is no silent process-local
    /// fallback; callers translate this into a Linux errno plus diagnostics.
    Exhausted {
        section: &'static str,
        capacity: usize,
    },
}

impl PermitSection {
    const STATE_ACQUIRING: u64 = 1 << 62;

    fn pack(pid: HostPid, generation: ProcessGeneration) -> u64 {
        Self::STATE_ACQUIRING
            | ((u64::from(generation.raw()) & ((1u64 << 30) - 1)) << 32)
            | u64::from(pid.raw())
    }

    pub fn try_claim_slot(
        &self,
        pid: HostPid,
        generation: ProcessGeneration,
    ) -> Result<usize, ArenaError> {
        let packed = Self::pack(pid, generation);
        for (i, slot) in self.slots.iter().enumerate() {
            if slot
                .compare_exchange(0, packed, Ordering::SeqCst, Ordering::Relaxed)
                .is_ok()
            {
                return Ok(i);
            }
        }
        Err(ArenaError::Exhausted {
            section: "permits",
            capacity: PERMIT_MAX_SLOTS,
        })
    }
}

pub struct KernelArena {
    base: usize,
    _fd: libc::c_int,
}

// SAFETY: `base` points at a process-lifetime MAP_SHARED mapping; shared
// mutation goes through atomics.
unsafe impl Send for KernelArena {}
// SAFETY: same as Send; the layout uses atomics for shared state.
unsafe impl Sync for KernelArena {}

impl KernelArena {
    /// Create the region as an unlinked temp file, ftruncate it to the fixed
    /// layout size, and publish the header magic last.
    pub fn create() -> std::io::Result<KernelArena> {
        let serial = ARENA_FILE_COUNTER.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "carrick-kernel-arena-{}-{serial}",
            std::process::id()
        ));
        Self::create_with_path(&path, true)
    }

    /// Create the arena at a stable path so later `carrick exec` processes can
    /// attach to the same run-scoped region. The file is left linked on
    /// success and created with `O_EXCL` so callers never attach stale state by
    /// accident.
    pub fn create_at(path: &Path) -> std::io::Result<KernelArena> {
        Self::create_with_path(path, false)
    }

    /// Attach to an existing arena and fail closed on layout mismatch.
    pub fn attach(path: &Path) -> std::io::Result<KernelArena> {
        let size = std::mem::size_of::<ArenaLayout>();
        let cpath = std::ffi::CString::new(path.as_os_str().as_bytes())
            .map_err(|_| std::io::Error::other("arena path contains NUL"))?;

        let fd = unsafe { libc::open(cpath.as_ptr(), libc::O_RDWR) };
        if fd < 0 {
            return Err(std::io::Error::last_os_error());
        }

        let mut stat = std::mem::MaybeUninit::<libc::stat>::uninit();
        if unsafe { libc::fstat(fd, stat.as_mut_ptr()) } != 0 {
            let err = std::io::Error::last_os_error();
            unsafe {
                libc::close(fd);
            }
            return Err(err);
        }
        let stat = unsafe { stat.assume_init() };
        if stat.st_size < size as libc::off_t {
            unsafe {
                libc::close(fd);
            }
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "kernel arena file is too small",
            ));
        }

        let base = match Self::map_file(fd, size) {
            Ok(base) => base,
            Err(err) => {
                unsafe {
                    libc::close(fd);
                }
                return Err(err);
            }
        };
        let arena = KernelArena { base, _fd: fd };
        let layout = arena.layout();
        let magic = layout.header.magic.load(Ordering::Acquire);
        let version = layout.header.version.load(Ordering::Acquire);
        if magic != ARENA_MAGIC || version != ARENA_VERSION {
            unsafe {
                libc::munmap(base as *mut libc::c_void, size);
                libc::close(fd);
            }
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "kernel arena magic/version mismatch",
            ));
        }
        Ok(arena)
    }

    /// Process-wide singleton. Must be initialized before the first guest fork;
    /// repeated calls return the same inherited mapping.
    #[allow(clippy::panic)]
    pub fn init_global() -> &'static KernelArena {
        static GLOBAL: OnceLock<KernelArena> = OnceLock::new();
        GLOBAL.get_or_init(|| match KernelArena::create_or_attach_from_env() {
            Ok(arena) => arena,
            Err(err) => {
                panic!("carrick-kernel arena creation failed: {err}");
            }
        })
    }

    pub fn global() -> &'static KernelArena {
        Self::init_global()
    }

    pub fn layout(&self) -> &ArenaLayout {
        unsafe { &*(self.base as *const ArenaLayout) }
    }

    fn create_or_attach_from_env() -> std::io::Result<KernelArena> {
        match std::env::var_os(ARENA_PATH_ENV) {
            Some(path) => {
                let path = Path::new(&path);
                if path.exists() {
                    Self::attach(path)
                } else {
                    Self::create_at(path)
                }
            }
            None => Self::create(),
        }
    }

    fn create_with_path(path: &Path, unlink_on_success: bool) -> std::io::Result<KernelArena> {
        let size = std::mem::size_of::<ArenaLayout>();
        let cpath = std::ffi::CString::new(path.as_os_str().as_bytes())
            .map_err(|_| std::io::Error::other("arena path contains NUL"))?;

        let fd = unsafe {
            libc::open(
                cpath.as_ptr(),
                libc::O_RDWR | libc::O_CREAT | libc::O_EXCL,
                0o600,
            )
        };
        if fd < 0 {
            return Err(std::io::Error::last_os_error());
        }

        if unsafe { libc::ftruncate(fd, size as libc::off_t) } != 0 {
            let err = std::io::Error::last_os_error();
            unsafe {
                libc::close(fd);
                libc::unlink(cpath.as_ptr());
            }
            return Err(err);
        }

        let base = match Self::map_file(fd, size) {
            Ok(base) => base,
            Err(err) => {
                unsafe {
                    libc::close(fd);
                    libc::unlink(cpath.as_ptr());
                }
                return Err(err);
            }
        };
        if unlink_on_success {
            unsafe {
                libc::unlink(cpath.as_ptr());
            }
        }

        let arena = KernelArena { base, _fd: fd };
        arena.publish_fresh_header();
        Ok(arena)
    }

    fn map_file(fd: libc::c_int, size: usize) -> std::io::Result<usize> {
        let ptr = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                size,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_SHARED,
                fd,
                0,
            )
        };
        if ptr == libc::MAP_FAILED {
            return Err(std::io::Error::last_os_error());
        }
        Ok(ptr as usize)
    }

    fn publish_fresh_header(&self) {
        let layout = self.layout();
        layout.header.next_generation.store(1, Ordering::Relaxed);
        layout
            .header
            .version
            .store(ARENA_VERSION, Ordering::Relaxed);
        layout.permits.next_generation.store(1, Ordering::Relaxed);
        layout
            .permits
            .version
            .store(PERMIT_VERSION, Ordering::Relaxed);
        layout.processes.next_ns_pid.store(2, Ordering::Relaxed);
        layout.vm_slots.next_generation.store(1, Ordering::Relaxed);
        layout
            .vm_slots
            .version
            .store(PERMIT_VERSION, Ordering::Relaxed);
        layout.vm_slots.magic.store(PERMIT_MAGIC, Ordering::Release);
        layout.permits.magic.store(PERMIT_MAGIC, Ordering::Release);
        layout.header.magic.store(ARENA_MAGIC, Ordering::Release);
    }

    /// Shared monotonic generation: 30-bit wrap, never 0.
    pub fn allocate_generation(&self) -> ProcessGeneration {
        loop {
            let generation = self
                .layout()
                .header
                .next_generation
                .fetch_add(1, Ordering::AcqRel)
                & ((1 << 30) - 1);
            if generation != 0 {
                return ProcessGeneration::new(generation);
            }
        }
    }
}

#[cfg(test)]
#[allow(clippy::panic, clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn create_publishes_versioned_header() {
        let arena = KernelArena::create().unwrap();
        let l = arena.layout();
        assert_eq!(
            l.header.magic.load(std::sync::atomic::Ordering::Acquire),
            ARENA_MAGIC
        );
        assert_eq!(
            l.header.version.load(std::sync::atomic::Ordering::Relaxed),
            ARENA_VERSION
        );
        assert_eq!(
            l.permits.magic.load(std::sync::atomic::Ordering::Acquire),
            0x4352_5031
        );
        assert_eq!(
            l.permits
                .next_generation
                .load(std::sync::atomic::Ordering::Relaxed),
            1
        );
        assert_eq!(
            l.processes
                .next_ns_pid
                .load(std::sync::atomic::Ordering::Relaxed),
            2
        );
    }

    #[test]
    fn generations_are_monotonic_and_skip_zero() {
        let arena = KernelArena::create().unwrap();
        let g1 = arena.allocate_generation();
        let g2 = arena.allocate_generation();
        assert_ne!(g1.raw(), 0);
        assert_ne!(g2.raw(), 0);
        assert_ne!(g1, g2);
    }

    #[test]
    fn arena_is_visible_across_fork() {
        let arena = KernelArena::create().unwrap();
        let l = arena.layout();
        let child = unsafe { libc::fork() };
        assert!(child >= 0);
        if child == 0 {
            l.header
                .run_token
                .store(0x5eed, std::sync::atomic::Ordering::Release);
            unsafe { libc::_exit(0) };
        }
        let mut status = 0;
        unsafe { libc::waitpid(child, &mut status, 0) };
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
        while l
            .header
            .run_token
            .load(std::sync::atomic::Ordering::Acquire)
            != 0x5eed
        {
            assert!(
                std::time::Instant::now() < deadline,
                "child write not visible"
            );
            std::thread::yield_now();
        }
    }

    #[test]
    fn permit_section_exhaustion_is_loud() {
        let arena = KernelArena::create().unwrap();
        let l = arena.layout();
        for i in 0..PERMIT_MAX_SLOTS {
            let claimed = l.permits.try_claim_slot(
                crate::domains::HostPid::new(100 + i as u32),
                arena.allocate_generation(),
            );
            assert!(claimed.is_ok(), "slot {i} should claim");
        }
        let full = l.permits.try_claim_slot(
            crate::domains::HostPid::new(9999),
            arena.allocate_generation(),
        );
        match full {
            Err(ArenaError::Exhausted { section, capacity }) => {
                assert_eq!(section, "permits");
                assert_eq!(capacity, PERMIT_MAX_SLOTS);
            }
            other => panic!("expected loud exhaustion, got {other:?}"),
        }
    }

    #[test]
    fn attach_joins_an_existing_arena() {
        let dir = std::env::temp_dir().join(format!("cka-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("arena");
        let a = KernelArena::create_at(&path).unwrap();
        a.layout()
            .header
            .run_token
            .store(77, std::sync::atomic::Ordering::Release);
        let b = KernelArena::attach(&path).unwrap();
        assert_eq!(
            b.layout()
                .header
                .run_token
                .load(std::sync::atomic::Ordering::Acquire),
            77
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn attach_rejects_wrong_magic() {
        let dir = std::env::temp_dir().join(format!("cka-badmagic-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("arena");
        std::fs::write(&path, vec![0u8; std::mem::size_of::<ArenaLayout>()]).unwrap();
        let e = KernelArena::attach(&path).err().unwrap();
        assert_eq!(e.kind(), std::io::ErrorKind::InvalidData);
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn vm_slots_section_is_published_and_independent() {
        let arena = KernelArena::create().unwrap();
        let l = arena.layout();
        assert_eq!(
            l.vm_slots.magic.load(std::sync::atomic::Ordering::Acquire),
            PERMIT_MAGIC
        );
        assert_eq!(
            l.vm_slots
                .next_generation
                .load(std::sync::atomic::Ordering::Relaxed),
            1
        );
        // Claiming in vm_slots must not consume permit slots (independent tables).
        let claimed = l.vm_slots.try_claim_slot(
            crate::domains::HostPid::new(42),
            arena.allocate_generation(),
        );
        assert!(claimed.is_ok());
        assert_eq!(
            l.permits.slots[claimed.unwrap()].load(std::sync::atomic::Ordering::SeqCst),
            0
        );
    }
}
