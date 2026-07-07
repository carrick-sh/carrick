//! The kernel arena: one file-backed `MAP_SHARED` region per run, mapped
//! before the first guest fork and inherited by every descendant. Fixed
//! `#[repr(C)]` layout; version-stamped header published magic-last; all
//! cross-process access is atomics plus robust locks for multi-record sections.

use std::os::unix::ffi::OsStrExt;
use std::sync::OnceLock;
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};

use crate::domains::{HostPid, ProcessGeneration};

pub const ARENA_MAGIC: u32 = 0x434b_4131;
pub const ARENA_VERSION: u32 = 1;

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
        let size = std::mem::size_of::<ArenaLayout>();
        let serial = ARENA_FILE_COUNTER.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "carrick-kernel-arena-{}-{serial}",
            std::process::id()
        ));
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

        let rc = unsafe { libc::ftruncate(fd, size as libc::off_t) };
        if rc != 0 {
            let err = std::io::Error::last_os_error();
            unsafe {
                libc::close(fd);
                libc::unlink(cpath.as_ptr());
            }
            return Err(err);
        }

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
        unsafe { libc::unlink(cpath.as_ptr()) };
        if ptr == libc::MAP_FAILED {
            let err = std::io::Error::last_os_error();
            unsafe {
                libc::close(fd);
            }
            return Err(err);
        }

        let arena = KernelArena {
            base: ptr as usize,
            _fd: fd,
        };
        let layout = arena.layout();
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
        layout.permits.magic.store(PERMIT_MAGIC, Ordering::Release);
        layout.header.magic.store(ARENA_MAGIC, Ordering::Release);
        Ok(arena)
    }

    /// Process-wide singleton. Must be initialized before the first guest fork;
    /// repeated calls return the same inherited mapping.
    #[allow(clippy::panic)]
    pub fn init_global() -> &'static KernelArena {
        static GLOBAL: OnceLock<KernelArena> = OnceLock::new();
        GLOBAL.get_or_init(|| match KernelArena::create() {
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
            std::process::exit(0);
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
}
