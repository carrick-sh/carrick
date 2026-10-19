//! Machine-neutral host-backed guest RAM.
use std::sync::{Arc, RwLock};

use carrick_hal::OsError;
#[cfg(target_arch = "aarch64")]
use carrick_mem::memory::LINUX_NULL_GUARD_END;
use carrick_mem::protections::MemoryProtections;

/// Guest-physical address the EL1 vector stores to on an EL0 `svc`.
pub const SENTINEL_GPA: u64 = 0x50_0000_0000; // 320 GiB

/// Guest-physical address the EL1 vector stores to on an EL0 *fault*.
pub const FAULT_SENTINEL_GPA: u64 = 0x51_0000_0000; // 324 GiB

/// Guest-physical address the EL1 stage-1 MAINTENANCE trampoline stores to once
/// it has flushed the stage-1 TLB.
pub const MAINT_SENTINEL_GPA: u64 = 0x52_0000_0000; // 328 GiB

/// Whether the host `mmap` backing a guest-physical window is shared across
/// `fork(2)` (`MAP_SHARED`) or copy-on-write snapshotted (`MAP_PRIVATE`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WindowKind {
    Private,
    Shared,
}

/// A `Send` descriptor of one host-backed guest window, used to hand a
/// `clone(CLONE_THREAD)` sibling a view of the SAME backing across host threads.
#[derive(Debug, Clone, Copy)]
pub struct WindowDesc {
    base: u64,
    host: usize,
    len: usize,
    kind: WindowKind,
    /// Alias windows: the hardware-slot GPA (differs from `base`). `None` for ordinary
    /// identity windows.
    slot_gpa: Option<u64>,
}

#[derive(Clone)]
pub struct SharedWindows(Arc<RwLock<Vec<WindowDesc>>>);

/// Multi-window host-backed guest RAM.
pub struct GuestRam {
    windows: Arc<RwLock<Vec<WindowDesc>>>,
    protections: Arc<MemoryProtections>,
    owns_windows: bool,
}

impl Drop for GuestRam {
    fn drop(&mut self) {
        if !self.owns_windows {
            return;
        }
        let mut windows = self.windows.write().unwrap_or_else(|e| e.into_inner());
        for w in windows.iter() {
            unsafe {
                libc::munmap((w.host as *mut u8).cast::<libc::c_void>(), w.len);
            }
        }
        windows.clear();
    }
}

impl GuestRam {
    pub fn new() -> Self {
        Self {
            windows: Arc::new(RwLock::new(Vec::new())),
            protections: Arc::new(MemoryProtections::default()),
            owns_windows: true,
        }
    }

    pub fn shared_protections(&self) -> Arc<MemoryProtections> {
        Arc::clone(&self.protections)
    }

    #[cfg(target_arch = "aarch64")]
    pub fn protections_ref(&self) -> &MemoryProtections {
        &self.protections
    }

    #[cfg(target_arch = "aarch64")]
    pub fn range_no_access(&self, gpa: u64, len: usize) -> bool {
        self.protections.range_no_access(gpa, len)
    }

    #[cfg(target_arch = "aarch64")]
    pub fn set_no_access(&self, gpa: u64, len: usize, no_access: bool) {
        self.protections.set_no_access(gpa, len, no_access);
    }

    pub fn add_window(&mut self, base: u64, len: usize, kind: WindowKind) -> Result<(), OsError> {
        if len == 0 {
            return Ok(());
        }
        let end = base
            .checked_add(len as u64)
            .ok_or_else(|| OsError::new(format!("guest_ram: window 0x{base:x}+{len} overflows")))?;
        if (base <= SENTINEL_GPA && SENTINEL_GPA < end)
            || (base <= FAULT_SENTINEL_GPA && FAULT_SENTINEL_GPA < end)
            || (base <= MAINT_SENTINEL_GPA && MAINT_SENTINEL_GPA < end)
        {
            return Err(OsError::new(format!(
                "guest_ram: window 0x{base:x}..0x{end:x} would back a sentinel gpa \
                 (syscall 0x{SENTINEL_GPA:x} / fault 0x{FAULT_SENTINEL_GPA:x} / \
                 maint 0x{MAINT_SENTINEL_GPA:x}); all must stay unmapped"
            )));
        }
        let mmap_flags = match kind {
            WindowKind::Private => libc::MAP_PRIVATE | libc::MAP_ANONYMOUS | libc::MAP_NORESERVE,
            WindowKind::Shared => libc::MAP_SHARED | libc::MAP_ANONYMOUS | libc::MAP_NORESERVE,
        };
        let host = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                len,
                libc::PROT_READ | libc::PROT_WRITE,
                mmap_flags,
                -1,
                0,
            )
        };
        if host == libc::MAP_FAILED {
            return Err(OsError::new(format!(
                "guest_ram: guest RAM mmap failed for 0x{base:x}+{len}"
            )));
        }
        self.windows
            .write()
            .unwrap_or_else(|e| e.into_inner())
            .push(WindowDesc {
                base,
                host: host.cast::<u8>() as usize,
                len,
                kind,
                slot_gpa: None,
            });
        Ok(())
    }

    pub fn locate(&self, gpa: u64, len: usize) -> Option<(WindowDesc, usize)> {
        self.windows
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .iter()
            .find_map(|w| {
                let off = gpa.checked_sub(w.base)?;
                ((off as usize).checked_add(len)? <= w.len).then_some((*w, off as usize))
            })
    }

    #[cfg(target_arch = "aarch64")]
    pub fn safe_access_translated_raw(
        &self,
        va: u64,
        ipa: u64,
        len: usize,
    ) -> Result<*mut u8, carrick_guest_mem::region::GuestAccessError> {
        if len > 0 && va < LINUX_NULL_GUARD_END {
            return Err(carrick_guest_mem::region::GuestAccessError::OutOfBounds);
        }
        let windows = self.windows.read().unwrap_or_else(|e| e.into_inner());
        carrick_guest_mem::region::safe_guest_access_translated_in(
            |_g, _l| false,
            windows
                .iter()
                .map(|w| carrick_guest_mem::region::GuestMemoryRegion {
                    base: w.base,
                    len: w.len,
                    host_addr: w.host as *mut u8,
                }),
            va,
            ipa,
            len,
        )
    }

    pub fn write_gpa(&mut self, gpa: u64, data: &[u8]) -> Result<(), OsError> {
        let (host, off) = {
            let (w, off) = self.locate(gpa, data.len()).ok_or_else(|| {
                OsError::new(format!("guest_ram: write gpa 0x{gpa:x} out of guest RAM"))
            })?;
            (w.host, off)
        };
        unsafe {
            std::ptr::copy_nonoverlapping(data.as_ptr(), (host as *mut u8).add(off), data.len());
        }
        Ok(())
    }

    pub fn read(&self, gpa: u64, len: usize) -> Result<Vec<u8>, OsError> {
        let (w, off) = self.locate(gpa, len).ok_or_else(|| {
            OsError::new(format!(
                "guest_ram: read gpa 0x{gpa:x}+{len} out of guest RAM"
            ))
        })?;
        let mut out = vec![0u8; len];
        unsafe {
            std::ptr::copy_nonoverlapping((w.host as *mut u8).add(off), out.as_mut_ptr(), len);
        }
        Ok(out)
    }

    #[cfg(target_arch = "aarch64")]
    pub fn debug_access(&self, gpa: u64, len: usize) -> String {
        let located = self.locate(gpa, len).is_some();
        let no_access = self.range_no_access(gpa, len);
        let near: Vec<String> = self
            .protections
            .snapshot()
            .into_iter()
            .filter(|&(s, e)| {
                e > gpa.saturating_sub(0x100_0000) && s < gpa.saturating_add(0x100_0000)
            })
            .map(|(s, e)| format!("[0x{s:x}..0x{e:x})"))
            .collect();
        let windows = self.windows.read().unwrap_or_else(|e| e.into_inner());
        let mut wins: Vec<String> = windows
            .iter()
            .map(|w| {
                format!(
                    "[0x{:x}..0x{:x} {:?}{}]",
                    w.base,
                    w.base + w.len as u64,
                    w.kind,
                    w.slot_gpa
                        .map(|g| format!(" slot_gpa=0x{g:x}"))
                        .unwrap_or_default()
                )
            })
            .collect();
        wins.sort();
        format!(
            "gpa=0x{gpa:x} len={len} located={located} no_access={no_access} \
             no_access_ranges_near={} windows({})={}",
            if near.is_empty() {
                "(none)".to_string()
            } else {
                near.join(" ")
            },
            windows.len(),
            wins.join(" ")
        )
    }

    pub fn host_ptr(&self, gpa: u64, len: usize) -> Option<*mut u8> {
        let (w, off) = self.locate(gpa, len)?;
        Some(unsafe { (w.host as *mut u8).add(off) })
    }

    pub fn shared_futex_host_addr(&self, gpa: u64, len: usize) -> Option<usize> {
        let (w, off) = self.locate(gpa, len)?;
        if w.kind != WindowKind::Shared {
            return None;
        }
        Some(unsafe { (w.host as *mut u8).add(off) } as usize)
    }

    pub fn slot_windows(&self) -> Vec<(u64, *mut u8, usize)> {
        self.windows
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .iter()
            .map(|w| (w.slot_gpa.unwrap_or(w.base), w.host as *mut u8, w.len))
            .collect()
    }

    pub fn shared_windows(&self) -> SharedWindows {
        SharedWindows(Arc::clone(&self.windows))
    }

    pub fn from_shared_windows(
        windows: SharedWindows,
        protections: Arc<MemoryProtections>,
    ) -> Self {
        Self {
            windows: windows.0,
            protections,
            owns_windows: false,
        }
    }

    pub fn window_kinds(&self) -> Vec<WindowKind> {
        self.windows
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .iter()
            .map(|window| window.kind)
            .collect()
    }

    #[cfg(target_arch = "x86_64")]
    pub fn replace_private_windows_with_vfork_shadows(&self, shadows: &VforkShadows) {
        let mut windows = self.windows.write().unwrap_or_else(|e| e.into_inner());
        for window in windows
            .iter_mut()
            .filter(|window| window.kind == WindowKind::Private)
        {
            if let Some(shadow) = shadows.shadow_for(window.base, window.slot_gpa) {
                window.host = shadow;
            }
        }
    }

    #[cfg(target_arch = "x86_64")]
    pub fn prepare_vfork_shadows(&self, arena_high_water: u64) -> Result<VforkShadows, OsError> {
        let windows = self.windows.read().unwrap_or_else(|e| e.into_inner());
        let mut shadows = Vec::new();
        for w in windows.iter() {
            if w.kind != WindowKind::Private {
                continue;
            }
            // SAFETY: mmap is invoked with an anonymous fd and checked against
            // MAP_FAILED before the resulting region is retained or accessed.
            let shadow = unsafe {
                libc::mmap(
                    std::ptr::null_mut(),
                    w.len,
                    libc::PROT_READ | libc::PROT_WRITE,
                    libc::MAP_SHARED | libc::MAP_ANONYMOUS | libc::MAP_NORESERVE,
                    -1,
                    0,
                )
            };
            if shadow == libc::MAP_FAILED {
                for s in &shadows {
                    let s: &VforkShadow = s;
                    // SAFETY: every shadow is a live mapping created above and
                    // has not yet been transferred into the returned owner.
                    unsafe { libc::munmap(s.shadow as *mut libc::c_void, s.len) };
                }
                return Err(OsError::new(format!(
                    "guest_ram: vfork shadow mmap failed for window 0x{:x}+{}",
                    w.base, w.len
                )));
            }
            let scan = if w.base == carrick_mem::memory::LINUX_MMAP_BASE {
                arena_high_water
                    .saturating_sub(w.base)
                    .min(w.len as u64)
                    .try_into()
                    .unwrap_or(w.len)
            } else {
                w.len
            };
            // SAFETY: both retained source and checked shadow mappings cover
            // the supplied bounds and do not overlap.
            unsafe { copy_resident_pages(w.host as *const u8, shadow as *mut u8, scan, w.len) };
            shadows.push(VforkShadow {
                base: w.base,
                slot_gpa: w.slot_gpa,
                private_host: w.host,
                shadow: shadow as usize,
                len: w.len,
            });
        }
        Ok(VforkShadows { shadows })
    }

    #[cfg(target_arch = "x86_64")]
    pub fn finish_vfork_parent(&self, shadows: VforkShadows) {
        {
            let mut windows = self.windows.write().unwrap_or_else(|e| e.into_inner());
            for window in windows.iter_mut() {
                if let Some(shadow) = shadows
                    .shadows
                    .iter()
                    .find(|shadow| shadow.shadow == window.host)
                {
                    window.host = shadow.private_host;
                }
            }
        }
        for s in &shadows.shadows {
            // SAFETY: the shadow and private mappings are live, disjoint, and
            // cover `len`; this owner consumes each shadow exactly once.
            unsafe {
                copy_resident_pages(
                    s.shadow as *const u8,
                    s.private_host as *mut u8,
                    s.len,
                    s.len,
                );
                libc::munmap(s.shadow as *mut libc::c_void, s.len);
            }
        }
    }
}

impl Default for GuestRam {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(target_arch = "x86_64")]
/// Copy ONLY the RESIDENT pages of `[src, src+scan)` into `dst` (which must back
/// `total` >= `scan` bytes).
///
/// # Safety
///
/// - `src` must point to valid memory for reading at least `scan` bytes.
/// - `dst` must point to valid memory for writing at least `total` bytes.
unsafe fn copy_resident_pages(src: *const u8, dst: *mut u8, scan: usize, total: usize) {
    if scan == 0 {
        return;
    }
    let page = {
        // SAFETY: sysconf reads process configuration and has no pointer preconditions.
        let p = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
        if p <= 0 { 4096usize } else { p as usize }
    };
    let n_pages = scan.div_ceil(page);
    let mut resident = vec![0u8; n_pages];
    // SAFETY: the caller guarantees `src` covers `scan`; `resident` has one
    // byte for every queried host page as required by mincore(2).
    let rc = unsafe {
        libc::mincore(
            src as *mut libc::c_void,
            scan,
            resident.as_mut_ptr() as *mut _,
        )
    };
    if rc != 0 {
        // SAFETY: the function contract guarantees both disjoint ranges.
        unsafe { std::ptr::copy_nonoverlapping(src, dst, scan.min(total)) };
        return;
    }
    for (i, &flag) in resident.iter().enumerate() {
        if flag & 1 != 0 {
            let off = i * page;
            let len = page.min(total - off);
            // SAFETY: `off..off+len` is within both caller-provided ranges and
            // the source and destination mappings do not overlap.
            unsafe { std::ptr::copy_nonoverlapping(src.add(off), dst.add(off), len) };
        }
    }
}

#[cfg(target_arch = "x86_64")]
#[derive(Debug)]
struct VforkShadow {
    base: u64,
    slot_gpa: Option<u64>,
    private_host: usize,
    shadow: usize,
    len: usize,
}

#[cfg(target_arch = "x86_64")]
#[derive(Debug)]
pub struct VforkShadows {
    shadows: Vec<VforkShadow>,
}

#[cfg(target_arch = "x86_64")]
impl VforkShadows {
    pub fn is_empty(&self) -> bool {
        self.shadows.is_empty()
    }

    pub fn shadow_for(&self, base: u64, slot_gpa: Option<u64>) -> Option<usize> {
        self.shadows
            .iter()
            .find(|s| s.base == base && s.slot_gpa == slot_gpa)
            .map(|s| s.shadow)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shared_window_views_observe_late_insertions() {
        let mut parent = GuestRam::new();
        parent
            .add_window(0x1000, 0x1000, WindowKind::Private)
            .expect("initial window");
        let sibling =
            GuestRam::from_shared_windows(parent.shared_windows(), parent.shared_protections());

        assert!(sibling.host_ptr(0x1000, 1).is_some());

        parent
            .add_window(0x9000, 0x1000, WindowKind::Private)
            .expect("late window");
        assert!(
            sibling.host_ptr(0x9000, 1).is_some(),
            "sibling views must observe high-VA aliases added after clone"
        );
    }
}

impl GuestRam {
    /// # Safety
    /// `host` must name a live mapping of at least `len` bytes whose ownership
    /// is transferred to this `GuestRam`.
    pub unsafe fn push_window(
        &mut self,
        base: u64,
        host: *mut u8,
        len: usize,
        kind: WindowKind,
        slot_gpa: Option<u64>,
    ) {
        self.windows
            .write()
            .unwrap_or_else(|e| e.into_inner())
            .push(WindowDesc {
                base,
                host: host as usize,
                len,
                kind,
                slot_gpa,
            });
    }
}
