//! Guest bring-up for the KVM MVP: load the freestanding ELF into a host mmap,
//! reuse carrick-mem's architectural stage-1 / trampoline builders, install a
//! tiny EL1 vector whose lower-EL-sync slot STORES TO A SENTINEL gpa (the MMIO
//! trap vehicle) instead of HVF's `hvc #2`, and program the system registers
//! WITHOUT the Apple-Silicon FEAT_PAN3 / PSTATE.PAN=1 workaround.
use carrick_hal::{HvVcpu, HvVm, MemPerms, OsError, Reg, SysReg};
use carrick_mem::memory::{
    AddressSpace, LINUX_EL0_TRAMPOLINE_BASE, LINUX_EL1_VECTORS_BASE, LINUX_EL1_VECTORS_SIZE,
    LINUX_PAGE_TABLES_BASE, el0_trampoline_bytes, stage1_identity_page_tables,
    va_in_shared_aperture,
};

use crate::kvm::{KvmVcpu, KvmVm};

/// Guest-physical address the EL1 vector stores to on an EL0 `svc`.
///
/// Requirements: it must be (a) **stage-1 identity-mapped** (so the EL1 store
/// translates), yet (b) left UNMAPPED in every KVM memory region (so the access
/// faults out as `KVM_EXIT_MMIO { gpa: SENTINEL_GPA, .. }` — the trap vehicle).
///
/// 320 GiB satisfies both: the stage-1 identity map covers 0..512 GiB with
/// 1 GiB user blocks (`stage1_identity_page_tables`), and 320 GiB sits in the
/// gap between the heap (`LINUX_HEAP_BASE` = 256 GiB, +128 MiB) and the mmap
/// arena (`LINUX_MMAP_BASE` = 384 GiB), so it is never a real carrick region.
/// It is also far above the backed RAM window (which ends at the kernel hole,
/// ~180 GiB), so the store always faults to stage-2 / MMIO.
///
/// NOTE: it must NOT be `LINUX_HEAP_BASE` (256 GiB) — that collides with the
/// guest heap region.
pub const SENTINEL_GPA: u64 = 0x50_0000_0000; // 320 GiB

/// KVM memory-slot alignment. `KVM_SET_USER_MEMORY_REGION` requires the
/// guest-physical base and size to be a multiple of the HOST page size; 64 KiB
/// covers every aarch64 host granule (4K/16K/64K). The high guest regions are
/// already ≥ 64 KiB-aligned, so this only rounds the (16 KiB) sigreturn window
/// up — harmless extra lazy backing.
const KVM_SLOT_ALIGN: u64 = 0x10000;

fn align_down_slot(addr: u64) -> u64 {
    addr & !(KVM_SLOT_ALIGN - 1)
}

fn align_up_slot(addr: u64) -> Result<u64, OsError> {
    addr.checked_add(KVM_SLOT_ALIGN - 1)
        .map(|a| a & !(KVM_SLOT_ALIGN - 1))
        .ok_or_else(|| OsError::new(format!("kvm: region end 0x{addr:x} overflows on align")))
}

// The aarch64 vector table layout (matches carrick-mem's el1_vectors_bytes):
// 16 slots * 0x80 bytes; the lower-EL synchronous slot is at offset 0x400.
const AARCH64_VECTOR_SLOT_SIZE: u64 = 0x80;
const AARCH64_VECTOR_LOWER_EL_SYNC_OFFSET: u64 = 0x400;
const AARCH64_ERET_OPCODE: u32 = 0xd69f_03e0;
const AARCH64_NOP_OPCODE: u32 = 0xd503_201f;

// Encoders for the sentinel store sequence. We use x9 as scratch (the guest's
// svc convention leaves x0..x8 as the syscall frame; x9 is caller-saved and
// unobserved across the trap because the host reads the frame, completes the
// syscall, and resumes via ELR_EL1).
fn enc_movz_x9(imm16: u16, hw: u32) -> u32 {
    0xD280_0009 | (hw << 21) | (u32::from(imm16) << 5)
}
fn enc_movk_x9(imm16: u16, hw: u32) -> u32 {
    0xF280_0009 | (hw << 21) | (u32::from(imm16) << 5)
}
// `str x8, [x9]` — store the syscall number to the sentinel (any store works).
const ENC_STR_X8_X9: u32 = 0xf900_0128;

/// Build the EL1 vector page: every slot is `eret`, except the lower-EL sync
/// slot which materialises SENTINEL_GPA in x9 and stores there (-> MMIO exit),
/// then `eret`. Mirrors carrick-mem's `el1_vectors_bytes` shape but with the
/// sentinel store in place of `hvc #2`.
pub fn el1_vectors_sentinel_bytes() -> Vec<u8> {
    let size = LINUX_EL1_VECTORS_SIZE as usize;
    let mut bytes = vec![0u8; size];
    let put = |b: &mut [u8], off: usize, op: u32| {
        b[off..off + 4].copy_from_slice(&op.to_le_bytes());
    };
    // Fill all 16 slots with eret + nop padding.
    let mut slot = 0u64;
    while slot < 16 * AARCH64_VECTOR_SLOT_SIZE && (slot as usize) < size {
        let base = slot as usize;
        put(&mut bytes, base, AARCH64_ERET_OPCODE);
        let mut c = base + 4;
        while c + 4 <= base + AARCH64_VECTOR_SLOT_SIZE as usize {
            put(&mut bytes, c, AARCH64_NOP_OPCODE);
            c += 4;
        }
        slot += AARCH64_VECTOR_SLOT_SIZE;
    }
    // Overwrite the lower-EL sync slot with the sentinel store sequence.
    let s = AARCH64_VECTOR_LOWER_EL_SYNC_OFFSET as usize;
    let g = SENTINEL_GPA;
    put(&mut bytes, s, enc_movz_x9((g & 0xFFFF) as u16, 0));
    put(
        &mut bytes,
        s + 4,
        enc_movk_x9(((g >> 16) & 0xFFFF) as u16, 1),
    );
    put(
        &mut bytes,
        s + 8,
        enc_movk_x9(((g >> 32) & 0xFFFF) as u16, 2),
    );
    put(
        &mut bytes,
        s + 12,
        enc_movk_x9(((g >> 48) & 0xFFFF) as u16, 3),
    );
    put(&mut bytes, s + 16, ENC_STR_X8_X9);
    put(&mut bytes, s + 20, AARCH64_ERET_OPCODE);
    bytes
}

/// Whether the host `mmap` backing a guest-physical window is shared across
/// `fork(2)` (`MAP_SHARED`) or copy-on-write snapshotted (`MAP_PRIVATE`).
///
/// The KVM slot `flags` field is always `0` in both cases — KVM does not
/// distinguish; only the HOST mmap flags change.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum WindowKind {
    /// `MAP_PRIVATE`: copy-on-write on fork (image, heap, stack, page-tables,
    /// vectors, trampoline, private overlay).
    Private,
    /// `MAP_SHARED`: writes are visible across `fork(2)` — used for the
    /// boot-mapped shared aperture `[LINUX_SHARED_FILE_BASE,
    /// LINUX_SHARED_FILE_BASE + LINUX_SHARED_FILE_SIZE)` so that guest
    /// `MAP_SHARED` futex words survive the fork used by `clone(2)`.
    Shared,
}

/// One host-backed guest-physical window: [base, base+len) of guest-physical
/// space backed by a single host `mmap`. Each becomes one
/// `KVM_SET_USER_MEMORY_REGION` slot.
struct Window {
    base: u64,
    host: *mut u8,
    len: usize,
    /// Host mmap kind for this window. Read by
    /// [`GuestRam::shared_futex_host_addr`] (Task 7) to decide whether a guest
    /// futex word is a cross-process `MAP_SHARED` rendezvous (→ bare host
    /// `SYS_futex`) or a private in-process one (→ the parking-lot table).
    ///
    /// `rebuild_vm_for_child` (Task 2) re-registers ALL windows uniformly via
    /// `map_memory` — it does NOT branch on `kind`.  This is correct: `libc::fork`
    /// has already settled the memory semantics before `rebuild_vm_for_child` runs.
    /// Private (`MAP_PRIVATE|MAP_ANONYMOUS`) windows become Linux COW copies;
    /// the MAP_SHARED aperture continues to alias the same host pages.  Both
    /// simply reuse the inherited host VA that the parent's `Window::host` recorded
    /// — no re-mmap is needed.
    kind: WindowKind,
}

/// Multi-window host-backed guest RAM. The MVP used a single low window; a real
/// binary additionally needs the high runtime regions (stack near 1 TiB,
/// heap @ 256 GiB, mmap arena @ 384 GiB, sigreturn @ 192 GiB), which sit far
/// above the low window and at sparse, huge GPAs. Each is its own `MAP_NORESERVE`
/// window (lazily committed) and its own KVM slot — discrete windows, NOT one
/// giant slot, so the SENTINEL gpa stays UNMAPPED (the MMIO trap vehicle relies
/// on it faulting to stage-2). All windows are MAP_PRIVATE for now (no fork; the
/// host-MAP_SHARED fork-coherence model is the full-backend Phase D work).
pub struct GuestRam {
    windows: Vec<Window>,
    /// Sorted, merged guest-physical ranges the guest has made PROT_NONE
    /// (mmap(PROT_NONE)/mprotect/munmap). carrick backs the whole arena with
    /// accessible host memory, so a PROT_NONE buffer is otherwise readable on
    /// the syscall path — a guest passing such a buffer to a syscall must
    /// instead see EFAULT. This is the HOST-SIDE syscall-read check only
    /// (cheap, no page tables); making the GUEST itself fault mid-EL0 needs
    /// stage-1 edits + signal injection (Phase D), so `protect_range`/
    /// `unmap_range` stay no-ops for now.
    no_access: Vec<(u64, u64)>,
    /// Whether this `GuestRam` OWNS its window mmaps (and must `munmap` them on
    /// drop). `true` for the initial / fork-child / execve RAM. `false` for a
    /// `clone(CLONE_THREAD)` sibling's view (see [`Self::from_shared_windows`]):
    /// a sibling shares the SAME host mmaps as the parent thread (threads share
    /// the address space, no fork), so it must NEVER `munmap` them — the parent
    /// engine owns them and frees them at process exit. Double-`munmap` (or a
    /// sibling freeing pages a live parent vCPU still uses) would be UB.
    owns_windows: bool,
}

/// `munmap` the host backing of every window when the `GuestRam` is dropped.
///
/// For the long-lived initial / forked-child RAM this never fires in practice
/// (the engine lives for the process). It matters for
/// [`crate::trap_engine::KvmTrapEngine::execve_into`], which REPLACES `self.ram`
/// with a fresh `GuestRam` for the new image: the OLD `GuestRam` drops here and
/// must release its host mmaps, or repeated execve would leak the prior image's
/// windows (heap/mmap-arena/stack near 1 TiB are huge VA reservations).
///
/// The caller MUST have unregistered the KVM slots backed by these windows
/// before the drop (execve does: `unmap_memory_slot` for each old slot first),
/// so no live vCPU references the pages being unmapped.
impl Drop for GuestRam {
    fn drop(&mut self) {
        // A non-owning sibling VIEW (`clone(CLONE_THREAD)`) must NOT free the
        // shared host mmaps — the owning parent does, at process exit.
        if !self.owns_windows {
            return;
        }
        for w in &self.windows {
            // SAFETY: `host`..`host+len` is the mmap this window owns (created in
            // `add_window`); it is unmapped exactly once, on drop. KVM slots over
            // it were already deleted by the execve caller.
            unsafe {
                libc::munmap(w.host.cast::<libc::c_void>(), w.len);
            }
        }
    }
}

impl GuestRam {
    fn new() -> Self {
        Self {
            windows: Vec::new(),
            no_access: Vec::new(),
            owns_windows: true,
        }
    }

    /// Whether [gpa, gpa+len) overlaps any PROT_NONE range (so a syscall buffer
    /// there must fault with EFAULT). Mirrors carrick-hvf's `range_no_access`.
    pub(crate) fn range_no_access(&self, gpa: u64, len: usize) -> bool {
        let end = gpa.saturating_add(len as u64);
        if end <= gpa {
            return false;
        }
        let idx = self.no_access.partition_point(|&(_, e)| e <= gpa);
        self.no_access
            .get(idx)
            .is_some_and(|&(s, e)| gpa < e && s < end)
    }

    /// Record (`no_access=true`) or clear (`false`) a PROT_NONE range, keeping
    /// `no_access` sorted and merged. Add merges adjacent/overlapping ranges;
    /// clear subtracts the interval (splitting a straddled range). Mirrors
    /// carrick-hvf's `MemoryProtections::set_no_access`.
    pub(crate) fn set_no_access(&mut self, gpa: u64, len: usize, no_access: bool) {
        let end = gpa.saturating_add(len as u64);
        if end <= gpa {
            return;
        }
        if no_access {
            self.no_access.push((gpa, end));
            self.no_access.sort_by_key(|&(s, _)| s);
            let mut merged: Vec<(u64, u64)> = Vec::with_capacity(self.no_access.len());
            for (s, e) in std::mem::take(&mut self.no_access) {
                if let Some((_, last_end)) = merged.last_mut()
                    && s <= *last_end
                {
                    *last_end = (*last_end).max(e);
                    continue;
                }
                merged.push((s, e));
            }
            self.no_access = merged;
            return;
        }
        let mut next = Vec::with_capacity(self.no_access.len());
        for (s, e) in std::mem::take(&mut self.no_access) {
            if gpa <= s && end >= e {
                continue; // fully cleared
            }
            if end <= s || gpa >= e {
                next.push((s, e)); // disjoint
                continue;
            }
            if s < gpa {
                next.push((s, gpa)); // left remainder
            }
            if end < e {
                next.push((end, e)); // right remainder
            }
        }
        next.sort_by_key(|&(s, _)| s);
        self.no_access = next;
    }

    /// mmap `len` bytes (lazy, `MAP_NORESERVE`) to back guest-physical
    /// [base, base+len) and record the window. Refuses any window that would
    /// cover [`SENTINEL_GPA`] — that page MUST stay unmapped so the EL1 vector's
    /// sentinel store faults out as `KVM_EXIT_MMIO` (the syscall trap vehicle).
    ///
    /// `kind` selects the host mmap flags:
    /// - [`WindowKind::Private`] → `MAP_PRIVATE|MAP_ANONYMOUS|MAP_NORESERVE`
    ///   (copy-on-write on fork; used for image/heap/stack/page-tables/vectors).
    /// - [`WindowKind::Shared`] → `MAP_SHARED|MAP_ANONYMOUS|MAP_NORESERVE`
    ///   (writes survive fork; used for the shared aperture so guest `MAP_SHARED`
    ///   futex words remain coherent across the `fork` used by `clone(2)`).
    ///
    /// The KVM slot `flags` field is always `0` regardless of `kind`.
    fn add_window(&mut self, base: u64, len: usize, kind: WindowKind) -> Result<(), OsError> {
        if len == 0 {
            return Ok(());
        }
        let end = base
            .checked_add(len as u64)
            .ok_or_else(|| OsError::new(format!("kvm: window 0x{base:x}+{len} overflows")))?;
        if base <= SENTINEL_GPA && SENTINEL_GPA < end {
            return Err(OsError::new(format!(
                "kvm: window 0x{base:x}..0x{end:x} would back the sentinel gpa 0x{SENTINEL_GPA:x}"
            )));
        }
        let mmap_flags = match kind {
            WindowKind::Private => libc::MAP_PRIVATE | libc::MAP_ANONYMOUS | libc::MAP_NORESERVE,
            WindowKind::Shared => libc::MAP_SHARED | libc::MAP_ANONYMOUS | libc::MAP_NORESERVE,
        };
        // SAFETY: anonymous mapping (no fd); we own it for the VM's life.
        // MAP_SHARED|MAP_ANONYMOUS is used for the shared aperture so that guest
        // MAP_SHARED futex words remain coherent across fork(2)/clone(2); KVM
        // slot flags stay 0 in both cases — only the host mmap flags change.
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
                "kvm: guest RAM mmap failed for 0x{base:x}+{len}"
            )));
        }
        self.windows.push(Window {
            base,
            host: host.cast::<u8>(),
            len,
            kind,
        });
        Ok(())
    }

    /// The window whose [base, base+len) wholly contains [gpa, gpa+len), with
    /// the host offset of `gpa` within it.
    fn locate(&self, gpa: u64, len: usize) -> Option<(&Window, usize)> {
        self.windows.iter().find_map(|w| {
            let off = gpa.checked_sub(w.base)?;
            ((off as usize).checked_add(len)? <= w.len).then_some((w, off as usize))
        })
    }

    /// Copy `data` to guest-physical `gpa` (must lie wholly within one window).
    /// `pub(crate)` so the `GuestMemory` impl on [`crate::trap_engine::KvmTrapEngine`]
    /// can service guest `write_bytes` through the same bounds-checked path
    /// bring-up uses; the guest VA is identity-mapped to this GPA.
    pub(crate) fn write_gpa(&mut self, gpa: u64, data: &[u8]) -> Result<(), OsError> {
        let (host, off) = {
            let (w, off) = self.locate(gpa, data.len()).ok_or_else(|| {
                OsError::new(format!("kvm: write gpa 0x{gpa:x} out of guest RAM"))
            })?;
            (w.host, off)
        };
        // SAFETY: bounds checked by `locate`; host points at `len` writable bytes.
        unsafe {
            std::ptr::copy_nonoverlapping(data.as_ptr(), host.add(off), data.len());
        }
        Ok(())
    }

    /// Rebuild a fresh `KvmVm` + `KvmVcpu` over THIS `GuestRam`'s existing host
    /// mmaps — the child side of [`crate::trap_engine::KvmTrapEngine::fork`].
    ///
    /// After `libc::fork`, the child's inherited KVM fds point at the PARENT's
    /// kernel VM and are useless, so the child opens `/dev/kvm` afresh
    /// (`KVM_CREATE_VM`), re-registers EVERY window in the SAME order / GPA /
    /// slot id over the COW-inherited host VAs (the `SENTINEL_GPA` hole stays
    /// unmapped), and creates a vCPU (`KVM_CREATE_VCPU` + preferred-target init,
    /// via [`KvmVm::add_vcpu`]). PRIVATE windows are the Linux-COW copies; the
    /// `MAP_SHARED` aperture re-registers the SAME (inherited) host pages, so its
    /// writes stay coherent across the fork. The vCPU is returned UNPROGRAMMED;
    /// the caller restores the parent's [`VcpuSnapshot`] onto it.
    pub(crate) fn rebuild_vm_for_child(&self) -> Result<(KvmVm, KvmVcpu), OsError> {
        let mut vm = KvmVm::create_empty()?;
        for w in &self.windows {
            vm.map_memory(w.base, w.host, w.len, MemPerms::ReadWriteExec)?;
        }
        let vcpu = vm.add_vcpu()?;
        Ok((vm, vcpu))
    }

    /// Read `len` bytes of LIVE guest memory at guest-physical `gpa` (so guest
    /// writes are visible). `gpa` must lie wholly within one backed window — e.g.
    /// a `write(2)` buffer the guest passed in `x1`.
    pub fn read(&self, gpa: u64, len: usize) -> Result<Vec<u8>, OsError> {
        let (w, off) = self.locate(gpa, len).ok_or_else(|| {
            OsError::new(format!("kvm: read gpa 0x{gpa:x}+{len} out of guest RAM"))
        })?;
        let mut out = vec![0u8; len];
        // SAFETY: bounds checked by `locate`; host points at `len` readable bytes.
        unsafe {
            std::ptr::copy_nonoverlapping(w.host.add(off), out.as_mut_ptr(), len);
        }
        Ok(out)
    }

    /// Host virtual address of the `len`-byte word at guest-physical `gpa`, but
    /// ONLY when it lies wholly within a [`WindowKind::Shared`] window (the
    /// boot-mapped `MAP_SHARED|MAP_ANONYMOUS` aperture). That backing is the SAME
    /// physical page in parent and child across `fork(2)`, so it is a valid
    /// target for a bare host `SYS_futex` cross-process rendezvous (see
    /// [`crate::kvm_futex::KvmFutex::shared_wait`]). Returns `None` for a word in
    /// a `Private` (COW) window — those futexes stay in-process via the parking-
    /// lot [`carrick_thread::thread::FutexTable`]. The guest is identity-mapped
    /// (VA == GPA), so the dispatcher passes the guest futex VA straight in.
    pub fn shared_futex_host_addr(&self, gpa: u64, len: usize) -> Option<usize> {
        let (w, off) = self.locate(gpa, len)?;
        if w.kind != WindowKind::Shared {
            return None;
        }
        // SAFETY: `locate` proved [gpa, gpa+len) ⊆ this window, so `host + off`
        // points at `len` valid bytes of the shared aperture backing.
        Some(unsafe { w.host.add(off) } as usize)
    }
}

/// Result of bring-up: a VM + a vCPU initialised to the EL1 trampoline, ready
/// for the trap engine to drive. `ram` is kept alive (its mmap backs KVM).
pub struct BroughtUp {
    pub vm: KvmVm,
    pub vcpu: KvmVcpu,
    pub ram: GuestRam,
    pub entry: u64,
}

/// The low window covers the user image's low segments AND the kernel region
/// (EL0 trampoline / EL1 vectors / stage-1 page tables) at 180 GiB.
const KERNEL_HOLE_END: u64 = 0x2D_0020_0000; // LINUX_KERNEL_REGION_BASE + 2 MiB

impl GuestRam {
    /// Build a fresh `GuestRam` over a freshly-`mmap`'d set of host windows for
    /// `image`, and write the image segments + the architectural bring-up pages
    /// (EL0 trampoline / stage-1 identity tables / EL1 sentinel vectors) into
    /// them. This is the shared "lay out the guest physical RAM for an image"
    /// step used by BOTH the initial [`bring_up`] and
    /// [`crate::trap_engine::KvmTrapEngine::execve_into`] — execve replaces the
    /// guest image in place by building a new `GuestRam` here and re-registering
    /// its windows on the LIVE VM (the slots having first been unmapped).
    ///
    /// It does NOT touch any KVM object (no slot registration, no vCPU
    /// programming) — those steps differ between bring-up (fresh VM) and execve
    /// (live VM remap), so the caller drives them via [`Self::windows_for_kvm`]
    /// and [`program_sysregs`].
    pub(crate) fn build_for_image(image: &AddressSpace) -> Result<Self, OsError> {
        let mut ram = GuestRam::new();
        // Low window covers image segments + kernel-region pages; always private
        // (image text/data/bss are per-process, not shared across fork).
        ram.add_window(0, KERNEL_HOLE_END as usize, WindowKind::Private)?;

        // 1. ELF + runtime regions (identity GPA == region.start). `load_elf`
        //    also appends the guest's high runtime reservations (sigreturn @
        //    192 GiB, heap @ 256 GiB, mmap arena @ 384 GiB, shared aperture @
        //    576 GiB, private overlay @ 608 GiB), and `with_linux_initial_stack`
        //    appends the stack near 1 TiB. Low regions land in the low window;
        //    each HIGH region (>= KERNEL_HOLE_END) gets its own MAP_NORESERVE
        //    window + KVM slot, page-aligned and lazily committed. (`add_window`
        //    refuses any window that would back the unmapped SENTINEL gpa.)
        //
        //    WindowKind is derived from the MemoryRegion's `shared` flag:
        //    - `shared: true`  → MAP_SHARED (the boot-mapped shared aperture)
        //    - `shared: false` → MAP_PRIVATE (all other regions)
        //    The KVM slot `flags` field stays 0 in both cases.
        for region in image.regions() {
            if region.start < KERNEL_HOLE_END {
                let bytes = region.bytes();
                if !bytes.is_empty() {
                    ram.write_gpa(region.start, bytes)?;
                }
                continue;
            }
            let base = align_down_slot(region.start);
            let end = align_up_slot(region.end)?;
            // Derive kind from carrick-mem's `shared` flag, cross-checked against
            // the shared-aperture address range. Both must agree: if a region is
            // marked shared it must lie in the shared aperture, and vice versa.
            debug_assert_eq!(
                region.shared,
                va_in_shared_aperture(base, end - base),
                "region.shared / shared-aperture address mismatch at 0x{base:x}"
            );
            let kind = if region.shared {
                WindowKind::Shared
            } else {
                WindowKind::Private
            };
            ram.add_window(base, (end - base) as usize, kind)?;
            let bytes = region.bytes();
            if !bytes.is_empty() {
                ram.write_gpa(region.start, bytes)?;
            }
        }
        // 2. Architectural bring-up pages (low window), reused from carrick-mem.
        ram.write_gpa(LINUX_EL0_TRAMPOLINE_BASE, &el0_trampoline_bytes())?;
        ram.write_gpa(LINUX_PAGE_TABLES_BASE, &stage1_identity_page_tables())?;
        // 3. Our sentinel vector (NOT carrick-mem's hvc #2 variant).
        ram.write_gpa(LINUX_EL1_VECTORS_BASE, &el1_vectors_sentinel_bytes())?;
        Ok(ram)
    }

    /// Iterate every window as `(base, host, len)` for `KVM_SET_USER_MEMORY_REGION`
    /// registration, in slot order. Used by both bring-up and execve to publish
    /// the windows onto a (fresh or live) VM via [`KvmVm::map_memory`].
    pub(crate) fn windows_for_kvm(&self) -> impl Iterator<Item = (u64, *mut u8, usize)> + '_ {
        self.windows.iter().map(|w| (w.base, w.host, w.len))
    }

    /// Number of registered windows (== the number of KVM slots in use). Used by
    /// execve to know how many slots to unregister before remapping the new
    /// image.
    pub(crate) fn window_count(&self) -> usize {
        self.windows.len()
    }

    /// `Send`-safe descriptors of this RAM's host-backed windows, for handing a
    /// `clone(CLONE_THREAD)` sibling a VIEW of the SAME backing on another host
    /// thread. The host pointer is carried as a `usize` (raw `*mut u8` is not
    /// `Send`) — valid because threads share the address space (no fork), so the
    /// host VA is the same in the sibling thread. Reconstituted by
    /// [`Self::from_shared_windows`].
    pub(crate) fn window_descriptors(&self) -> Vec<WindowDesc> {
        self.windows
            .iter()
            .map(|w| WindowDesc {
                base: w.base,
                host: w.host as usize,
                len: w.len,
                kind: w.kind,
            })
            .collect()
    }

    /// Build a NON-OWNING `GuestRam` view over windows another thread owns (a
    /// `clone(CLONE_THREAD)` sibling). The windows alias the SAME host mmaps the
    /// parent engine owns; this view records them so the sibling's `read`/`write`
    /// syscall-buffer path works, but its `Drop` is a NO-OP (`owns_windows =
    /// false`) — only the owning parent `munmap`s, at process exit. `no_access`
    /// starts empty: the sibling shares the parent's address space, but the
    /// HOST-SIDE PROT_NONE bookkeeping is per-engine (a future Phase-4 concern);
    /// the MVP threads fixture touches no PROT_NONE buffers.
    pub(crate) fn from_shared_windows(descs: &[WindowDesc]) -> Self {
        let windows = descs
            .iter()
            .map(|d| Window {
                base: d.base,
                host: d.host as *mut u8,
                len: d.len,
                kind: d.kind,
            })
            .collect();
        Self {
            windows,
            no_access: Vec::new(),
            owns_windows: false,
        }
    }
}

/// A `Send` descriptor of one host-backed guest window, used to hand a
/// `clone(CLONE_THREAD)` sibling a view of the SAME backing across host threads.
/// `host` is a `usize` (not `*mut u8`) so the enclosing sibling-spec is `Send`;
/// it is the same host VA in every thread of the process (no fork involved).
#[derive(Debug, Clone, Copy)]
pub(crate) struct WindowDesc {
    pub base: u64,
    pub host: usize,
    pub len: usize,
    pub kind: WindowKind,
}

/// Load `image` (a freestanding aarch64 ELF), build the stage-1 identity map +
/// trampoline + sentinel vector, program the vCPU, and return it parked at the
/// EL1 trampoline. Reuses carrick-mem's architectural builders; does NOT use
/// the FEAT_PAN3 workaround (see `program_sysregs`).
pub fn bring_up(image: &AddressSpace) -> Result<BroughtUp, OsError> {
    // 1-3. Lay out guest physical RAM: windows + image segments + the
    //       architectural bring-up pages (shared with execve_into).
    let ram = GuestRam::build_for_image(image)?;

    // 4. Create VM + publish every window as its own KVM memory slot.
    let mut vm = KvmVm::create(image)?;
    for (base, host, len) in ram.windows_for_kvm() {
        vm.map_memory(base, host, len, MemPerms::ReadWriteExec)?;
    }
    let mut vcpu = vm.add_vcpu()?;

    // 5. Program registers (sys regs + entry/SP/PC), NO FEAT_PAN3 workaround.
    program_sysregs(&mut vcpu, image)?;

    Ok(BroughtUp {
        vm,
        vcpu,
        ram,
        entry: image.entry(),
    })
}

/// Program the vCPU's system + core registers for `image`: MAIR/TCR/TTBR0/1/
/// SCTLR/CPACR/VBAR + PSTATE/SPSR/ELR/PC/SP, with NO FEAT_PAN3 workaround (KVM
/// controls PSTATE, so PAN stays clear so the EL1 sentinel store reaches MMIO).
///
/// Shared by both [`bring_up`] (initial image) and
/// [`crate::trap_engine::KvmTrapEngine::execve_into`] (in-place image
/// replacement). `execve_into` additionally zeroes x0..x30 before calling this
/// (Linux execve clears the GPRs); this routine sets only SP/PC/PSTATE among the
/// core registers, leaving x0..x30 to the caller's zeroing — and resets
/// TPIDR_EL0 = 0 so the new image's libc re-initialises its thread pointer.
pub(crate) fn program_sysregs(vcpu: &mut KvmVcpu, image: &AddressSpace) -> Result<(), OsError> {
    // MAIR_EL1 slot 0 = Normal Inner/Outer WB cacheable (0xFF), as HVF.
    vcpu.set_sys_reg(SysReg::Mair, 0xFF)?;
    // TCR_EL1: identical bootstrap value to the HVF path. T0SZ=
    // T1SZ=16, Inner-WB/Inner-Shareable both halves, TG1=4K, IPS=40-bit, TBI0/1.
    const T0SZ: u64 = 16;
    const T1SZ: u64 = 16;
    const TCR_EL1_BOOTSTRAP: u64 = T0SZ
        | (0b11 << 8)
        | (0b11 << 10)
        | (0b11 << 12)
        | (T1SZ << 16)
        | (0b11 << 24)
        | (0b11 << 26)
        | (0b11 << 28)
        | (0b10 << 30)
        | (0b010 << 32)
        | (1 << 37)
        | (1 << 38);
    vcpu.set_sys_reg(SysReg::Tcr, TCR_EL1_BOOTSTRAP)?;
    vcpu.set_sys_reg(SysReg::Ttbr0, LINUX_PAGE_TABLES_BASE)?;
    vcpu.set_sys_reg(SysReg::Ttbr1, LINUX_PAGE_TABLES_BASE)?;

    // SCTLR_EL1: C(2), I(12), DZE(14), UCT(15), SPAN(23), UCI(26) + M(0)=1 (stage-1 on).
    //
    // SPAN(bit 23)=1 is LOAD-BEARING for the MMIO sentinel: it means
    // "PSTATE.PAN is left UNCHANGED on taking an exception to EL1". With SPAN=0
    // (the architectural default) the hardware sets PSTATE.PAN=1 on every
    // EL0-`svc` entry to EL1 (FEAT_PAN is mandatory ARMv8.1 and KVM-exposed);
    // the EL1 sentinel vector's `str x8,[x9]` to the EL0-accessible (AP=01)
    // sentinel page would then fault as a stage-1 PAN permission abort and
    // never reach stage-2 / KVM_EXIT_MMIO — wedging the first guest syscall.
    // The guest enters EL0 with PSTATE.PAN=0 (SPSR_EL1 below), so SPAN=1 keeps
    // PAN=0 through the svc trap and the sentinel store reaches the host.
    let sctlr: u64 = (1 << 2) | (1 << 12) | (1 << 14) | (1 << 15) | (1 << 23) | (1 << 26) | 1;
    vcpu.set_sys_reg(SysReg::Sctlr, sctlr)?;

    // FP/SIMD on (CPACR_EL1.FPEN = 0b11) so guest NEON memset doesn't trap.
    vcpu.set_sys_reg(SysReg::Cpacr, 0x3 << 20)?;

    // VBAR_EL1 -> our sentinel vector page.
    vcpu.set_sys_reg(SysReg::Vbar, LINUX_EL1_VECTORS_BASE)?;

    // TPIDR_EL0 = 0: the EL0 thread pointer starts cleared. On a fresh vCPU
    // (bring-up) this is already 0; on an execve-into-a-live-vCPU it RESETS a
    // value the prior image's libc may have installed (Linux execve clears the
    // thread pointer; the new image's libc re-initialises it via
    // set_thread_area). Mirrors the HVF execve path (trap.rs:3899-3903).
    vcpu.set_sys_reg(SysReg::TpidrEl0, 0)?;

    // THE PAN DIVERGENCE FROM HVF. Apple HVF forces PSTATE.PAN=1 and the
    // identity tables work around FEAT_PAN3 with AP=01+PXN=1 on user pages.
    // On KVM the host controls PSTATE. The sentinel store is issued from EL1
    // against an EL0-accessible (user) identity page, so PAN MUST be clear or
    // it would fault as a permission abort instead of reaching stage-2 / MMIO.
    const DAIF_MASKED: u64 = 0b1111 << 6;
    const PSTATE_M_EL1H: u64 = 0b0101; // M[3:0] = EL1h
    const PSTATE_M_EL0T: u64 = 0b0000; // M[3:0] = EL0t
    // Current PSTATE: run the EL0 trampoline at EL1h, DAIF masked, PAN(bit22)=0.
    vcpu.set_reg(Reg::Pstate, PSTATE_M_EL1H | DAIF_MASKED)?;

    // The trampoline ends in `eret`, which loads PC <- ELR_EL1 and
    // PSTATE <- SPSR_EL1. Program both so the eret drops to EL0 at the image
    // entry. (Mirrors the HVF path at carrick-hvf/src/trap.rs:1462-1476.)
    vcpu.set_reg(Reg::SpsrEl1, PSTATE_M_EL0T | DAIF_MASKED)?;
    vcpu.set_reg(Reg::ElrEl1, image.entry())?;

    // Start the vCPU executing the EL0 trampoline (in EL1h).
    vcpu.set_reg(Reg::Pc, LINUX_EL0_TRAMPOLINE_BASE)?;

    // The EL0 user stack lives in SP_EL0 (== Reg::Sp), NOT SP_EL1. The
    // freestanding MVP binary has no initial stack (load_elf_bytes leaves it
    // None) and never touches SP; a real image sets it via
    // `AddressSpace::with_linux_initial_stack` before bring-up.
    if let Some(sp) = image.initial_stack_pointer() {
        vcpu.set_reg(Reg::Sp, sp)?;
    }
    Ok(())
}

#[cfg(test)]
mod window_kind_tests {
    use super::*;
    use carrick_mem::memory::{LINUX_SHARED_FILE_BASE, LINUX_SHARED_FILE_SIZE};

    /// Verify that `add_window` stores the correct `WindowKind` on each window:
    /// the shared-aperture range gets `Shared`, all others get `Private`.
    #[test]
    fn shared_aperture_window_tagged_shared() {
        let mut ram = GuestRam::new();
        // Low window (private).
        ram.add_window(0, 0x10000, WindowKind::Private)
            .expect("low window");
        // Shared aperture window — uses real constants from carrick-mem.
        ram.add_window(
            LINUX_SHARED_FILE_BASE,
            LINUX_SHARED_FILE_SIZE as usize,
            WindowKind::Shared,
        )
        .expect("shared aperture window");
        // Another private high window (e.g. stack).
        ram.add_window(0xC0_0000_0000, 0x10000, WindowKind::Private)
            .expect("high private window");

        let kinds: Vec<WindowKind> = ram.windows.iter().map(|w| w.kind).collect();
        assert_eq!(kinds[0], WindowKind::Private, "low window must be Private");
        assert_eq!(
            kinds[1],
            WindowKind::Shared,
            "shared-aperture window must be Shared"
        );
        assert_eq!(
            kinds[2],
            WindowKind::Private,
            "high private window must be Private"
        );
    }

    /// COW probe: validates the OS-level mmap semantics that the `Shared` window
    /// path relies on, independent of carrick.
    ///
    /// Strategy: parent writes sentinel bytes into both a MAP_SHARED and a
    /// MAP_PRIVATE page BEFORE `fork`.  After `fork`, the parent overwrites only
    /// the MAP_SHARED page.  The child, signalled to read after the parent write,
    /// must observe the new value through the shared page (MAP_SHARED writes are
    /// immediately visible across the fork) and the old value through the private
    /// page (MAP_PRIVATE COW-snapshotted the page at fork time).
    #[test]
    fn cow_probe_shared_vs_private() {
        use std::os::unix::io::RawFd;

        const PAGE: usize = 4096;
        const BEFORE: u8 = 0xAB;
        const AFTER: u8 = 0xCD;

        // Allocate one shared and one private page, write BEFORE into both.
        let shared_pg = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                PAGE,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_SHARED | libc::MAP_ANONYMOUS,
                -1,
                0,
            )
        };
        assert_ne!(shared_pg, libc::MAP_FAILED, "shared mmap failed");

        let private_pg = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                PAGE,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                -1,
                0,
            )
        };
        assert_ne!(private_pg, libc::MAP_FAILED, "private mmap failed");

        unsafe { *(shared_pg as *mut u8) = BEFORE };
        unsafe { *(private_pg as *mut u8) = BEFORE };

        // Two pipes for coordination:
        //   p2c: parent sends one "go" byte to child after writing AFTER.
        //   c2p: child sends two result bytes back to parent.
        let mut p2c: [RawFd; 2] = [-1; 2];
        let mut c2p: [RawFd; 2] = [-1; 2];
        assert_eq!(unsafe { libc::pipe(p2c.as_mut_ptr()) }, 0, "pipe p2c");
        assert_eq!(unsafe { libc::pipe(c2p.as_mut_ptr()) }, 0, "pipe c2p");

        let pid = unsafe { libc::fork() };
        assert!(pid >= 0, "fork failed");

        if pid == 0 {
            // ── child ──────────────────────────────────────────────────────────
            unsafe {
                libc::close(p2c[1]); // close parent-write end
                libc::close(c2p[0]); // close child-read end
            }
            // Block until parent signals "go" (after writing AFTER to shared_pg).
            let mut go = [0u8; 1];
            unsafe { libc::read(p2c[0], go.as_mut_ptr() as *mut _, 1) };
            unsafe { libc::close(p2c[0]) };

            let sv = unsafe { *(shared_pg as *const u8) };
            let pv = unsafe { *(private_pg as *const u8) };
            let results = [sv, pv];
            unsafe { libc::write(c2p[1], results.as_ptr() as *const libc::c_void, 2) };
            unsafe { libc::close(c2p[1]) };
            unsafe { libc::_exit(0) };
        }

        // ── parent ─────────────────────────────────────────────────────────────
        unsafe {
            libc::close(p2c[0]); // close child-read end
            libc::close(c2p[1]); // close child-write end
        }

        // Overwrite only the MAP_SHARED page AFTER fork.
        unsafe { *(shared_pg as *mut u8) = AFTER };
        // MAP_PRIVATE page intentionally unchanged (stays BEFORE in child's snapshot).

        // Signal child to proceed.
        let go = [1u8];
        unsafe { libc::write(p2c[1], go.as_ptr() as *const libc::c_void, 1) };
        unsafe { libc::close(p2c[1]) };

        // Read child's observations.
        let mut results = [0u8; 2];
        let n = unsafe { libc::read(c2p[0], results.as_mut_ptr() as *mut libc::c_void, 2) };
        assert_eq!(n, 2, "expected 2 result bytes from child");
        unsafe { libc::close(c2p[0]) };

        let mut status: libc::c_int = 0;
        unsafe { libc::waitpid(pid, &mut status, 0) };

        unsafe {
            libc::munmap(shared_pg, PAGE);
            libc::munmap(private_pg, PAGE);
        }

        assert_eq!(
            results[0], AFTER,
            "child must observe parent's post-fork write through MAP_SHARED \
             (expected 0x{AFTER:02x}, got 0x{:02x})",
            results[0]
        );
        assert_eq!(
            results[1], BEFORE,
            "child must NOT observe parent's post-fork write through MAP_PRIVATE \
             (expected 0x{BEFORE:02x}, got 0x{:02x})",
            results[1]
        );
    }
}
