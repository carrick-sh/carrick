//! Guest bring-up for the KVM MVP: load the freestanding ELF into a host mmap,
//! reuse carrick-mem's architectural stage-1 / trampoline builders, install a
//! tiny EL1 vector whose lower-EL-sync slot STORES TO A SENTINEL gpa (the MMIO
//! trap vehicle) instead of HVF's `hvc #2`, and program the system registers
//! WITHOUT the Apple-Silicon FEAT_PAN3 / PSTATE.PAN=1 workaround.
use std::sync::Arc;

use carrick_hal::{HvVcpu, HvVm, MemPerms, OsError, Reg, SysReg};
use carrick_mem::memory::{
    AddressSpace, LINUX_EL0_TRAMPOLINE_BASE, LINUX_EL1_VECTORS_BASE, LINUX_EL1_VECTORS_SIZE,
    LINUX_PAGE_TABLES_BASE, el0_trampoline_bytes, stage1_identity_page_tables,
    va_in_shared_aperture,
};
use carrick_mem::protections::MemoryProtections;

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

/// Guest-physical address the EL1 vector stores to on an EL0 *fault* (a data /
/// instruction abort or alignment fault, as opposed to an `svc`). Distinct from
/// [`SENTINEL_GPA`] so the host distinguishes a syscall trap from a fault trap
/// by the MMIO `gpa` alone. Same dual constraints as SENTINEL_GPA: stage-1
/// identity-mapped yet UNMAPPED in every KVM slot. 324 GiB sits in the same
/// heap/mmap gap (between 320 GiB SENTINEL and 384 GiB `LINUX_MMAP_BASE`), so
/// the store always faults to stage-2 / MMIO.
pub const FAULT_SENTINEL_GPA: u64 = 0x51_0000_0000; // 324 GiB

/// Base of the KVM alias-GPA arena: a free identity hole between the private
/// overlay (608+2 GiB) and the stack (~1 TiB), within the 40-bit nested-KVM IPA
/// limit (lima reports `IPA Size Limit: 40 bits`). A guest `mmap(MAP_SHARED, fd)`
/// (or other [`carrick_mem::memory::is_high_va`] alias) gets a dispatcher-chosen
/// VA >= `LINUX_HIGH_VA_THRESHOLD` (1 TiB), which exceeds the IPA limit and so
/// cannot itself be a KVM GPA. KVM instead backs it with a slot at
/// `KVM_ALIAS_GPA_BASE + (va - LINUX_HIGH_VA_THRESHOLD)` — a deterministic,
/// collision-free low GPA (the dispatcher's alias VAs are already unique and span
/// exactly `LINUX_ALIAS_IPA_SIZE`), and maps VA -> that GPA in stage-1. HVF, with
/// its own per-region `hv_vm_map`, uses the dispatcher's low IPA directly; this is
/// the KVM-specific stage-2 glue.
pub(crate) const KVM_ALIAS_GPA_BASE: u64 = 0xA0_0000_0000; // 640 GiB
/// Size of the KVM alias-GPA arena. Matches `LINUX_ALIAS_IPA_SIZE` (64 GiB) so the
/// VA->GPA delta always lands in-arena; ends at 704 GiB, well below the stack.
pub(crate) const KVM_ALIAS_GPA_SIZE: u64 = 0x10_0000_0000; // 64 GiB

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

// Encoders for the sentinel store sequence. The sentinel store needs a scratch
// register holding the sentinel GPA (`str x8, [x9]`), and we use x9. But the
// Linux aarch64 syscall ABI PRESERVES x1..x30 across an `svc` (the kernel
// saves/restores the full register frame), and real code relies on it — e.g.
// musl's `__expand_heap` keeps its malloc-context pointer in x9 across the
// `brk(2)` svc, then does `str x10, [x9, #920]` AFTER. So the vector first SAVES
// x9 to `TPIDR_EL1` (a per-vCPU EL1 sysreg carrick does NOT otherwise use on KVM:
// the guest runs at EL0 and uses TPIDR_EL0 for TLS), and `complete_syscall`
// restores x9 from it on the way out. (glibc happened never to hold a live x9
// across an svc, which masked this for a long time; musl/alpine exposed it.)
fn enc_movz_x9(imm16: u16, hw: u32) -> u32 {
    0xD280_0009 | (hw << 21) | (u32::from(imm16) << 5)
}
fn enc_movk_x9(imm16: u16, hw: u32) -> u32 {
    0xF280_0009 | (hw << 21) | (u32::from(imm16) << 5)
}
// `str x8, [x9]` — store the syscall number to the sentinel (any store works).
const ENC_STR_X8_X9: u32 = 0xf900_0128;
// `msr tpidr_el1, x9` — save the guest's live x9 before the vector clobbers it as
// the sentinel-store scratch (see the comment above). Assembled via GNU `as`.
const ENC_MSR_TPIDR_EL1_X9: u32 = 0xd518_d089;

// EL0-fault discriminator opcodes. The lower-EL-sync slot is entered by BOTH an
// EL0 `svc` AND an EL0 synchronous fault (data/instruction abort, alignment),
// because KVM/arm64 vectors a guest EL0 abort to the guest's own VBAR_EL1 — it
// is NOT a KVM_RUN exit. So the slot must read ESR_EL1, extract the exception
// class, and branch to a SECOND (fault) sentinel store when it is not an svc;
// otherwise a fault would be mishandled as a syscall and re-fault forever.
// These four opcodes were verified against the GNU assembler (`as`) and are
// re-asserted by the `lower_el_sync_slot_*` test below.
const ENC_MRS_X9_ESR_EL1: u32 = 0xd538_5209; // mrs  x9, esr_el1
const ENC_UBFX_X9_X9_EC: u32 = 0xd35a_7d29; // ubfx x9, x9, #26, #6  (EC = ESR[31:26])
const ENC_CMP_X9_SVC: u32 = 0xf100_553f; // cmp  x9, #0x15  (subs xzr, x9, #EC_SVC64)
const ENC_BNE_FAULT: u32 = 0x5400_00e1; // b.ne +7 instructions -> the fault block

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
    // Overwrite the lower-EL sync slot. It is entered by an EL0 `svc` AND by an
    // EL0 synchronous fault, so it discriminates on ESR.EC: EC == 0x15 (SVC64)
    // takes the syscall path (store to SENTINEL_GPA); anything else is a fault
    // and takes the fault path (store to FAULT_SENTINEL_GPA). 17 instructions,
    // well within the 0x80 (32-instruction) slot.
    //
    // s+0 SAVES the guest's x9 to TPIDR_EL1 BEFORE clobbering it (the ABI
    // preserves x9; see the encoder comment). `complete_syscall` restores it.
    // The `mrs x9, esr_el1` then MUST run before any sentinel store: that store
    // is itself a stage-2 MMIO abort, but because it does NOT take an EL1
    // exception it leaves ESR_EL1/FAR_EL1 holding the ORIGINAL EL0-fault values
    // for the host to read. The b.ne jumps +7 instructions to the fault block, so
    // the fault block MUST stay exactly 7 instructions after it (the test asserts
    // this) — the +1 leading `msr` shifts BOTH paths uniformly, so +7 is intact.
    let s = AARCH64_VECTOR_LOWER_EL_SYNC_OFFSET as usize;
    // movz x9, gpa[0]; movk x9, gpa[1..4] — materialize a 64-bit gpa into x9.
    let materialize = |b: &mut [u8], off: usize, g: u64| {
        put(b, off, enc_movz_x9((g & 0xFFFF) as u16, 0));
        put(b, off + 4, enc_movk_x9(((g >> 16) & 0xFFFF) as u16, 1));
        put(b, off + 8, enc_movk_x9(((g >> 32) & 0xFFFF) as u16, 2));
        put(b, off + 12, enc_movk_x9(((g >> 48) & 0xFFFF) as u16, 3));
    };
    // Save x9 (s+0), then the ESR.EC discriminator (s+4 .. s+16).
    put(&mut bytes, s, ENC_MSR_TPIDR_EL1_X9); //   msr  tpidr_el1, x9  (save live x9)
    put(&mut bytes, s + 4, ENC_MRS_X9_ESR_EL1); // mrs  x9, esr_el1
    put(&mut bytes, s + 8, ENC_UBFX_X9_X9_EC); //  ubfx x9, x9, #26, #6  (x9 = EC)
    put(&mut bytes, s + 12, ENC_CMP_X9_SVC); //    cmp  x9, #0x15
    put(&mut bytes, s + 16, ENC_BNE_FAULT); //     b.ne fault_block (+7)
    // SVC path (EC == 0x15), s+20 .. s+40: re-materialize x9 (clobbered by the
    // mrs) with SENTINEL_GPA, store, eret.
    materialize(&mut bytes, s + 20, SENTINEL_GPA);
    put(&mut bytes, s + 36, ENC_STR_X8_X9); //     str x8, [x9]  (host: gpa == SENTINEL_GPA)
    put(&mut bytes, s + 40, AARCH64_ERET_OPCODE); // eret
    // FAULT path (EC != 0x15), s+44 .. s+64: store to FAULT_SENTINEL_GPA so the
    // host captures ESR/FAR/ELR and delivers a guest signal, then eret.
    materialize(&mut bytes, s + 44, FAULT_SENTINEL_GPA);
    put(&mut bytes, s + 60, ENC_STR_X8_X9); //     str x8, [x9]  (host: gpa == FAULT_SENTINEL_GPA)
    put(&mut bytes, s + 64, AARCH64_ERET_OPCODE); // eret
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
    /// For a dynamic ALIAS window (a guest `mmap(MAP_SHARED, fd)` / high-VA
    /// mapping whose dispatcher-chosen VA is >= 1 TiB and so cannot itself be a
    /// KVM GPA under the 40-bit nested-KVM IPA limit): the GPA the KVM slot is
    /// registered at (a free identity hole < 1 TiB), which DIFFERS from `base`
    /// (the guest VA used for the syscall-path `locate`). `None` for an ordinary
    /// identity window (`base` IS the GPA). The guest reaches the backing via
    /// stage-1 (VA -> this GPA, built by `map_aliased`) then stage-2 (the slot);
    /// the host syscall path reaches the SAME backing by `locate(VA)`.
    slot_gpa: Option<u64>,
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
    /// Guest-physical ranges the guest has made PROT_NONE (mmap(PROT_NONE)/
    /// mprotect/munmap). carrick backs the whole arena with accessible host
    /// memory, so a PROT_NONE buffer is otherwise readable on the syscall path —
    /// a guest passing such a buffer to a syscall must instead see EFAULT. This
    /// is the HOST-SIDE syscall-read check only (cheap, no page tables); making
    /// the GUEST itself fault mid-EL0 needs stage-1 edits + signal injection
    /// (Phase D), so `protect_range`/`unmap_range` stay no-ops for now.
    ///
    /// SHARED (`Arc`) with every sibling vCPU thread's `GuestRam`, exactly like
    /// HVF: a `clone(CLONE_VM)` thread group runs on one VM, so a `mprotect`
    /// made by any thread MUST be observed by every other thread's syscall-path
    /// checks. A per-thread copy diverges — one thread reserves a region
    /// PROT_NONE, another commits it, and the first then wrongly EFAULTs a valid
    /// buffer there (the Go-on-KVM `futexwakeup … EFAULT` crash). A `fork(2)`
    /// child gets an INDEPENDENT copy (the COW of the whole process duplicates
    /// the `Arc`'s target); `execve` starts fresh. The neutral-core type is
    /// shared with HVF: [`carrick_mem::protections::MemoryProtections`].
    protections: Arc<MemoryProtections>,
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
            protections: Arc::new(MemoryProtections::default()),
            owns_windows: true,
        }
    }

    /// The shared PROT_NONE bookkeeping handle, cloned into a `clone(CLONE_VM)`
    /// sibling so it observes this thread's `mprotect`s (and vice versa).
    pub(crate) fn shared_protections(&self) -> Arc<MemoryProtections> {
        Arc::clone(&self.protections)
    }

    /// Whether [gpa, gpa+len) overlaps any PROT_NONE range (so a syscall buffer
    /// there must fault with EFAULT). Delegates to the SHARED, process-wide
    /// [`MemoryProtections`] so a sibling thread's `mprotect` is visible here.
    pub(crate) fn range_no_access(&self, gpa: u64, len: usize) -> bool {
        self.protections.range_no_access(gpa, len)
    }

    /// Record (`no_access=true`) or clear (`false`) a PROT_NONE range on the
    /// SHARED bookkeeping (interior-mutable, so `&self`): the change is observed
    /// by every sibling vCPU thread's syscall-path access checks.
    pub(crate) fn set_no_access(&self, gpa: u64, len: usize, no_access: bool) {
        self.protections.set_no_access(gpa, len, no_access);
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
        if (base <= SENTINEL_GPA && SENTINEL_GPA < end)
            || (base <= FAULT_SENTINEL_GPA && FAULT_SENTINEL_GPA < end)
        {
            return Err(OsError::new(format!(
                "kvm: window 0x{base:x}..0x{end:x} would back a sentinel gpa \
                 (syscall 0x{SENTINEL_GPA:x} / fault 0x{FAULT_SENTINEL_GPA:x}); both must stay unmapped"
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
            slot_gpa: None,
        });
        Ok(())
    }

    /// Back a dynamic ALIAS mapping on the LIVE VM: host-mmap the backing (a
    /// `MAP_SHARED` dup'd fd for a guest `mmap(MAP_SHARED, fd)`, coherent across
    /// fork + other openers; or `MAP_PRIVATE|MAP_ANON` seeded with `payload`),
    /// register a NEW KVM memory slot at `gpa` (a low identity hole), and track
    /// the window keyed by the guest `va` (which differs from `gpa`). The caller
    /// then builds the VA->`gpa` stage-1 path via `map_aliased`. The host backing
    /// is owned by this `GuestRam` and `munmap`'d on drop. Mirrors HVF's
    /// `map_host_alias`, with a KVM slot in place of `hv_vm_map`.
    pub(crate) fn add_alias(
        &mut self,
        vm: &mut KvmVm,
        va: u64,
        gpa: u64,
        len: u64,
        backing: AliasBacking,
    ) -> Result<(), OsError> {
        let size = usize::try_from(align_up_slot(len)?)
            .map_err(|_| OsError::new(format!("kvm: alias len {len} too large")))?;
        // The slot GPA must never back a sentinel (the KVM alias arena sits at
        // 640..704 GiB, above both 320/324 GiB sentinels, but assert the contract).
        let gpa_end = gpa
            .checked_add(size as u64)
            .ok_or_else(|| OsError::new(format!("kvm: alias slot 0x{gpa:x}+{size} overflows")))?;
        if (gpa <= SENTINEL_GPA && SENTINEL_GPA < gpa_end)
            || (gpa <= FAULT_SENTINEL_GPA && FAULT_SENTINEL_GPA < gpa_end)
        {
            return Err(OsError::new(format!(
                "kvm: alias slot 0x{gpa:x}..0x{gpa_end:x} would back a sentinel gpa"
            )));
        }
        let (host, kind) = match backing {
            AliasBacking::File { fd, offset, prot } => {
                // MAP_SHARED of the dup'd fd: writes hit the page cache (coherent
                // with other openers + across fork). We own the dup; mmap takes its
                // own reference, so close it once mapped.
                let h = unsafe {
                    libc::mmap(
                        std::ptr::null_mut(),
                        size,
                        prot,
                        libc::MAP_SHARED,
                        fd,
                        offset,
                    )
                };
                unsafe { libc::close(fd) };
                if h == libc::MAP_FAILED {
                    return Err(OsError::new(format!(
                        "kvm: alias MAP_SHARED file (fd={fd} off={offset} size={size} prot={prot}) failed"
                    )));
                }
                (h.cast::<u8>(), WindowKind::Shared)
            }
            AliasBacking::Anon { payload } => {
                let h = unsafe {
                    libc::mmap(
                        std::ptr::null_mut(),
                        size,
                        libc::PROT_READ | libc::PROT_WRITE,
                        libc::MAP_PRIVATE | libc::MAP_ANONYMOUS | libc::MAP_NORESERVE,
                        -1,
                        0,
                    )
                };
                if h == libc::MAP_FAILED {
                    return Err(OsError::new(format!(
                        "kvm: alias anon mmap size={size} failed"
                    )));
                }
                if !payload.is_empty() {
                    let n = payload.len().min(size);
                    unsafe { std::ptr::copy_nonoverlapping(payload.as_ptr(), h.cast::<u8>(), n) };
                }
                (h.cast::<u8>(), WindowKind::Private)
            }
        };
        // Register the LIVE KVM slot at the alias GPA. On failure, unmap before
        // returning so we never leak the host backing.
        if let Err(e) = vm.map_memory(gpa, host, size, MemPerms::ReadWriteExec) {
            unsafe { libc::munmap(host.cast::<libc::c_void>(), size) };
            return Err(e);
        }
        self.windows.push(Window {
            base: va,
            host,
            len: size,
            kind,
            slot_gpa: Some(gpa),
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

    /// Diagnostic: describe why an access at `[gpa, gpa+len)` would (not) resolve
    /// — the located window or the nearest windows, plus no_access state. Gated
    /// callers only (CARRICK_MEM_DEBUG); allocates, so never on the hot path.
    pub(crate) fn debug_access(&self, gpa: u64, len: usize) -> String {
        let located = self.locate(gpa, len).is_some();
        let no_access = self.range_no_access(gpa, len);
        // The PROT_NONE intervals straddling (or within ~16 MiB of) the access,
        // so a stale-reserve vs genuine-uncommitted range is distinguishable.
        let near: Vec<String> = self
            .protections
            .snapshot()
            .into_iter()
            .filter(|&(s, e)| e > gpa.saturating_sub(0x100_0000) && s < gpa.saturating_add(0x100_0000))
            .map(|(s, e)| format!("[0x{s:x}..0x{e:x})"))
            .collect();
        let mut wins: Vec<String> = self
            .windows
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
            self.windows.len(),
            wins.join(" ")
        )
    }

    /// Host virtual address of the `len`-byte span at guest-physical `gpa`,
    /// regardless of window kind, or `None` if it does not lie wholly within one
    /// backed window. Used by the live stage-1 page-table editor to `sync_to_host`
    /// changed descriptors straight into the guest's page-table backing (at
    /// `LINUX_PAGE_TABLES_BASE`, in the low window). Unlike
    /// [`Self::shared_futex_host_addr`], this does NOT require a `Shared` window.
    pub(crate) fn host_ptr(&self, gpa: u64, len: usize) -> Option<*mut u8> {
        let (w, off) = self.locate(gpa, len)?;
        // SAFETY: `locate` proved [gpa, gpa+len) ⊆ this window, so `host + off`
        // points at `len` valid bytes of that window's backing.
        Some(unsafe { w.host.add(off) })
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
        // An alias window registers its KVM slot at `slot_gpa` (a low identity
        // hole), NOT `base` (its high guest VA); an ordinary window has base==gpa.
        self.windows
            .iter()
            .map(|w| (w.slot_gpa.unwrap_or(w.base), w.host, w.len))
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
                slot_gpa: w.slot_gpa,
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
    /// Build a NON-OWNING sibling view over the parent's window descriptors,
    /// SHARING the parent's PROT_NONE bookkeeping (`protections`) so the sibling
    /// observes the parent's (and every other sibling's) `mprotect`s — and they
    /// observe its. A fresh per-thread set would diverge (the Go-on-KVM EFAULT
    /// crash); see [`MemoryProtections`]'s sharing contract.
    pub(crate) fn from_shared_windows(
        descs: &[WindowDesc],
        protections: Arc<MemoryProtections>,
    ) -> Self {
        let windows = descs
            .iter()
            .map(|d| Window {
                base: d.base,
                host: d.host as *mut u8,
                len: d.len,
                kind: d.kind,
                slot_gpa: d.slot_gpa,
            })
            .collect();
        Self {
            windows,
            protections,
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
    /// Alias windows: the KVM-slot GPA (differs from `base`). `None` for ordinary
    /// identity windows. See [`Window::slot_gpa`].
    pub slot_gpa: Option<u64>,
}

/// How [`GuestRam::add_alias`] backs a dynamic alias mapping's host memory.
pub(crate) enum AliasBacking<'a> {
    /// A guest `mmap(MAP_SHARED, fd)`: `MAP_SHARED` of a dup'd host fd at `offset`
    /// with host `prot`, so guest writes hit the file's page cache (coherent with
    /// other openers and inherited across `fork(2)`). `GuestRam::add_alias` owns
    /// the dup and closes it after the mmap takes its own reference.
    File {
        fd: libc::c_int,
        offset: libc::off_t,
        prot: libc::c_int,
    },
    /// A high-VA anonymous alias: `MAP_PRIVATE|MAP_ANON` seeded with `payload`
    /// (empty for a zero-filled region).
    Anon { payload: &'a [u8] },
}

/// Load `image` (a freestanding aarch64 ELF), build the stage-1 identity map +
/// trampoline + sentinel vector, program the vCPU, and return it parked at the
/// EL1 trampoline. Reuses carrick-mem's architectural builders; does NOT use
/// the FEAT_PAN3 workaround (see `program_sysregs`).
pub fn bring_up(image: &AddressSpace) -> Result<BroughtUp, OsError> {
    // 1-3. Lay out guest physical RAM: windows + image segments + the
    //       architectural bring-up pages (shared with execve_into).
    let mut ram = GuestRam::build_for_image(image)?;

    // 4. Create VM + publish every window as its own KVM memory slot.
    let mut vm = KvmVm::create(image)?;
    for (base, host, len) in ram.windows_for_kvm() {
        vm.map_memory(base, host, len, MemPerms::ReadWriteExec)?;
    }
    let mut vcpu = vm.add_vcpu()?;

    // 5. Program registers (sys regs + entry/SP/PC), NO FEAT_PAN3 workaround.
    program_sysregs(&mut vcpu, image)?;

    // 6. Calibrate the vDSO clock so its `cntvct_el0` fast path returns correct
    //    wall-clock time (EL0 counter access is enabled per-vCPU in the vCPU
    //    create path). Best-effort: a calibration failure leaves the vvar zeroed
    //    (realtime reads as boot-relative) rather than aborting bring-up.
    let _ = populate_vdso_vvar(&vcpu, &mut ram);

    Ok(BroughtUp {
        vm,
        vcpu,
        ram,
        entry: image.entry(),
    })
}

/// Calibrate the vDSO clock data page (vvar). The vDSO computes
/// `realtime_ns = CNTVCT_EL0/CNTFRQ_EL0*1e9 + realtime_off`, reading CNTVCT/CNTFRQ
/// directly at EL0 (enabled per-vCPU via CNTKCTL_EL1 in the vCPU create path) and
/// `realtime_off` from the vvar. So write `realtime_off = unix_ns - cnt/freq*1e9`
/// measured here against the GUEST's counter (KVM_REG_ARM_TIMER_CNT — the value
/// the guest's `mrs cntvct_el0` returns) and the CNTFRQ_EL0 the vDSO reads. The
/// offset is constant; as the guest counter advances, the vDSO tracks real time.
/// (The vDSO reads the freq from the sysreg, not the vvar, so only offset 16 is
/// filled.) Mirrors HVF's `populate_vdso_data_page`, calibrated to the guest's own
/// counter rather than macOS CLOCK_UPTIME_RAW. Re-run on execve (new image RAM)
/// and on the fork child (new VM = new counter basis).
/// Read the host's `CNTFRQ_EL0` (timer frequency, Hz). Unconditionally
/// EL0-readable on aarch64, and equal to the KVM guest's CNTFRQ_EL0 (the same
/// physical counter) — which KVM does not surface through `KVM_GET_ONE_REG`.
fn host_cntfrq_el0() -> u64 {
    let freq: u64;
    // SAFETY: `cntfrq_el0` is an unprivileged read on aarch64 Linux.
    unsafe {
        core::arch::asm!("mrs {}, cntfrq_el0", out(reg) freq, options(nomem, nostack));
    }
    freq
}

pub(crate) fn populate_vdso_vvar(vcpu: &KvmVcpu, ram: &mut GuestRam) -> Result<(), OsError> {
    use carrick_mem::vdso::{LINUX_VVAR_BASE, VVAR_OFF_REALTIME_OFF_NS};
    // KVM does NOT expose CNTFRQ_EL0 via KVM_GET_ONE_REG (ENOENT), but the guest's
    // CNTFRQ_EL0 (what the vDSO reads) is the SAME physical timer frequency the
    // host sees — and CNTFRQ_EL0 is unconditionally EL0-readable on aarch64 Linux,
    // so read it directly from the host. The COUNTER, however, must come from the
    // guest (KVM_REG_ARM_TIMER_CNT) — it has the guest's CNTVOFF baked in.
    let freq = host_cntfrq_el0();
    let cnt = vcpu.get_timer_cnt()?;
    if std::env::var_os("CARRICK_VDSO_DEBUG").is_some() {
        eprintln!("[VDSODBG] host_cntfrq={freq} guest_timer_cnt={cnt}");
    }
    if freq == 0 {
        return Ok(()); // no counter — the vDSO clock falls back to syscalls
    }
    let mono_ns = ((cnt as u128) * 1_000_000_000u128 / (freq as u128)) as u64;
    let unix_ns = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0);
    let realtime_off = unix_ns.wrapping_sub(mono_ns);
    ram.write_gpa(
        LINUX_VVAR_BASE + VVAR_OFF_REALTIME_OFF_NS as u64,
        &realtime_off.to_le_bytes(),
    )
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
mod vector_tests {
    use super::*;

    /// Byte-assert the lower-EL-sync slot: the ESR.EC discriminator, the svc
    /// path (SENTINEL_GPA), and the fault path (FAULT_SENTINEL_GPA), plus that the
    /// `b.ne` jumps exactly +7 instructions to the fault block. Hand-assembled
    /// vector asm is high-risk; this locks every opcode + the branch offset.
    #[test]
    fn lower_el_sync_slot_discriminates_svc_vs_fault() {
        let bytes = el1_vectors_sentinel_bytes();
        let s = AARCH64_VECTOR_LOWER_EL_SYNC_OFFSET as usize;
        let op = |off: usize| -> u32 {
            u32::from_le_bytes(bytes[s + off..s + off + 4].try_into().unwrap())
        };
        // s+0 saves the guest's live x9 (the ABI preserves x9; the vector clobbers
        // it as the sentinel-store scratch, and complete_syscall restores it).
        assert_eq!(
            op(0),
            ENC_MSR_TPIDR_EL1_X9,
            "s+0 msr tpidr_el1, x9 (save x9)"
        );
        // Discriminator (shifted +4 by the leading save).
        assert_eq!(op(4), ENC_MRS_X9_ESR_EL1, "s+4 mrs x9, esr_el1");
        assert_eq!(op(8), ENC_UBFX_X9_X9_EC, "s+8 ubfx x9,x9,#26,#6");
        assert_eq!(op(12), ENC_CMP_X9_SVC, "s+12 cmp x9,#0x15");
        assert_eq!(op(16), ENC_BNE_FAULT, "s+16 b.ne fault");
        // A B.cond imm19 (bits[23:5]) is the branch distance in INSTRUCTIONS; the
        // fault block (s+44) is 7 instructions after the b.ne (s+16) — both paths
        // shifted uniformly by the leading save, so the distance is unchanged.
        assert_eq!(
            (op(16) >> 5) & 0x7_ffff,
            7,
            "b.ne must jump +7 instructions"
        );
        assert_eq!((44 - 16) / 4, 7, "fault block is +7 instructions from b.ne");
        // SVC path: SENTINEL_GPA materialize + str + eret.
        assert_eq!(
            op(20),
            enc_movz_x9((SENTINEL_GPA & 0xFFFF) as u16, 0),
            "s+20 movz SENTINEL"
        );
        assert_eq!(op(36), ENC_STR_X8_X9, "s+36 svc str x8,[x9]");
        assert_eq!(op(40), AARCH64_ERET_OPCODE, "s+40 svc eret");
        // FAULT path: FAULT_SENTINEL_GPA materialize + str + eret.
        assert_eq!(
            op(44),
            enc_movz_x9((FAULT_SENTINEL_GPA & 0xFFFF) as u16, 0),
            "s+44 movz FAULT"
        );
        assert_eq!(
            op(48),
            enc_movk_x9(((FAULT_SENTINEL_GPA >> 16) & 0xFFFF) as u16, 1),
            "s+48 movk FAULT"
        );
        assert_eq!(op(60), ENC_STR_X8_X9, "s+60 fault str x8,[x9]");
        assert_eq!(op(64), AARCH64_ERET_OPCODE, "s+64 fault eret");
    }
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
