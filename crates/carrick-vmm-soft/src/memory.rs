//! Flat guest-physical memory for the soft carrier, seated in one
//! [`LinearPlacement`] with one authenticated [`ExtentRecord`] per window.
//!
//! The KVM carrier registers each prepared RAM window as its own memslot.
//! `SoftMmuMemory` requires `host = gpa + K`, so this M1 probe places every
//! window at its guest-physical offset in a single lazily committed
//! reservation and copies the prepared bytes in. The retained-allocation
//! backend (`CarrierMemoryIo` over soft memslots) is the follow-up slice.

use std::num::NonZeroU64;
use std::ptr::NonNull;

use carrick_hal::TrapError;
use carrick_softcpu_x86::{
    ExtentRecord, ExtentTable, FrameGpa, LinearPlacement, OwnerGeneration, RootGpa, SoftMmuMemory,
};
use carrick_x86::cpl0_entry::CpuBinding;
use carrick_x86_cpl0_host::cpl0_boot::{
    BINDING_OFFSET, INITIAL_EXTENT_GPA, KERNEL_REGION_GPA, LAYOUT, META_GPA, PreparedBoot, STRIDE,
    fail,
};

/// One owner generation authenticates every bootstrap extent and the root.
const BOOT_GENERATION: OwnerGeneration = OwnerGeneration::FIRST;
const PAGE: u64 = 4096;

/// Lazily committed anonymous reservation; unmapped on drop.
struct Arena {
    base: NonNull<u8>,
    len: usize,
}

impl Arena {
    fn reserve(len: usize) -> Result<Self, TrapError> {
        // SAFETY: a fresh anonymous private mapping aliases no Rust object.
        let raw = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                len,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_PRIVATE | libc::MAP_ANONYMOUS | libc::MAP_NORESERVE,
                -1,
                0,
            )
        };
        if raw == libc::MAP_FAILED {
            return Err(fail(format!("soft carrier reservation of {len:#x} bytes")));
        }
        let base = NonNull::new(raw.cast::<u8>()).ok_or_else(|| fail("null soft reservation"))?;
        Ok(Self { base, len })
    }

    fn ptr(&self, gpa: u64, len: usize) -> Result<*mut u8, TrapError> {
        let offset = usize::try_from(gpa).map_err(|_| fail("soft gpa width"))?;
        if offset.checked_add(len).is_none_or(|end| end > self.len) {
            return Err(fail(format!(
                "soft gpa {gpa:#x}+{len:#x} outside reservation"
            )));
        }
        // SAFETY: `offset + len` lies inside the live reservation.
        Ok(unsafe { self.base.as_ptr().add(offset) })
    }
}

impl Drop for Arena {
    fn drop(&mut self) {
        // SAFETY: `base`/`len` name exactly the mapping `reserve` created, and
        // every borrower (placement, registration) is dropped before it.
        unsafe { libc::munmap(self.base.as_ptr().cast(), self.len) };
    }
}

/// Soft carrier physical memory: the prepared bootstrap windows, the
/// supervisor kernel region and the optional initial guest-MM extent.
pub struct SoftBootMemory {
    placement: LinearPlacement,
    extents: ExtentTable,
    // Field order is drop order: the registration and placement borrow the
    // reservation, which must be released last.
    _file_region: carrick_el1_abi::FileRegionRegistration,
    arena: Arena,
}

impl SoftBootMemory {
    /// Seat `prepared` (and its stopped-carrier records) in flat soft memory.
    /// Mirrors the KVM carrier's installation order before CPU creation:
    /// bootstrap windows, kernel region with its file region and fault
    /// records, the initial extent, and each CPU binding's file region.
    pub fn install(
        prepared: &PreparedBoot,
        initial_extent_bytes: Option<usize>,
        carrier_identity: NonZeroU64,
    ) -> Result<Self, TrapError> {
        if !prepared.ipc_backings.is_empty() {
            return Err(fail(
                "soft carrier: IPC window backings are not installed yet",
            ));
        }
        let region_len = carrick_el1_abi::EL1_REGION_SIZE;
        let mut extents: Vec<(u64, u64, Option<*const u8>)> = prepared
            .ram
            .slot_windows()
            .into_iter()
            .map(|(gpa, host, len)| (gpa, len as u64, Some(host.cast_const())))
            .collect();
        extents.push((KERNEL_REGION_GPA, region_len, None));
        if let Some(len) = initial_extent_bytes {
            extents.push((INITIAL_EXTENT_GPA, len as u64, None));
        }
        let span = extents
            .iter()
            .map(|&(gpa, len, _)| gpa.saturating_add(len))
            .max()
            .ok_or_else(|| fail("soft carrier has no memory"))?
            .next_multiple_of(PAGE);
        let arena = Arena::reserve(usize::try_from(span).map_err(|_| fail("soft span width"))?)?;
        // SAFETY: `arena` is a page-aligned private mapping covering `span`,
        // zero-initialized and valid for (atomic) reads and writes. It is
        // owned by the returned value, never moves, and outlives `placement`.
        // The default x86 holes exclude the xAPIC page from backing access.
        let placement =
            unsafe { LinearPlacement::with_x86_defaults(arena.base.as_ptr() as usize, span) }
                .map_err(|error| fail(format!("soft placement: {error:?}")))?;
        let mut table =
            ExtentTable::new().map_err(|_| fail("soft extent table generation exhausted"))?;
        for &(gpa, len, source) in &extents {
            if gpa % PAGE != 0 || len % PAGE != 0 {
                return Err(fail(format!("soft extent {gpa:#x}+{len:#x} unaligned")));
            }
            if let Some(source) = source {
                let bytes = usize::try_from(len).map_err(|_| fail("soft window width"))?;
                let destination = arena.ptr(gpa, bytes)?;
                // SAFETY: `source` is the prepared window's live host backing of
                // `bytes` bytes (retained by `prepared`); `destination` is a
                // disjoint range inside the private reservation.
                unsafe { std::ptr::copy_nonoverlapping(source, destination, bytes) };
            }
            if !table.install(ExtentRecord::new(FrameGpa::new(gpa), len, BOOT_GENERATION)) {
                return Err(fail(format!("soft extent {gpa:#x}+{len:#x} refused")));
            }
        }
        let root = RootGpa::page_aligned(FrameGpa::new(LAYOUT.pml4_base))
            .ok_or_else(|| fail("bootstrap root alignment"))?;
        if !table.set_root_generation(root, BOOT_GENERATION) {
            return Err(fail("bootstrap root generation refused"));
        }

        let binding = carrick_el1_abi::FileRegionBinding::new(
            carrick_el1_abi::FileRegionId::from_carrier(carrier_identity),
            carrick_guest_arch::KernelVa::new(carrick_el1_abi::X86_CPL0_REGION_BASE),
            FrameGpa::new(KERNEL_REGION_GPA),
            carrick_guest_arch::GuestLen::new(region_len),
        )
        .map_err(|error| fail(format!("file region binding: {error:?}")))?;
        let region = usize::try_from(region_len).map_err(|_| fail("kernel region width"))?;
        let mapped = NonNull::new(arena.ptr(KERNEL_REGION_GPA, region)?)
            .ok_or_else(|| fail("null kernel region"))?;
        // SAFETY: the zeroed kernel region covers the whole binding, has no
        // guest, CPU or table user yet, and stays mapped until the
        // registration (dropped before `arena`) is released.
        let file_region =
            unsafe { carrick_el1_abi::FileRegionRegistration::initialize(mapped, binding) }
                .map_err(|error| fail(format!("file region publication: {error:?}")))?;
        let record = |offset: u64, size: usize, align: usize| -> Result<*mut u8, TrapError> {
            let ptr = arena.ptr(KERNEL_REGION_GPA + offset, size)?;
            if !(ptr as usize).is_multiple_of(align) {
                return Err(fail("boot record alignment"));
            }
            Ok(ptr)
        };
        let residency = record(
            carrick_el1_abi::EL1_FRAME_GRANT_RESIDENCY_OFFSET,
            size_of::<carrick_el1_abi::FrameGrantResidencyTable>(),
            align_of::<carrick_el1_abi::FrameGrantResidencyTable>(),
        )?;
        let ingress = record(
            carrick_el1_abi::EL1_SIGNAL_INGRESS_OFFSET,
            size_of::<carrick_el1_abi::SharedSignalIngressQueue>(),
            align_of::<carrick_el1_abi::SharedSignalIngressQueue>(),
        )?;
        let portal = record(
            carrick_el1_abi::EL1_MM_PORTAL_OFFSET,
            size_of::<carrick_el1_abi::MmPortalSlots>(),
            align_of::<carrick_el1_abi::MmPortalSlots>(),
        )?;
        // SAFETY: exclusive stopped-carrier memory; each record has checked
        // bounds and alignment inside the kernel region, as in
        // `CarrierMemory::initialize_fault_records`.
        unsafe {
            carrick_el1_abi::FrameGrantResidencyTable::init_in_place(residency.cast());
            carrick_el1_abi::SharedSignalIngressQueue::initialize_at(ingress.cast());
            portal
                .cast::<carrick_el1_abi::MmPortalSlots>()
                .write(carrick_el1_abi::MmPortalSlots::new());
        }
        for index in 0..2 {
            let slot = arena.ptr(
                META_GPA + BINDING_OFFSET + index * STRIDE,
                size_of::<CpuBinding>(),
            )?;
            // SAFETY: `prepare_boot` initialized this retained binding (copied
            // above); no CPU exists yet.
            unsafe { (*slot.cast::<CpuBinding>()).file_region = binding };
        }
        Ok(Self {
            placement,
            extents: table,
            _file_region: file_region,
            arena,
        })
    }

    /// The stopped carrier's CPU binding for `slot`.
    pub fn binding(&self, slot: u64) -> Result<&CpuBinding, TrapError> {
        let ptr = self.arena.ptr(
            META_GPA + BINDING_OFFSET + slot * STRIDE,
            size_of::<CpuBinding>(),
        )?;
        // SAFETY: initialized retained binding; its mutable fields are atomics.
        Ok(unsafe { &*ptr.cast::<CpuBinding>() })
    }

    /// Borrow an initialized retained record at `gpa`.
    ///
    /// # Safety
    /// `T` must be initialized at `gpa` and accessed only through atomics
    /// while any CPU runs.
    pub unsafe fn record<T>(&self, gpa: u64) -> Result<&T, TrapError> {
        let ptr = self.arena.ptr(gpa, size_of::<T>())?;
        if !(ptr as usize).is_multiple_of(align_of::<T>()) {
            return Err(fail("record alignment"));
        }
        // SAFETY: bounds and alignment checked; initialization is the caller's.
        Ok(unsafe { &*ptr.cast::<T>() })
    }

    /// Copy `len` bytes of guest-physical memory (diagnostics only).
    pub fn read_gpa(&self, gpa: u64, len: usize) -> Result<Vec<u8>, TrapError> {
        let ptr = self.arena.ptr(gpa, len)?;
        let mut out = vec![0; len];
        // SAFETY: in-bounds initialized bytes; the probe reads while stopped.
        unsafe { std::ptr::copy_nonoverlapping(ptr, out.as_mut_ptr(), len) };
        Ok(out)
    }
}

// SAFETY: `placement` describes the live private reservation owned by
// `arena`, and `extents` is this memory's single inventory domain; both
// outlive every translation a CPU seated here can cache.
unsafe impl SoftMmuMemory for SoftBootMemory {
    fn placement(&self) -> &LinearPlacement {
        &self.placement
    }
    fn extents(&self) -> &ExtentTable {
        &self.extents
    }
    fn extents_mut(&mut self) -> &mut ExtentTable {
        &mut self.extents
    }
}
