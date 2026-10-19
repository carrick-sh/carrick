//! Linear placement of guest-physical memory (`host = gpa + K`) and MMIO holes.
//!
//! [`LinearPlacement::host`] is the **only** place in the software vCPU stack where an
//! extent-authenticated guest-physical address ([`AuthenticatedGpa`]) becomes a [`HostVa`].

use crate::domains::{AuthenticatedGpa, PAGE_OFFSET_MASK_4K, PAGE_SIZE_4K};

/// Default x86 local APIC (xAPIC) MMIO base GPA (`0xfee0_0000`).
pub const LAPIC_MMIO_BASE_GPA: u64 = 0xfee0_0000;
/// Default x86 local APIC (xAPIC) MMIO window size in bytes (`4096`).
pub const LAPIC_MMIO_SIZE_BYTES: u64 = PAGE_SIZE_4K;
/// Maximum number of disjoint MMIO holes tracked in a [`MmioHoles`] set.
pub const MAX_MMIO_HOLES: usize = 8;

pub use carrick_guest_arch::HostVa;

/// x86 4 KiB page base for [`HostVa`].
#[inline]
pub const fn host_page_base_4k(host_va: HostVa) -> usize {
    host_va.raw() & (crate::domains::PAGE_BASE_MASK_4K as usize)
}

/// x86 4 KiB page geometry helper for [`HostVa`].
pub trait X86HostPage4K {
    fn page_base(self) -> usize;
}

impl X86HostPage4K for HostVa {
    #[inline]
    fn page_base(self) -> usize {
        host_page_base_4k(self)
    }
}


mod sealed {
    use crate::domains::AuthenticatedGpa;
    pub trait Sealed {}
    impl Sealed for AuthenticatedGpa {}
}

/// Sealed marker trait for extent-authenticated guest-physical address types accepted by
/// [`LinearPlacement::host`] (implemented **only** for [`AuthenticatedGpa`]).
pub trait PlacementGpa: sealed::Sealed + Copy {
    fn raw_gpa(self) -> u64;
}

impl PlacementGpa for AuthenticatedGpa {
    fn raw_gpa(self) -> u64 {
        self.raw()
    }
}

/// One guest-physical MMIO hole excluded from [`LinearPlacement`] and [`crate::tlb::SoftTlb`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MmioHole {
    pub base_gpa: u64,
    pub size_bytes: u64,
}

impl MmioHole {
    /// Construct a page-aligned MMIO hole.
    pub const fn new(base_gpa: u64, size_bytes: u64) -> Result<Self, PlacementError> {
        if size_bytes == 0
            || (base_gpa & PAGE_OFFSET_MASK_4K) != 0
            || (size_bytes & PAGE_OFFSET_MASK_4K) != 0
        {
            return Err(PlacementError::UnalignedHole {
                base_gpa,
                size_bytes,
            });
        }
        if base_gpa.checked_add(size_bytes).is_none() {
            return Err(PlacementError::AddressOverflow { gpa: base_gpa });
        }
        Ok(Self {
            base_gpa,
            size_bytes,
        })
    }
    pub const fn end_gpa(self) -> u64 {
        self.base_gpa.saturating_add(self.size_bytes)
    }
    pub const fn contains(self, gpa: u64) -> bool {
        gpa >= self.base_gpa && gpa < self.end_gpa()
    }
    pub const fn overlaps(self, base_gpa: u64, len: u64) -> bool {
        if len == 0 {
            return self.contains(base_gpa);
        }
        base_gpa < self.end_gpa() && base_gpa.saturating_add(len) > self.base_gpa
    }
}

/// Fixed-capacity collection of guest-physical MMIO holes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MmioHoles {
    holes: [MmioHole; MAX_MMIO_HOLES],
    len: usize,
}

impl MmioHoles {
    pub const fn empty() -> Self {
        let zero = MmioHole {
            base_gpa: 0,
            size_bytes: PAGE_SIZE_4K,
        };
        Self {
            holes: [zero; MAX_MMIO_HOLES],
            len: 0,
        }
    }
    /// Default x86 hole set containing the xAPIC MMIO page at `0xfee0_0000..0xfee0_1000`.
    pub const fn x86_default() -> Self {
        let mut set = Self::empty();
        set.holes[0] = MmioHole {
            base_gpa: LAPIC_MMIO_BASE_GPA,
            size_bytes: LAPIC_MMIO_SIZE_BYTES,
        };
        set.len = 1;
        set
    }
    /// Return a new [`MmioHoles`] with an additional page-aligned hole `[base_gpa, base_gpa + size_bytes)`.
    pub const fn with_hole(
        mut self,
        base_gpa: u64,
        size_bytes: u64,
    ) -> Result<Self, PlacementError> {
        let hole = match MmioHole::new(base_gpa, size_bytes) {
            Ok(h) => h,
            Err(e) => return Err(e),
        };
        if self.len >= MAX_MMIO_HOLES {
            return Err(PlacementError::TooManyHoles);
        }
        self.holes[self.len] = hole;
        self.len += 1;
        Ok(self)
    }
    pub fn as_slice(&self) -> &[MmioHole] {
        &self.holes[..self.len]
    }
    pub const fn contains_gpa(&self, gpa: u64) -> bool {
        let mut i = 0;
        while i < self.len {
            if self.holes[i].contains(gpa) {
                return true;
            }
            i += 1;
        }
        false
    }
    pub const fn overlaps_range(&self, base_gpa: u64, len: u64) -> bool {
        let mut i = 0;
        while i < self.len {
            if self.holes[i].overlaps(base_gpa, len) {
                return true;
            }
            i += 1;
        }
        false
    }
}

impl Default for MmioHoles {
    fn default() -> Self {
        Self::x86_default()
    }
}

/// Errors returned when constructing or querying [`LinearPlacement`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PlacementError {
    UnalignedPlacement {
        base_host_addr: usize,
        span_bytes: u64,
    },
    UnalignedHole {
        base_gpa: u64,
        size_bytes: u64,
    },
    TooManyHoles,
    MmioHole {
        gpa: u64,
    },
    OutOfBounds {
        gpa: u64,
        span_bytes: u64,
    },
    AddressOverflow {
        gpa: u64,
    },
}

/// Typed linear placement (`host = gpa + K`) of guest-physical memory.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LinearPlacement {
    base_host_addr: usize,
    span_bytes: u64,
    holes: MmioHoles,
}

impl LinearPlacement {
    /// Construct a placement over caller-managed host memory.
    ///
    /// Safe code cannot supply an arbitrary host address:
    ///
    /// ```compile_fail,E0133
    /// use carrick_softmmu::{LinearPlacement, MmioHoles};
    /// let _ = LinearPlacement::new(0x1000, 4096, MmioHoles::empty());
    /// ```
    ///
    /// # Safety
    ///
    /// If construction succeeds, `base_host_addr` must identify a 4096-byte-aligned
    /// host allocation covering `span_bytes`. Every byte outside `holes` must be
    /// initialized and valid for reads and writes, including atomic `AtomicU64`
    /// accesses to aligned page-table words. The backing must stay at the same
    /// address and outlive every access through this placement, its copies, and
    /// cached translations derived from it. Copies and cached addresses do not own
    /// the backing or extend its lifetime. The caller must prevent conflicting
    /// Rust references and data races (including concurrent atomic and non-atomic accesses).
    /// Alignment, size and overflow checks alone do not establish memory validity.
    pub unsafe fn new(
        base_host_addr: usize,
        span_bytes: u64,
        holes: MmioHoles,
    ) -> Result<Self, PlacementError> {
        if span_bytes == 0
            || (base_host_addr & (PAGE_OFFSET_MASK_4K as usize)) != 0
            || (span_bytes & PAGE_OFFSET_MASK_4K) != 0
        {
            return Err(PlacementError::UnalignedPlacement {
                base_host_addr,
                span_bytes,
            });
        }
        let span_usize = usize::try_from(span_bytes)
            .map_err(|_| PlacementError::AddressOverflow { gpa: span_bytes })?;
        base_host_addr
            .checked_add(span_usize)
            .ok_or(PlacementError::AddressOverflow { gpa: span_bytes })?;
        Ok(Self {
            base_host_addr,
            span_bytes,
            holes,
        })
    }
    /// Construct a placement with the default x86 MMIO holes.
    ///
    /// ```compile_fail,E0133
    /// use carrick_softmmu::LinearPlacement;
    /// let _ = LinearPlacement::with_x86_defaults(0x1000, 4096);
    /// ```
    ///
    /// # Safety
    ///
    /// The validity, alignment, lifetime and aliasing requirements of [`Self::new`]
    /// apply, with [`MmioHoles::x86_default`] excluded from the backing accesses.
    pub unsafe fn with_x86_defaults(
        base_host_addr: usize,
        span_bytes: u64,
    ) -> Result<Self, PlacementError> {
        // SAFETY: the caller guarantees `new`'s backing contract for these default holes.
        unsafe { Self::new(base_host_addr, span_bytes, MmioHoles::x86_default()) }
    }
    pub const fn base_host_addr(&self) -> usize {
        self.base_host_addr
    }
    pub const fn span_bytes(&self) -> u64 {
        self.span_bytes
    }
    pub const fn holes(&self) -> &MmioHoles {
        &self.holes
    }
    pub const fn is_mmio_hole(&self, gpa: u64) -> bool {
        self.holes.contains_gpa(gpa)
    }

    /// Convert an extent-authenticated guest-physical address ([`AuthenticatedGpa`]) to [`HostVa`].
    pub fn host<G: PlacementGpa>(&self, gpa: G) -> Result<HostVa, PlacementError> {
        let raw = gpa.raw_gpa();
        if self.holes.contains_gpa(raw) {
            return Err(PlacementError::MmioHole { gpa: raw });
        }
        if raw >= self.span_bytes {
            return Err(PlacementError::OutOfBounds {
                gpa: raw,
                span_bytes: self.span_bytes,
            });
        }
        let offset =
            usize::try_from(raw).map_err(|_| PlacementError::AddressOverflow { gpa: raw })?;
        let addr = self
            .base_host_addr
            .checked_add(offset)
            .ok_or(PlacementError::AddressOverflow { gpa: raw })?;
        Ok(HostVa::new(addr))
    }

    /// Validate a contiguous `[frame_gpa, frame_gpa + len)` byte extent and return its starting [`HostVa`].
    pub fn host_range(
        &self,
        frame_gpa: AuthenticatedGpa,
        len: usize,
    ) -> Result<HostVa, PlacementError> {
        if len == 0 {
            return self.host(frame_gpa);
        }
        let raw = frame_gpa.raw();
        let len_u64 = len as u64;
        let end = raw
            .checked_add(len_u64)
            .ok_or(PlacementError::AddressOverflow { gpa: raw })?;
        if end > self.span_bytes {
            return Err(PlacementError::OutOfBounds {
                gpa: raw,
                span_bytes: self.span_bytes,
            });
        }
        if self.holes.overlaps_range(raw, len_u64) {
            return Err(PlacementError::MmioHole { gpa: raw });
        }
        self.host(frame_gpa)
    }
}
