//! Linear placement of guest-physical memory (`host = gpa + K`) and MMIO holes.
//!
//! [`LinearPlacement::host`] is the **only** place in the software vCPU stack
//! where a guest-physical address ([`FrameGpa`] or [`RootGpa`]) becomes a
//! [`HostVa`]. Both the private field of [`HostVa`] and the `lint-domains`
//! semgrep gate enforce that no other code manufactures a [`HostVa`].

use crate::domains::{FrameGpa, PAGE_OFFSET_MASK_4K, PAGE_SIZE_4K, RootGpa};

/// Default x86 local APIC (xAPIC) MMIO base GPA (`0xfee0_0000`).
pub const LAPIC_MMIO_BASE_GPA: u64 = 0xfee0_0000;

/// Default x86 local APIC (xAPIC) MMIO window size in bytes (`4096`).
pub const LAPIC_MMIO_SIZE_BYTES: u64 = PAGE_SIZE_4K;

/// Maximum number of disjoint MMIO holes tracked in a [`MmioHoles`] set.
pub const MAX_MMIO_HOLES: usize = 8;

/// Host virtual address within a [`LinearPlacement`] reservation (`host = gpa + K`).
///
/// The inner `usize` is private to this module: only [`LinearPlacement::host`]
/// can construct a [`HostVa`].
#[repr(transparent)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct HostVa(usize);

impl HostVa {
    /// Return the raw host virtual address as `usize`.
    #[inline]
    pub const fn raw(self) -> usize {
        self.0
    }

    /// Return the 4 KiB page-aligned base of this host virtual address.
    #[inline]
    pub const fn page_base(self) -> usize {
        self.0 & !(PAGE_OFFSET_MASK_4K as usize)
    }

    /// Return a const pointer to `T` at this host virtual address.
    #[inline]
    pub const fn as_ptr<T>(self) -> *const T {
        self.0 as *const T
    }

    /// Return a mutable pointer to `T` at this host virtual address.
    #[inline]
    pub const fn as_mut_ptr<T>(self) -> *mut T {
        self.0 as *mut T
    }
}

mod sealed {
    use crate::domains::{FrameGpa, RootGpa};

    pub trait Sealed {}
    impl Sealed for FrameGpa {}
    impl Sealed for RootGpa {}
}

/// Sealed marker trait for authenticated guest-physical address types accepted
/// by [`LinearPlacement::host`].
///
/// Implemented **only** for [`FrameGpa`] (obtained after authenticating a
/// [`crate::domains::Stage1Gpa`] and [`crate::domains::OwnerGeneration`] against
/// the extent table) and [`RootGpa`] (page-table root). Unauthenticated
/// [`crate::domains::Stage1Gpa`], [`crate::domains::GuestVa`],
/// [`crate::domains::UserVa`], [`HostVa`], and raw integers are rejected at
/// compile time.
pub trait PlacementGpa: sealed::Sealed + Copy {
    /// Underlying guest-physical byte address.
    fn raw_gpa(self) -> u64;
}

impl PlacementGpa for FrameGpa {
    #[inline]
    fn raw_gpa(self) -> u64 {
        self.raw()
    }
}

impl PlacementGpa for RootGpa {
    #[inline]
    fn raw_gpa(self) -> u64 {
        self.address().raw()
    }
}

/// One guest-physical MMIO hole excluded from [`LinearPlacement`] and [`crate::tlb::SoftTlb`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MmioHole {
    /// 4 KiB-aligned guest-physical start address of the hole.
    pub base_gpa: u64,
    /// Non-zero 4 KiB-multiple byte length of the hole.
    pub size_bytes: u64,
}

impl MmioHole {
    /// Construct a page-aligned MMIO hole.
    #[inline]
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

    /// Exclusive end GPA (`base_gpa + size_bytes`).
    #[inline]
    pub const fn end_gpa(self) -> u64 {
        self.base_gpa.saturating_add(self.size_bytes)
    }

    /// Return `true` if `gpa` falls inside `[base_gpa, base_gpa + size_bytes)`.
    #[inline]
    pub const fn contains(self, gpa: u64) -> bool {
        gpa >= self.base_gpa && gpa < self.end_gpa()
    }

    /// Return `true` if `[base_gpa, base_gpa + len)` overlaps this hole.
    #[inline]
    pub const fn overlaps(self, base_gpa: u64, len: u64) -> bool {
        if len == 0 {
            return self.contains(base_gpa);
        }
        let end = match base_gpa.checked_add(len) {
            Some(end) => end,
            None => u64::MAX,
        };
        base_gpa < self.end_gpa() && end > self.base_gpa
    }
}

/// Fixed-capacity collection of guest-physical MMIO holes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MmioHoles {
    holes: [MmioHole; MAX_MMIO_HOLES],
    len: usize,
}

impl MmioHoles {
    /// Empty hole set.
    #[inline]
    pub const fn empty() -> Self {
        Self {
            holes: [MmioHole {
                base_gpa: 0,
                size_bytes: PAGE_SIZE_4K,
            }; MAX_MMIO_HOLES],
            len: 0,
        }
    }

    /// Default x86 hole set containing the xAPIC MMIO page at `0xfee0_0000..0xfee0_1000`.
    #[inline]
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

    /// Active MMIO holes.
    #[inline]
    pub fn as_slice(&self) -> &[MmioHole] {
        &self.holes[..self.len]
    }

    /// Return `true` if `gpa` lies inside any registered MMIO hole.
    #[inline]
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

    /// Return `true` if `[base_gpa, base_gpa + len)` overlaps any registered MMIO hole.
    #[inline]
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
    #[inline]
    fn default() -> Self {
        Self::x86_default()
    }
}

/// Errors returned when constructing or querying [`LinearPlacement`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PlacementError {
    /// Placement base host address or span size is zero or not 4 KiB-aligned.
    UnalignedPlacement {
        /// Base host address (`K`).
        base_host_addr: usize,
        /// Span size in bytes.
        span_bytes: u64,
    },
    /// MMIO hole is zero-sized or not 4 KiB-aligned.
    UnalignedHole {
        /// Hole base GPA.
        base_gpa: u64,
        /// Hole size in bytes.
        size_bytes: u64,
    },
    /// Exceeded [`MAX_MMIO_HOLES`].
    TooManyHoles,
    /// Requested GPA lies inside a registered MMIO hole (e.g. xAPIC `0xfee0_0000`).
    MmioHole {
        /// Rejected GPA.
        gpa: u64,
    },
    /// Requested GPA or `[gpa, gpa + len)` exceeds the reserved guest-physical span.
    OutOfBounds {
        /// Rejected GPA.
        gpa: u64,
        /// Configured span in bytes.
        span_bytes: u64,
    },
    /// Arithmetic overflow when computing `base_host_addr + gpa`.
    AddressOverflow {
        /// GPA that overflowed host pointer arithmetic.
        gpa: u64,
    },
}

/// Typed linear placement (`host = gpa + K`) of guest-physical memory.
///
/// [`LinearPlacement::host`] is the single conversion from an authenticated
/// guest-physical address ([`FrameGpa`] or [`RootGpa`]) to [`HostVa`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LinearPlacement {
    base_host_addr: usize,
    span_bytes: u64,
    holes: MmioHoles,
}

impl LinearPlacement {
    /// Construct a [`LinearPlacement`] for a 4 KiB-aligned host base `K`, non-zero 4 KiB-aligned
    /// guest-physical span, and explicit [`MmioHoles`].
    pub fn new(
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
        let _end = base_host_addr
            .checked_add(span_usize)
            .ok_or(PlacementError::AddressOverflow { gpa: span_bytes })?;
        Ok(Self {
            base_host_addr,
            span_bytes,
            holes,
        })
    }

    /// Construct a [`LinearPlacement`] with [`MmioHoles::x86_default`] (the xAPIC hole at `0xfee0_0000`).
    pub fn with_x86_defaults(
        base_host_addr: usize,
        span_bytes: u64,
    ) -> Result<Self, PlacementError> {
        Self::new(base_host_addr, span_bytes, MmioHoles::x86_default())
    }

    /// Carrier placement constant `K` (`host = gpa + K`).
    #[inline]
    pub const fn base_host_addr(&self) -> usize {
        self.base_host_addr
    }

    /// Total reserved guest-physical span in bytes.
    #[inline]
    pub const fn span_bytes(&self) -> u64 {
        self.span_bytes
    }

    /// Registered MMIO holes that are never placed or cached in `SoftTlb`.
    #[inline]
    pub const fn holes(&self) -> &MmioHoles {
        &self.holes
    }

    /// Return `true` if `gpa` falls inside a registered MMIO hole.
    #[inline]
    pub const fn is_mmio_hole(&self, gpa: u64) -> bool {
        self.holes.contains_gpa(gpa)
    }

    /// Convert an authenticated guest-physical address (`FrameGpa` or `RootGpa`) to [`HostVa`]
    /// via `host = gpa + K`.
    ///
    /// Rejects GPAs that fall in a registered MMIO hole or outside `0..span_bytes`.
    #[inline]
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
        Ok(HostVa(addr))
    }

    /// Validate a contiguous `[frame_gpa, frame_gpa + len)` byte extent against the placement span
    /// and MMIO holes, returning the starting [`HostVa`].
    #[inline]
    pub fn host_range(&self, frame_gpa: FrameGpa, len: usize) -> Result<HostVa, PlacementError> {
        let raw = frame_gpa.raw();
        let len_u64 = len as u64;
        if len == 0 {
            return self.host(frame_gpa);
        }
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
