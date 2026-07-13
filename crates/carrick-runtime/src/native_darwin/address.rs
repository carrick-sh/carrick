use std::ops::Range;

use carrick_guest_mem::{GuestVa, HostVa};

use crate::dispatch::MemoryLayout;
use crate::memory::AddressSpace;

pub(super) const BIAS_CANDIDATES: [u64; 4] = [
    0x80_0000_0000,
    0xc0_0000_0000,
    0x100_0000_0000,
    0x140_0000_0000,
];
const DARWIN_USER_VA_END: u64 = 0x8000_0000_0000;

pub(super) struct OwnedHostMapping {
    range: Range<HostVa>,
    unmap_on_drop: bool,
}

impl OwnedHostMapping {
    pub(super) fn map_exact(
        requested: HostVa,
        length: usize,
        prot: i32,
        flags: i32,
    ) -> Result<Self, NativeAddressError> {
        if length == 0 {
            return Err(NativeAddressError::InvalidHostRange {
                start: requested.raw(),
                length,
            });
        }
        let end =
            requested
                .raw()
                .checked_add(length)
                .ok_or(NativeAddressError::InvalidHostRange {
                    start: requested.raw(),
                    length,
                })?;
        let requested_ptr = requested.raw() as *mut libc::c_void;
        let mapped =
            unsafe { libc::mmap(requested_ptr, length, prot, flags & !libc::MAP_FIXED, -1, 0) };
        if mapped == libc::MAP_FAILED {
            return Err(NativeAddressError::HostMapping {
                requested: requested.raw(),
                length,
                source: std::io::Error::last_os_error(),
            });
        }
        let actual = mapped as usize;
        if actual != requested.raw() {
            unsafe {
                libc::munmap(mapped, length);
            }
            return Err(NativeAddressError::HostCollision {
                requested: requested.raw(),
                actual,
                length,
            });
        }
        Ok(Self {
            range: requested..HostVa(end),
            unmap_on_drop: true,
        })
    }

    #[cfg(test)]
    pub(super) fn range(&self) -> Range<HostVa> {
        self.range.clone()
    }

    pub(super) fn commit(mut self) -> Range<HostVa> {
        self.unmap_on_drop = false;
        self.range.clone()
    }
}

impl Drop for OwnedHostMapping {
    fn drop(&mut self) {
        if !self.unmap_on_drop {
            return;
        }
        let length = self.range.end.raw().saturating_sub(self.range.start.raw());
        if length != 0 {
            unsafe {
                libc::munmap(self.range.start.raw() as *mut libc::c_void, length);
            }
        }
    }
}

pub(super) struct CandidateLayout {
    mode: NativeAddressMode,
    ranges: Vec<Range<HostVa>>,
}

impl CandidateLayout {
    fn for_image(
        image: &AddressSpace,
        layout: MemoryLayout,
        host_page_size: u64,
        mode: NativeAddressMode,
    ) -> Result<Self, NativeAddressError> {
        let mut guest_ranges = Vec::with_capacity(image.regions().len() + 5);
        for region in image.regions() {
            guest_ranges.push(GuestVa(region.start)..GuestVa(region.end));
        }
        guest_ranges.extend([
            GuestVa(super::NATIVE_DARWIN_SIGRETURN_TRAMPOLINE_BASE)
                ..GuestVa(
                    super::NATIVE_DARWIN_SIGRETURN_TRAMPOLINE_BASE
                        .checked_add(carrick_mem::memory::LINUX_SIGRETURN_TRAMPOLINE_SIZE)
                        .ok_or(NativeAddressError::GuestRangeOverflow {
                            start: super::NATIVE_DARWIN_SIGRETURN_TRAMPOLINE_BASE,
                            length: carrick_mem::memory::LINUX_SIGRETURN_TRAMPOLINE_SIZE,
                        })?,
                ),
            checked_guest_range(layout.heap_base, layout.heap_size)?,
            checked_guest_range(layout.mmap_base, layout.mmap_size)?,
            checked_guest_range(
                crate::memory::LINUX_SHARED_FILE_BASE,
                crate::memory::LINUX_SHARED_FILE_SIZE,
            )?,
            checked_guest_range(
                crate::memory::LINUX_PRIVATE_OVERLAY_BASE,
                crate::memory::LINUX_PRIVATE_OVERLAY_SIZE,
            )?,
        ]);

        let page_mask =
            host_page_size
                .checked_sub(1)
                .ok_or(NativeAddressError::InvalidPageSize {
                    page_size: host_page_size,
                })?;
        if !host_page_size.is_power_of_two() {
            return Err(NativeAddressError::InvalidPageSize {
                page_size: host_page_size,
            });
        }
        let mut ranges = Vec::with_capacity(guest_ranges.len());
        for guest in guest_ranges {
            if guest.start.raw() >= guest.end.raw() {
                return Err(NativeAddressError::InvalidGuestRange {
                    start: guest.start.raw(),
                    end: guest.end.raw(),
                    page_size: host_page_size,
                });
            }
            // Mach VM owns mappings in host-page units even when an ELF or
            // injected runtime region contains fewer bytes (the vvar is a
            // Linux 4K page under native16k). Reserve the complete host pages
            // that a later fixed mapping can replace, rather than rejecting a
            // valid image because its byte range is not host-page sized.
            let aligned_start = guest.start.raw() & !page_mask;
            let aligned_end = guest
                .end
                .raw()
                .checked_add(page_mask)
                .map(|end| end & !page_mask)
                .ok_or(NativeAddressError::GuestRangeOverflow {
                    start: guest.start.raw(),
                    length: guest.end.raw().saturating_sub(guest.start.raw()),
                })?;
            let host = mode.to_host_range(GuestVa(aligned_start)..GuestVa(aligned_end))?;
            if host.end.raw() as u64 > DARWIN_USER_VA_END {
                return Err(NativeAddressError::OutsideDarwinUserRange {
                    start: host.start.raw(),
                    end: host.end.raw(),
                });
            }
            ranges.push(host);
        }
        ranges.sort_unstable_by_key(|range| range.start.raw());
        let mut merged: Vec<Range<HostVa>> = Vec::with_capacity(ranges.len());
        for range in ranges {
            if let Some(last) = merged.last_mut()
                && range.start.raw() <= last.end.raw()
            {
                if range.end.raw() > last.end.raw() {
                    last.end = range.end;
                }
                continue;
            }
            merged.push(range);
        }
        Ok(Self {
            mode,
            ranges: merged,
        })
    }

    fn try_map(&self) -> Result<Vec<OwnedHostMapping>, NativeAddressError> {
        let mut mappings = Vec::with_capacity(self.ranges.len());
        for range in &self.ranges {
            mappings.push(map_reservation(range.start.raw(), range.end.raw())?);
        }
        Ok(mappings)
    }

    #[cfg(test)]
    fn test_fixture(ranges: [Range<HostVa>; 2]) -> Self {
        Self {
            mode: NativeAddressMode::Direct,
            ranges: ranges.into(),
        }
    }
}

fn map_reservation(start: usize, end: usize) -> Result<OwnedHostMapping, NativeAddressError> {
    let length = end
        .checked_sub(start)
        .ok_or(NativeAddressError::InvalidHostRange { start, length: 0 })?;
    OwnedHostMapping::map_exact(
        HostVa(start),
        length,
        libc::PROT_NONE,
        libc::MAP_ANON | libc::MAP_PRIVATE | libc::MAP_NORESERVE,
    )
}

fn checked_guest_range(start: u64, length: u64) -> Result<Range<GuestVa>, NativeAddressError> {
    let end = start
        .checked_add(length)
        .ok_or(NativeAddressError::GuestRangeOverflow { start, length })?;
    Ok(GuestVa(start)..GuestVa(end))
}

pub(super) struct NativeLayout {
    mode: NativeAddressMode,
    reservations: Vec<OwnedHostMapping>,
    owned_ranges: Vec<Range<HostVa>>,
}

impl NativeLayout {
    #[cfg(test)]
    pub(super) fn direct() -> Self {
        Self {
            mode: NativeAddressMode::Direct,
            reservations: Vec::new(),
            owned_ranges: Vec::new(),
        }
    }

    pub(super) fn for_image(
        image: &AddressSpace,
        layout: MemoryLayout,
        host_page_size: u64,
    ) -> Result<Self, NativeAddressError> {
        if image
            .regions()
            .iter()
            .all(|region| region.start >= super::NATIVE_DARWIN_HARD_PAGEZERO_END)
        {
            let candidate = CandidateLayout::for_image(
                image,
                layout,
                host_page_size,
                NativeAddressMode::Direct,
            )?;
            // Preserve the established direct PIE fast path: identity mappings
            // retain their legacy MAP_FIXED behavior. We still normalize and
            // record the complete typed host-page ownership plan so exec can
            // transfer overlapping Carrick-owned intervals and retire every
            // old page. Only biased layouts acquire collision-probed RAII
            // reservations.
            return Ok(Self {
                mode: NativeAddressMode::Direct,
                reservations: Vec::new(),
                owned_ranges: candidate.ranges,
            });
        }

        let mut last_error = None;
        for bias in BIAS_CANDIDATES {
            let host_bias = NativeHostBias::new(bias, host_page_size)?;
            let candidate = match CandidateLayout::for_image(
                image,
                layout,
                host_page_size,
                NativeAddressMode::Biased { host_bias },
            ) {
                Ok(candidate) => candidate,
                Err(error) => {
                    last_error = Some(error.to_string());
                    continue;
                }
            };
            match candidate.try_map() {
                Ok(reservations) => {
                    return Ok(Self {
                        mode: candidate.mode,
                        reservations,
                        owned_ranges: candidate.ranges,
                    });
                }
                Err(error) => last_error = Some(error.to_string()),
            }
        }
        Err(NativeAddressError::NoCollisionFreeBias {
            detail: last_error.unwrap_or_else(|| "no bias candidates were attempted".to_string()),
        })
    }

    pub(super) fn address_mode(&self) -> NativeAddressMode {
        self.mode
    }

    pub(super) fn fixed_mapping_flags(
        &self,
        start: HostVa,
        length: usize,
        flags: i32,
    ) -> Result<i32, NativeAddressError> {
        self.mode
            .fixed_mapping_flags(&self.owned_ranges, start, length, flags)
    }

    pub(super) fn owned_ranges(&self) -> &[Range<HostVa>] {
        &self.owned_ranges
    }

    pub(super) fn commit_if_ok<T, E>(self, result: Result<T, E>) -> Result<T, E> {
        match result {
            Ok(value) => {
                let _ = self.commit();
                Ok(value)
            }
            Err(error) => Err(error),
        }
    }

    pub(super) fn commit(mut self) -> (NativeAddressMode, Vec<Range<HostVa>>) {
        for reservation in self.reservations.drain(..) {
            let _ = reservation.commit();
        }
        (self.mode, self.owned_ranges)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct NativeHostBias(u64);

impl NativeHostBias {
    pub(super) fn new(bias: u64, page_size: u64) -> Result<Self, NativeAddressError> {
        if bias == 0 || !page_size.is_power_of_two() || bias & page_size.saturating_sub(1) != 0 {
            return Err(NativeAddressError::InvalidBias { bias, page_size });
        }
        Ok(Self(bias))
    }

    pub(super) const fn get(self) -> u64 {
        self.0
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum NativeAddressMode {
    Direct,
    Biased { host_bias: NativeHostBias },
}

impl NativeAddressMode {
    pub(super) fn to_host(self, address: GuestVa) -> Result<HostVa, NativeAddressError> {
        let bias = self.bias();
        let translated = address
            .raw()
            .checked_add(bias)
            .ok_or(NativeAddressError::Overflow {
                address: address.raw(),
                bias,
            })?;
        usize::try_from(translated)
            .map(HostVa)
            .map_err(|_| NativeAddressError::Overflow {
                address: address.raw(),
                bias,
            })
    }

    pub(super) fn to_guest(self, address: HostVa) -> Result<GuestVa, NativeAddressError> {
        let address = address.raw() as u64;
        let bias = self.bias();
        address
            .checked_sub(bias)
            .map(GuestVa)
            .ok_or(NativeAddressError::BelowBias { address, bias })
    }

    pub(super) fn to_host_range(
        self,
        range: Range<GuestVa>,
    ) -> Result<Range<HostVa>, NativeAddressError> {
        Ok(self.to_host(range.start)?..self.to_host(range.end)?)
    }

    #[cfg_attr(not(test), allow(dead_code))]
    pub(super) fn to_guest_range(
        self,
        range: Range<HostVa>,
    ) -> Result<Range<GuestVa>, NativeAddressError> {
        Ok(self.to_guest(range.start)?..self.to_guest(range.end)?)
    }

    pub(super) fn bias(self) -> u64 {
        match self {
            Self::Direct => 0,
            Self::Biased { host_bias } => host_bias.0,
        }
    }

    pub(super) fn fixed_mapping_flags(
        self,
        owned_ranges: &[Range<HostVa>],
        start: HostVa,
        length: usize,
        flags: i32,
    ) -> Result<i32, NativeAddressError> {
        let end = start
            .raw()
            .checked_add(length)
            .ok_or(NativeAddressError::InvalidHostRange {
                start: start.raw(),
                length,
            })?;
        let owned = start.raw() < end
            && owned_ranges
                .iter()
                .any(|range| start.raw() >= range.start.raw() && end <= range.end.raw());
        if matches!(self, Self::Biased { .. }) && !owned {
            return Err(NativeAddressError::FixedOutsideOwned {
                start: start.raw(),
                length,
            });
        }
        Ok(flags | libc::MAP_FIXED)
    }
}

#[derive(Debug, thiserror::Error)]
pub(super) enum NativeAddressError {
    #[error("native host bias 0x{bias:x} is invalid for page size 0x{page_size:x}")]
    InvalidBias { bias: u64, page_size: u64 },
    #[error("native address translation overflow: address=0x{address:x} bias=0x{bias:x}")]
    Overflow { address: u64, bias: u64 },
    #[error("host address 0x{address:x} is below native bias 0x{bias:x}")]
    BelowBias { address: u64, bias: u64 },
    #[error("invalid native host range: start=0x{start:x} length=0x{length:x}")]
    InvalidHostRange { start: usize, length: usize },
    #[error(
        "native host range collision: requested=0x{requested:x} actual=0x{actual:x} length=0x{length:x}"
    )]
    HostCollision {
        requested: usize,
        actual: usize,
        length: usize,
    },
    #[error("native host mapping failed at 0x{requested:x}+0x{length:x}: {source}")]
    HostMapping {
        requested: usize,
        length: usize,
        #[source]
        source: std::io::Error,
    },
    #[error("native host page size 0x{page_size:x} is invalid")]
    InvalidPageSize { page_size: u64 },
    #[error(
        "native guest range is invalid or unaligned: 0x{start:x}..0x{end:x} page_size=0x{page_size:x}"
    )]
    InvalidGuestRange {
        start: u64,
        end: u64,
        page_size: u64,
    },
    #[error("native guest range overflows: start=0x{start:x} length=0x{length:x}")]
    GuestRangeOverflow { start: u64, length: u64 },
    #[error("native host range is outside Darwin user VA: 0x{start:x}..0x{end:x}")]
    OutsideDarwinUserRange { start: usize, end: usize },
    #[error("no collision-free native host bias: {detail}")]
    NoCollisionFreeBias { detail: String },
    #[error("native fixed mapping is outside an owned range: 0x{start:x}+0x{length:x}")]
    FixedOutsideOwned { start: usize, length: usize },
}

#[cfg(test)]
mod tests {
    use super::{
        CandidateLayout, NativeAddressError, NativeAddressMode, NativeHostBias, NativeLayout,
        OwnedHostMapping,
    };
    use crate::dispatch::MemoryLayout;
    use crate::memory::AddressSpace;
    use carrick_guest_mem::{GuestVa, HostVa};
    use std::ops::Range;
    use std::ptr::NonNull;

    const TEST_PAGE_SIZE: usize = 0x4000;

    fn fork_test(test: impl FnOnce() + std::panic::UnwindSafe) {
        let pid = unsafe { libc::fork() };
        assert!(pid >= 0, "fork failed: {}", std::io::Error::last_os_error());
        if pid == 0 {
            let passed = std::panic::catch_unwind(test).is_ok();
            unsafe { libc::_exit(i32::from(!passed)) };
        }
        let mut status = 0;
        assert_eq!(unsafe { libc::waitpid(pid, &mut status, 0) }, pid);
        assert!(libc::WIFEXITED(status), "child status was 0x{status:x}");
        assert_eq!(libc::WEXITSTATUS(status), 0);
    }

    fn map_any_page() -> NonNull<u8> {
        let mapped = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                TEST_PAGE_SIZE,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_ANON | libc::MAP_PRIVATE,
                -1,
                0,
            )
        };
        assert_ne!(mapped, libc::MAP_FAILED);
        NonNull::new(mapped.cast()).expect("mmap returned null")
    }

    fn vacant_test_ranges() -> [Range<HostVa>; 2] {
        let mapped = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                2 * TEST_PAGE_SIZE,
                libc::PROT_NONE,
                libc::MAP_ANON | libc::MAP_PRIVATE,
                -1,
                0,
            )
        };
        assert_ne!(mapped, libc::MAP_FAILED);
        assert_eq!(unsafe { libc::munmap(mapped, 2 * TEST_PAGE_SIZE) }, 0);
        let start = mapped as usize;
        [
            HostVa(start)..HostVa(start + TEST_PAGE_SIZE),
            HostVa(start + TEST_PAGE_SIZE)..HostVa(start + 2 * TEST_PAGE_SIZE),
        ]
    }

    #[test]
    fn direct_mode_is_identity() {
        let mode = NativeAddressMode::Direct;
        assert_eq!(mode.to_host(GuestVa(0x4000)).unwrap(), HostVa(0x4000));
        assert_eq!(mode.to_guest(HostVa(0x4000)).unwrap(), GuestVa(0x4000));
    }

    #[test]
    fn biased_mode_round_trips_guest_addresses() {
        let bias = NativeHostBias::new(0x20_0000_0000, 0x4000).unwrap();
        let mode = NativeAddressMode::Biased { host_bias: bias };
        let host = mode.to_host(GuestVa(0x40_0000)).unwrap();
        assert_eq!(host, HostVa(0x20_0040_0000));
        assert_eq!(mode.to_guest(host).unwrap(), GuestVa(0x40_0000));
    }

    #[test]
    fn bias_rejects_zero_misalignment_and_overflow() {
        assert!(NativeHostBias::new(0x20_0000_0000, 0).is_err());
        assert!(NativeHostBias::new(0x20_0000_0000, 0x3000).is_err());
        assert!(NativeHostBias::new(0, 0x4000).is_err());
        assert!(NativeHostBias::new(0x20_0000_0001, 0x4000).is_err());
        let mode = NativeAddressMode::Biased {
            host_bias: NativeHostBias::new(u64::MAX & !0x3fff, 0x4000).unwrap(),
        };
        assert!(mode.to_host(GuestVa(0x4000)).is_err());
    }

    #[test]
    fn range_translation_checks_both_ends() {
        let mode = NativeAddressMode::Biased {
            host_bias: NativeHostBias::new(0x20_0000_0000, 0x4000).unwrap(),
        };
        assert_eq!(
            mode.to_host_range(GuestVa(0x4000)..GuestVa(0x8000))
                .unwrap(),
            HostVa(0x20_0000_4000)..HostVa(0x20_0000_8000)
        );
        assert_eq!(
            mode.to_guest_range(HostVa(0x20_0000_4000)..HostVa(0x20_0000_8000))
                .unwrap(),
            GuestVa(0x4000)..GuestVa(0x8000)
        );

        let near_end = NativeAddressMode::Biased {
            host_bias: NativeHostBias::new(u64::MAX & !0x3fff, 0x4000).unwrap(),
        };
        assert!(near_end.to_host_range(GuestVa(0)..GuestVa(0x4000)).is_err());
    }

    #[test]
    fn exact_mapping_never_replaces_an_existing_page() {
        fork_test(|| {
            let sentinel = map_any_page();
            unsafe { std::ptr::write_bytes(sentinel.as_ptr(), 0x5a, TEST_PAGE_SIZE) };
            let result = OwnedHostMapping::map_exact(
                HostVa(sentinel.as_ptr() as usize),
                TEST_PAGE_SIZE,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_PRIVATE | libc::MAP_ANON,
            );
            assert!(matches!(
                result,
                Err(NativeAddressError::HostCollision { .. })
            ));
            assert_eq!(unsafe { *sentinel.as_ptr() }, 0x5a);
            assert_eq!(
                unsafe { libc::munmap(sentinel.as_ptr().cast(), TEST_PAGE_SIZE) },
                0
            );
        });
    }

    #[test]
    fn failed_candidate_unmaps_every_acquired_range() {
        fork_test(|| {
            let ranges = vacant_test_ranges();
            let collision = OwnedHostMapping::map_exact(
                ranges[1].start,
                TEST_PAGE_SIZE,
                libc::PROT_NONE,
                libc::MAP_PRIVATE | libc::MAP_ANON,
            )
            .expect("occupy second candidate range");
            let candidate = CandidateLayout::test_fixture(ranges.clone());
            assert!(candidate.try_map().is_err());
            let first = OwnedHostMapping::map_exact(
                ranges[0].start,
                TEST_PAGE_SIZE,
                libc::PROT_NONE,
                libc::MAP_PRIVATE | libc::MAP_ANON,
            )
            .expect("first candidate range was rolled back");
            drop(first);
            drop(collision);
        });
    }

    #[test]
    fn low_image_skips_a_colliding_bias_candidate() {
        fork_test(|| {
            let page_size = TEST_PAGE_SIZE as u64;
            let guest_start = GuestVa(0x40_0000);
            let first_host = HostVa((0x80_0000_0000 + guest_start.raw()) as usize);
            let collision = OwnedHostMapping::map_exact(
                first_host,
                TEST_PAGE_SIZE,
                libc::PROT_NONE,
                libc::MAP_PRIVATE | libc::MAP_ANON,
            )
            .expect("occupy first bias candidate");
            let image = AddressSpace::from_segments(
                guest_start.raw(),
                [(
                    guest_start.raw(),
                    carrick_mem::elf::SegmentPerms {
                        read: true,
                        write: false,
                        execute: true,
                    },
                    vec![0; TEST_PAGE_SIZE],
                    page_size,
                )],
            )
            .expect("build low test image");
            let layout = MemoryLayout {
                heap_base: 0x8_0000_0000,
                heap_size: page_size,
                mmap_base: 0xa0_0000_0000,
                mmap_size: page_size,
            };
            let selected = NativeLayout::for_image(&image, layout, page_size)
                .expect("select collision-free bias");
            assert_eq!(
                selected.address_mode().to_host(guest_start).unwrap(),
                HostVa((0xc0_0000_0000 + guest_start.raw()) as usize)
            );
            drop(selected);
            drop(collision);
        });
    }

    #[test]
    fn biased_fixed_mapping_is_limited_to_owned_ranges() {
        fork_test(|| {
            let page_size = TEST_PAGE_SIZE as u64;
            let guest_start = GuestVa(0x40_0000);
            let image = AddressSpace::from_segments(
                guest_start.raw(),
                [(
                    guest_start.raw(),
                    carrick_mem::elf::SegmentPerms {
                        read: true,
                        write: true,
                        execute: false,
                    },
                    vec![0; TEST_PAGE_SIZE],
                    page_size,
                )],
            )
            .expect("build low test image");
            let layout = MemoryLayout {
                heap_base: 0x8_0000_0000,
                heap_size: page_size,
                mmap_base: 0xa0_0000_0000,
                mmap_size: page_size,
            };
            let selected =
                NativeLayout::for_image(&image, layout, page_size).expect("select biased layout");
            let owned = selected
                .address_mode()
                .to_host(guest_start)
                .expect("translate owned guest page");
            assert_eq!(
                selected
                    .fixed_mapping_flags(owned, TEST_PAGE_SIZE, libc::MAP_ANON | libc::MAP_PRIVATE,)
                    .unwrap()
                    & libc::MAP_FIXED,
                libc::MAP_FIXED
            );
            assert!(matches!(
                selected.fixed_mapping_flags(
                    HostVa(owned.raw() + 2 * TEST_PAGE_SIZE),
                    TEST_PAGE_SIZE,
                    libc::MAP_ANON | libc::MAP_PRIVATE,
                ),
                Err(NativeAddressError::FixedOutsideOwned { .. })
            ));
        });
    }

    #[test]
    fn failed_post_mapping_setup_releases_candidate_ranges() {
        fork_test(|| {
            let page_size = TEST_PAGE_SIZE as u64;
            let guest_start = GuestVa(0x40_0000);
            let image = AddressSpace::from_segments(
                guest_start.raw(),
                [(
                    guest_start.raw(),
                    carrick_mem::elf::SegmentPerms {
                        read: true,
                        write: true,
                        execute: false,
                    },
                    vec![0; TEST_PAGE_SIZE],
                    page_size,
                )],
            )
            .expect("build low test image");
            let layout = MemoryLayout {
                heap_base: 0x8_0000_0000,
                heap_size: page_size,
                mmap_base: 0xa0_0000_0000,
                mmap_size: page_size,
            };
            let selected =
                NativeLayout::for_image(&image, layout, page_size).expect("select biased layout");
            let host_start = selected
                .address_mode()
                .to_host(guest_start)
                .expect("translate mapped guest page");
            let flags = selected
                .fixed_mapping_flags(
                    host_start,
                    TEST_PAGE_SIZE,
                    libc::MAP_ANON | libc::MAP_PRIVATE,
                )
                .expect("authorize owned fixed mapping");
            let mapped = unsafe {
                libc::mmap(
                    host_start.raw() as *mut libc::c_void,
                    TEST_PAGE_SIZE,
                    libc::PROT_READ | libc::PROT_WRITE,
                    flags,
                    -1,
                    0,
                )
            };
            assert_eq!(mapped as usize, host_start.raw());

            let setup: Result<(), &str> = Err("injected post-mapping setup failure");
            assert!(selected.commit_if_ok(setup).is_err());

            let vacant = OwnedHostMapping::map_exact(
                host_start,
                TEST_PAGE_SIZE,
                libc::PROT_NONE,
                libc::MAP_ANON | libc::MAP_PRIVATE,
            )
            .expect("failed setup rolled back the mapped candidate page");
            drop(vacant);
        });
    }

    #[test]
    fn adjacent_linux_subpages_share_one_host_page_reservation_and_roll_back() {
        fork_test(|| {
            let linux_page_size = 0x1000_u64;
            let host_page_size = TEST_PAGE_SIZE as u64;
            let guest_start = 0x40_0000_u64;
            let image = AddressSpace::from_segments(
                guest_start,
                [
                    (
                        guest_start,
                        carrick_mem::elf::SegmentPerms {
                            read: true,
                            write: false,
                            execute: true,
                        },
                        vec![0x11; linux_page_size as usize],
                        linux_page_size,
                    ),
                    (
                        guest_start + linux_page_size,
                        carrick_mem::elf::SegmentPerms {
                            read: true,
                            write: true,
                            execute: false,
                        },
                        vec![0x22; linux_page_size as usize],
                        linux_page_size,
                    ),
                ],
            )
            .expect("build adjacent-subpage image");
            let layout = MemoryLayout {
                heap_base: 0x8_0000_0000,
                heap_size: host_page_size,
                mmap_base: 0xa0_0000_0000,
                mmap_size: host_page_size,
            };
            let selected =
                NativeLayout::for_image(&image, layout, host_page_size).expect("select layout");
            let host_start = selected
                .address_mode()
                .to_host(GuestVa(guest_start))
                .expect("translate first subpage");
            let containing: Vec<_> = selected
                .owned_ranges()
                .iter()
                .filter(|range| {
                    range.start.raw() <= host_start.raw() && host_start.raw() < range.end.raw()
                })
                .collect();
            assert_eq!(containing.len(), 1, "adjacent subpages must coalesce");
            assert_eq!(
                containing[0].clone(),
                host_start..HostVa(host_start.raw() + TEST_PAGE_SIZE)
            );

            drop(selected);
            let vacancy = OwnedHostMapping::map_exact(
                host_start,
                TEST_PAGE_SIZE,
                libc::PROT_NONE,
                libc::MAP_ANON | libc::MAP_PRIVATE,
            )
            .expect("dropping the candidate releases the complete host page");
            drop(vacancy);
        });
    }

    #[test]
    fn direct_replacement_records_the_same_typed_owned_ranges() {
        fork_test(|| {
            let page_size = TEST_PAGE_SIZE as u64;
            let start = 0x70_1000_0000_u64;
            let image = AddressSpace::from_segments(
                start,
                [(
                    start,
                    carrick_mem::elf::SegmentPerms {
                        read: true,
                        write: false,
                        execute: true,
                    },
                    vec![0; TEST_PAGE_SIZE],
                    page_size,
                )],
            )
            .expect("build direct replacement image");
            let layout = MemoryLayout {
                heap_base: 0x70_2000_0000,
                heap_size: page_size,
                mmap_base: 0x70_3000_0000,
                mmap_size: page_size,
            };
            let initial =
                NativeLayout::for_image(&image, layout, page_size).expect("reserve direct image");
            assert_eq!(initial.address_mode(), NativeAddressMode::Direct);
            let (_, owned) = initial.commit();
            let replacement = NativeLayout::for_image(&image, layout, page_size)
                .expect("plan replacement direct ranges");
            assert_eq!(replacement.address_mode(), NativeAddressMode::Direct);
            assert_eq!(replacement.owned_ranges(), owned);
            drop(replacement);
        });
    }
}
