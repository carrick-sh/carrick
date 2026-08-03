//! Native address-layout selection for the same-ISA (DSR) backend.
//!
//! Owns `NativeAddressMode` (direct vs biased guest→host translation), the
//! collision-probed bias/reservation machinery (`NativeLayout`,
//! `CandidateLayout`, `OwnedHostMapping`), and the address-layout constants.
//! Moved verbatim from the runtime's `native_darwin::address` as part of the
//! staged native-backend extraction (see docs/superpowers/specs/
//! 2026-07-17-native-backend-portability-seams-design.md); the runtime module
//! re-exports everything so existing call paths resolve unchanged.

use std::ops::Range;

use carrick_guest_mem::{GuestVa, HostVa};

use carrick_mem::memory::AddressSpace;
use carrick_mem::memory::MemoryLayout;

// Address-layout constants that came along from `native_darwin.rs`: the
// injected sigreturn-trampoline base is one of the guest ranges every
// candidate layout must reserve, and the hard page-zero end gates the direct
// (identity) mapping fast path.
pub const NATIVE_DARWIN_SIGRETURN_TRAMPOLINE_BASE: u64 = 0x7_0000_0000;
pub const NATIVE_DARWIN_HARD_PAGEZERO_END: u64 = 0x1_0000_0000;

/// The aperture-disjoint, ORR-encodable bias the compact biased-memory
/// lowering (H008 Spike 1) requires: `guest | bias == guest + bias` for every
/// in-aperture guest address, and the bias is one AArch64 logical immediate.
///
/// It is deliberately NOT a production candidate. Selecting it activates the
/// compact lowering, which a paired screen measured at 3.76% SLOWER than the
/// general lowering (losing 5 of 6 pairs) while carrying an unfixed
/// host-address leak. The constant is retained so the emitter's tests can
/// still construct that bias explicitly; see
/// `docs/perf-results/native-wall-time-campaign.md` H008.
pub const APERTURE_DISJOINT_ORR_BIAS: u64 = 0x200_0000_0000;

pub const BIAS_CANDIDATES: [u64; 4] = [
    0x80_0000_0000,
    0xc0_0000_0000,
    0x100_0000_0000,
    0x140_0000_0000,
];
const DARWIN_USER_VA_END: u64 = 0x8000_0000_0000;
// Go's arm64 runtime probes and fixes its heap arena at 0x140_0000_0000, above
// Carrick's Linux stack placement. The biased aperture is the emulated task
// address ceiling, not the stack ceiling, and must own that complete range so
// unchecked translated guest pointers cannot alias unrelated host mappings.
pub const BIASED_GUEST_APERTURE_END: u64 = 0x200_0000_0000;
// AArch64 literal loads have a signed imm19 scaled by four, so their complete
// displacement window is 1 MiB. Reserve that window plus one host page: the
// page-sized headroom contains the tail of the maximum-width (16-byte) access
// and keeps the bound aligned with Mach VM ownership granularity.
const BIASED_GUEST_LITERAL_DISPLACEMENT_WINDOW: u64 = 1024 * 1024;
pub const BIASED_GUEST_LITERAL_TARGET_END: u64 =
    BIASED_GUEST_APERTURE_END + BIASED_GUEST_LITERAL_DISPLACEMENT_WINDOW;
// The compact biased lowering validates only the BASE register against the
// aperture, so a bounded negative immediate displacement can reach below
// guest zero — i.e. below the bias in host coordinates. Owning one literal
// window below the bias keeps those accesses faulting inside Carrick-owned
// PROT_NONE space instead of aliasing an unrelated host mapping.
pub const BIASED_GUEST_UNDERFLOW_WINDOW: u64 = 1024 * 1024;
pub const INVALID_BIASED_HOST_ADDRESS_BIT: u64 = 1 << 47;

/// First host VA ABOVE every span a biased candidate layout can reserve —
/// the exclusion floor for other subsystems' deliberate long-lived host
/// placements.
///
/// The bias probe treats `[bias - underflow, bias + literal-target-end]`
/// as its own for every candidate, and it FAILS CLOSED when no candidate's
/// span is free. Tier D's identity-tier placement hints once started at
/// exactly `BIAS_CANDIDATES[0]`: its process-lifetime guest mappings then
/// occupied the first candidate's span, and in a process whose remaining
/// candidates were also occupied the probe had nowhere left to go —
/// `NoCollisionFreeBias` on a healthy host (caught by
/// `biased_address_above_ceiling_cannot_alias_an_outside_host_sentinel`
/// running after tier D tests in one process). Anything that CHOOSES where
/// to put long-lived host mappings must choose at or above this address.
///
/// Derived (and compile-asserted) from the largest constructible bias —
/// the test-only compact-lowering bias, which exceeds every production
/// candidate — plus the span a candidate reserves, rounded up to a whole
/// TiB.
pub const BIASED_HOST_RESERVATION_CEILING: u64 = 0x500_0000_0000;
const _: () = {
    let mut index = 0;
    while index < BIAS_CANDIDATES.len() {
        assert!(BIAS_CANDIDATES[index] <= APERTURE_DISJOINT_ORR_BIAS);
        index += 1;
    }
    // One host page of tail slack beyond the literal window, matching the
    // observed reservation length, plus headroom.
    assert!(
        APERTURE_DISJOINT_ORR_BIAS + BIASED_GUEST_LITERAL_TARGET_END + 0x10000
            < BIASED_HOST_RESERVATION_CEILING
    );
    assert!(BIASED_HOST_RESERVATION_CEILING < DARWIN_USER_VA_END);
};

pub struct OwnedHostMapping {
    range: Range<HostVa>,
    unmap_on_drop: bool,
}

impl OwnedHostMapping {
    pub fn map_exact(
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

    fn prepare_adoption(range: Range<HostVa>) -> Result<Self, NativeAddressError> {
        if range.start.raw() >= range.end.raw() {
            return Err(NativeAddressError::InvalidHostRange {
                start: range.start.raw(),
                length: range.end.raw().saturating_sub(range.start.raw()),
            });
        }
        Ok(Self {
            range,
            unmap_on_drop: false,
        })
    }

    fn arm_prepared_adoption(&mut self) {
        self.unmap_on_drop = true;
    }

    // `test-hooks` (not bare `cfg(test)`): the runtime's native test module
    // drives this cross-crate, and cross-crate `cfg(test)` does not compose —
    // see the module note in `crate::test_hooks`.
    #[cfg(any(test, feature = "test-hooks"))]
    pub fn range(&self) -> Range<HostVa> {
        self.range.clone()
    }

    pub fn commit(mut self) -> Range<HostVa> {
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

pub struct CandidateLayout {
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
            GuestVa(NATIVE_DARWIN_SIGRETURN_TRAMPOLINE_BASE)
                ..GuestVa(
                    NATIVE_DARWIN_SIGRETURN_TRAMPOLINE_BASE
                        .checked_add(carrick_mem::memory::LINUX_SIGRETURN_TRAMPOLINE_SIZE)
                        .ok_or(NativeAddressError::GuestRangeOverflow {
                            start: NATIVE_DARWIN_SIGRETURN_TRAMPOLINE_BASE,
                            length: carrick_mem::memory::LINUX_SIGRETURN_TRAMPOLINE_SIZE,
                        })?,
                ),
            checked_guest_range(layout.heap_base, layout.heap_size)?,
            checked_guest_range(layout.mmap_base, layout.mmap_size)?,
            checked_guest_range(
                carrick_mem::memory::LINUX_SHARED_FILE_BASE,
                carrick_mem::memory::LINUX_SHARED_FILE_SIZE,
            )?,
            checked_guest_range(
                carrick_mem::memory::LINUX_PRIVATE_OVERLAY_BASE,
                carrick_mem::memory::LINUX_PRIVATE_OVERLAY_SIZE,
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
        let biased = matches!(mode, NativeAddressMode::Biased { .. });
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
            if biased && aligned_end > BIASED_GUEST_APERTURE_END {
                return Err(NativeAddressError::OutsideBiasedGuestAperture {
                    start: aligned_start,
                    end: aligned_end,
                    aperture_end: BIASED_GUEST_APERTURE_END,
                });
            }
            let host = mode.to_host_range(GuestVa(aligned_start)..GuestVa(aligned_end))?;
            if host.end.raw() as u64 > DARWIN_USER_VA_END {
                return Err(NativeAddressError::OutsideDarwinUserRange {
                    start: host.start.raw(),
                    end: host.end.raw(),
                });
            }
            ranges.push(host);
        }
        if biased {
            let guard_size = BIASED_GUEST_LITERAL_DISPLACEMENT_WINDOW
                .checked_add(host_page_size)
                .ok_or(NativeAddressError::GuestRangeOverflow {
                    start: BIASED_GUEST_APERTURE_END,
                    length: BIASED_GUEST_LITERAL_DISPLACEMENT_WINDOW,
                })?;
            let guard_end = BIASED_GUEST_APERTURE_END.checked_add(guard_size).ok_or(
                NativeAddressError::GuestRangeOverflow {
                    start: BIASED_GUEST_APERTURE_END,
                    length: guard_size,
                },
            )?;
            let host = mode.to_host_range(GuestVa(0)..GuestVa(guard_end))?;
            if host.end.raw() as u64 > DARWIN_USER_VA_END {
                return Err(NativeAddressError::OutsideDarwinUserRange {
                    start: host.start.raw(),
                    end: host.end.raw(),
                });
            }
            // Extend the reservation one underflow window below guest zero
            // (see `BIASED_GUEST_UNDERFLOW_WINDOW`). Every candidate bias is
            // far larger than the window; the saturating fallback would pull
            // the range into the hard page-zero region, where `try_map`
            // rejects the candidate rather than mapping it.
            let start = HostVa(
                host.start
                    .raw()
                    .saturating_sub(BIASED_GUEST_UNDERFLOW_WINDOW as usize),
            );
            ranges.clear();
            ranges.push(start..host.end);
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

    #[cfg(all(test, target_os = "macos"))] // its only callers are the macos-gated hint tests
    fn try_map(&self) -> Result<Vec<OwnedHostMapping>, NativeAddressError> {
        self.try_map_excluding(&[])
    }

    fn try_map_excluding(
        &self,
        reusable: &[Range<HostVa>],
    ) -> Result<Vec<OwnedHostMapping>, NativeAddressError> {
        let target_only = subtract_host_ranges(&self.ranges, reusable);
        let mut mappings = Vec::with_capacity(self.ranges.len());
        for range in &target_only {
            mappings.push(map_reservation(range.start.raw(), range.end.raw())?);
        }
        Ok(mappings)
    }

    #[cfg(all(test, target_os = "macos"))] // its only callers are the macos-gated hint tests
    fn test_fixture(ranges: [Range<HostVa>; 2]) -> Self {
        Self {
            mode: NativeAddressMode::Direct,
            ranges: ranges.into(),
        }
    }
}

fn subtract_host_ranges(
    ranges: &[Range<HostVa>],
    reusable: &[Range<HostVa>],
) -> Vec<Range<HostVa>> {
    let mut result = Vec::new();
    for range in ranges {
        let mut cursor = range.start.raw();
        for keep in reusable {
            if keep.end.raw() <= cursor || keep.start.raw() >= range.end.raw() {
                continue;
            }
            if keep.start.raw() > cursor {
                result.push(HostVa(cursor)..HostVa(keep.start.raw()));
            }
            cursor = cursor.max(keep.end.raw()).min(range.end.raw());
            if cursor == range.end.raw() {
                break;
            }
        }
        if cursor < range.end.raw() {
            result.push(HostVa(cursor)..HostVa(range.end.raw()));
        }
    }
    result
}

fn intersect_host_ranges(
    ranges: &[Range<HostVa>],
    reusable: &[Range<HostVa>],
) -> Vec<Range<HostVa>> {
    let mut result = Vec::new();
    for range in ranges {
        for keep in reusable {
            let start = range.start.raw().max(keep.start.raw());
            let end = range.end.raw().min(keep.end.raw());
            if start < end {
                result.push(HostVa(start)..HostVa(end));
            }
        }
    }
    result
}

/// Reserve one inaccessible guard span of the guest aperture.
///
/// On Darwin this deliberately does NOT go through `mmap`. XNU splits a large
/// anonymous `vm_map_enter` into 128 MiB `ANON_CHUNK_SIZE` entries unless the
/// mapping's `max_protection` is `VM_PROT_NONE`, and BSD `mmap` hardcodes
/// `maxprot = VM_PROT_ALL` for anonymous mappings, so `mmap(PROT_NONE)` of the
/// 2 TiB biased aperture produced ~16.4k map entries. `vm_map_fork` re-inserts
/// every one of them into each forked child, which measured as the single
/// largest term in Carrick's host `fork(2)` cost. `mach_vm_map` can ask for
/// `max_protection = VM_PROT_NONE` directly and yields ONE entry.
/// See `carrick_host::host_proc::reserve_inaccessible_vm_span`.
fn map_reservation(start: usize, end: usize) -> Result<OwnedHostMapping, NativeAddressError> {
    let length = end
        .checked_sub(start)
        .ok_or(NativeAddressError::InvalidHostRange { start, length: 0 })?;
    #[cfg(target_os = "macos")]
    {
        map_inaccessible_span(
            HostVa(start),
            length,
            carrick_host::host_proc::InaccessibleSpanPlacement::FailIfOccupied,
        )
    }
    #[cfg(not(target_os = "macos"))]
    {
        // MAP_NORESERVE is load-bearing on Darwin (reservations must not charge
        // swap); FreeBSD's libc deprecates it as a no-op since FreeBSD 11, which
        // is exactly the semantics we want there too.
        #[allow(deprecated)]
        let flags = libc::MAP_ANON | libc::MAP_PRIVATE | libc::MAP_NORESERVE;
        OwnedHostMapping::map_exact(HostVa(start), length, libc::PROT_NONE, flags)
    }
}

/// Darwin single-entry inaccessible reservation, mapped onto the same
/// `OwnedHostMapping` rollback contract `map_exact` provides. A collision or a
/// redirect surfaces as `HostCollision` so the bias-candidate probe keeps
/// falling through to the next candidate exactly as it did under `mmap`.
#[cfg(target_os = "macos")]
fn map_inaccessible_span(
    requested: HostVa,
    length: usize,
    placement: carrick_host::host_proc::InaccessibleSpanPlacement,
) -> Result<OwnedHostMapping, NativeAddressError> {
    use carrick_host::host_proc::{InaccessibleReservation, reserve_inaccessible_vm_span};

    if length == 0 {
        return Err(NativeAddressError::InvalidHostRange {
            start: requested.raw(),
            length,
        });
    }
    let end = requested
        .raw()
        .checked_add(length)
        .ok_or(NativeAddressError::InvalidHostRange {
            start: requested.raw(),
            length,
        })?;
    let outcome = reserve_inaccessible_vm_span(requested.raw() as u64, length as u64, placement)
        .map_err(|source| NativeAddressError::HostMapping {
            requested: requested.raw(),
            length,
            source: std::io::Error::other(source.to_string()),
        })?;
    match outcome {
        InaccessibleReservation::Reserved => Ok(OwnedHostMapping {
            range: requested..HostVa(end),
            unmap_on_drop: true,
        }),
        InaccessibleReservation::NoSpace => Err(NativeAddressError::HostCollision {
            requested: requested.raw(),
            actual: requested.raw(),
            length,
        }),
        InaccessibleReservation::Redirected { actual } => {
            let actual = actual as usize;
            // The kernel placed it elsewhere; give the span straight back so a
            // failed candidate never leaks VA.
            let _ = unsafe { libc::munmap(actual as *mut libc::c_void, length) };
            Err(NativeAddressError::HostCollision {
                requested: requested.raw(),
                actual,
                length,
            })
        }
    }
}

fn checked_guest_range(start: u64, length: u64) -> Result<Range<GuestVa>, NativeAddressError> {
    let end = start
        .checked_add(length)
        .ok_or(NativeAddressError::GuestRangeOverflow { start, length })?;
    Ok(GuestVa(start)..GuestVa(end))
}

pub struct NativeLayout {
    mode: NativeAddressMode,
    reservations: Vec<OwnedHostMapping>,
    prepared_adoptions: Vec<OwnedHostMapping>,
    owned_ranges: Vec<Range<HostVa>>,
}

impl NativeLayout {
    /// Empty direct-mode layout. Was `#[cfg(test)]` inside the runtime; the
    /// gate cannot survive the crate split (the runtime's own tests build
    /// `carrick-dsr` without `cfg(test)`), so it is plain `pub` now — it
    /// remains a test-only convenience constructor.
    pub fn direct() -> Self {
        Self {
            mode: NativeAddressMode::Direct,
            reservations: Vec::new(),
            prepared_adoptions: Vec::new(),
            owned_ranges: Vec::new(),
        }
    }

    pub fn for_image(
        image: &AddressSpace,
        layout: MemoryLayout,
        host_page_size: u64,
    ) -> Result<Self, NativeAddressError> {
        Self::select(image, layout, host_page_size, &[])
    }

    pub fn for_exec(
        image: &AddressSpace,
        layout: MemoryLayout,
        host_page_size: u64,
        reusable_owned_ranges: &[Range<HostVa>],
    ) -> Result<Self, NativeAddressError> {
        Self::select(image, layout, host_page_size, reusable_owned_ranges)
    }

    fn select(
        image: &AddressSpace,
        layout: MemoryLayout,
        host_page_size: u64,
        reusable_owned_ranges: &[Range<HostVa>],
    ) -> Result<Self, NativeAddressError> {
        if image
            .regions()
            .iter()
            .all(|region| region.start >= NATIVE_DARWIN_HARD_PAGEZERO_END)
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
                prepared_adoptions: Vec::new(),
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
            match candidate.try_map_excluding(reusable_owned_ranges) {
                Ok(reservations) => {
                    // A biased exec replacement may still lose the exec race
                    // or fail sibling teardown after this preflight. Allocate
                    // and validate all reusable ownership metadata now, but
                    // keep it disarmed until replacement crosses the actual
                    // destructive ownership-transfer boundary.
                    let reusable = intersect_host_ranges(&candidate.ranges, reusable_owned_ranges);
                    let mut prepared_adoptions = Vec::with_capacity(reusable.len());
                    for range in reusable {
                        prepared_adoptions.push(OwnedHostMapping::prepare_adoption(range)?);
                    }
                    return Ok(Self {
                        mode: candidate.mode,
                        reservations,
                        prepared_adoptions,
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

    pub fn address_mode(&self) -> NativeAddressMode {
        self.mode
    }

    pub fn fixed_mapping_flags(
        &self,
        start: HostVa,
        length: usize,
        flags: i32,
    ) -> Result<i32, NativeAddressError> {
        self.mode
            .fixed_mapping_flags(&self.owned_ranges, start, length, flags)
    }

    pub fn owned_ranges(&self) -> &[Range<HostVa>] {
        &self.owned_ranges
    }

    /// Transfer reusable exec ranges into this layout's rollback ownership.
    ///
    /// Every guard and vector slot is prepared during preflight; arming only
    /// flips guard state and therefore cannot allocate at the point of no
    /// return.
    pub fn arm_prepared_adoptions(&mut self) {
        for adoption in &mut self.prepared_adoptions {
            adoption.arm_prepared_adoption();
        }
    }

    pub fn reset_biased_aperture_to_guards(&self) -> Result<(), NativeAddressError> {
        if !matches!(self.mode, NativeAddressMode::Biased { .. }) {
            return Ok(());
        }
        for range in &self.owned_ranges {
            let length = range.end.raw().checked_sub(range.start.raw()).ok_or(
                NativeAddressError::InvalidHostRange {
                    start: range.start.raw(),
                    length: 0,
                },
            )?;
            // Ownership check first: this path replaces whatever currently
            // occupies the range, so it must stay confined to owned ranges
            // exactly as the MAP_FIXED form was.
            #[allow(deprecated)]
            let requested_flags = libc::MAP_ANON | libc::MAP_PRIVATE | libc::MAP_NORESERVE;
            let flags = self.fixed_mapping_flags(range.start, length, requested_flags)?;
            #[cfg(target_os = "macos")]
            {
                let _ = flags;
                // Rebuild the guard as a single entry, for the same reason the
                // initial reservation does — otherwise every post-`execve`
                // fork pays the ~16.4k-entry re-insertion cost again.
                map_inaccessible_span(
                    range.start,
                    length,
                    carrick_host::host_proc::InaccessibleSpanPlacement::ReplaceOwnedRange,
                )?
                .commit();
            }
            #[cfg(not(target_os = "macos"))]
            {
                // See `map_reservation` on the MAP_NORESERVE deprecation.
                let mapped = unsafe {
                    libc::mmap(
                        range.start.raw() as *mut libc::c_void,
                        length,
                        libc::PROT_NONE,
                        flags,
                        -1,
                        0,
                    )
                };
                if mapped == libc::MAP_FAILED || mapped as usize != range.start.raw() {
                    return Err(NativeAddressError::HostMapping {
                        requested: range.start.raw(),
                        length,
                        source: std::io::Error::last_os_error(),
                    });
                }
            }
        }
        Ok(())
    }

    pub fn commit_if_ok<T, E>(self, result: Result<T, E>) -> Result<T, E> {
        match result {
            Ok(value) => {
                let _ = self.commit();
                Ok(value)
            }
            Err(error) => Err(error),
        }
    }

    pub fn commit(mut self) -> (NativeAddressMode, Vec<Range<HostVa>>) {
        for reservation in self.reservations.drain(..) {
            let _ = reservation.commit();
        }
        for adoption in self.prepared_adoptions.drain(..) {
            let _ = adoption.commit();
        }
        (self.mode, self.owned_ranges)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NativeHostBias(u64);

impl NativeHostBias {
    pub fn new(bias: u64, page_size: u64) -> Result<Self, NativeAddressError> {
        if bias == 0 || !page_size.is_power_of_two() || bias & page_size.saturating_sub(1) != 0 {
            return Err(NativeAddressError::InvalidBias { bias, page_size });
        }
        Ok(Self(bias))
    }

    pub const fn get(self) -> u64 {
        self.0
    }

    /// `(immr, imms)` fields (N=1) of the single AArch64 64-bit logical
    /// immediate encoding this bias — but only when the bias also sits
    /// entirely at or above `BIASED_GUEST_APERTURE_END`, so that
    /// `guest | bias == guest + bias` for every in-aperture guest address.
    /// `None` means the compact biased-memory lowering must not be used
    /// for this bias.
    pub fn aperture_disjoint_orr_immediate(self) -> Option<(u32, u32)> {
        let bias = self.0;
        if bias & (BIASED_GUEST_APERTURE_END - 1) != 0 {
            return None;
        }
        let shift = bias.trailing_zeros();
        let run = bias >> shift;
        let len = run.trailing_ones();
        let contiguous = if len >= 64 {
            run == u64::MAX
        } else {
            run == (1u64 << len) - 1
        };
        if len == 0 || !contiguous {
            return None;
        }
        Some(((64 - shift) % 64, len - 1))
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NativeAddressMode {
    Direct,
    Biased { host_bias: NativeHostBias },
}

impl NativeAddressMode {
    pub fn to_host(self, address: GuestVa) -> Result<HostVa, NativeAddressError> {
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

    pub fn to_guest(self, address: HostVa) -> Result<GuestVa, NativeAddressError> {
        let address = address.raw() as u64;
        let bias = self.bias();
        address
            .checked_sub(bias)
            .map(GuestVa)
            .ok_or(NativeAddressError::BelowBias { address, bias })
    }

    pub fn to_host_range(self, range: Range<GuestVa>) -> Result<Range<HostVa>, NativeAddressError> {
        Ok(self.to_host(range.start)?..self.to_host(range.end)?)
    }

    #[cfg_attr(not(test), allow(dead_code))]
    pub fn to_guest_range(
        self,
        range: Range<HostVa>,
    ) -> Result<Range<GuestVa>, NativeAddressError> {
        Ok(self.to_guest(range.start)?..self.to_guest(range.end)?)
    }

    pub fn bias(self) -> u64 {
        match self {
            Self::Direct => 0,
            Self::Biased { host_bias } => host_bias.0,
        }
    }

    pub fn fixed_mapping_flags(
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
pub enum NativeAddressError {
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
    #[error(
        "native guest range 0x{start:x}..0x{end:x} exceeds biased aperture end 0x{aperture_end:x}"
    )]
    OutsideBiasedGuestAperture {
        start: u64,
        end: u64,
        aperture_end: u64,
    },
    #[error("no collision-free native host bias: {detail}")]
    NoCollisionFreeBias { detail: String },
    #[error("native fixed mapping is outside an owned range: 0x{start:x}+0x{length:x}")]
    FixedOutsideOwned { start: usize, length: usize },
}

#[cfg(test)]
mod tests {
    #[cfg(target_os = "macos")]
    use super::{
        BIASED_GUEST_APERTURE_END, BIASED_GUEST_LITERAL_DISPLACEMENT_WINDOW, CandidateLayout,
    };
    use super::{
        NativeAddressError, NativeAddressMode, NativeHostBias, NativeLayout, OwnedHostMapping,
    };
    use carrick_guest_mem::{GuestVa, HostVa};
    use carrick_mem::memory::AddressSpace;
    use carrick_mem::memory::MemoryLayout;
    #[cfg(target_os = "macos")]
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

    // The tests below marked `#[cfg(target_os = "macos")]` assert layouts that
    // require the host to honor an EXACT non-MAP_FIXED mmap hint whenever the
    // range is vacant. That is Darwin semantics, and it is what production
    // `map_exact` collision-probing relies on — and only the Darwin lane runs
    // this machinery today. FreeBSD's ASLR'd first-fit ignores the hint (the
    // FreeBSD native lane will need MAP_FIXED|MAP_EXCL probing through the
    // NativeHost seam instead — M1 in the portability-seams design), so on
    // this rig those tests would fail against semantics no production code
    // exercises yet. Gating them keeps the exact pre-move coverage: they ran
    // only in the macOS `just ci` before the move too (the runtime does not
    // build on FreeBSD). The arithmetic and collision-detection tests stay
    // ungated and run everywhere.
    #[cfg(target_os = "macos")]
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
    fn aperture_disjoint_orr_immediates_are_recognized() {
        let orr = |bias: u64| {
            NativeHostBias::new(bias, 0x4000)
                .unwrap()
                .aperture_disjoint_orr_immediate()
        };
        // Single bit at the aperture end: shift 41 -> immr 23, one-bit run.
        assert_eq!(orr(0x200_0000_0000), Some((23, 0)));
        // Single bit one above: shift 42 -> immr 22.
        assert_eq!(orr(0x400_0000_0000), Some((22, 0)));
        // Contiguous two-bit run at shift 41 -> immr 23, imms len-1 = 1.
        assert_eq!(orr(0x600_0000_0000), Some((23, 1)));
        // Encodable but below the aperture end: guest bits can overlap.
        assert_eq!(orr(0x80_0000_0000), None);
        assert_eq!(orr(0x140_0000_0000), None);
        // Bit 40 overlaps the aperture even though bit 42 clears it.
        assert_eq!(orr(0x500_0000_0000), None);
        // Aperture-disjoint but not one contiguous run.
        assert_eq!(orr(0xa00_0000_0000), None);
    }

    #[test]
    fn no_production_bias_candidate_activates_the_compact_lowering() {
        // H008 Spike 1 measured 3.76% SLOWER than the general lowering and
        // still leaks a host address, so no candidate the selector can pick
        // may satisfy the compact predicate.
        for candidate in super::BIAS_CANDIDATES {
            assert!(
                NativeHostBias::new(candidate, 0x4000)
                    .unwrap()
                    .aperture_disjoint_orr_immediate()
                    .is_none(),
                "candidate 0x{candidate:x} would activate the compact lowering"
            );
        }
        // The retained constant still satisfies it, so the emitter's tests can
        // construct that bias explicitly.
        assert!(
            NativeHostBias::new(super::APERTURE_DISJOINT_ORR_BIAS, 0x4000)
                .unwrap()
                .aperture_disjoint_orr_immediate()
                .is_some()
        );
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
            host_bias: NativeHostBias::new(!0x3fff_u64, 0x4000).unwrap(),
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
            host_bias: NativeHostBias::new(!0x3fff_u64, 0x4000).unwrap(),
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
    #[cfg(target_os = "macos")] // exact-mmap-hint semantics; see note above `vacant_test_ranges`
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
    #[cfg(target_os = "macos")] // exact-mmap-hint semantics; see note above `vacant_test_ranges`
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
    #[cfg(target_os = "macos")] // exact-mmap-hint semantics; see note above `vacant_test_ranges`
    fn vacant_host_reserves_the_underflow_window_below_the_selected_bias() {
        fork_test(|| {
            let page_size = TEST_PAGE_SIZE as u64;
            let guest_start = GuestVa(0x40_0000);
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
            let selected =
                NativeLayout::for_image(&image, layout, page_size).expect("select first bias");
            assert_eq!(
                selected.address_mode().to_host(guest_start).unwrap(),
                HostVa((0x80_0000_0000 + guest_start.raw()) as usize),
                "a vacant host must select the first candidate"
            );
            let owned = selected
                .owned_ranges()
                .first()
                .expect("biased selection owns one merged range")
                .clone();
            assert_eq!(
                owned.start,
                HostVa((0x80_0000_0000 - super::BIASED_GUEST_UNDERFLOW_WINDOW) as usize),
                "the reservation must extend one underflow window below guest zero"
            );
        });
    }

    #[test]
    #[cfg(target_os = "macos")] // exact-mmap-hint semantics; see note above `vacant_test_ranges`
    fn biased_aperture_guards_null_and_unmodeled_gaps_without_replacing_sentinels() {
        fork_test(|| {
            let page_size = TEST_PAGE_SIZE as u64;
            let guest_start = GuestVa(0x40_0000);
            let first_null_host = HostVa(0x80_0000_0000);
            let sentinel = OwnedHostMapping::map_exact(
                first_null_host,
                TEST_PAGE_SIZE,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_PRIVATE | libc::MAP_ANON,
            )
            .expect("occupy first candidate's translated null page");
            unsafe {
                std::ptr::write_bytes(first_null_host.raw() as *mut u8, 0x5a, TEST_PAGE_SIZE);
            }
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
                .expect("select collision-free guarded aperture");
            assert_eq!(
                selected.address_mode().to_host(GuestVa(0)).unwrap(),
                HostVa(0xc0_0000_0000),
                "the pre-existing null-page collision must reject the first bias"
            );
            assert_eq!(unsafe { *(first_null_host.raw() as *const u8) }, 0x5a);

            let gap_guest = GuestVa(0x10_0000_0000);
            let gap_host = selected
                .address_mode()
                .to_host(gap_guest)
                .expect("translate unmodeled guest gap");
            assert!(
                matches!(
                    OwnedHostMapping::map_exact(
                        gap_host,
                        TEST_PAGE_SIZE,
                        libc::PROT_READ | libc::PROT_WRITE,
                        libc::MAP_PRIVATE | libc::MAP_ANON,
                    ),
                    Err(NativeAddressError::HostCollision { .. })
                ),
                "a later host mapping must not acquire an owned guest gap"
            );
            assert!(selected.owned_ranges().iter().any(|range| {
                range.start <= selected.address_mode().to_host(GuestVa(0)).unwrap()
                    && gap_host < range.end
            }));
            let aperture_last = selected
                .address_mode()
                .to_host(GuestVa(BIASED_GUEST_APERTURE_END - 1))
                .expect("translate last in-aperture byte");
            let aperture_guard = selected
                .address_mode()
                .to_host(GuestVa(BIASED_GUEST_APERTURE_END))
                .expect("translate first byte above guest ceiling");
            assert!(
                selected
                    .owned_ranges()
                    .iter()
                    .any(|range| { range.start <= aperture_last && aperture_guard < range.end })
            );
            drop(selected);
            drop(sentinel);
        });
    }

    #[test]
    #[cfg(target_os = "macos")] // exact-mmap-hint semantics; see note above `vacant_test_ranges`
    fn biased_literal_max_width_access_is_collision_probed_past_the_old_guard() {
        fork_test(|| {
            const MAX_POSITIVE_LITERAL_DISPLACEMENT: u64 =
                BIASED_GUEST_LITERAL_DISPLACEMENT_WINDOW - 4;
            const MAX_LITERAL_ACCESS_WIDTH: u64 = 16;

            let page_size = TEST_PAGE_SIZE as u64;
            let low_guest_start = 0x40_0000;
            let ceiling_guest_start = BIASED_GUEST_APERTURE_END - page_size;
            let old_guard_end =
                BIASED_GUEST_APERTURE_END + BIASED_GUEST_LITERAL_DISPLACEMENT_WINDOW;
            let first_sentinel_host = HostVa((0x80_0000_0000 + old_guard_end) as usize);
            let sentinel = OwnedHostMapping::map_exact(
                first_sentinel_host,
                TEST_PAGE_SIZE,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_PRIVATE | libc::MAP_ANON,
            )
            .expect("map sentinel immediately beyond the old literal guard");
            unsafe {
                std::ptr::write_bytes(first_sentinel_host.raw() as *mut u8, 0x5a, TEST_PAGE_SIZE);
            }
            let image = AddressSpace::from_segments(
                low_guest_start,
                [
                    (
                        low_guest_start,
                        carrick_mem::elf::SegmentPerms {
                            read: true,
                            write: false,
                            execute: true,
                        },
                        vec![0; TEST_PAGE_SIZE],
                        page_size,
                    ),
                    (
                        ceiling_guest_start,
                        carrick_mem::elf::SegmentPerms {
                            read: true,
                            write: false,
                            execute: true,
                        },
                        vec![0; TEST_PAGE_SIZE],
                        page_size,
                    ),
                ],
            )
            .expect("build near-ceiling literal image");
            let layout = MemoryLayout {
                heap_base: 0x8_0000_0000,
                heap_size: page_size,
                mmap_base: 0xa0_0000_0000,
                mmap_size: page_size,
            };

            assert!(matches!(
                NativeLayout::for_image(&image, layout, page_size),
                Err(NativeAddressError::NoCollisionFreeBias { .. })
            ));
            assert_eq!(unsafe { *(first_sentinel_host.raw() as *const u8) }, 0x5a);
            drop(sentinel);

            let selected = NativeLayout::for_image(&image, layout, page_size)
                .expect("select collision-free literal guard after removing sentinel");

            let instruction = BIASED_GUEST_APERTURE_END - 4;
            let literal_start = instruction + MAX_POSITIVE_LITERAL_DISPLACEMENT;
            let literal_end = literal_start + MAX_LITERAL_ACCESS_WIDTH;
            let host_start = selected
                .address_mode()
                .to_host(GuestVa(literal_start))
                .expect("translate maximum positive literal target");
            let host_end = selected
                .address_mode()
                .to_host(GuestVa(literal_end))
                .expect("translate maximum-width literal end");
            assert!(
                selected
                    .owned_ranges()
                    .iter()
                    .any(|range| { range.start <= host_start && host_end <= range.end })
            );

            drop(selected);
        });
    }

    #[test]
    #[cfg(target_os = "macos")] // exact-mmap-hint semantics; see note above `vacant_test_ranges`
    fn biased_fixed_mapping_accepts_owned_gaps_and_rejects_outside_aperture() {
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
            assert_eq!(
                selected
                    .fixed_mapping_flags(
                        HostVa(owned.raw() + 2 * TEST_PAGE_SIZE),
                        TEST_PAGE_SIZE,
                        libc::MAP_ANON | libc::MAP_PRIVATE,
                    )
                    .expect("authorize fixed replacement inside owned gap")
                    & libc::MAP_FIXED,
                libc::MAP_FIXED
            );
            let go_arena = selected
                .address_mode()
                .to_host(GuestVa(0x140_0000_0000))
                .expect("translate Go fixed arena");
            assert_eq!(
                selected
                    .fixed_mapping_flags(go_arena, 0x400_000, libc::MAP_ANON | libc::MAP_PRIVATE,)
                    .expect("authorize Go fixed arena inside owned aperture")
                    & libc::MAP_FIXED,
                libc::MAP_FIXED
            );
            let outside = selected.owned_ranges().last().unwrap().end;
            assert!(matches!(
                selected.fixed_mapping_flags(
                    outside,
                    TEST_PAGE_SIZE,
                    libc::MAP_ANON | libc::MAP_PRIVATE,
                ),
                Err(NativeAddressError::FixedOutsideOwned { .. })
            ));
        });
    }

    #[test]
    #[cfg(target_os = "macos")] // exact-mmap-hint semantics; see note above `vacant_test_ranges`
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
    #[cfg(target_os = "macos")] // exact-mmap-hint semantics; see note above `vacant_test_ranges`
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
            assert!(containing[0].start.raw() < host_start.raw());
            assert!(containing[0].end.raw() >= host_start.raw() + TEST_PAGE_SIZE);

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
