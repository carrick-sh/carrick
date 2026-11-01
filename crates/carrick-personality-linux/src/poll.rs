//! Linux `poll(2)`/`ppoll(2)`: one body for every ISA and venue.
//!
//! The body decodes the arguments in Linux's order (timeout, then signal
//! mask, then the descriptor count against `RLIMIT_NOFILE`, then the
//! `pollfd` array), resolves each entry through the caller's venue, applies
//! Linux's `revents` rule and decides how the call completes. Venues supply
//! only user copies and descriptor resolution.
//!
//! A venue names one of two descriptor namespaces:
//! - [`PollNamespace::Ring`]: the caller's ring-owned descriptor table (a
//!   native process). Each entry resolves to an in-zone readiness level, a
//!   host-backed description, an absent descriptor, or a contended lookup.
//!   This lane has no wait yet (#894 slice 1). A set that would block, holds
//!   a host-backed entry, meets contention, or cannot be copied exactly now
//!   returns [`FamilyCompletion::Forward`] before any effect: no `revents`
//!   are written and no mask changes, so the call keeps the route it had
//!   before the ring served it.
//! - [`PollNamespace::Delegated`]: the existing delegated descriptor map with
//!   its carrier readiness crossing (x86 CPL0). That owner resolves and
//!   waits on the decoded set as one unit, so the body hands it the whole
//!   set, including an empty one, which still carries its timer wait.

extern crate alloc;

use crate::dispatch::FamilyCompletion;
use alloc::vec::Vec;
use carrick_syscall_abi::{
    LINUX_EINVAL, LINUX_ENOMEM, LINUX_POLLERR, LINUX_POLLHUP, LINUX_POLLNVAL, LinuxErrno,
};
use zerocopy::IntoBytes;

/// Linux `struct pollfd`.
#[repr(C)]
#[derive(
    ::core::clone::Clone,
    ::core::marker::Copy,
    ::core::fmt::Debug,
    ::core::default::Default,
    ::core::cmp::PartialEq,
    ::core::cmp::Eq,
    ::zerocopy::FromBytes,
    ::zerocopy::IntoBytes,
    ::zerocopy::Immutable,
    ::zerocopy::KnownLayout,
)]
pub struct PollFd {
    pub fd: i32,
    pub events: i16,
    pub revents: i16,
}

/// Bytes of the kernel `sigset_t` that `ppoll` accepts (`sigsetsize`).
pub const LINUX_SIGSET_BYTES: u64 = 8;

/// How the native call encodes its timeout.
#[derive(::core::clone::Clone, ::core::marker::Copy, ::core::fmt::Debug)]
pub enum PollTimeoutKind {
    /// `poll(2)`: an `int` count of milliseconds, negative meaning none.
    Milliseconds,
    /// `ppoll(2)`: a `struct timespec` pointer, NULL meaning none.
    Timespec,
}

/// The signal mask the call runs under.
#[derive(::core::clone::Clone, ::core::marker::Copy, ::core::fmt::Debug)]
pub enum PollSignalMask {
    Inherit,
    Replace(carrick_signal_core::SignalSet),
}

/// Round a `ppoll` timespec up to whole milliseconds, saturating at
/// `i32::MAX`. Linux rejects a negative second count or a nanosecond count
/// outside `0..1e9` with `EINVAL`.
pub fn ppoll_timeout_ms(seconds: i64, nanoseconds: i64) -> Result<i32, LinuxErrno> {
    if seconds < 0 || !(0..1_000_000_000).contains(&nanoseconds) {
        return Err(LINUX_EINVAL);
    }
    let milliseconds = seconds
        .saturating_mul(1_000)
        .saturating_add((nanoseconds + 999_999) / 1_000_000);
    Ok(milliseconds.min(i64::from(i32::MAX)) as i32)
}

/// Which descriptor namespace resolves this caller's entries.
#[derive(::core::clone::Clone, ::core::marker::Copy, ::core::fmt::Debug, PartialEq, Eq)]
pub enum PollNamespace {
    Ring,
    Delegated,
}

/// What one nonnegative descriptor names in a ring namespace.
#[derive(::core::clone::Clone, ::core::marker::Copy, ::core::fmt::Debug, PartialEq, Eq)]
pub enum PollTarget {
    /// An in-zone object and its current level, as Linux poll bits.
    InZone(u16),
    /// A host-backed open description.
    HostBacked,
    /// No open descriptor with this number.
    Absent,
    /// The table or object is contended now.
    Busy,
}

/// A decoded call, before its descriptors are resolved.
#[derive(::core::clone::Clone, ::core::marker::Copy, ::core::fmt::Debug)]
pub struct PollRequest {
    /// User address of the `pollfd` array.
    pub fds: u64,
    /// Milliseconds; zero never waits, negative waits without a deadline.
    pub timeout_ms: i32,
    pub sig_mask: PollSignalMask,
}

/// The caller's view of user memory and descriptors.
pub trait PollVenue {
    fn namespace(&self) -> PollNamespace;
    /// Canonical argument `index` of the call.
    fn argument(&self, index: usize) -> u64;
    fn timeout_kind(&self) -> PollTimeoutKind;
    fn copy_in(&mut self, dst: &mut [u8], src: u64) -> bool;
    fn copy_out(&mut self, dst: u64, src: &[u8]) -> bool;
    /// The completion for a user copy this venue cannot perform exactly now.
    fn copy_refused(&self) -> FamilyCompletion;
    /// The caller's soft `RLIMIT_NOFILE`, or `None` while it is contended.
    fn descriptor_limit(&mut self) -> Option<u64>;
    /// Resolve one nonnegative descriptor in a ring namespace.
    fn resolve(&mut self, fd: i32) -> PollTarget {
        let _ = fd;
        PollTarget::Busy
    }
    /// Serve the decoded set through the delegated descriptor owner.
    fn serve_delegated(
        &mut self,
        request: &PollRequest,
        pollfds: &mut [PollFd],
    ) -> FamilyCompletion {
        let _ = (request, pollfds);
        FamilyCompletion::Forward
    }
}

fn errno(errno: LinuxErrno) -> FamilyCompletion {
    FamilyCompletion::Complete(errno.guest_retval())
}

/// Linux's `revents` for one entry whose object reports `level`: requested
/// bits, plus the error, hangup and invalid bits whether requested or not.
pub const fn revents(events: i16, level: u16) -> i16 {
    let always = (LINUX_POLLERR | LINUX_POLLHUP | LINUX_POLLNVAL) as u16;
    ((events as u16 & level) | (level & always)) as i16
}

fn decode(venue: &mut dyn PollVenue) -> Result<PollRequest, FamilyCompletion> {
    let kind = venue.timeout_kind();
    let timeout_ms = match kind {
        PollTimeoutKind::Milliseconds => venue.argument(2) as i32,
        PollTimeoutKind::Timespec => match venue.argument(2) {
            0 => -1,
            address => {
                let mut ts = [0u8; 16];
                if !venue.copy_in(&mut ts, address) {
                    return Err(venue.copy_refused());
                }
                let mut seconds = [0u8; 8];
                let mut nanoseconds = [0u8; 8];
                seconds.copy_from_slice(&ts[..8]);
                nanoseconds.copy_from_slice(&ts[8..]);
                ppoll_timeout_ms(i64::from_le_bytes(seconds), i64::from_le_bytes(nanoseconds))
                    .map_err(errno)?
            }
        },
    };
    let sig_mask = match (kind, venue.argument(3)) {
        (PollTimeoutKind::Milliseconds, _) | (PollTimeoutKind::Timespec, 0) => {
            PollSignalMask::Inherit
        }
        (PollTimeoutKind::Timespec, address) => {
            if venue.argument(4) != LINUX_SIGSET_BYTES {
                return Err(errno(LINUX_EINVAL));
            }
            let mut bits = [0u8; LINUX_SIGSET_BYTES as usize];
            if !venue.copy_in(&mut bits, address) {
                return Err(venue.copy_refused());
            }
            PollSignalMask::Replace(
                carrick_signal_core::SignalSet::from_bits(u64::from_le_bytes(bits))
                    .without(carrick_signal_core::policy::Signal::KILL)
                    .without(carrick_signal_core::policy::Signal::STOP),
            )
        }
    };
    Ok(PollRequest {
        fds: venue.argument(0),
        timeout_ms,
        sig_mask,
    })
}

/// Serve one `poll`/`ppoll` call.
pub fn serve(venue: &mut dyn PollVenue) -> FamilyCompletion {
    let request = match decode(venue) {
        Ok(request) => request,
        Err(completion) => return completion,
    };
    let nfds = venue.argument(1);
    let Some(limit) = venue.descriptor_limit() else {
        return FamilyCompletion::Forward;
    };
    if nfds > limit {
        return errno(LINUX_EINVAL);
    }
    // RLIMIT_NOFILE is the semantic bound; the ring's memory is a separate
    // one. A set the ring cannot hold is ENOMEM, never an aborting
    // allocation.
    let Some(mut pollfds) = usize::try_from(nfds).ok().and_then(|count| {
        let mut pollfds = Vec::new();
        pollfds.try_reserve_exact(count).ok()?;
        pollfds.resize(count, PollFd::default());
        Some(pollfds)
    }) else {
        return errno(LINUX_ENOMEM);
    };
    if !pollfds.is_empty() && !venue.copy_in(pollfds.as_mut_bytes(), request.fds) {
        return venue.copy_refused();
    }
    match venue.namespace() {
        PollNamespace::Delegated => venue.serve_delegated(&request, &mut pollfds),
        PollNamespace::Ring => serve_ring(venue, &request, &mut pollfds),
    }
}

/// One scan of a ring namespace. Every refusal returns before any effect.
fn serve_ring(
    venue: &mut dyn PollVenue,
    request: &PollRequest,
    pollfds: &mut [PollFd],
) -> FamilyCompletion {
    let mut ready: i64 = 0;
    for entry in pollfds.iter_mut() {
        entry.revents = if entry.fd < 0 {
            0
        } else {
            match venue.resolve(entry.fd) {
                PollTarget::InZone(level) => revents(entry.events, level),
                PollTarget::Absent => LINUX_POLLNVAL,
                // One ready count covers the whole set, so answering only
                // its in-zone part would mis-serve it: refuse the call.
                PollTarget::HostBacked | PollTarget::Busy => return FamilyCompletion::Forward,
            }
        };
        ready += i64::from(entry.revents != 0);
    }
    if ready == 0 {
        // No ring wait yet: a blocking set keeps its route, never a fake
        // timeout. Under a replaced mask, a signal the new mask unblocks is
        // reported before an empty zero-timeout result; that order is
        // settled with the wait itself.
        if request.timeout_ms != 0 || matches!(request.sig_mask, PollSignalMask::Replace(_)) {
            return FamilyCompletion::Forward;
        }
    }
    if !venue.copy_out(request.fds, pollfds.as_bytes()) {
        return venue.copy_refused();
    }
    FamilyCompletion::Complete(ready)
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;
    use alloc::vec::Vec;
    use carrick_syscall_abi::{LINUX_POLLIN, LINUX_POLLOUT, LINUX_POLLRDNORM, LINUX_POLLWRNORM};

    #[test]
    fn ppoll_timeout_rounds_up_and_rejects_invalid_nanoseconds() {
        assert_eq!(ppoll_timeout_ms(0, 1), Ok(1));
        assert_eq!(ppoll_timeout_ms(0, 999_999), Ok(1));
        assert_eq!(ppoll_timeout_ms(0, 1_000_001), Ok(2));
        assert_eq!(ppoll_timeout_ms(0, 1_000_000_000), Err(LINUX_EINVAL));
        assert_eq!(ppoll_timeout_ms(-1, 0), Err(LINUX_EINVAL));
        assert_eq!(ppoll_timeout_ms(i64::MAX, 999_999_999), Ok(i32::MAX));
    }

    #[test]
    fn revents_keeps_requested_bits_and_unconditional_error_hangup_invalid() {
        let reader = (LINUX_POLLIN | LINUX_POLLRDNORM | LINUX_POLLHUP) as u16;
        assert_eq!(revents(0, reader), LINUX_POLLHUP);
        assert_eq!(revents(LINUX_POLLIN, reader), LINUX_POLLIN | LINUX_POLLHUP);
        let writer = (LINUX_POLLOUT | LINUX_POLLWRNORM | LINUX_POLLERR) as u16;
        assert_eq!(revents(0, writer), LINUX_POLLERR);
        assert_eq!(revents(LINUX_POLLIN, 0), 0);
    }

    /// A ring venue over in-memory user words and a scripted table.
    struct Script {
        args: [u64; 5],
        memory: Vec<u8>,
        targets: Vec<(i32, PollTarget)>,
        limit: Option<u64>,
        writes: usize,
        resolves: usize,
    }
    const BASE: u64 = 0x1000;
    impl Script {
        fn new(fds: &[PollFd], timeout: Option<[i64; 2]>) -> Self {
            let mut memory = vec![0u8; 256];
            let bytes = fds.as_bytes();
            memory[..bytes.len()].copy_from_slice(bytes);
            let timeout_at = BASE + 128;
            if let Some([seconds, nanoseconds]) = timeout {
                memory[128..136].copy_from_slice(&seconds.to_le_bytes());
                memory[136..144].copy_from_slice(&nanoseconds.to_le_bytes());
            }
            Self {
                args: [
                    BASE,
                    fds.len() as u64,
                    timeout.map_or(0, |_| timeout_at),
                    0,
                    0,
                ],
                memory,
                targets: Vec::new(),
                limit: Some(64),
                writes: 0,
                resolves: 0,
            }
        }
        fn slice(&mut self, address: u64, len: usize) -> Option<&mut [u8]> {
            let start = address.checked_sub(BASE)? as usize;
            self.memory.get_mut(start..start.checked_add(len)?)
        }
        fn fds(&mut self, count: usize) -> Vec<PollFd> {
            let bytes = self.slice(BASE, count * 8).unwrap().to_vec();
            bytes
                .chunks_exact(8)
                .map(|chunk| PollFd {
                    fd: i32::from_le_bytes(chunk[..4].try_into().unwrap()),
                    events: i16::from_le_bytes(chunk[4..6].try_into().unwrap()),
                    revents: i16::from_le_bytes(chunk[6..].try_into().unwrap()),
                })
                .collect()
        }
    }
    impl PollVenue for Script {
        fn namespace(&self) -> PollNamespace {
            PollNamespace::Ring
        }
        fn argument(&self, index: usize) -> u64 {
            self.args[index]
        }
        fn timeout_kind(&self) -> PollTimeoutKind {
            PollTimeoutKind::Timespec
        }
        fn copy_in(&mut self, dst: &mut [u8], src: u64) -> bool {
            self.slice(src, dst.len())
                .map(|bytes| dst.copy_from_slice(bytes))
                .is_some()
        }
        fn copy_out(&mut self, dst: u64, src: &[u8]) -> bool {
            self.writes += 1;
            self.slice(dst, src.len())
                .map(|bytes| bytes.copy_from_slice(src))
                .is_some()
        }
        fn copy_refused(&self) -> FamilyCompletion {
            FamilyCompletion::Forward
        }
        fn descriptor_limit(&mut self) -> Option<u64> {
            self.limit
        }
        fn resolve(&mut self, fd: i32) -> PollTarget {
            self.resolves += 1;
            self.targets
                .iter()
                .find(|(number, _)| *number == fd)
                .map_or(PollTarget::Absent, |(_, target)| *target)
        }
    }

    fn pollfd(fd: i32, events: i16) -> PollFd {
        PollFd {
            fd,
            events,
            revents: 0x7777,
        }
    }

    #[test]
    fn ring_scan_reports_levels_ignores_negative_and_counts_invalid() {
        let mut venue = Script::new(
            &[
                pollfd(3, LINUX_POLLIN),
                pollfd(-1, LINUX_POLLIN),
                pollfd(9, 0),
            ],
            Some([0, 0]),
        );
        venue.targets.push((
            3,
            PollTarget::InZone((LINUX_POLLIN | LINUX_POLLRDNORM) as u16),
        ));
        assert_eq!(serve(&mut venue), FamilyCompletion::Complete(2));
        let out = venue.fds(3);
        assert_eq!(out[0].revents, LINUX_POLLIN);
        assert_eq!(out[1].revents, 0);
        assert_eq!(out[2].revents, LINUX_POLLNVAL);
        assert_eq!(venue.resolves, 2, "a negative descriptor is never resolved");
    }

    #[test]
    fn ring_would_block_host_backed_and_busy_refuse_before_any_effect() {
        for (target, timeout) in [
            (PollTarget::InZone(0), Some([1, 0])),
            (PollTarget::InZone(0), None),
            (PollTarget::HostBacked, Some([0, 0])),
            (PollTarget::Busy, Some([0, 0])),
        ] {
            let mut venue =
                Script::new(&[pollfd(3, LINUX_POLLIN), pollfd(4, LINUX_POLLIN)], timeout);
            venue.targets.push((3, PollTarget::InZone(0)));
            venue.targets.push((4, target));
            assert_eq!(serve(&mut venue), FamilyCompletion::Forward, "{target:?}");
            assert_eq!(venue.writes, 0, "{target:?} wrote revents");
            assert!(venue.fds(2).iter().all(|entry| entry.revents == 0x7777));
        }
    }

    #[test]
    fn empty_zero_timeout_set_completes_and_a_replaced_mask_keeps_its_route() {
        let mut venue = Script::new(&[], Some([0, 0]));
        assert_eq!(serve(&mut venue), FamilyCompletion::Complete(0));
        let mut venue = Script::new(&[pollfd(3, LINUX_POLLIN)], Some([0, 0]));
        venue.targets.push((3, PollTarget::InZone(0)));
        venue.args[3] = BASE + 160;
        venue.args[4] = LINUX_SIGSET_BYTES;
        assert_eq!(serve(&mut venue), FamilyCompletion::Forward);
        assert_eq!(venue.writes, 0);
    }

    #[test]
    fn invalid_arguments_are_linux_einval_in_linux_order() {
        let einval = FamilyCompletion::Complete(LINUX_EINVAL.guest_retval());
        // A bad timespec precedes a bad mask size and the descriptor count.
        let mut venue = Script::new(&[pollfd(3, LINUX_POLLIN)], Some([0, 1_000_000_000]));
        venue.args[1] = 1 << 20;
        venue.args[3] = BASE + 160;
        venue.args[4] = 4;
        assert_eq!(serve(&mut venue), einval);
        let mut venue = Script::new(&[pollfd(3, LINUX_POLLIN)], Some([-1, 0]));
        assert_eq!(serve(&mut venue), einval);
        let mut venue = Script::new(&[pollfd(3, LINUX_POLLIN)], Some([0, 0]));
        venue.args[3] = BASE + 160;
        venue.args[4] = 4;
        assert_eq!(serve(&mut venue), einval);
        // nfds above the soft limit, not a fixed cap.
        let mut venue = Script::new(&[pollfd(3, LINUX_POLLIN)], Some([0, 0]));
        venue.args[1] = 65;
        assert_eq!(serve(&mut venue), einval);
        venue.args[1] = 64;
        venue.limit = None;
        assert_eq!(serve(&mut venue), FamilyCompletion::Forward);
        assert_eq!(venue.resolves + venue.writes, 0);
    }

    #[test]
    fn a_huge_set_below_the_limit_is_enomem_without_allocating_or_copying() {
        // 2^61 entries are 2^64 bytes: the reservation fails before any
        // allocation, so the call neither aborts nor over-allocates.
        let mut venue = Script::new(&[pollfd(3, LINUX_POLLIN)], Some([0, 0]));
        venue.limit = Some(u64::MAX);
        venue.args[1] = 1 << 61;
        assert_eq!(
            serve(&mut venue),
            FamilyCompletion::Complete(LINUX_ENOMEM.guest_retval())
        );
        assert_eq!(venue.resolves + venue.writes, 0);
        assert_eq!(venue.fds(1)[0].revents, 0x7777);
        // The exact RLIMIT_NOFILE check still comes first.
        venue.limit = Some(1 << 60);
        assert_eq!(
            serve(&mut venue),
            FamilyCompletion::Complete(LINUX_EINVAL.guest_retval())
        );
    }

    #[test]
    fn unreadable_arguments_take_the_venue_refusal() {
        let mut venue = Script::new(&[pollfd(3, LINUX_POLLIN)], Some([0, 0]));
        venue.args[0] = 0x9000;
        assert_eq!(serve(&mut venue), FamilyCompletion::Forward);
        venue.args[0] = BASE;
        venue.args[2] = 0x9000;
        assert_eq!(serve(&mut venue), FamilyCompletion::Forward);
        assert_eq!(venue.writes, 0);
    }
}
