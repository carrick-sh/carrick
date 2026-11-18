//! Host-bound poll readiness: the carrier side of the x86 CPL0 ring's
//! [`HostReadinessCrossing`].
//!
//! The ring owns `poll`/`ppoll` and every in-zone descriptor. Only a
//! descriptor bound to a real host object (the CLI's stdio) crosses, as a
//! typed [`HostReadinessEntry`] batch in the stopped task's supervisor
//! region. This module is the carrier-neutral part of answering it, shared
//! by every x86 CPL0 carrier (KVM through the runtime executor, the soft
//! carrier): decode the crossing frame ([`ReadinessCrossing::decode`]),
//! resolve each entry through host-owned descriptor authority
//! ([`BoundHostFds`]), and sample host readiness once
//! ([`sample_host_readiness`]). Parking a task that must wait is the
//! executor's: [`HostReadinessRequest::wait`] says only whether, and how
//! long, the wait may last.

use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::time::{Duration, Instant};

use carrick_el1_abi::{
    HostBoundFd, HostObjectBinding, HostReadinessCrossing, HostReadinessEntry, HostReadinessTimeout,
};
use carrick_hal::TrapError;
use carrick_x86::cpl0_entry::NativeFrame;

use crate::carrier_cpu::CarrierCpuIo;
use crate::carrier_memory::CarrierMemoryIo;
use crate::cpl0_boot::{ForwardVenue, fail};

/// One decoded readiness crossing.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HostReadinessRequest {
    /// The batch's supervisor address in the stopped task's region.
    pub address: u64,
    pub count: usize,
    /// `None`: no deadline (a negative Linux `poll` timeout).
    pub deadline: Option<Instant>,
    pub sig_mask: carrick_abi::WaitSigMask,
}

/// How a forwarded frame relates to [`HostReadinessCrossing`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReadinessCrossing {
    /// Not a readiness crossing: route the frame elsewhere.
    Other,
    /// A malformed crossing, answered with this errno.
    Refused(carrick_abi::LinuxErrno),
    Request(HostReadinessRequest),
}

impl ReadinessCrossing {
    /// Decode `frame`, timing a finite timeout from `now`.
    pub fn decode(frame: &NativeFrame, now: Instant) -> Result<Self, TrapError> {
        if frame.rax != HostReadinessCrossing::NUMBER
            || !HostReadinessCrossing::is_crossing(frame.rcx)
        {
            return Ok(Self::Other);
        }
        let sig_mask = match frame.r8 {
            HostReadinessCrossing::MASK_NONE => carrick_abi::WaitSigMask::NONE,
            HostReadinessCrossing::MASK_REPLACE => {
                carrick_abi::WaitSigMask::Replace(carrick_abi::SigSet::from_raw(frame.r10))
            }
            _ => return Ok(Self::Refused(carrick_abi::LINUX_EINVAL)),
        };
        let count =
            usize::try_from(frame.rsi).map_err(|_| fail("host readiness count overflow"))?;
        let Some(timeout) = HostReadinessTimeout::from_wire(frame.rdx) else {
            return Ok(Self::Refused(carrick_abi::LINUX_EINVAL));
        };
        let timeout_ms = timeout.millis();
        let deadline = u64::try_from(timeout_ms)
            .ok()
            .map(|millis| now + Duration::from_millis(millis));
        Ok(Self::Request(HostReadinessRequest {
            address: frame.rdi,
            count,
            deadline,
            sig_mask,
        }))
    }
}

/// Whether a request that sampled nothing ready may still wait.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReadinessWait {
    /// The deadline has passed: the crossing returns 0.
    Expired,
    /// Wait at most this long (`None`: no deadline).
    Until(Option<Duration>),
}

impl HostReadinessRequest {
    pub fn wait(&self, now: Instant) -> ReadinessWait {
        match self.deadline {
            None => ReadinessWait::Until(None),
            Some(deadline) => {
                let left = deadline.saturating_duration_since(now);
                if left.is_zero() {
                    ReadinessWait::Expired
                } else {
                    ReadinessWait::Until(Some(left))
                }
            }
        }
    }
}

/// What the run's dispatcher says one stdio descriptor is bound to.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StdioBinding {
    /// A sink that never blocks (captured output).
    AlwaysWritable,
    /// A host descriptor the dispatcher supplied.
    Host(HostBoundFd),
}

/// One resolved readiness binding.
#[derive(Debug)]
pub enum BoundReadiness {
    Host(OwnedFd),
    AlwaysWritable,
    Invalid,
}

/// Host-owned descriptor authority for the current CPL0 stdio bindings.
/// A guest-supplied raw host number is never admitted by this table.
#[derive(Debug)]
pub struct BoundHostFds {
    stdio: [BoundReadiness; 3],
}

impl BoundHostFds {
    /// Bind stdin, stdout and stderr (`None`: not open).
    pub fn from_stdio(stdio: [Option<StdioBinding>; 3]) -> Result<Self, TrapError> {
        let [stdin, stdout, stderr] = stdio;
        Ok(Self {
            stdio: [Self::bind(stdin)?, Self::bind(stdout)?, Self::bind(stderr)?],
        })
    }

    fn bind(binding: Option<StdioBinding>) -> Result<BoundReadiness, TrapError> {
        match binding {
            Some(StdioBinding::AlwaysWritable) => Ok(BoundReadiness::AlwaysWritable),
            None => Ok(BoundReadiness::Invalid),
            Some(StdioBinding::Host(fd)) => {
                // The host dispatcher, rather than CPL0, supplied this fd.
                // Duplicate it now so close/reuse of the source number cannot
                // redirect a later poll or reactor registration.
                // SAFETY: F_DUPFD_CLOEXEC reads no memory; a bad number fails.
                let owned = unsafe { libc::fcntl(fd.raw(), libc::F_DUPFD_CLOEXEC, 0) };
                if owned < 0 {
                    let error = std::io::Error::last_os_error();
                    if error.raw_os_error() == Some(libc::EBADF) {
                        return Ok(BoundReadiness::Invalid);
                    }
                    return Err(fail(format!("bind stdio readiness descriptor: {error}")));
                }
                // SAFETY: F_DUPFD_CLOEXEC returned a fresh owned host fd.
                Ok(BoundReadiness::Host(unsafe { OwnedFd::from_raw_fd(owned) }))
            }
        }
    }

    pub fn resolve(&self, binding: HostObjectBinding) -> Option<&BoundReadiness> {
        let index = usize::try_from(binding.stdio_fd()?).ok()?;
        self.stdio.get(index)
    }
}

/// One host readiness sample.
#[derive(Debug, PartialEq, Eq)]
pub enum HostReadinessStep {
    /// This many entries have nonzero `revents` (the crossing's result).
    Ready(i64),
    /// Nothing is ready: the host descriptors a wait would watch.
    Wait(Vec<(HostBoundFd, carrick_abi::PollEvents)>),
}

/// Sample `request`'s batch, in the stopped task's supervisor region, once.
pub fn sample_host_readiness<M: CarrierCpuIo, Mem: CarrierMemoryIo>(
    venue: &mut ForwardVenue<'_, M, Mem>,
    request: &HostReadinessRequest,
    bound: &BoundHostFds,
) -> Result<HostReadinessStep, TrapError> {
    venue.with_host_readiness_entries(request.address, request.count, |entries| {
        sample_entries(entries, bound)
    })?
}

/// Fill each entry's `revents` from one zero-timeout host `poll`.
pub fn sample_entries(
    entries: &mut [HostReadinessEntry],
    bound: &BoundHostFds,
) -> Result<HostReadinessStep, TrapError> {
    let mut pollfds: Vec<libc::pollfd> = entries
        .iter()
        .map(|entry| {
            let readiness = bound
                .resolve(entry.binding)
                .ok_or_else(|| fail("unbound CPL0 host readiness descriptor"))?;
            Ok(libc::pollfd {
                fd: match readiness {
                    BoundReadiness::Host(fd) => fd.as_raw_fd(),
                    BoundReadiness::AlwaysWritable | BoundReadiness::Invalid => -1,
                },
                events: entry.events,
                revents: 0,
            })
        })
        .collect::<Result<Vec<_>, TrapError>>()?;
    // SAFETY: `pollfds` is a live, exclusively borrowed array of its length.
    let result = unsafe { libc::poll(pollfds.as_mut_ptr(), pollfds.len() as libc::nfds_t, 0) };
    if result < 0 {
        return Err(fail(format!(
            "host readiness probe: {}",
            std::io::Error::last_os_error()
        )));
    }
    let mut ready = 0i64;
    for (entry, pollfd) in entries.iter_mut().zip(&pollfds) {
        entry.revents = match bound.resolve(entry.binding) {
            Some(BoundReadiness::AlwaysWritable) => entry.events & libc::POLLOUT,
            Some(BoundReadiness::Invalid) => libc::POLLNVAL,
            Some(BoundReadiness::Host(_)) => pollfd.revents,
            None => return Err(fail("host readiness binding disappeared")),
        };
        ready += i64::from(entry.revents != 0);
    }
    if ready > 0 {
        Ok(HostReadinessStep::Ready(ready))
    } else {
        Ok(HostReadinessStep::Wait(
            pollfds
                .into_iter()
                .filter(|fd| fd.fd >= 0)
                .filter_map(|fd| {
                    HostBoundFd::new(fd.fd)
                        .map(|host_fd| (host_fd, carrick_abi::PollEvents::from_bits(fd.events)))
                })
                .collect(),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn frame(r8: u64, rdx: u64) -> NativeFrame {
        NativeFrame {
            rax: HostReadinessCrossing::NUMBER,
            rcx: HostReadinessCrossing::FRAME_TAG,
            rdi: 0x1000,
            rsi: 3,
            rdx,
            r10: 1 << 9,
            r8,
            ..NativeFrame::default()
        }
    }

    fn entry(fd: usize, events: i16) -> HostReadinessEntry {
        HostReadinessEntry {
            binding: [
                HostObjectBinding::STDIN,
                HostObjectBinding::STDOUT,
                HostObjectBinding::STDERR,
            ][fd],
            events,
            revents: 0,
            poll_index: 0,
        }
    }

    #[test]
    fn decode_routes_only_tagged_crossings_and_refuses_malformed_ones() {
        let now = Instant::now();
        let untagged = NativeFrame {
            rcx: 0x40_1000,
            ..frame(HostReadinessCrossing::MASK_NONE, 0)
        };
        assert_eq!(
            ReadinessCrossing::decode(&untagged, now).unwrap(),
            ReadinessCrossing::Other
        );
        assert_eq!(
            ReadinessCrossing::decode(&frame(7, 0), now).unwrap(),
            ReadinessCrossing::Refused(carrick_abi::LINUX_EINVAL)
        );
        assert_eq!(
            ReadinessCrossing::decode(&frame(HostReadinessCrossing::MASK_NONE, 1 << 40), now)
                .unwrap(),
            ReadinessCrossing::Refused(carrick_abi::LINUX_EINVAL)
        );
        let ReadinessCrossing::Request(request) =
            ReadinessCrossing::decode(&frame(HostReadinessCrossing::MASK_REPLACE, 250), now)
                .unwrap()
        else {
            panic!("tagged crossing")
        };
        assert_eq!((request.address, request.count), (0x1000, 3));
        assert_eq!(
            request.sig_mask,
            carrick_abi::WaitSigMask::Replace(carrick_abi::SigSet::from_raw(1 << 9))
        );
        assert_eq!(
            request.wait(now),
            ReadinessWait::Until(Some(Duration::from_millis(250)))
        );
        assert_eq!(
            request.wait(now + Duration::from_millis(250)),
            ReadinessWait::Expired
        );
        let ReadinessCrossing::Request(forever) = ReadinessCrossing::decode(
            &frame(HostReadinessCrossing::MASK_NONE, (-1i64) as u64),
            now,
        )
        .unwrap() else {
            panic!("tagged crossing")
        };
        assert_eq!(forever.wait(now), ReadinessWait::Until(None));
    }

    /// Rust std's startup probe: `poll` fds 0-2 with no events and a zero
    /// timeout. Open descriptors report nothing; a closed one `POLLNVAL`.
    #[test]
    fn stdio_sample_reports_open_and_closed_descriptors() {
        let bound = BoundHostFds::from_stdio([
            None,
            Some(StdioBinding::AlwaysWritable),
            Some(StdioBinding::AlwaysWritable),
        ])
        .unwrap();
        let mut entries = [entry(0, 0), entry(1, 0), entry(2, 0)];
        assert_eq!(
            sample_entries(&mut entries, &bound).unwrap(),
            HostReadinessStep::Ready(1)
        );
        assert_eq!(entries.map(|entry| entry.revents), [libc::POLLNVAL, 0, 0]);
        let mut writable = [entry(1, libc::POLLOUT)];
        assert_eq!(
            sample_entries(&mut writable, &bound).unwrap(),
            HostReadinessStep::Ready(1)
        );
        assert_eq!(writable[0].revents, libc::POLLOUT);
    }

    /// A host-bound stdin with nothing to read is sampled through the
    /// table's own duplicate, and a wait watches that duplicate.
    #[test]
    fn an_idle_host_stdin_asks_to_wait_on_its_duplicate() {
        let mut pipe = [0; 2];
        // SAFETY: `pipe` is a live two-element array.
        assert_eq!(unsafe { libc::pipe(pipe.as_mut_ptr()) }, 0);
        // SAFETY: both ends were just created and are owned here.
        let (read, _write) =
            unsafe { (OwnedFd::from_raw_fd(pipe[0]), OwnedFd::from_raw_fd(pipe[1])) };
        let bound = BoundHostFds::from_stdio([
            Some(StdioBinding::Host(
                HostBoundFd::new(read.as_raw_fd()).unwrap(),
            )),
            None,
            None,
        ])
        .unwrap();
        let mut entries = [entry(0, libc::POLLIN)];
        let HostReadinessStep::Wait(fds) = sample_entries(&mut entries, &bound).unwrap() else {
            panic!("an empty pipe is not readable")
        };
        assert_eq!(fds.len(), 1);
        assert_ne!(fds[0].0.raw(), read.as_raw_fd());
        assert_eq!(entries[0].revents, 0);
    }
}
