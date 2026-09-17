//! Retained completion state for poll/select waits.
//!
//! The operation owns the request snapshot and exact descriptor leases.  A
//! wake never re-runs the raw syscall arguments: it samples these descriptions
//! and either completes the original request or parks the same operation with
//! its original absolute deadline.

use std::os::fd::{FromRawFd, OwnedFd};
use std::sync::Arc;
use std::time::Instant;

use carrick_guest_mem::CurrentMmMemory;

use carrick_vfs::errno::HostSyscallResult;

use super::{DispatchOutcome, SyscallDispatcher, WaitFdAuthority, WaitFds};
use crate::dispatch::format_time::{TimerFdPollSource, timerfd_poll_source_from_lease};
use crate::kernel::objects::FileDescriptionFdLease;
use crate::linux_abi::{LINUX_EFAULT, LinuxErrno};

const LINUX_POLLFD_REVENTS_OFFSET: u64 =
    core::mem::offset_of!(carrick_abi::LinuxPollFd, revents) as u64;

#[derive(Clone, Debug)]
pub struct RetainedPollFd {
    pub(crate) guest_fd: i32,
    pub(crate) events: i16,
    pub(crate) address: u64,
    pub(crate) source: RetainedFdSource,
}

/// The exact source sampled after an fd wait wakes.  A bare stdio descriptor
/// has no `FileDescription` to lease, while a negative poll fd is ignored.
/// Keeping those cases distinct prevents a bare stdin wait from becoming
/// permanently unreadable merely because it has no table slot.
#[derive(Clone, Debug)]
pub enum RetainedFdSource {
    Leased(FileDescriptionFdLease),
    BareStdio,
    Negative,
}

#[derive(Clone, Debug)]
pub enum BlockingFdWaitKind {
    Poll {
        entries: Vec<RetainedPollFd>,
    },
    Select {
        entries: Vec<RetainedSelectFd>,
        read: Option<RetainedFdSet>,
        write: Option<RetainedFdSet>,
        except: Option<RetainedFdSet>,
    },
}

#[derive(Clone, Debug)]
pub struct RetainedSelectFd {
    pub(crate) fd: i32,
    pub(crate) requested: u8,
    pub(crate) source: RetainedFdSource,
}

#[derive(Clone, Debug)]
pub struct RetainedFdSet {
    pub(crate) address: u64,
    pub(crate) input: Vec<u8>,
}

/// One host wait target duplicated exactly once when the guest operation is
/// admitted.  Reactor registrations clone this `Arc`; they must never reopen
/// or duplicate the raw target when a retained operation re-parks.
#[derive(Clone, Debug)]
pub struct RetainedFdRegistration {
    pub(crate) fd: Arc<OwnedFd>,
    pub(crate) events: i16,
}

#[derive(Clone, Debug)]
pub struct BlockingFdWait {
    identity: Arc<()>,
    /// Fixed at syscall admission.  Re-parks never reconstruct this from a
    /// relative timeout supplied in guest memory/registers.
    caller_deadline: Option<Instant>,
    kind: Box<BlockingFdWaitKind>,
    /// Host registrations and exact slot authority admitted with the request.
    /// Re-parks retain these objects rather than rebuilding numeric targets
    /// after close/reuse.
    registrations: Arc<[RetainedFdRegistration]>,
    authority: WaitFdAuthority,
}

impl PartialEq for BlockingFdWait {
    fn eq(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.identity, &other.identity)
    }
}
impl Eq for BlockingFdWait {}

#[derive(Debug)]
pub enum BlockingFdWaitStep {
    Done(DispatchOutcome),
    Wait(BlockingFdWait),
}

impl BlockingFdWait {
    /// Admit one retained operation. Equality is operation identity: re-parks
    /// preserve this identity, while separate syscalls are never equal merely
    /// because their request shape or deadline happens to match.
    pub(crate) fn new(
        kind: BlockingFdWaitKind,
        caller_deadline: Option<Instant>,
        wait_fds: WaitFds,
    ) -> Result<Self, LinuxErrno> {
        let mut registrations = Vec::new();
        for wait_fd in wait_fds.iter().filter(|wait_fd| wait_fd.fd() >= 0) {
            let duplicated = unsafe { libc::fcntl(wait_fd.fd(), libc::F_DUPFD_CLOEXEC, 0) }
                .host_syscall_errno()?;
            registrations.push(RetainedFdRegistration {
                fd: Arc::new(unsafe { OwnedFd::from_raw_fd(duplicated) }),
                events: wait_fd.events(),
            });
        }
        Ok(Self {
            identity: Arc::new(()),
            caller_deadline,
            kind: Box::new(kind),
            registrations: registrations.into(),
            authority: wait_fds.authority().clone(),
        })
    }

    pub(crate) const fn caller_deadline(&self) -> Option<Instant> {
        self.caller_deadline
    }

    pub(crate) fn registrations(&self) -> &Arc<[RetainedFdRegistration]> {
        &self.registrations
    }

    pub(crate) fn authority(&self) -> &WaitFdAuthority {
        &self.authority
    }

    /// Reconstruct timer readiness sources only from the leases already
    /// admitted with this operation.  This deliberately avoids a slot lookup:
    /// a close/reuse after admission must not retarget the wait.
    pub(crate) fn timer_sources(&self) -> Vec<TimerFdPollSource> {
        let retain = |source: &RetainedFdSource| match source {
            RetainedFdSource::Leased(lease) => timerfd_poll_source_from_lease(lease.clone()),
            RetainedFdSource::BareStdio | RetainedFdSource::Negative => None,
        };
        match self.kind.as_ref() {
            BlockingFdWaitKind::Poll { entries } => entries
                .iter()
                .filter_map(|entry| retain(&entry.source))
                .collect(),
            BlockingFdWaitKind::Select { entries, .. } => entries
                .iter()
                .filter_map(|entry| retain(&entry.source))
                .collect(),
        }
    }

    fn poll_events(
        source: &RetainedFdSource,
        fd: i32,
        events: i16,
        dispatcher: &SyscallDispatcher,
    ) -> i16 {
        match source {
            RetainedFdSource::Leased(lease) => {
                let interest = carrick_abi::LinuxPollEvents::from_bits_truncate(events);
                lease
                    .description()
                    .readiness(interest.to_epoll(), dispatcher)
                    .to_poll()
                    .bits()
            }
            RetainedFdSource::BareStdio => dispatcher.bare_stdio_poll_ready_events(fd, events),
            RetainedFdSource::Negative => 0,
        }
    }

    pub fn complete(
        self,
        memory: &mut impl CurrentMmMemory,
        dispatcher: &SyscallDispatcher,
    ) -> BlockingFdWaitStep {
        match self.kind.as_ref() {
            BlockingFdWaitKind::Poll { entries } => {
                let mut ready = 0_i64;
                let mut output = Vec::with_capacity(entries.len());
                for entry in entries {
                    let revents =
                        Self::poll_events(&entry.source, entry.guest_fd, entry.events, dispatcher);
                    if revents != 0 {
                        ready += 1;
                    }
                    output.push((entry.address, revents));
                }
                if ready == 0
                    && self
                        .caller_deadline
                        .is_none_or(|deadline| Instant::now() < deadline)
                {
                    return BlockingFdWaitStep::Wait(self);
                }
                for (address, revents) in output {
                    // `pollfd.fd` and `.events` are inputs. Linux writes only
                    // `.revents` on completion, so a parked call must not
                    // restore stale input fields over guest memory.
                    let Some(revents_address) = address.checked_add(LINUX_POLLFD_REVENTS_OFFSET)
                    else {
                        return BlockingFdWaitStep::Done(DispatchOutcome::errno(LINUX_EFAULT));
                    };
                    if memory
                        .write_bytes(revents_address, &revents.to_ne_bytes())
                        .is_err()
                    {
                        return BlockingFdWaitStep::Done(DispatchOutcome::errno(LINUX_EFAULT));
                    }
                }
                BlockingFdWaitStep::Done(DispatchOutcome::Returned { value: ready })
            }
            BlockingFdWaitKind::Select {
                entries,
                read,
                write,
                except,
            } => {
                let mut read_out = read.as_ref().map(|set| vec![0; set.input.len()]);
                let mut write_out = write.as_ref().map(|set| vec![0; set.input.len()]);
                let mut except_out = except.as_ref().map(|set| vec![0; set.input.len()]);
                let mut ready = 0_i64;
                for entry in entries {
                    let events = Self::poll_events(
                        &entry.source,
                        entry.fd,
                        libc::POLLIN | libc::POLLOUT | libc::POLLPRI,
                        dispatcher,
                    );
                    let set_bit = |out: &mut Option<Vec<u8>>| {
                        if let Some(out) = out {
                            let index = entry.fd as usize / 8;
                            if index < out.len() {
                                out[index] |= 1 << (entry.fd as usize % 8);
                            }
                        }
                    };
                    if entry.requested & 1 != 0
                        && events & (libc::POLLIN | libc::POLLHUP | libc::POLLERR) != 0
                    {
                        set_bit(&mut read_out);
                        ready += 1;
                    }
                    if entry.requested & 2 != 0
                        && events & (libc::POLLOUT | libc::POLLHUP | libc::POLLERR) != 0
                    {
                        set_bit(&mut write_out);
                        ready += 1;
                    }
                    if entry.requested & 4 != 0 && events & (libc::POLLPRI | libc::POLLERR) != 0 {
                        set_bit(&mut except_out);
                        ready += 1;
                    }
                }
                if ready == 0
                    && self
                        .caller_deadline
                        .is_none_or(|deadline| Instant::now() < deadline)
                {
                    return BlockingFdWaitStep::Wait(self);
                }
                for (set, output) in [(read, read_out), (write, write_out), (except, except_out)] {
                    if let (Some(set), Some(output)) = (set, output)
                        && memory.write_bytes(set.address, &output).is_err()
                    {
                        return BlockingFdWaitStep::Done(DispatchOutcome::errno(LINUX_EFAULT));
                    }
                }
                BlockingFdWaitStep::Done(DispatchOutcome::Returned { value: ready })
            }
        }
    }
}

#[cfg(test)]
mod tests;
