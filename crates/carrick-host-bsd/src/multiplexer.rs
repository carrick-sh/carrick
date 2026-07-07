//! BSD-family EventMultiplexer implementation based on kqueue.

#[cfg(target_os = "macos")]
use crate::kqueue::NOTE_EXITSTATUS;
#[cfg(any(target_os = "macos", target_os = "openbsd", target_os = "dragonfly"))]
use crate::kqueue::{EVFILT_EXCEPT, NOTE_OOB};
use crate::kqueue::{Kevent, Kqueue};
use carrick_hal::error::OsError;
use carrick_hal::event::{
    EventMultiplexer, Interest, PollEvent, Readiness, TriggerMode, VnodeEvents,
};
use std::os::fd::RawFd;
use std::time::Duration;

/// Decode a `waitpid(2)`-format status word into the BARE exit code the
/// [`PollEvent::exit_status`](carrick_hal::event::PollEvent::exit_status)
/// contract carries: `WEXITSTATUS` for a normal exit, `128 + WTERMSIG` for a
/// signal death (the shell convention, matching the Linux `EpollMultiplexer`'s
/// `waitid(P_PIDFD)` si_status). A still-running/unknown word falls back to the
/// low byte so the value is always a small integer.
#[cfg(target_os = "macos")]
fn wait_status_to_bare(status: i32) -> i32 {
    if libc::WIFEXITED(status) {
        libc::WEXITSTATUS(status)
    } else if libc::WIFSIGNALED(status) {
        128 + libc::WTERMSIG(status)
    } else {
        status & 0xff
    }
}

pub struct KqueueMultiplexer {
    kq: Kqueue,
}

impl KqueueMultiplexer {
    pub fn new() -> Result<Self, OsError> {
        let kq = Kqueue::new_internal().ok_or_else(|| OsError::last("KqueueMultiplexer::new"))?;
        Ok(Self { kq })
    }
}

impl EventMultiplexer for KqueueMultiplexer {
    fn register_io(
        &mut self,
        fd: RawFd,
        token: u64,
        interest: Interest,
        mode: TriggerMode,
    ) -> Result<(), OsError> {
        let mut base = libc::EV_ADD | libc::EV_ENABLE;
        if mode == TriggerMode::Edge {
            base |= libc::EV_CLEAR | libc::EV_DISPATCH;
        }

        let mut changes = Vec::with_capacity(3);
        if interest.read {
            if mode == TriggerMode::Edge {
                let _ = self.kq.apply(&[Kevent::read(fd, libc::EV_DELETE)]);
            }
            let read = match interest.read_lowat {
                Some(lowat) => Kevent::read_lowat(fd, base, lowat),
                None => Kevent::read(fd, base),
            };
            changes.push(read.with_udata_u64(token));
        } else {
            let _ = self.kq.apply(&[Kevent::read(fd, libc::EV_DELETE)]);
        }
        if interest.write {
            if mode == TriggerMode::Edge {
                let _ = self.kq.apply(&[Kevent::write(fd, libc::EV_DELETE)]);
            }
            changes.push(Kevent::write(fd, base).with_udata_u64(token));
        } else {
            let _ = self.kq.apply(&[Kevent::write(fd, libc::EV_DELETE)]);
        }
        if interest.oob {
            #[cfg(any(target_os = "freebsd", target_os = "netbsd"))]
            {
                return Err(OsError::from_raw(libc::EOPNOTSUPP));
            }
            #[cfg(not(any(target_os = "freebsd", target_os = "netbsd")))]
            if mode == TriggerMode::Edge {
                let _ = self.kq.apply(&[Kevent::oob(fd, libc::EV_DELETE)]);
            }
            #[cfg(not(any(target_os = "freebsd", target_os = "netbsd")))]
            changes.push(Kevent::oob(fd, base).with_udata_u64(token));
        } else {
            let _ = self.kq.apply(&[Kevent::oob(fd, libc::EV_DELETE)]);
        }

        if !changes.is_empty() {
            self.kq.apply(&changes).map_err(OsError::from_raw)?;
        }
        Ok(())
    }

    fn register_vnode(&mut self, fd: RawFd, token: u64, mask: VnodeEvents) -> Result<(), OsError> {
        let note = mask.to_note();
        let ev = Kevent::vnode(fd, note).with_udata_u64(token);
        self.kq.apply(&[ev]).map_err(OsError::from_raw)
    }

    fn watch_process_exit(&mut self, pid: i32, token: u64) -> Result<(), OsError> {
        let ev = Kevent::proc_exit(pid).with_udata_u64(token);
        self.kq.apply(&[ev]).map_err(OsError::from_raw)
    }

    fn register_user(&mut self, ident: u64) -> Result<(), OsError> {
        let ev = Kevent::user(ident as usize, libc::EV_ADD | libc::EV_CLEAR);
        self.kq.apply(&[ev]).map_err(OsError::from_raw)
    }

    fn trigger_user(&self, ident: u64) -> Result<(), OsError> {
        crate::kqueue::trigger_user(self.kq.raw_fd(), ident as usize).map_err(OsError::from_raw)
    }

    fn register_timer(
        &mut self,
        token: u64,
        interval: Duration,
        oneshot: bool,
    ) -> Result<(), OsError> {
        let flags = if oneshot {
            libc::EV_ADD | libc::EV_ONESHOT
        } else {
            libc::EV_ADD
        };
        let interval_ns = interval.as_nanos() as i64;
        let ev = Kevent::timer(token as usize, flags, interval_ns).with_udata_u64(token);
        self.kq.apply(&[ev]).map_err(OsError::from_raw)
    }

    fn deregister(&mut self, fd: RawFd) -> Result<(), OsError> {
        let _ = self.kq.apply(&[Kevent::read(fd, libc::EV_DELETE)]);
        let _ = self.kq.apply(&[Kevent::write(fd, libc::EV_DELETE)]);
        let _ = self.kq.apply(&[Kevent::oob(fd, libc::EV_DELETE)]);
        let _ = self.kq.apply(&[Kevent::vnode_delete(fd)]);
        Ok(())
    }

    fn wait(
        &mut self,
        out: &mut Vec<PollEvent>,
        timeout: Option<Duration>,
    ) -> Result<usize, OsError> {
        out.clear();
        let mut events = [Kevent::empty(); 128];
        let timeout_ts = timeout.map(|d| libc::timespec {
            tv_sec: d.as_secs() as _,
            tv_nsec: d.subsec_nanos() as _,
        });

        let n = self
            .kq
            .wait(&[], &mut events, timeout_ts.as_ref())
            .map_err(OsError::from_raw)?;

        for ev in events.iter().take(n).copied() {
            let token = ev.udata_u64();
            let filter = ev.filter();
            let flags = ev.flags();
            let fflags = ev.fflags();

            let eof = flags & libc::EV_EOF != 0;

            let error = if flags & libc::EV_ERROR != 0 {
                Some(ev.data() as i32)
            } else if eof && fflags != 0 {
                Some(fflags as i32)
            } else {
                None
            };

            let mut readiness = Readiness::empty();
            let mut is_eof = false;
            #[cfg_attr(not(target_os = "macos"), allow(unused_mut))]
            let mut exit_status = None;
            let mut vnode = None;

            match filter {
                f if f == libc::EVFILT_READ => {
                    readiness.read = true;
                    if eof {
                        is_eof = true;
                    }
                }
                f if f == libc::EVFILT_WRITE => {
                    readiness.write = true;
                    if eof {
                        is_eof = true;
                    }
                }
                // EVFILT_EXCEPT/NOTE_OOB exists on Darwin/OpenBSD/DragonFly;
                // FreeBSD/NetBSD use an impossible sentinel and reject OOB
                // registration as unsupported.
                #[cfg(any(target_os = "macos", target_os = "openbsd", target_os = "dragonfly"))]
                f if f == EVFILT_EXCEPT => {
                    if fflags & NOTE_OOB != 0 {
                        readiness.oob = true;
                    }
                }
                f if f == libc::EVFILT_VNODE => {
                    readiness.read = true;
                    // Carry the precise filesystem events so the inotify
                    // emulation can derive the exact Linux `inotify_event` mask.
                    vnode = Some(VnodeEvents::from_note(fflags));
                }
                f if f == libc::EVFILT_PROC => {
                    readiness.read = true;
                    if fflags & libc::NOTE_EXIT != 0 {
                        is_eof = true;
                    }
                    // macOS delivers the exit status in `data` only when the
                    // NOTE_EXITSTATUS fflag was requested. `data` is the raw
                    // `waitpid(2)` out-parameter STATUS WORD; the
                    // `PollEvent.exit_status` contract is the BARE exit code
                    // (WEXITSTATUS, or 128+signal for a signal death — matching
                    // the Linux `EpollMultiplexer`'s `waitid(P_PIDFD)` si_status).
                    // Decode here so both backends agree.
                    #[cfg(target_os = "macos")]
                    if fflags & NOTE_EXITSTATUS != 0 {
                        exit_status = Some(wait_status_to_bare(ev.data() as i32));
                    }
                    // FreeBSD carries the wait-status in `data` UNCONDITIONALLY
                    // under NOTE_EXIT. TODO(part-c): wire it into exit_status with
                    // a proc-exit kqueue test when EventMultiplexer::watch_process_exit
                    // lands (the proc_exit_status accessor already reads `data`).
                }
                // A user-triggered wake is a "something changed, re-check"
                // signal, not fd readiness: it carries NO IO readiness bits (the
                // consumer recomputes its own state on return). Surfacing it as
                // read-readiness would make an epoll consumer report a spurious
                // EPOLLIN on the wake's `token`. (Matches the epoll path's old
                // `kevent_to_epoll`, which returned 0 for EVFILT_USER.)
                f if f == libc::EVFILT_USER => {}
                f if f == libc::EVFILT_TIMER => {
                    readiness.read = true;
                }
                _ => {}
            }

            out.push(PollEvent {
                token,
                readiness,
                readiness_count: ev.data(),
                error,
                eof: is_eof,
                exit_status,
                vnode,
            });
        }
        Ok(n)
    }

    fn poll_fd(&self) -> RawFd {
        self.kq.raw_fd()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use std::os::fd::AsRawFd;
    use std::os::unix::net::UnixStream;

    #[test]
    fn read_lowat_suppresses_socket_until_threshold_growth() {
        let (reader, mut writer) = UnixStream::pair().expect("socketpair");
        reader.set_nonblocking(true).expect("reader nonblocking");
        writer.set_nonblocking(true).expect("writer nonblocking");

        let mut mux = KqueueMultiplexer::new().expect("kqueue");
        mux.register_io(
            reader.as_raw_fd(),
            0xabc,
            Interest {
                read: true,
                write: false,
                oob: false,
                read_lowat: Some(113),
            },
            TriggerMode::Edge,
        )
        .expect("register lowat read");

        writer.write_all(&[0xaa; 112]).expect("write below lowat");
        let mut events = Vec::new();
        assert_eq!(
            mux.wait(&mut events, Some(Duration::ZERO))
                .expect("wait below lowat"),
            0
        );

        writer.write_all(&[0xbb; 1]).expect("write to lowat");
        let n = mux
            .wait(&mut events, Some(Duration::ZERO))
            .expect("wait at lowat");
        assert_eq!(n, 1);
        assert_eq!(events[0].token, 0xabc);
        assert!(events[0].readiness.read);
        assert!(events[0].readiness_count >= 113);
    }

    #[test]
    fn read_lowat_rearm_after_edge_suppresses_until_growth() {
        let (reader, mut writer) = UnixStream::pair().expect("socketpair");
        reader.set_nonblocking(true).expect("reader nonblocking");
        writer.set_nonblocking(true).expect("writer nonblocking");

        let mut mux = KqueueMultiplexer::new().expect("kqueue");
        mux.register_io(reader.as_raw_fd(), 0xabc, Interest::READ, TriggerMode::Edge)
            .expect("register initial read");

        writer.write_all(&[0xaa; 112]).expect("write initial bytes");
        let mut events = Vec::new();
        let n = mux
            .wait(&mut events, Some(Duration::ZERO))
            .expect("initial wait");
        assert_eq!(n, 1);
        assert_eq!(events[0].token, 0xabc);
        assert!(events[0].readiness.read);

        mux.register_io(
            reader.as_raw_fd(),
            0xdef,
            Interest {
                read: true,
                write: false,
                oob: false,
                read_lowat: Some(113),
            },
            TriggerMode::Edge,
        )
        .expect("rearm lowat read");

        assert_eq!(
            mux.wait(&mut events, Some(Duration::ZERO))
                .expect("wait after lowat rearm"),
            0
        );

        writer.write_all(&[0xbb; 1]).expect("write to lowat");
        let n = mux
            .wait(&mut events, Some(Duration::ZERO))
            .expect("wait after growth");
        assert_eq!(n, 1);
        assert_eq!(events[0].token, 0xdef);
        assert!(events[0].readiness.read);
        assert!(events[0].readiness_count >= 113);
    }

    #[test]
    fn read_lowat_one_still_reports_socket_eof() {
        let (reader, writer) = UnixStream::pair().expect("socketpair");
        reader.set_nonblocking(true).expect("reader nonblocking");
        drop(writer);

        let mut mux = KqueueMultiplexer::new().expect("kqueue");
        mux.register_io(
            reader.as_raw_fd(),
            0xabc,
            Interest {
                read: true,
                write: false,
                oob: false,
                read_lowat: Some(1),
            },
            TriggerMode::Edge,
        )
        .expect("register lowat read");

        let mut events = Vec::new();
        let n = mux
            .wait(&mut events, Some(Duration::ZERO))
            .expect("wait for eof");
        assert_eq!(n, 1);
        assert_eq!(events[0].token, 0xabc);
        assert!(events[0].readiness.read);
        assert!(events[0].eof);
    }
}
