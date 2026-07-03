//! Named-FIFO writer-presence "beacon", to give FIFO read-ends correct
//! writer-close EOF readiness — which macOS won't.
//!
//! macOS `poll`/`kqueue` are SILENT on a named-FIFO read-end when the last
//! writer closes (proven: a host probe shows EVFILT_READ never fires for a
//! `mkfifo` FIFO, while it DOES fire `EV_EOF` for an anonymous `pipe(2)`).
//! Linux instead reports `POLLHUP` and a read returns 0. So a guest in the
//! netpoller (`epoll_wait` on an `O_NONBLOCK` FIFO) hangs forever after the
//! writer closes (Go issue 66239).
//!
//! Rather than have carrick DECIDE readiness in userspace, we let the KERNEL do
//! it on an object macOS handles correctly — an anonymous pipe: per FIFO
//! identity `(dev, ino)` we keep a "beacon" pipe whose WRITE end is held only by
//! the guest's FIFO writers (one dup per writer; carrick holds NO write anchor),
//! and whose READ end carrick keeps. The kernel then refcounts the writers —
//! correctly across `fork`, since the write fds are real kernel fds — and
//! `poll`ing the beacon read end reports `POLLHUP` exactly when all writers have
//! closed. The FIFO's actual DATA still flows through the real host FIFO node
//! (so reconnect/multi-writer data + `stat` as `S_IFIFO` keep working); only the
//! EOF *readiness* comes from the beacon.
//!
//! Scope/limits (documented): the beacon is created at the first WRITER open, so
//! a reader that polls strictly before any writer opens isn't covered (rare; the
//! netpoller pattern opens/writes before the read loop). Writers in a different
//! process that did not inherit the beacon via `fork` (a separate carrick guest,
//! or the macOS host) aren't counted.

use std::collections::HashMap;
use std::sync::{LazyLock, Mutex};

struct Beacon {
    /// Read end of the beacon pipe (carrick-held). `poll`ing it reports POLLHUP
    /// once every writer's beacon-write fd has closed.
    read_fd: i32,
    /// guest writer host-fd → that writer's beacon write fd (closed when the
    /// guest writer closes). The kernel refcounts these.
    writer_bw: HashMap<i32, i32>,
}

#[derive(Default)]
struct State {
    /// FIFO identity → beacon.
    beacons: HashMap<(u64, u64), Beacon>,
    /// guest FIFO read host-fd → FIFO identity (to find its beacon at readiness).
    read_ends: HashMap<i32, (u64, u64)>,
}

static STATE: LazyLock<Mutex<State>> = LazyLock::new(|| Mutex::new(State::default()));

fn fd_is_open(fd: i32) -> bool {
    fd >= 0 && unsafe { libc::fcntl(fd, libc::F_GETFD) } != -1
}

fn fifo_identity(host_fd: i32) -> Option<(u64, u64)> {
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    if unsafe { libc::fstat(host_fd, &mut st) } != 0 {
        return None;
    }
    Some((st.st_dev as u64, st.st_ino as u64))
}

/// Register a freshly-opened FIFO host fd. `access_idx` is Linux `O_ACCMODE`:
/// 0 = RDONLY, 1 = WRONLY, 2 = RDWR.
pub(crate) fn register_open(host_fd: i32, access_idx: u32) {
    let Some(id) = fifo_identity(host_fd) else {
        return;
    };
    let mut st = STATE.lock().unwrap_or_else(|e| e.into_inner());
    let has_write = access_idx != 0;
    let has_read = access_idx != 1;
    if has_write {
        // Give this writer a beacon write fd. Create the beacon pipe on the first
        // writer; otherwise dup an existing write end so the kernel refcount
        // tracks every concurrent writer. carrick keeps NO standalone write
        // anchor, so the read end hits POLLHUP exactly when all writers close.
        let bw = match st.beacons.get(&id) {
            Some(b) => {
                let existing = *b.writer_bw.values().next().unwrap_or(&-1);
                if existing >= 0 {
                    unsafe { libc::dup(existing) }
                } else {
                    -1
                }
            }
            None => {
                let mut fds = [0i32; 2];
                if unsafe { libc::pipe(fds.as_mut_ptr()) } != 0 {
                    -1
                } else {
                    // Read end is carrick's beacon; CLOEXEC both so guest execs
                    // don't leak them.
                    unsafe {
                        libc::fcntl(fds[0], libc::F_SETFD, libc::FD_CLOEXEC);
                        libc::fcntl(fds[1], libc::F_SETFD, libc::FD_CLOEXEC);
                    }
                    st.beacons.insert(
                        id,
                        Beacon {
                            read_fd: fds[0],
                            writer_bw: HashMap::new(),
                        },
                    );
                    fds[1]
                }
            }
        };
        if bw >= 0 {
            if let Some(b) = st.beacons.get_mut(&id) {
                b.writer_bw.insert(host_fd, bw);
            } else {
                unsafe { libc::close(bw) };
            }
        }
    }
    if has_read {
        st.read_ends.insert(host_fd, id);
    }
}

/// Unregister a closing FIFO host fd. Returns `true` if it was a writer (the
/// caller should then wake epoll/poll so read-ends re-check the beacon — the
/// close may have dropped the writer count to zero).
pub(crate) fn register_close(host_fd: i32) -> bool {
    let mut st = STATE.lock().unwrap_or_else(|e| e.into_inner());
    st.read_ends.remove(&host_fd);
    // Find which FIFO (if any) this fd was a writer for.
    let mut writer_of = None;
    for (id, b) in st.beacons.iter() {
        if b.writer_bw.contains_key(&host_fd) {
            writer_of = Some(*id);
            break;
        }
    }
    if let Some(id) = writer_of {
        if let Some(b) = st.beacons.get_mut(&id)
            && let Some(bw) = b.writer_bw.remove(&host_fd)
        {
            unsafe { libc::close(bw) };
        }
        return true;
    }
    false
}

/// Reconcile the process-local beacon registry after fork in the child.
///
/// The backing kernel fds are inherited, but this HashMap is only a snapshot of
/// the parent's dispatcher state. If fork-child setup closes or rearranges guest
/// fds, stale writer entries must not keep a beacon write fd open forever and
/// suppress FIFO EOF readiness in the child.
pub(crate) fn after_fork_child() {
    let mut st = STATE.lock().unwrap_or_else(|e| e.into_inner());
    st.read_ends.retain(|fd, _| fd_is_open(*fd));

    let read_ids: std::collections::HashSet<(u64, u64)> = st.read_ends.values().copied().collect();
    let mut empty_unread_beacons = Vec::new();
    for (id, beacon) in &mut st.beacons {
        beacon.writer_bw.retain(|writer_fd, beacon_write_fd| {
            if fd_is_open(*writer_fd) {
                true
            } else {
                unsafe { libc::close(*beacon_write_fd) };
                false
            }
        });
        if beacon.writer_bw.is_empty() && !read_ids.contains(id) {
            unsafe { libc::close(beacon.read_fd) };
            empty_unread_beacons.push(*id);
        }
    }
    for id in empty_unread_beacons {
        st.beacons.remove(&id);
    }
}

/// True iff `host_fd` is a FIFO read-end whose writers have all closed — decided
/// by the KERNEL: poll the beacon read end for POLLHUP (it hangs up exactly when
/// every writer's beacon-write fd has closed). macOS reports pipe HUP correctly,
/// unlike FIFO HUP. A read on the real FIFO then returns 0 (EOF), which macOS
/// also delivers correctly.
pub(crate) fn read_end_at_eof(host_fd: i32) -> bool {
    let st = STATE.lock().unwrap_or_else(|e| e.into_inner());
    let Some(id) = st.read_ends.get(&host_fd) else {
        return false;
    };
    let Some(b) = st.beacons.get(id) else {
        return false;
    };
    let mut pfd = libc::pollfd {
        fd: b.read_fd,
        events: libc::POLLIN,
        revents: 0,
    };
    let rc = unsafe { libc::poll(&mut pfd, 1, 0) };
    rc > 0 && pfd.revents & libc::POLLHUP != 0
}

#[cfg(test)]
mod tests {
    use super::*;

    fn reset_state_for_test() {
        let mut st = STATE.lock().unwrap_or_else(|e| e.into_inner());
        for beacon in st.beacons.values() {
            unsafe { libc::close(beacon.read_fd) };
            for fd in beacon.writer_bw.values() {
                unsafe { libc::close(*fd) };
            }
        }
        *st = State::default();
    }

    #[test]
    fn fork_child_reset_drops_closed_fifo_beacon_writers() {
        reset_state_for_test();
        let mut beacon_pipe = [0i32; 2];
        let mut read_fd_pipe = [0i32; 2];
        assert_eq!(unsafe { libc::pipe(beacon_pipe.as_mut_ptr()) }, 0);
        assert_eq!(unsafe { libc::pipe(read_fd_pipe.as_mut_ptr()) }, 0);

        {
            let mut st = STATE.lock().unwrap_or_else(|e| e.into_inner());
            st.read_ends.insert(read_fd_pipe[0], (1, 2));
            st.beacons.insert(
                (1, 2),
                Beacon {
                    read_fd: beacon_pipe[0],
                    writer_bw: HashMap::from([(-1, beacon_pipe[1])]),
                },
            );
        }

        after_fork_child();

        assert!(
            read_end_at_eof(read_fd_pipe[0]),
            "closed inherited FIFO writer bookkeeping must release the beacon"
        );
        unsafe {
            libc::close(read_fd_pipe[0]);
            libc::close(read_fd_pipe[1]);
        }
        reset_state_for_test();
    }
}
