//! Named-FIFO writer-presence "beacon" and peer-presence signaling, to give FIFO
//! open handshakes and read-ends correct writer-close EOF readiness — which macOS won't.
//!
//! # 1. EOF Readiness (historical beacon)
//! macOS `poll`/`kqueue` are SILENT on a named-FIFO read-end when the last
//! writer closes (proven: a host probe shows EVFILT_READ never fires for a
//! `mkfifo` FIFO, while it DOES fire `EV_EOF` for an anonymous `pipe(2)`).
//! Linux instead reports `POLLHUP` and a read returns 0. So a guest in the
//! netpoller (`epoll_wait` on an `O_NONBLOCK` FIFO) hangs forever after the
//! writer closes (Go issue 66239).
//!
//! We keep a "beacon" pipe per FIFO identity `(dev, ino)` whose WRITE end is held
//! only by the guest's FIFO writers (one dup per writer; carrick holds NO write
//! anchor), and whose READ end carrick keeps. The kernel refcounts the writers,
//! and `poll`ing the beacon read end reports `POLLHUP` exactly when all writers
//! have closed.
//!
//! # 2. Peer Presence Signaling (open handshake)
//! Linux FIFO open semantics require blocking until the peer arrives:
//! - `O_RDONLY` without `O_NONBLOCK` blocks until a writer (or `O_RDWR`) opens.
//! - `O_WRONLY` without `O_NONBLOCK` blocks until a reader (or `O_RDWR`) opens.
//!
//! We provide two level-triggered presence pipes per FIFO identity `(dev, ino)`:
//! - `readers_present`: holds exactly 1 byte while reader count > 0 (including
//!   parked readers); drained when reader count drops to 0.
//! - `writers_present`: holds exactly 1 byte while writer count > 0 (including
//!   parked writers); drained when writer count drops to 0.
//!
//! A blocked opener waits with `POLLIN` on the read end of the peer's presence
//! pipe using `DispatchOutcome::WaitOnFds`. When a peer arrives, it asserts presence,
//! level-triggering readiness on all waiters. The waiters wake and re-dispatch
//! `openat` from scratch.

use std::collections::HashMap;
use std::sync::{LazyLock, Mutex};

use super::fd_table::HostFdRef;

struct PresencePipe {
    read_fd: i32,
    write_fd: i32,
    asserted: bool,
}

impl PresencePipe {
    fn new() -> Self {
        let mut fds = [-1i32; 2];
        if unsafe { libc::pipe(fds.as_mut_ptr()) } == 0 {
            unsafe {
                libc::fcntl(fds[0], libc::F_SETFD, libc::FD_CLOEXEC);
                libc::fcntl(fds[1], libc::F_SETFD, libc::FD_CLOEXEC);
                let fl0 = libc::fcntl(fds[0], libc::F_GETFL);
                if fl0 >= 0 {
                    libc::fcntl(fds[0], libc::F_SETFL, fl0 | libc::O_NONBLOCK);
                }
                let fl1 = libc::fcntl(fds[1], libc::F_GETFL);
                if fl1 >= 0 {
                    libc::fcntl(fds[1], libc::F_SETFL, fl1 | libc::O_NONBLOCK);
                }
            }
        }
        Self {
            read_fd: fds[0],
            write_fd: fds[1],
            asserted: false,
        }
    }

    fn is_valid(&self) -> bool {
        self.read_fd >= 0 && self.write_fd >= 0
    }

    fn set_asserted(&mut self, present: bool) {
        if !self.is_valid() {
            return;
        }
        if present && !self.asserted {
            let b = 1u8;
            unsafe {
                libc::write(self.write_fd, &b as *const _ as *const libc::c_void, 1);
            }
            self.asserted = true;
        } else if !present && self.asserted {
            let mut buf = [0u8; 16];
            loop {
                let n = unsafe {
                    libc::read(
                        self.read_fd,
                        buf.as_mut_ptr() as *mut libc::c_void,
                        buf.len(),
                    )
                };
                if n <= 0 {
                    break;
                }
            }
            self.asserted = false;
        }
    }
}

impl Drop for PresencePipe {
    fn drop(&mut self) {
        if self.read_fd >= 0 {
            unsafe {
                libc::close(self.read_fd);
            }
        }
        if self.write_fd >= 0 {
            unsafe {
                libc::close(self.write_fd);
            }
        }
    }
}

struct Beacon {
    /// Read end of the EOF beacon pipe (carrick-held). `poll`ing it reports POLLHUP
    /// once every writer's beacon-write fd has closed.
    eof_read_fd: i32,
    /// guest writer host-fd → that writer's beacon write fd (closed when the
    /// guest writer closes). The kernel refcounts these.
    writer_bw: HashMap<i32, i32>,
    /// Presence pipe asserted while reader count > 0 (including parked readers).
    readers_present: PresencePipe,
    /// Presence pipe asserted while writer count > 0 (including parked writers).
    writers_present: PresencePipe,
    /// Parked writer tokens for this FIFO: token_id -> ().
    parked_writers: HashMap<u64, ()>,
}

impl Beacon {
    fn new_for_identity() -> Self {
        Self {
            eof_read_fd: -1,
            writer_bw: HashMap::new(),
            readers_present: PresencePipe::new(),
            writers_present: PresencePipe::new(),
            parked_writers: HashMap::new(),
        }
    }
}

impl Drop for Beacon {
    fn drop(&mut self) {
        if self.eof_read_fd >= 0 {
            unsafe {
                libc::close(self.eof_read_fd);
            }
        }
        for (_, bw) in self.writer_bw.drain() {
            unsafe {
                libc::close(bw);
            }
        }
    }
}

#[derive(Default)]
struct State {
    /// FIFO identity → beacon.
    beacons: HashMap<(u64, u64), Beacon>,
    /// guest FIFO read host-fd → FIFO identity (to find its beacon at readiness).
    read_ends: HashMap<i32, (u64, u64)>,
    /// parked writer token_id → FIFO identity.
    parked_writers: HashMap<u64, (u64, u64)>,
    /// Next parked-writer token id; minted under this lock.
    next_parked_writer_token: u64,
}

static STATE: LazyLock<Mutex<State>> = LazyLock::new(|| Mutex::new(State::default()));

pub(crate) fn fifo_identity(host_fd: i32) -> Option<(u64, u64)> {
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    if unsafe { libc::fstat(host_fd, &mut st) } != 0 {
        return None;
    }
    Some((st.st_dev as u64, st.st_ino as u64))
}

pub(crate) fn is_writer_present(id: (u64, u64)) -> bool {
    let st = STATE.lock().unwrap_or_else(|e| e.into_inner());
    st.beacons
        .get(&id)
        .is_some_and(|b| !b.writer_bw.is_empty() || !b.parked_writers.is_empty())
}

#[cfg(test)]
pub(crate) fn is_reader_present(id: (u64, u64)) -> bool {
    let st = STATE.lock().unwrap_or_else(|e| e.into_inner());
    st.read_ends.values().any(|&r_id| r_id == id)
}

#[cfg(test)]
pub(crate) fn readers_present_read_fd(id: (u64, u64)) -> Option<i32> {
    let mut st = STATE.lock().unwrap_or_else(|e| e.into_inner());
    let beacon = st
        .beacons
        .entry(id)
        .or_insert_with(Beacon::new_for_identity);
    let fd = beacon.readers_present.read_fd;
    if fd >= 0 { Some(fd) } else { None }
}

pub(crate) fn writers_present_read_fd(id: (u64, u64)) -> Option<i32> {
    let mut st = STATE.lock().unwrap_or_else(|e| e.into_inner());
    let beacon = st
        .beacons
        .entry(id)
        .or_insert_with(Beacon::new_for_identity);
    let fd = beacon.writers_present.read_fd;
    if fd >= 0 { Some(fd) } else { None }
}

/// An owned token representing a parked FIFO opener (reader or writer) blocking in `openat`.
///
/// When the wait finishes or is interrupted/aborted, dropping this token unregisters the
/// parked opener from `fifo_beacon` (draining presence pipes and removing empty beacon nodes)
/// and closes any held host fd.
#[derive(Debug, Clone)]
pub(crate) struct ParkedOpenerToken(#[allow(dead_code)] std::sync::Arc<ParkedOpenerInner>);

#[derive(Debug)]
struct ParkedOpenerInner {
    kind: ParkedOpenerKind,
}

#[derive(Debug)]
enum ParkedOpenerKind {
    Reader { host_fd: i32, id: (u64, u64) },
    Writer { token_id: u64, id: (u64, u64) },
}

impl ParkedOpenerToken {
    /// Create a parked reader token holding an open nonblocking host read fd.
    /// Asserts `readers_present` in the FIFO's beacon.
    pub(crate) fn new_reader(host_fd: i32, id: (u64, u64)) -> Self {
        let mut st = STATE.lock().unwrap_or_else(|e| e.into_inner());
        let State {
            beacons, read_ends, ..
        } = &mut *st;
        read_ends.insert(host_fd, id);
        let beacon = beacons.entry(id).or_insert_with(Beacon::new_for_identity);
        beacon.readers_present.set_asserted(true);
        Self(std::sync::Arc::new(ParkedOpenerInner {
            kind: ParkedOpenerKind::Reader { host_fd, id },
        }))
    }

    /// Create a parked writer token waiting for a reader. Asserts `writers_present`
    /// in the FIFO's beacon, and returns the `readers_present` pipe read fd to poll on.
    pub(crate) fn new_writer(id: (u64, u64)) -> Option<(i32, Self)> {
        let mut st = STATE.lock().unwrap_or_else(|e| e.into_inner());
        let State {
            beacons,
            parked_writers,
            next_parked_writer_token,
            ..
        } = &mut *st;
        // Token ids are minted under the same lock that owns the parked-writer
        // tables, so the counter is part of `State` rather than a second
        // process-global.
        let token_id = *next_parked_writer_token;
        *next_parked_writer_token += 1;
        let beacon = beacons.entry(id).or_insert_with(Beacon::new_for_identity);
        let readers_present_read_fd = beacon.readers_present.read_fd;
        if readers_present_read_fd < 0 {
            return None;
        }
        parked_writers.insert(token_id, id);
        beacon.parked_writers.insert(token_id, ());
        beacon.writers_present.set_asserted(true);
        Some((
            readers_present_read_fd,
            Self(std::sync::Arc::new(ParkedOpenerInner {
                kind: ParkedOpenerKind::Writer { token_id, id },
            })),
        ))
    }
}

impl Drop for ParkedOpenerInner {
    fn drop(&mut self) {
        match self.kind {
            ParkedOpenerKind::Reader { host_fd, id } => {
                let mut st = STATE.lock().unwrap_or_else(|e| e.into_inner());
                st.read_ends.remove(&host_fd);
                let has_readers = st.read_ends.values().any(|&r_id| r_id == id);
                let has_writers = st
                    .beacons
                    .get(&id)
                    .is_some_and(|b| !b.writer_bw.is_empty() || !b.parked_writers.is_empty());

                if let Some(b) = st.beacons.get_mut(&id) {
                    b.readers_present.set_asserted(has_readers);
                    b.writers_present.set_asserted(has_writers);
                }

                if !has_readers && !has_writers {
                    st.beacons.remove(&id);
                }
                drop(st);
                unsafe {
                    libc::close(host_fd);
                }
            }
            ParkedOpenerKind::Writer { token_id, id } => {
                let mut st = STATE.lock().unwrap_or_else(|e| e.into_inner());
                st.parked_writers.remove(&token_id);
                if let Some(b) = st.beacons.get_mut(&id) {
                    b.parked_writers.remove(&token_id);
                }
                let has_readers = st.read_ends.values().any(|&r_id| r_id == id);
                let has_writers = st
                    .beacons
                    .get(&id)
                    .is_some_and(|b| !b.writer_bw.is_empty() || !b.parked_writers.is_empty());

                if let Some(b) = st.beacons.get_mut(&id) {
                    b.readers_present.set_asserted(has_readers);
                    b.writers_present.set_asserted(has_writers);
                }

                if !has_readers && !has_writers {
                    st.beacons.remove(&id);
                }
            }
        }
    }
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
    let State {
        beacons, read_ends, ..
    } = &mut *st;

    let beacon = beacons.entry(id).or_insert_with(Beacon::new_for_identity);

    if has_write {
        // Give this writer a beacon write fd. Create the beacon pipe on the first
        // writer; otherwise dup an existing write end so the kernel refcount
        // tracks every concurrent writer. carrick keeps NO standalone write
        // anchor, so the read end hits POLLHUP exactly when all writers close.
        let existing_writer = beacon.writer_bw.values().next().copied();
        let bw = if let Some(existing) = existing_writer {
            unsafe { libc::dup(existing) }
        } else {
            let mut fds = [0i32; 2];
            if unsafe { libc::pipe(fds.as_mut_ptr()) } != 0 {
                -1
            } else {
                unsafe {
                    libc::fcntl(fds[0], libc::F_SETFD, libc::FD_CLOEXEC);
                    libc::fcntl(fds[1], libc::F_SETFD, libc::FD_CLOEXEC);
                }
                if beacon.eof_read_fd >= 0 {
                    debug_assert!(beacon.writer_bw.is_empty());
                    unsafe { libc::close(beacon.eof_read_fd) };
                }
                beacon.eof_read_fd = fds[0];
                fds[1]
            }
        };
        if bw >= 0 {
            unsafe {
                libc::fcntl(bw, libc::F_SETFD, libc::FD_CLOEXEC);
            }
            beacon.writer_bw.insert(host_fd, bw);
        }
        beacon.writers_present.set_asserted(true);
    }
    if has_read {
        read_ends.insert(host_fd, id);
        beacon.readers_present.set_asserted(true);
    }
}

/// Unregister a closing FIFO host fd while its owner is still alive. Returns
/// `true` if it was a writer (the caller should then wake epoll/poll so
/// read-ends re-check the beacon — the close may have dropped the writer count
/// to zero). Borrowing the owner makes raw-fd reuse between unregister and
/// close impossible.
pub(crate) fn register_close(host_fd: &HostFdRef) -> bool {
    let host_fd = host_fd.raw();
    let mut st = STATE.lock().unwrap_or_else(|e| e.into_inner());
    let read_id = st.read_ends.remove(&host_fd);
    let mut writer_of = None;
    for (id, b) in st.beacons.iter_mut() {
        if let Some(bw) = b.writer_bw.remove(&host_fd) {
            unsafe { libc::close(bw) };
            writer_of = Some(*id);
            break;
        }
    }
    let was_writer = writer_of.is_some();

    let mut ids_to_check = Vec::with_capacity(2);
    if let Some(r) = read_id {
        ids_to_check.push(r);
    }
    if let Some(w) = writer_of {
        if !ids_to_check.contains(&w) {
            ids_to_check.push(w);
        }
    }

    for id in ids_to_check {
        let has_readers = st.read_ends.values().any(|&r_id| r_id == id);
        let has_writers = st
            .beacons
            .get(&id)
            .is_some_and(|b| !b.writer_bw.is_empty() || !b.parked_writers.is_empty());

        if let Some(b) = st.beacons.get_mut(&id) {
            b.readers_present.set_asserted(has_readers);
            b.writers_present.set_asserted(has_writers);
        }

        if !has_readers && !has_writers {
            st.beacons.remove(&id);
        }
    }

    was_writer
}

#[cfg(test)]
pub(crate) fn has_beacon_for_fd(host_fd: i32) -> bool {
    let st = STATE.lock().unwrap_or_else(|e| e.into_inner());
    st.read_ends.contains_key(&host_fd)
        || st
            .beacons
            .values()
            .any(|b| b.writer_bw.contains_key(&host_fd))
}

#[cfg(test)]
pub(crate) fn has_beacon_for_identity(id: (u64, u64)) -> bool {
    let st = STATE.lock().unwrap_or_else(|e| e.into_inner());
    st.beacons.contains_key(&id)
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
    if b.eof_read_fd < 0 {
        return false;
    }
    let mut pfd = libc::pollfd {
        fd: b.eof_read_fd,
        events: libc::POLLIN,
        revents: 0,
    };
    let rc = unsafe { libc::poll(&mut pfd, 1, 0) };
    rc > 0 && pfd.revents & libc::POLLHUP != 0
}

#[cfg(test)]
mod tests {
    use super::*;

    fn is_readable(fd: i32) -> bool {
        let mut pfd = libc::pollfd {
            fd,
            events: libc::POLLIN,
            revents: 0,
        };
        let rc = unsafe { libc::poll(&mut pfd, 1, 0) };
        rc > 0 && pfd.revents & libc::POLLIN != 0
    }

    #[test]
    fn register_close_requires_a_live_host_fd_owner() {
        let mut fds = [0i32; 2];
        assert_eq!(unsafe { libc::pipe(fds.as_mut_ptr()) }, 0);
        let writer = crate::dispatch::fd_table::HostFdRef::new(fds[1]);

        assert!(!register_close(&writer));

        unsafe { libc::close(fds[0]) };
    }

    #[test]
    fn writer_reopen_rearms_a_live_reader_beacon() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("reopen-fifo");
        let c_path =
            std::ffi::CString::new(path.to_str().expect("utf-8 path")).expect("cstring path");
        assert_eq!(unsafe { libc::mkfifo(c_path.as_ptr(), 0o600) }, 0);

        let read_fd = unsafe { libc::open(c_path.as_ptr(), libc::O_RDONLY | libc::O_NONBLOCK) };
        assert!(read_fd >= 0, "open read end");
        let read_fd = HostFdRef::new(read_fd);
        register_open(read_fd.raw(), 0);

        let first_writer =
            unsafe { libc::open(c_path.as_ptr(), libc::O_WRONLY | libc::O_NONBLOCK) };
        assert!(first_writer >= 0, "open first writer");
        let first_writer = HostFdRef::new(first_writer);
        register_open(first_writer.raw(), 1);
        assert!(
            !read_end_at_eof(read_fd.raw()),
            "live writer keeps beacon armed"
        );

        assert!(register_close(&first_writer));
        drop(first_writer);
        assert!(
            read_end_at_eof(read_fd.raw()),
            "last writer close reports EOF"
        );

        let second_writer =
            unsafe { libc::open(c_path.as_ptr(), libc::O_WRONLY | libc::O_NONBLOCK) };
        assert!(second_writer >= 0, "open replacement writer");
        let second_writer = HostFdRef::new(second_writer);
        register_open(second_writer.raw(), 1);
        assert!(
            !read_end_at_eof(read_fd.raw()),
            "replacement writer must re-arm the retained reader beacon"
        );

        assert!(register_close(&second_writer));
        drop(second_writer);
        assert!(
            read_end_at_eof(read_fd.raw()),
            "replacement writer close must restore EOF"
        );
        assert!(!register_close(&read_fd));
        let read_raw = read_fd.raw();
        drop(read_fd);
        assert!(
            !has_beacon_for_fd(read_raw),
            "last reader close must remove the exhausted beacon"
        );
    }

    #[test]
    fn readers_present_becomes_readable_and_unreadable_on_close() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("readers-present-fifo");
        let c_path =
            std::ffi::CString::new(path.to_str().expect("utf-8 path")).expect("cstring path");
        assert_eq!(unsafe { libc::mkfifo(c_path.as_ptr(), 0o600) }, 0);

        let r1 = unsafe { libc::open(c_path.as_ptr(), libc::O_RDONLY | libc::O_NONBLOCK) };
        assert!(r1 >= 0, "open reader 1");
        let r1 = HostFdRef::new(r1);
        let id = fifo_identity(r1.raw()).expect("identity");
        let r_pipe = readers_present_read_fd(id).expect("readers_present pipe");
        assert!(!is_readable(r_pipe), "no reader yet");

        register_open(r1.raw(), 0);
        assert!(is_readable(r_pipe), "first reader asserts presence");

        let r2 = unsafe { libc::open(c_path.as_ptr(), libc::O_RDONLY | libc::O_NONBLOCK) };
        assert!(r2 >= 0, "open reader 2");
        let r2 = HostFdRef::new(r2);
        register_open(r2.raw(), 0);
        assert!(is_readable(r_pipe), "second reader keeps presence asserted");

        // Keep a writer registered so the beacon node is not destroyed when readers close
        let (_, parked_writer) = ParkedOpenerToken::new_writer(id).expect("parked writer");

        assert!(!register_close(&r1));
        drop(r1);
        assert!(
            is_readable(r_pipe),
            "one reader remaining keeps presence asserted"
        );

        assert!(!register_close(&r2));
        drop(r2);
        assert!(!is_readable(r_pipe), "last reader closed drains presence");

        drop(parked_writer);
    }

    #[test]
    fn writers_present_becomes_readable_and_unreadable_on_close() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("writers-present-fifo");
        let c_path =
            std::ffi::CString::new(path.to_str().expect("utf-8 path")).expect("cstring path");
        assert_eq!(unsafe { libc::mkfifo(c_path.as_ptr(), 0o600) }, 0);

        let reader = unsafe { libc::open(c_path.as_ptr(), libc::O_RDONLY | libc::O_NONBLOCK) };
        assert!(reader >= 0, "open reader");
        let reader = HostFdRef::new(reader);
        let id = fifo_identity(reader.raw()).expect("identity");
        register_open(reader.raw(), 0);

        let w1 = unsafe { libc::open(c_path.as_ptr(), libc::O_WRONLY | libc::O_NONBLOCK) };
        assert!(w1 >= 0, "open writer 1");
        let w1 = HostFdRef::new(w1);
        let w_pipe = writers_present_read_fd(id).expect("writers_present pipe");
        assert!(!is_readable(w_pipe), "no writer yet");

        register_open(w1.raw(), 1);
        assert!(is_readable(w_pipe), "first writer asserts presence");

        let w2 = unsafe { libc::open(c_path.as_ptr(), libc::O_WRONLY | libc::O_NONBLOCK) };
        assert!(w2 >= 0, "open writer 2");
        let w2 = HostFdRef::new(w2);
        register_open(w2.raw(), 1);
        assert!(is_readable(w_pipe), "second writer keeps presence asserted");

        assert!(register_close(&w1));
        drop(w1);
        assert!(
            is_readable(w_pipe),
            "one writer remaining keeps presence asserted"
        );

        assert!(register_close(&w2));
        drop(w2);
        assert!(!is_readable(w_pipe), "last writer closed drains presence");

        assert!(!register_close(&reader));
        let reader_raw = reader.raw();
        drop(reader);
        assert!(!has_beacon_for_fd(reader_raw));
    }

    #[test]
    fn rdwr_registration_asserts_both_presence_pipes() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("rdwr-present-fifo");
        let c_path =
            std::ffi::CString::new(path.to_str().expect("utf-8 path")).expect("cstring path");
        assert_eq!(unsafe { libc::mkfifo(c_path.as_ptr(), 0o600) }, 0);

        let rw = unsafe { libc::open(c_path.as_ptr(), libc::O_RDWR) };
        assert!(rw >= 0, "open rdwr");
        let rw = HostFdRef::new(rw);
        let id = fifo_identity(rw.raw()).expect("identity");

        register_open(rw.raw(), 2);
        let r_pipe = readers_present_read_fd(id).expect("readers_present pipe");
        let w_pipe = writers_present_read_fd(id).expect("writers_present pipe");
        assert!(is_readable(r_pipe), "O_RDWR asserts reader presence");
        assert!(is_readable(w_pipe), "O_RDWR asserts writer presence");

        assert!(register_close(&rw));
        let rw_raw = rw.raw();
        drop(rw);
        assert!(!has_beacon_for_fd(rw_raw));
    }

    #[test]
    fn parked_reader_and_writer_cleanup_drains_presence_and_removes_beacon() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("parked-token-cleanup-fifo");
        let c_path =
            std::ffi::CString::new(path.to_str().expect("utf-8 path")).expect("cstring path");
        assert_eq!(unsafe { libc::mkfifo(c_path.as_ptr(), 0o600) }, 0);

        // 1. Parked reader cleanup test
        let read_fd = unsafe { libc::open(c_path.as_ptr(), libc::O_RDONLY | libc::O_NONBLOCK) };
        assert!(read_fd >= 0, "open reader for parking");
        let id = fifo_identity(read_fd).expect("fifo identity");

        let parked_reader = ParkedOpenerToken::new_reader(read_fd, id);
        let r_pipe = readers_present_read_fd(id).expect("readers_present pipe");
        let w_pipe = writers_present_read_fd(id).expect("writers_present pipe");

        assert!(is_readable(r_pipe), "parked reader asserts readers_present");
        assert!(!is_readable(w_pipe), "no writer present yet");
        assert!(is_reader_present(id));
        assert!(has_beacon_for_fd(read_fd));
        assert!(has_beacon_for_identity(id));

        // Dropping parked reader unregisters, drains presence pipe, closes read_fd, and frees beacon
        drop(parked_reader);
        assert!(!is_reader_present(id), "reader count dropped to 0");
        assert!(!has_beacon_for_fd(read_fd));
        assert!(
            !has_beacon_for_identity(id),
            "beacon node removed when empty"
        );
        // Verify read_fd was closed
        assert_eq!(unsafe { libc::fcntl(read_fd, libc::F_GETFD) }, -1);
        assert_eq!(
            std::io::Error::last_os_error().raw_os_error(),
            Some(libc::EBADF)
        );

        // 2. Parked writer cleanup test
        let (r_pipe, parked_writer) =
            ParkedOpenerToken::new_writer(id).expect("register parked writer");
        let w_pipe = writers_present_read_fd(id).expect("writers_present pipe");

        assert!(is_readable(w_pipe), "parked writer asserts writers_present");
        assert!(!is_readable(r_pipe), "no reader present");
        assert!(is_writer_present(id));
        assert!(has_beacon_for_identity(id));

        // Dropping parked writer unregisters, drains presence pipe, and frees beacon
        drop(parked_writer);
        assert!(!is_writer_present(id), "writer count dropped to 0");
        assert!(
            !has_beacon_for_identity(id),
            "beacon node removed when empty"
        );

        // 3. Multiple parked openers cleanup
        let r1_fd = unsafe { libc::open(c_path.as_ptr(), libc::O_RDONLY | libc::O_NONBLOCK) };
        assert!(r1_fd >= 0);
        let r2_fd = unsafe { libc::open(c_path.as_ptr(), libc::O_RDONLY | libc::O_NONBLOCK) };
        assert!(r2_fd >= 0);

        let t_r1 = ParkedOpenerToken::new_reader(r1_fd, id);
        let t_r2 = ParkedOpenerToken::new_reader(r2_fd, id);
        let r_pipe = readers_present_read_fd(id).expect("readers_present pipe");
        assert!(is_readable(r_pipe));

        drop(t_r1);
        assert!(
            is_readable(r_pipe),
            "second parked reader keeps presence asserted"
        );
        assert_eq!(unsafe { libc::fcntl(r1_fd, libc::F_GETFD) }, -1);

        drop(t_r2);
        assert!(!is_reader_present(id));
        assert!(!has_beacon_for_identity(id));
        assert_eq!(unsafe { libc::fcntl(r2_fd, libc::F_GETFD) }, -1);
    }
}
