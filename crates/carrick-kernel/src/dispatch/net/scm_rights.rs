//! In-flight `SCM_RIGHTS`: guest file descriptions crossing a guest socket.
//!
//! # Why this exists
//!
//! Guest AF_UNIX sockets are host-backed, so passing an fd rides the real
//! Darwin `sendmsg(SCM_RIGHTS)`. Sending the raw host fd of a description
//! was wrong twice over. Everything carrick owns itself — guest pipes since
//! `12b7300a1`, eventfds, memfds, epoll sets, … — has no host fd to dup into
//! the peer, so the send answered EBADF (CPython's multiprocessing forkserver
//! passes `os.pipe()` ends on every `ensure_running`, and that EBADF killed
//! the forkserver and every test that used it). And a host-backed
//! description (a `--fs host` file, /dev/shm, /tmp) that did cross arrived
//! as a NEW description built from the host fd alone: status flags 0, path
//! `scm:[received]`, and so `mmap(PROT_WRITE, MAP_SHARED)` of a passed
//! `multiprocessing.heap.Arena` file answered EACCES.
//!
//! Linux passes ANY fd, and the receiver gets a new fd sharing the SAME open
//! file description (like `dup`): status flags, offset, path, writability.
//! Both ends of a guest AF_UNIX connection live in this carrier, so the
//! description itself can cross: the sender parks the `Arc<FileDescription>`
//! here and sends a **placeholder** host fd whose kernel identity names the
//! parked entry; the receiver looks the placeholder up and installs the
//! parked description instead of wrapping the placeholder. Every guest fd
//! goes this way; wrapping a raw received host fd is left for fds that a
//! non-guest host peer sent.
//!
//! # The placeholder
//!
//! A fresh host `pipe()`. Its READ end travels in the host message (Darwin
//! dups it into the receiver like any passed fd); its WRITE end stays here.
//! The key is the pipe's `(st_dev, st_ino)`: XNU stats a pipe by object
//! identity, so every dup of the read end — the one in flight, the one the
//! receiver gets — reports the same pair. Holding the write end keeps the
//! kernel object alive for as long as the entry exists, so a live key can
//! never be reused by another pipe.
//!
//! # Garbage collection
//!
//! The parked description holds one logical fd reference (like an in-flight fd
//! on Linux). If the message is never received and the socket closes, read ends
//! die and the retained writer reports `POLLERR`/`POLLHUP` from `poll(2)`: that
//! signals nothing can claim the entry, releasing its reference. `gc` runs on
//! every park/claim and socket close to collect orphaned entries.
//!
//! # Scope
//!
//! This registry is CARRIER-scoped on purpose: the placeholder keys are host
//! kernel identities, unique per carrier, and a message may cross guest
//! process boundaries inside one carrier. It is not per-Linux-process state.

use std::collections::HashMap;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::sync::{Arc, LazyLock, Mutex};

use crate::kernel::FileDescription;

/// A description in flight, keyed by its placeholder pipe's identity.
struct Parked {
    description: Arc<FileDescription>,
    /// The placeholder's write end; closing it is what lets the read ends
    /// finally EOF, and its `POLLERR` is the "no reader left" signal for GC.
    writer: OwnedFd,
}

/// `(st_dev, st_ino, st_ctime)` of a placeholder pipe from `fstat` of either end.
///
/// Nanosecond creation timestamp keeps key identity unambiguous across allocations.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub(super) struct PlaceholderKey {
    dev: u64,
    ino: u64,
    ctime: (i64, i64),
}

impl PlaceholderKey {
    pub(super) fn from_stat(st: &libc::stat) -> Self {
        Self {
            dev: st.st_dev as u64,
            ino: st.st_ino,
            ctime: (st.st_ctime as i64, carrick_portable::stat_ctime_nsec(st)),
        }
    }

    fn of_host_fd(host_fd: i32) -> Option<Self> {
        let mut st: libc::stat = unsafe { std::mem::zeroed() };
        (unsafe { libc::fstat(host_fd, &mut st) } == 0).then(|| Self::from_stat(&st))
    }
}

static VAULT: LazyLock<Mutex<HashMap<PlaceholderKey, Parked>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

fn lock() -> std::sync::MutexGuard<'static, HashMap<PlaceholderKey, Parked>> {
    VAULT
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// Park `description` for an `SCM_RIGHTS` send and return the placeholder
/// host fd (the pipe's read end) to put in the host control message. The
/// caller owns that fd and closes it once the host `sendmsg` has either
/// delivered it or failed (see [`InFlightRights`]).
fn park(description: Arc<FileDescription>) -> Option<(PlaceholderKey, OwnedFd)> {
    let mut fds = [-1i32; 2];
    if unsafe { libc::pipe(fds.as_mut_ptr()) } != 0 {
        return None;
    }
    // SAFETY: pipe() just created both descriptors and nothing else owns them.
    let (reader, writer) = unsafe { (OwnedFd::from_raw_fd(fds[0]), OwnedFd::from_raw_fd(fds[1])) };
    let key = PlaceholderKey::of_host_fd(reader.as_raw_fd())?;
    description.retain_fd_ref();
    let mut vault = lock();
    collect(&mut vault);
    let prev = vault.insert(
        key,
        Parked {
            description,
            writer,
        },
    );
    assert!(prev.is_none(), "vault key collision: entry already exists");
    Some((key, reader))
}

/// Claim the description parked under `key`, if `key` names a placeholder.
/// The returned description still carries the vault's fd reference; the
/// caller must either install it (which takes its own reference) and then
/// `release_fd_ref`, or release it outright.
pub(super) fn claim(key: PlaceholderKey) -> Option<Arc<FileDescription>> {
    let mut vault = lock();
    let parked = vault.remove(&key);
    collect(&mut vault);
    parked.map(|p| p.description)
}

/// Release every parked description whose placeholder can no longer be
/// received (all read-end references are gone).
pub(super) fn gc() {
    let mut vault = lock();
    collect(&mut vault);
}

fn collect(vault: &mut HashMap<PlaceholderKey, Parked>) {
    if vault.is_empty() {
        return;
    }
    let mut dead = Vec::new();
    for (key, parked) in vault.iter() {
        let mut pfd = libc::pollfd {
            fd: parked.writer.as_raw_fd(),
            events: libc::POLLOUT,
            revents: 0,
        };
        let rc = unsafe { libc::poll(&mut pfd, 1, 0) };
        if rc > 0 && pfd.revents & (libc::POLLERR | libc::POLLHUP | libc::POLLNVAL) != 0 {
            dead.push(*key);
        }
    }
    for key in dead {
        if let Some(parked) = vault.remove(&key) {
            parked.description.release_fd_ref();
        }
    }
}

/// The host fds for one `SCM_RIGHTS` send: real host fds for host-backed
/// descriptions, placeholder read ends for parked carrick-owned ones. Drop
/// closes the placeholders (the delivered message holds its own dups);
/// [`InFlightRights::abort`] additionally un-parks their descriptions when
/// the send never happened.
pub(super) struct InFlightRights {
    placeholders: Vec<(PlaceholderKey, OwnedFd)>,
    /// The placeholder read ends, in send order: what the host message carries.
    host_fds: Vec<i32>,
}

impl InFlightRights {
    pub(super) fn new() -> Self {
        Self {
            placeholders: Vec::new(),
            host_fds: Vec::new(),
        }
    }

    /// Park a description; `false` if the host refused a placeholder pipe
    /// (EMFILE/ENFILE), in which case the whole send fails.
    pub(super) fn push_parked(&mut self, description: Arc<FileDescription>) -> bool {
        let Some((key, reader)) = park(description) else {
            return false;
        };
        self.host_fds.push(reader.as_raw_fd());
        self.placeholders.push((key, reader));
        true
    }

    /// The host fds to put in the `SCM_RIGHTS` cmsg, in send order.
    pub(super) fn host_fds(&self) -> &[i32] {
        &self.host_fds
    }

    /// The send failed: nothing will ever claim the placeholders, so return
    /// the parked references now rather than waiting for GC.
    pub(super) fn abort(mut self) {
        for (key, reader) in self.placeholders.drain(..) {
            drop(reader);
            if let Some(description) = claim(key) {
                description.release_fd_ref();
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dispatch::fd_table::{EventFdState, OpenDescription, OpenDescriptionBase, OpenFile};
    use parking_lot::RwLock;

    fn eventfd_description() -> Arc<FileDescription> {
        OpenFile::from_open_description_with_status_flags(
            Arc::new(RwLock::new(OpenDescription::EventFd {
                state: Arc::new(EventFdState::new(0)),

                base: OpenDescriptionBase::new(0),
            })),
            crate::linux_abi::LINUX_O_RDWR,
            0,
        )
        .description()
    }

    #[test]
    fn red_until_step3_m4_rights_create_placeholder_per_message() {
        use crate::kernel::ids::ObjectIdRegistry;
        use crate::kernel::{FileSlotNumber, FileTable};
        for messages in [1, 8, 64] {
            let ids = ObjectIdRegistry::new();
            let sender = FileTable::new(ids.file_table_id().unwrap());
            let receiver = FileTable::new(ids.file_table_id().unwrap());
            let mut placeholders = 0;
            for _ in 0..messages {
                let original = eventfd_description();
                original.retain_fd_ref();
                sender.install(
                    FileSlotNumber::for_open_fd(3).unwrap(),
                    Arc::clone(&original),
                    false,
                );
                let (key, placeholder) = park(Arc::clone(&original)).unwrap();
                placeholders +=
                    usize::from(PlaceholderKey::of_host_fd(placeholder.as_raw_fd()).is_some());
                let old = sender.write_open_files().remove(&3).unwrap();
                old.description.release_fd_ref();
                let replacement = eventfd_description();
                replacement.retain_fd_ref();
                sender.install(
                    FileSlotNumber::for_open_fd(3).unwrap(),
                    Arc::clone(&replacement),
                    false,
                );
                let received = claim(key).unwrap();
                assert!(Arc::ptr_eq(&received, &original));
                assert!(!Arc::ptr_eq(&received, &replacement));
                received.retain_fd_ref();
                receiver.install(
                    FileSlotNumber::for_open_fd(3).unwrap(),
                    Arc::clone(&received),
                    true,
                );
                received.release_fd_ref();
                assert_eq!(original.fd_ref_count(), 1);
                let installed = receiver.write_open_files().remove(&3).unwrap();
                assert_ne!(installed.fd_flags, 0);
                installed.description.release_fd_ref();
                assert_eq!(original.fd_ref_count(), 0);
                sender
                    .write_open_files()
                    .remove(&3)
                    .unwrap()
                    .description
                    .release_fd_ref();
                assert_eq!(replacement.fd_ref_count(), 0);
                drop(placeholder);
                assert!(claim(key).is_none());
            }
            assert_eq!(placeholders, messages);
            let result = if placeholders == 0 {
                Ok(())
            } else {
                Err("guest rights transport creates host placeholder pipes")
            };
            assert_eq!(
                result.expect_err("flips at M4 cutover"),
                "guest rights transport creates host placeholder pipes"
            );
        }
    }

    #[test]
    fn red_until_step3_m4_cyclic_rights_survive_last_external_close() {
        use crate::dispatch::fd_table::HostFdRef;
        use crate::kernel::ids::ObjectIdRegistry;
        use crate::kernel::{FileSlotNumber, FileTable};
        use std::collections::VecDeque;
        fn send_right(socket: i32, right: i32) {
            let mut byte = 1u8;
            let mut iov = libc::iovec {
                iov_base: (&mut byte as *mut u8).cast(),
                iov_len: 1,
            };
            let space = unsafe { libc::CMSG_SPACE(core::mem::size_of::<i32>() as u32) } as usize;
            let mut control = vec![0usize; space.div_ceil(core::mem::size_of::<usize>())];
            let mut msg: libc::msghdr = unsafe { core::mem::zeroed() };
            msg.msg_iov = &mut iov;
            msg.msg_iovlen = 1;
            msg.msg_control = control.as_mut_ptr().cast();
            msg.msg_controllen = space as _;
            // SAFETY: aligned control backing covers CMSG_SPACE for one fd;
            // the byte, iovec and control remain live through synchronous send.
            unsafe {
                let header = libc::CMSG_FIRSTHDR(&msg);
                assert!(!header.is_null());
                (*header).cmsg_level = libc::SOL_SOCKET;
                (*header).cmsg_type = libc::SCM_RIGHTS;
                (*header).cmsg_len = libc::CMSG_LEN(core::mem::size_of::<i32>() as u32) as _;
                core::ptr::write_unaligned(libc::CMSG_DATA(header).cast::<i32>(), right);
                assert_eq!(libc::sendmsg(socket, &msg, 0), 1);
            }
        }
        for cycles in [1, 8, 64] {
            let ids = ObjectIdRegistry::new();
            let first = FileTable::new(ids.file_table_id().unwrap());
            let second = FileTable::new(ids.file_table_id().unwrap());
            let mut retained = 0;
            for _ in 0..cycles {
                let mut pair = [-1; 2];
                // SAFETY: pair is writable for the two newly owned descriptors.
                assert_eq!(
                    unsafe {
                        libc::socketpair(libc::AF_UNIX, libc::SOCK_STREAM, 0, pair.as_mut_ptr())
                    },
                    0
                );
                let descriptions: Vec<_> = pair
                    .iter()
                    .map(|raw| {
                        let mut base = OpenDescriptionBase::new(crate::linux_abi::LINUX_O_RDWR);
                        base.set_connected(true);
                        crate::dispatch::fd_table::kernel_file_description(
                            Arc::new(RwLock::new(OpenDescription::HostSocket {
                                base,
                                host_fd: HostFdRef::new(*raw),
                                family: crate::linux_abi::LINUX_AF_UNIX,
                                type_: crate::linux_abi::LINUX_SOCK_STREAM,
                                protocol: 0,
                                mcast_memberships: Vec::new(),
                                synthetic_recv: VecDeque::new(),
                            })),
                            crate::linux_abi::LINUX_O_RDWR,
                        )
                    })
                    .collect();
                for (table, description) in
                    [(&first, &descriptions[0]), (&second, &descriptions[1])]
                {
                    description.retain_fd_ref();
                    table.install(
                        FileSlotNumber::for_open_fd(3).unwrap(),
                        Arc::clone(description),
                        false,
                    );
                }
                let (left_key, left_placeholder) = park(Arc::clone(&descriptions[0])).unwrap();
                let (right_key, right_placeholder) = park(Arc::clone(&descriptions[1])).unwrap();
                // Each queued placeholder retains the description of its own
                // receiving socket: two genuine host-message rights cycles.
                send_right(pair[0], right_placeholder.as_raw_fd());
                send_right(pair[1], left_placeholder.as_raw_fd());
                drop(left_placeholder);
                drop(right_placeholder);
                for table in [&first, &second] {
                    table
                        .write_open_files()
                        .remove(&3)
                        .unwrap()
                        .description
                        .release_fd_ref();
                }
                gc();
                {
                    let vault = lock();
                    retained += usize::from(vault.contains_key(&left_key));
                    retained += usize::from(vault.contains_key(&right_key));
                }
                assert_eq!(descriptions[0].fd_ref_count(), 1);
                assert_eq!(descriptions[1].fd_ref_count(), 1);
                // Bounded fixture cleanup, not production cycle collection.
                let left = claim(left_key).unwrap();
                let right = claim(right_key).unwrap();
                left.release_fd_ref();
                right.release_fd_ref();
                assert_eq!(descriptions[0].fd_ref_count(), 0);
                assert_eq!(descriptions[1].fd_ref_count(), 0);
            }
            assert_eq!(retained, cycles * 2);
            let result = if retained == 0 {
                Ok(())
            } else {
                Err("SCM vault cannot collect queued socket-description cycles")
            };
            assert_eq!(
                result.expect_err("flips at M4 cutover"),
                "SCM vault cannot collect queued socket-description cycles"
            );
        }
    }

    #[test]
    fn a_dup_of_the_placeholder_claims_the_parked_description() {
        let description = eventfd_description();
        let (key, reader) = park(Arc::clone(&description)).expect("placeholder pipe");
        assert_eq!(
            description.fd_ref_count(),
            1,
            "parking holds one fd reference"
        );
        // What the receiver sees is a kernel dup of the read end.
        let dup = unsafe { libc::dup(reader.as_raw_fd()) };
        assert!(dup >= 0);
        drop(reader);
        let seen = PlaceholderKey::of_host_fd(dup).expect("fstat");
        assert_eq!(seen, key);
        let claimed = claim(seen).expect("parked entry");
        assert!(Arc::ptr_eq(&claimed, &description));
        assert!(claim(seen).is_none(), "claim is one-shot");
        unsafe { libc::close(dup) };
        claimed.release_fd_ref();
        assert_eq!(description.fd_ref_count(), 0);
    }

    #[test]
    fn gc_releases_a_placeholder_nobody_can_receive_any_more() {
        let description = eventfd_description();
        let (key, reader) = park(Arc::clone(&description)).expect("placeholder pipe");
        gc();
        assert_eq!(
            description.fd_ref_count(),
            1,
            "a live read end keeps the entry"
        );
        drop(reader);
        gc();
        assert_eq!(
            description.fd_ref_count(),
            0,
            "the last read end gone must release the parked reference"
        );
        assert!(claim(key).is_none());
    }

    #[test]
    fn abort_returns_the_references_of_an_unsent_batch() {
        let description = eventfd_description();
        let mut batch = InFlightRights::new();
        assert!(batch.push_parked(Arc::clone(&description)));
        assert!(batch.push_parked(Arc::clone(&description)));
        assert_eq!(batch.host_fds().len(), 2);
        assert_eq!(description.fd_ref_count(), 2);
        batch.abort();
        assert_eq!(description.fd_ref_count(), 0);
        let mut batch = InFlightRights::new();
        assert!(batch.push_parked(Arc::clone(&description)));
        assert_eq!(description.fd_ref_count(), 1);
        batch.abort();
        assert_eq!(description.fd_ref_count(), 0);
    }

    #[test]
    fn stale_placeholder_key_cannot_claim_recycled_pipe_allocation() {
        let original = eventfd_description();
        let (stale_key, reader) = park(Arc::clone(&original)).unwrap();
        let claimed = claim(stale_key).unwrap();
        claimed.release_fd_ref();
        drop(reader);

        // Allocate placeholder pipes until the kernel reuses the stale inode.
        // The key must be unambiguous across pipe allocations so that stale_key
        // can never claim a new entry parked under a recycled kernel inode.
        let mut parked_entries = Vec::new();
        for _ in 0..100 {
            let next_desc = eventfd_description();
            let (next_key, next_reader) = park(Arc::clone(&next_desc)).unwrap();
            assert!(
                claim(stale_key).is_none(),
                "stale key must not claim a newly parked entry even if (dev, ino) was recycled"
            );
            parked_entries.push((next_key, next_reader, next_desc));
        }
        for (k, _r, d) in parked_entries {
            let c = claim(k).unwrap();
            assert!(Arc::ptr_eq(&c, &d));
            c.release_fd_ref();
        }
    }

    #[test]
    fn concurrent_scm_rights_do_not_interfere() {
        let barrier = Arc::new(std::sync::Barrier::new(8));
        let mut handles = Vec::new();
        for i in 0..8 {
            let b = Arc::clone(&barrier);
            handles.push(std::thread::spawn(move || {
                b.wait();
                for _ in 0..10 {
                    match i % 3 {
                        0 => red_until_step3_m4_rights_create_placeholder_per_message(),
                        1 => red_until_step3_m4_cyclic_rights_survive_last_external_close(),
                        _ => gc_releases_a_placeholder_nobody_can_receive_any_more(),
                    }
                }
            }));
        }
        for h in handles {
            h.join().unwrap();
        }
    }
}
