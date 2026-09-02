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
//! The parked description holds one logical fd reference, exactly like an
//! in-flight fd on Linux (a passed pipe writer keeps the pipe open until it
//! is received and closed). If the message is never received — the
//! receiving socket is closed with the message still queued — every read-end
//! reference dies inside the kernel and the retained write end reports
//! `POLLERR`/`POLLHUP` from `poll(2)`: that is the signal that nothing can
//! ever claim the entry, and its reference is released. `gc` runs on every
//! park/claim and on socket close, so an orphaned entry is collected at the
//! next rights operation or socket close in the carrier.
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

/// `(st_dev, st_ino)` of a placeholder pipe, as reported by `fstat` of either
/// end (or any dup of one).
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub(super) struct PlaceholderKey {
    dev: u64,
    ino: u64,
}

impl PlaceholderKey {
    pub(super) fn from_stat(st: &libc::stat) -> Self {
        Self {
            dev: st.st_dev as u64,
            ino: st.st_ino,
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
    vault.insert(
        key,
        Parked {
            description,
            writer,
        },
    );
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
                semaphore: false,
                base: OpenDescriptionBase::new(0),
            })),
            crate::linux_abi::LINUX_O_RDWR,
            0,
        )
        .description()
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
}
