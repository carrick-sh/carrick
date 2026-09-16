//! fanotify(7) notification groups, synthesized on carrick's syscall seam.
//!
//! # Why this is not a kqueue/FSEvents backend
//!
//! macOS can observe host vnode changes (`EVFILT_VNODE`, FSEvents), but a host
//! vnode change is the WRONG observable: it cannot say which guest process
//! acted, which mark's mask applies, whether the object was the marked inode or
//! a child of a marked directory, or whether an ignore mask suppresses the
//! report. All four are load-bearing in `fanotify(7)`. Carrick already
//! intercepts every guest fd syscall, so the guest's INTENT is available
//! directly at the dispatch seam — the same seam
//! [`crate::inotify::InotifyRegistry`] already uses to synthesize precise
//! inotify events. This module extends that seam rather than adding a second,
//! coarser observer that would have to be reconciled with it.
//!
//! # Scope, stated honestly
//!
//! Only NOTIFICATION events are implemented, and only for groups that do NOT
//! identify objects by file handle. That is not an arbitrary subset — it is
//! exactly the set `fanotify_mark(2)` says is legal without `FAN_REPORT_FID`:
//!
//! * **Implemented:** `FAN_ACCESS`, `FAN_MODIFY`, `FAN_CLOSE_WRITE`,
//!   `FAN_CLOSE_NOWRITE`, `FAN_OPEN`, `FAN_OPEN_EXEC`, with the
//!   `FAN_EVENT_ON_CHILD` / `FAN_ONDIR` modifiers, inode / mount / filesystem
//!   marks, per-mark ignore masks, and `FAN_REPORT_TID`.
//! * **Refused with `EINVAL` at `fanotify_mark`, matching Linux:** permission
//!   events (`FAN_OPEN_PERM`, `FAN_ACCESS_PERM`, `FAN_OPEN_EXEC_PERM`), which
//!   would need a verdict channel carrick does not have; and the dirent /
//!   inode-identity events (`FAN_CREATE`, `FAN_DELETE`, `FAN_MOVED_*`,
//!   `FAN_ATTRIB`, `FAN_DELETE_SELF`, `FAN_MOVE_SELF`, `FAN_RENAME`,
//!   `FAN_FS_ERROR`), which need `FAN_REPORT_FID` — refused at
//!   `fanotify_init` because carrick has no `name_to_handle_at` backend.
//!
//! All three `FAN_CLASS_*` values are accepted at `fanotify_init`. A kernel
//! without `CONFIG_FANOTIFY_ACCESS_PERMISSIONS` behaves the same way: the init
//! succeeds and only a mark requesting a permission event fails. Rejecting the
//! class at init instead turns LTP's intended `TCONF` probe into a hard
//! `TBROK`, because that probe wraps the init in `SAFE_FANOTIFY_INIT`.
//!
//! # Where the marks live
//!
//! Marks are keyed by resolved guest path in a registry shared by `Arc` across
//! guest `fork` — deliberately NOT deep-copied the way the inotify registry is.
//! On Linux a mark lives on the inode and a group outlives any single fd
//! referencing it, so a forked child that closes its inherited fanotify fd must
//! still GENERATE events its parent reads (LTP `fanotify12` does exactly that).
//! A per-process copy of the mark table would lose those events. Each mark
//! therefore holds a [`Weak`] on its group: the group dies when the last fd
//! referencing it closes anywhere, and its marks are pruned lazily on the next
//! sweep, which is the group lifetime `fanotify(7)` specifies.

use std::collections::HashMap;
use std::collections::VecDeque;
use std::sync::{Arc, Weak};

use carrick_abi::{
    LINUX_FAN_NOFD, LINUX_FANOTIFY_EVENT_METADATA_LEN, LINUX_FANOTIFY_METADATA_VERSION,
    LinuxFanotifyEvents, LinuxFanotifyInitFlags, LinuxFanotifyMarkType,
};

use crate::dispatch::fd_table::HostFdRef;

thread_local! {
    /// Depth of "carrick is opening a file on the guest's behalf, as part of
    /// servicing a syscall rather than because the guest asked to open it".
    static INTERNAL_OPEN_DEPTH: std::cell::Cell<u32> = const { std::cell::Cell::new(0) };
}

/// Suppress notification events for opens carrick performs internally.
///
/// Reading a fanotify group opens one descriptor per event so the reader gets a
/// usable fd. Those opens go through the ordinary `openat` machinery, which
/// emits `FAN_OPEN` — and the object is by definition marked, or there would be
/// no event. Without this guard a single `read(2)` would refill the queue it
/// just drained, and a mark on a file would turn every read into an unbounded
/// event loop. Linux has no such problem: it attaches an already-open `struct
/// file` to the event instead of routing through the open path.
///
/// The guard also covers inotify's open hooks, for the same reason and with no
/// behaviour change to inotify-only guests: it can only ever be active inside a
/// fanotify read, which does not run unless a fanotify group exists.
pub(crate) struct InternalOpenGuard(());

impl InternalOpenGuard {
    pub(crate) fn enter() -> Self {
        INTERNAL_OPEN_DEPTH.with(|depth| depth.set(depth.get() + 1));
        Self(())
    }
}

impl Drop for InternalOpenGuard {
    fn drop(&mut self) {
        INTERNAL_OPEN_DEPTH.with(|depth| depth.set(depth.get().saturating_sub(1)));
    }
}

/// True while an [`InternalOpenGuard`] is held on this thread: the open now in
/// flight is carrick's own, and must generate no guest-visible event.
pub(crate) fn internal_open_in_progress() -> bool {
    INTERNAL_OPEN_DEPTH.with(|depth| depth.get() != 0)
}

/// One event that has been generated but not yet `read(2)` out of its group.
///
/// The object is remembered as a PATH, not as an already-open fd, because
/// Linux allocates the event's descriptor in the READER's file-descriptor
/// table at `read(2)` time — not in the table of whatever process acted. A
/// forked child triggering an event must not consume a slot in its own table,
/// and the parent must receive a descriptor it can `fstat` and `close`.
#[derive(Debug, Clone)]
pub(crate) struct PendingEvent {
    /// Deliverable event bits only — never `FAN_EVENT_ON_CHILD`/`FAN_ONDIR`.
    pub(crate) mask: LinuxFanotifyEvents,
    /// Resolved guest path of the object the event happened on.
    pub(crate) path: String,
    /// Value for the wire `pid` field: the acting thread-group id, or the
    /// acting thread id when the group was created with `FAN_REPORT_TID`.
    pub(crate) pid: i32,
}

/// One fanotify group: everything created by a single `fanotify_init(2)` call.
///
/// Shared by `Arc` between every fd that refers to it (`dup`, and inheritance
/// across guest `fork`). Dropping the last reference destroys the group, which
/// is what invalidates its marks.
#[derive(Debug)]
pub(crate) struct FanotifyGroup {
    init_flags: LinuxFanotifyInitFlags,
    /// The `event_f_flags` argument of `fanotify_init(2)`: the open flags each
    /// event descriptor is opened with.
    event_f_flags: u64,
    queue: parking_lot::Mutex<VecDeque<PendingEvent>>,
    /// Host pipe whose read end holds a byte iff the queue is non-empty. This
    /// gives the group a REAL host fd, which is what a blocking `read(2)` parks
    /// on (`DispatchOutcome::WaitOnFds`) and what `poll`/`epoll` watch — the
    /// same mechanism carrick's eventfd emulation uses, and the
    /// reason a blocking fanotify read can be woken by a sibling guest thread
    /// (LTP `fanotify11` reads before its worker thread has created the file).
    /// `None` if pipe creation failed, in which case blocking reads degrade to
    /// `EAGAIN` rather than sleeping forever.
    read_fd: Option<HostFdRef>,
    write_fd: Option<HostFdRef>,
}

impl FanotifyGroup {
    pub(crate) fn new(init_flags: LinuxFanotifyInitFlags, event_f_flags: u64) -> Self {
        let (read_fd, write_fd) = match crate::dispatch::fd_table::make_readiness_pipe() {
            Some((read_fd, write_fd)) => (Some(read_fd), Some(write_fd)),
            None => (None, None),
        };
        Self {
            init_flags,
            event_f_flags,
            queue: parking_lot::Mutex::new(VecDeque::new()),
            read_fd,
            write_fd,
        }
    }

    /// `FAN_REPORT_TID`: report the acting THREAD id rather than its
    /// thread-group id in the event's `pid` field.
    pub(crate) fn reports_tid(&self) -> bool {
        self.init_flags.contains(LinuxFanotifyInitFlags::REPORT_TID)
    }

    /// `FAN_NONBLOCK` from `fanotify_init`. Distinct from `O_NONBLOCK` set
    /// later via `fcntl`; a read is non-blocking if EITHER is set.
    pub(crate) fn init_nonblocking(&self) -> bool {
        self.init_flags.contains(LinuxFanotifyInitFlags::NONBLOCK)
    }

    /// Open flags for the descriptors handed to the reader in each event.
    pub(crate) fn event_f_flags(&self) -> u64 {
        self.event_f_flags
    }

    /// Host fd `poll`/`epoll`/a blocking read watch for readability. `-1` when
    /// the readiness pipe could not be created (poll ignores a negative fd).
    pub(crate) fn poll_fd(&self) -> i32 {
        self.read_fd.as_ref().map_or(-1, |fd| fd.raw())
    }

    /// Queue one event and make the group readable.
    pub(crate) fn enqueue(&self, event: PendingEvent) {
        let mut queue = self.queue.lock();
        queue.push_back(event);
        let len = queue.len();
        drop(queue);
        self.sync_readiness(len);
    }

    /// Whether any event is queued (poll/epoll readiness).
    pub(crate) fn has_events(&self) -> bool {
        !self.queue.lock().is_empty()
    }

    /// Remove and return up to `max` events in FIFO order. Ordering is
    /// load-bearing: `fanotify02` asserts an exact open/modify/close sequence.
    pub(crate) fn take(&self, max: usize) -> Vec<PendingEvent> {
        let mut queue = self.queue.lock();
        let take = max.min(queue.len());
        let events: Vec<PendingEvent> = queue.drain(..take).collect();
        let len = queue.len();
        drop(queue);
        self.sync_readiness(len);
        events
    }

    /// Put events back at the FRONT of the queue, preserving their order.
    ///
    /// Used when copying the drained records out to the guest faults partway:
    /// a `read(2)` that returns `EFAULT` must not have consumed the events, so
    /// the ones already taken are restored rather than dropped.
    pub(crate) fn requeue_front(&self, events: Vec<PendingEvent>) {
        let mut queue = self.queue.lock();
        for event in events.into_iter().rev() {
            queue.push_front(event);
        }
        let len = queue.len();
        drop(queue);
        self.sync_readiness(len);
    }

    /// Make the readiness pipe readable iff `queued > 0`.
    fn sync_readiness(&self, queued: usize) {
        let (Some(read_fd), Some(write_fd)) = (&self.read_fd, &self.write_fd) else {
            return;
        };
        if queued > 0 {
            let byte = [1u8];
            // BLOCKING-IO-OK: readiness pipe is created O_NONBLOCK; a full pipe
            // just EAGAINs, which is the already-readable state we want.
            unsafe { libc::write(write_fd.raw(), byte.as_ptr().cast(), 1) };
        } else {
            let mut buf = [0u8; 64];
            loop {
                // BLOCKING-IO-OK: readiness pipe is created O_NONBLOCK.
                let n = unsafe { libc::read(read_fd.raw(), buf.as_mut_ptr().cast(), buf.len()) };
                if n <= 0 {
                    break;
                }
            }
            // Re-check under no lock: a concurrent producer may have enqueued
            // between the drain and here, and its byte could have been eaten by
            // this drain — a parked reader would then sleep past a ready queue.
            if !self.queue.lock().is_empty() {
                let byte = [1u8];
                // BLOCKING-IO-OK: readiness pipe is created O_NONBLOCK.
                unsafe { libc::write(write_fd.raw(), byte.as_ptr().cast(), 1) };
            }
        }
    }
}

/// Encode one `struct fanotify_event_metadata` record.
///
/// ```text
/// struct fanotify_event_metadata {
///     __u32 event_len;      /* total record length, incl. any info records */
///     __u8  vers;           /* FANOTIFY_METADATA_VERSION */
///     __u8  reserved;
///     __u16 metadata_len;   /* length of this fixed header */
///     __aligned_u64 mask;
///     __s32 fd;
///     __s32 pid;
/// };
/// ```
///
/// carrick emits no trailing info records, so `event_len == metadata_len ==
/// FAN_EVENT_METADATA_LEN` (24). `vers` is checked by userspace and aborted on
/// mismatch, so it is a hard ABI constant.
pub(crate) fn encode_event(mask: LinuxFanotifyEvents, fd: i32, pid: i32) -> Vec<u8> {
    let len = LINUX_FANOTIFY_EVENT_METADATA_LEN as u32;
    let mut out = Vec::with_capacity(LINUX_FANOTIFY_EVENT_METADATA_LEN);
    out.extend_from_slice(&len.to_ne_bytes());
    out.push(LINUX_FANOTIFY_METADATA_VERSION);
    out.push(0); // reserved
    out.extend_from_slice(&(len as u16).to_ne_bytes());
    out.extend_from_slice(&mask.bits().to_ne_bytes());
    out.extend_from_slice(&fd.to_ne_bytes());
    out.extend_from_slice(&pid.to_ne_bytes());
    debug_assert_eq!(out.len(), LINUX_FANOTIFY_EVENT_METADATA_LEN);
    out
}

/// The `fd` value for an event that carries no descriptor.
pub(crate) const NOFD: i32 = LINUX_FAN_NOFD;

/// One mark: what a single group asked to be told about one object.
///
/// `mask` and `ignored_mask` are two fields of ONE mark, not two marks:
/// `FAN_MARK_ADD | FAN_MARK_IGNORED_MASK` updates the ignore mask of the mark
/// already on the object (LTP `fanotify12` adds a normal mark and then an
/// ignore mark to the same file and expects the second to filter the first).
#[derive(Debug, Clone)]
struct Mark {
    /// Weak so the group's lifetime is exactly "some fd still refers to it".
    group: Weak<FanotifyGroup>,
    mask: LinuxFanotifyEvents,
    ignored_mask: LinuxFanotifyEvents,
}

impl Mark {
    fn is_empty(&self) -> bool {
        self.mask.is_empty() && self.ignored_mask.is_empty()
    }
}

#[derive(Debug, Default)]
struct Inner {
    /// Inode marks, keyed by the resolved guest path the mark was added on.
    inode: HashMap<String, Vec<Mark>>,
    /// Mount and filesystem marks, as `(root path, type, mark)`. There are very
    /// few of these in practice, so a linear prefix scan beats a second index.
    subtree: Vec<(String, LinuxFanotifyMarkType, Mark)>,
}

/// Dispatch-layer fanotify mark table.
///
/// Cloning shares the SAME table (an `Arc`), unlike
/// [`crate::inotify::InotifyRegistry`], whose per-process deep copy is correct
/// for inotify watches but would lose a forked child's events here. See the
/// module docs for why.
#[derive(Debug, Clone, Default)]
pub(crate) struct FanotifyRegistry {
    inner: Arc<parking_lot::RwLock<Inner>>,
}

/// Which side of the object/parent relationship a mark sits on. Governs the
/// `FAN_EVENT_ON_CHILD` gate.
#[derive(Clone, Copy, PartialEq, Eq)]
enum MarkRole {
    /// The mark is on the object the event happened to.
    SelfObject,
    /// The mark is on the object's parent directory.
    Child,
}

impl FanotifyRegistry {
    /// True iff no mark exists anywhere. The fs hot paths test this first, so
    /// an unmarked guest pays one uncontended read lock and returns.
    pub(crate) fn is_empty(&self) -> bool {
        let inner = self.inner.read();
        inner.inode.is_empty() && inner.subtree.is_empty()
    }

    /// Add (OR in) `mask` for `group` on `path`.
    ///
    /// `ignored` selects which of the mark's two masks is updated:
    /// `FAN_MARK_IGNORED_MASK` updates the ignore mask, otherwise the event
    /// mask. `mark_type` selects the inode table or the mount/filesystem
    /// subtree list.
    pub(crate) fn add_mark(
        &self,
        path: &str,
        mark_type: LinuxFanotifyMarkType,
        group: &Arc<FanotifyGroup>,
        mask: LinuxFanotifyEvents,
        ignored: bool,
    ) {
        let key = normalize_path(path);
        let mut inner = self.inner.write();
        let existing = match mark_type {
            LinuxFanotifyMarkType::Inode => inner
                .inode
                .entry(key)
                .or_default()
                .iter_mut()
                .find(|m| weak_is(&m.group, group)),
            _ => inner
                .subtree
                .iter_mut()
                .find(|(root, ty, m)| *root == key && *ty == mark_type && weak_is(&m.group, group))
                .map(|(_, _, m)| m),
        };
        if let Some(mark) = existing {
            if ignored {
                mark.ignored_mask |= mask;
            } else {
                mark.mask |= mask;
            }
            return;
        }
        let mark = Mark {
            group: Arc::downgrade(group),
            mask: if ignored {
                LinuxFanotifyEvents::empty()
            } else {
                mask
            },
            ignored_mask: if ignored {
                mask
            } else {
                LinuxFanotifyEvents::empty()
            },
        };
        match mark_type {
            LinuxFanotifyMarkType::Inode => {
                let key = normalize_path(path);
                inner.inode.entry(key).or_default().push(mark);
            }
            _ => {
                let key = normalize_path(path);
                inner.subtree.push((key, mark_type, mark));
            }
        }
    }

    /// Clear `mask` from `group`'s mark on `path`, dropping the mark once both
    /// of its masks are empty.
    ///
    /// Returns `false` when no such mark exists — `fanotify_mark(2)` specifies
    /// `ENOENT` for removing a mark from an unmarked object, so the caller
    /// lowers a `false` to that errno rather than silently succeeding.
    pub(crate) fn remove_mark(
        &self,
        path: &str,
        mark_type: LinuxFanotifyMarkType,
        group: &Arc<FanotifyGroup>,
        mask: LinuxFanotifyEvents,
        ignored: bool,
    ) -> bool {
        let key = normalize_path(path);
        let mut inner = self.inner.write();
        let found = match mark_type {
            LinuxFanotifyMarkType::Inode => inner
                .inode
                .get_mut(&key)
                .and_then(|marks| marks.iter_mut().find(|m| weak_is(&m.group, group))),
            _ => inner
                .subtree
                .iter_mut()
                .find(|(root, ty, m)| *root == key && *ty == mark_type && weak_is(&m.group, group))
                .map(|(_, _, m)| m),
        };
        let Some(mark) = found else {
            return false;
        };
        if ignored {
            mark.ignored_mask -= mask;
        } else {
            mark.mask -= mask;
        }
        inner.prune();
        true
    }

    /// `FAN_MARK_FLUSH`: drop every mark of `group` whose type matches
    /// `mark_type`. Per `fanotify_mark(2)`, a flush is scoped to one class of
    /// mark — mounts, filesystems, or "directories and files" — never all
    /// three at once.
    pub(crate) fn flush(&self, group: &Arc<FanotifyGroup>, mark_type: LinuxFanotifyMarkType) {
        let mut inner = self.inner.write();
        match mark_type {
            LinuxFanotifyMarkType::Inode => {
                inner.inode.retain(|_, marks| {
                    marks.retain(|m| !weak_is(&m.group, group));
                    !marks.is_empty()
                });
            }
            ty => inner
                .subtree
                .retain(|(_, mark_ty, m)| !(*mark_ty == ty && weak_is(&m.group, group))),
        }
    }

    /// Drop every mark belonging to groups that no longer exist. Called when a
    /// fanotify fd closes: if that was the last reference, the group's `Weak`s
    /// are now dead and its marks must stop matching.
    pub(crate) fn prune_dead_groups(&self) {
        self.inner.write().prune();
    }

    /// Fan one operation out to every group that asked for it.
    ///
    /// `events` carries only deliverable bits. `is_dir` says whether the object
    /// is a directory (gates `FAN_ONDIR`). `tgid`/`tid` are the acting task's
    /// ids; each group picks one according to its `FAN_REPORT_TID` setting.
    ///
    /// A group that matches through several marks at once (say an inode mark on
    /// the file AND an `FAN_EVENT_ON_CHILD` mark on its directory) receives ONE
    /// event carrying the union of what those marks allow, which is how Linux
    /// merges concurrent marks — not one event per mark.
    pub(crate) fn notify(
        &self,
        path: &str,
        events: LinuxFanotifyEvents,
        is_dir: bool,
        tgid: i32,
        tid: i32,
    ) {
        let events = events & LinuxFanotifyEvents::DELIVERABLE;
        if events.is_empty() {
            return;
        }
        let key = normalize_path(path);
        // (group, accumulated mask) — a short Vec beats a HashMap here; a guest
        // realistically has a handful of groups, not thousands.
        let mut per_group: Vec<(Arc<FanotifyGroup>, LinuxFanotifyEvents)> = Vec::new();
        {
            let inner = self.inner.read();
            let mut consider = |mark: &Mark, role: MarkRole| {
                let Some(group) = mark.group.upgrade() else {
                    return;
                };
                // FAN_EVENT_ON_CHILD: a mark on a directory only reports its
                // children's events when it asked to.
                if role == MarkRole::Child
                    && !mark.mask.contains(LinuxFanotifyEvents::EVENT_ON_CHILD)
                {
                    return;
                }
                // FAN_ONDIR: events whose object IS a directory are reported
                // only when the mark asked for them.
                if is_dir && !mark.mask.contains(LinuxFanotifyEvents::ONDIR) {
                    return;
                }
                // Intersect with what the mark wants, then subtract its ignore
                // mask. `DELIVERABLE` strips the two modifier bits out of the
                // mark mask so they can never leak into the wire event.
                let delivered = (events & mark.mask & LinuxFanotifyEvents::DELIVERABLE)
                    .difference(mark.ignored_mask);
                if delivered.is_empty() {
                    return;
                }
                match per_group.iter_mut().find(|(g, _)| Arc::ptr_eq(g, &group)) {
                    Some((_, mask)) => *mask |= delivered,
                    None => per_group.push((group, delivered)),
                }
            };
            if let Some(marks) = inner.inode.get(&key) {
                for mark in marks {
                    consider(mark, MarkRole::SelfObject);
                }
            }
            let (parent, name) = split_parent_name(&key);
            if !name.is_empty()
                && let Some(marks) = inner.inode.get(parent)
            {
                for mark in marks {
                    consider(mark, MarkRole::Child);
                }
            }
            // A mount/filesystem mark covers every object in its subtree as the
            // object itself, so it is never gated on FAN_EVENT_ON_CHILD.
            for (root, _, mark) in &inner.subtree {
                if path_within(root, &key) {
                    consider(mark, MarkRole::SelfObject);
                }
            }
        }
        for (group, mask) in per_group {
            let pid = if group.reports_tid() { tid } else { tgid };
            group.enqueue(PendingEvent {
                mask,
                path: key.clone(),
                pid,
            });
        }
    }
}

impl Inner {
    /// Drop marks with nothing left to report and marks whose group has died.
    fn prune(&mut self) {
        self.inode.retain(|_, marks| {
            marks.retain(|m| !m.is_empty() && m.group.strong_count() > 0);
            !marks.is_empty()
        });
        self.subtree
            .retain(|(_, _, m)| !m.is_empty() && m.group.strong_count() > 0);
    }
}

/// Is this `Weak` a reference to exactly this group?
fn weak_is(weak: &Weak<FanotifyGroup>, group: &Arc<FanotifyGroup>) -> bool {
    std::ptr::eq(weak.as_ptr(), Arc::as_ptr(group))
}

/// Normalize a guest path to the registry key form: absolute, no trailing
/// slash (except root). Marks and lookups must agree on the exact key, so both
/// sides route through this — the same contract
/// [`crate::inotify`] uses for its watch keys.
fn normalize_path(path: &str) -> String {
    let trimmed = path.trim_end_matches('/');
    if trimmed.is_empty() {
        "/".to_owned()
    } else {
        trimmed.to_owned()
    }
}

/// Split a normalized path into `(parent, basename)`. Root and bare names map
/// to parent `"/"`.
fn split_parent_name(path: &str) -> (&str, &str) {
    match path.rfind('/') {
        Some(0) => ("/", &path[1..]),
        Some(idx) => (&path[..idx], &path[idx + 1..]),
        None => ("/", path),
    }
}

/// Is `path` inside the subtree rooted at `root` (or the root itself)?
/// Compares whole components, so `/mnt/ab` is NOT inside `/mnt/a`.
fn path_within(root: &str, path: &str) -> bool {
    if root == "/" {
        return true;
    }
    if path == root {
        return true;
    }
    path.starts_with(root) && path.as_bytes().get(root.len()) == Some(&b'/')
}

#[cfg(test)]
mod tests {
    use super::*;

    fn group() -> Arc<FanotifyGroup> {
        Arc::new(FanotifyGroup::new(LinuxFanotifyInitFlags::empty(), 0))
    }

    fn tid_group() -> Arc<FanotifyGroup> {
        Arc::new(FanotifyGroup::new(LinuxFanotifyInitFlags::REPORT_TID, 0))
    }

    #[test]
    fn inode_mark_reports_the_object_itself() {
        let reg = FanotifyRegistry::default();
        let g = group();
        reg.add_mark(
            "/tmp/f",
            LinuxFanotifyMarkType::Inode,
            &g,
            LinuxFanotifyEvents::OPEN,
            false,
        );
        reg.notify("/tmp/f", LinuxFanotifyEvents::OPEN, false, 7, 9);
        let events = g.take(16);
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].mask, LinuxFanotifyEvents::OPEN);
        assert_eq!(events[0].path, "/tmp/f");
        assert_eq!(
            events[0].pid, 7,
            "without FAN_REPORT_TID the pid is the tgid"
        );
    }

    #[test]
    fn mask_filters_events_the_mark_did_not_ask_for() {
        let reg = FanotifyRegistry::default();
        let g = group();
        reg.add_mark(
            "/tmp/f",
            LinuxFanotifyMarkType::Inode,
            &g,
            LinuxFanotifyEvents::OPEN,
            false,
        );
        reg.notify("/tmp/f", LinuxFanotifyEvents::MODIFY, false, 7, 9);
        assert!(g.take(16).is_empty());
    }

    #[test]
    fn child_events_need_event_on_child() {
        let reg = FanotifyRegistry::default();
        let g = group();
        // Directory mark WITHOUT FAN_EVENT_ON_CHILD sees nothing from a child.
        reg.add_mark(
            "/tmp/d",
            LinuxFanotifyMarkType::Inode,
            &g,
            LinuxFanotifyEvents::OPEN,
            false,
        );
        reg.notify("/tmp/d/child", LinuxFanotifyEvents::OPEN, false, 7, 9);
        assert!(g.take(16).is_empty());

        // Adding the modifier turns the same operation into an event.
        reg.add_mark(
            "/tmp/d",
            LinuxFanotifyMarkType::Inode,
            &g,
            LinuxFanotifyEvents::EVENT_ON_CHILD,
            false,
        );
        reg.notify("/tmp/d/child", LinuxFanotifyEvents::OPEN, false, 7, 9);
        let events = g.take(16);
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].path, "/tmp/d/child");
    }

    #[test]
    fn removing_event_on_child_stops_child_events_but_keeps_self_events() {
        // This is LTP fanotify02's third phase exactly.
        let reg = FanotifyRegistry::default();
        let g = group();
        reg.add_mark(
            "/tmp/d",
            LinuxFanotifyMarkType::Inode,
            &g,
            LinuxFanotifyEvents::OPEN
                | LinuxFanotifyEvents::EVENT_ON_CHILD
                | LinuxFanotifyEvents::ONDIR,
            false,
        );
        assert!(reg.remove_mark(
            "/tmp/d",
            LinuxFanotifyMarkType::Inode,
            &g,
            LinuxFanotifyEvents::EVENT_ON_CHILD,
            false,
        ));
        reg.notify("/tmp/d/child", LinuxFanotifyEvents::OPEN, false, 7, 9);
        assert!(g.take(16).is_empty(), "child events are gone");
        reg.notify("/tmp/d", LinuxFanotifyEvents::OPEN, true, 7, 9);
        assert_eq!(g.take(16).len(), 1, "the directory's own events remain");
    }

    #[test]
    fn ondir_gates_directory_objects_and_never_leaks_into_the_wire_mask() {
        let reg = FanotifyRegistry::default();
        let g = group();
        reg.add_mark(
            "/tmp/d",
            LinuxFanotifyMarkType::Inode,
            &g,
            LinuxFanotifyEvents::OPEN,
            false,
        );
        reg.notify("/tmp/d", LinuxFanotifyEvents::OPEN, true, 7, 9);
        assert!(g.take(16).is_empty(), "no FAN_ONDIR -> no directory event");

        reg.add_mark(
            "/tmp/d",
            LinuxFanotifyMarkType::Inode,
            &g,
            LinuxFanotifyEvents::ONDIR,
            false,
        );
        reg.notify("/tmp/d", LinuxFanotifyEvents::OPEN, true, 7, 9);
        let events = g.take(16);
        assert_eq!(events.len(), 1);
        // fanotify04 asserts `event->mask == FAN_OPEN` EXACTLY here.
        assert_eq!(events[0].mask, LinuxFanotifyEvents::OPEN);
    }

    #[test]
    fn ignore_mask_subtracts_from_the_delivered_mask() {
        // LTP fanotify12 case 5: mask FAN_OPEN|FAN_OPEN_EXEC, ignore
        // FAN_OPEN_EXEC -> an exec reports plain FAN_OPEN.
        let reg = FanotifyRegistry::default();
        let g = group();
        reg.add_mark(
            "/tmp/app",
            LinuxFanotifyMarkType::Inode,
            &g,
            LinuxFanotifyEvents::OPEN | LinuxFanotifyEvents::OPEN_EXEC,
            false,
        );
        reg.add_mark(
            "/tmp/app",
            LinuxFanotifyMarkType::Inode,
            &g,
            LinuxFanotifyEvents::OPEN_EXEC,
            true,
        );
        reg.notify(
            "/tmp/app",
            LinuxFanotifyEvents::OPEN | LinuxFanotifyEvents::OPEN_EXEC,
            false,
            7,
            9,
        );
        let events = g.take(16);
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].mask, LinuxFanotifyEvents::OPEN);
    }

    #[test]
    fn ignoring_everything_suppresses_the_event_entirely() {
        let reg = FanotifyRegistry::default();
        let g = group();
        reg.add_mark(
            "/tmp/app",
            LinuxFanotifyMarkType::Inode,
            &g,
            LinuxFanotifyEvents::OPEN,
            false,
        );
        reg.add_mark(
            "/tmp/app",
            LinuxFanotifyMarkType::Inode,
            &g,
            LinuxFanotifyEvents::OPEN,
            true,
        );
        reg.notify("/tmp/app", LinuxFanotifyEvents::OPEN, false, 7, 9);
        assert!(g.take(16).is_empty());
    }

    #[test]
    fn report_tid_reports_the_thread_not_the_group() {
        let reg = FanotifyRegistry::default();
        let g = tid_group();
        reg.add_mark(
            "/tmp/f",
            LinuxFanotifyMarkType::Inode,
            &g,
            LinuxFanotifyEvents::OPEN,
            false,
        );
        reg.notify("/tmp/f", LinuxFanotifyEvents::OPEN, false, 7, 9);
        assert_eq!(g.take(16)[0].pid, 9);
    }

    #[test]
    fn one_group_marked_twice_gets_one_merged_event() {
        let reg = FanotifyRegistry::default();
        let g = group();
        // Mark the file itself for FAN_OPEN...
        reg.add_mark(
            "/tmp/d/f",
            LinuxFanotifyMarkType::Inode,
            &g,
            LinuxFanotifyEvents::OPEN,
            false,
        );
        // ...and its directory for FAN_MODIFY on children.
        reg.add_mark(
            "/tmp/d",
            LinuxFanotifyMarkType::Inode,
            &g,
            LinuxFanotifyEvents::MODIFY | LinuxFanotifyEvents::EVENT_ON_CHILD,
            false,
        );
        reg.notify(
            "/tmp/d/f",
            LinuxFanotifyEvents::OPEN | LinuxFanotifyEvents::MODIFY,
            false,
            7,
            9,
        );
        let events = g.take(16);
        assert_eq!(events.len(), 1, "two matching marks merge into one event");
        assert_eq!(
            events[0].mask,
            LinuxFanotifyEvents::OPEN | LinuxFanotifyEvents::MODIFY
        );
    }

    #[test]
    fn mount_mark_covers_the_whole_subtree_but_not_a_sibling_prefix() {
        let reg = FanotifyRegistry::default();
        let g = group();
        reg.add_mark(
            "/mnt/a",
            LinuxFanotifyMarkType::Mount,
            &g,
            LinuxFanotifyEvents::MODIFY,
            false,
        );
        reg.notify("/mnt/a/deep/file", LinuxFanotifyEvents::MODIFY, false, 7, 9);
        assert_eq!(g.take(16).len(), 1);
        // `/mnt/ab` shares a string prefix with `/mnt/a` but is a different
        // directory — a naive `starts_with` would wrongly report it.
        reg.notify("/mnt/ab/file", LinuxFanotifyEvents::MODIFY, false, 7, 9);
        assert!(g.take(16).is_empty());
    }

    #[test]
    fn flush_is_scoped_to_one_mark_class() {
        let reg = FanotifyRegistry::default();
        let g = group();
        reg.add_mark(
            "/tmp/f",
            LinuxFanotifyMarkType::Inode,
            &g,
            LinuxFanotifyEvents::OPEN,
            false,
        );
        reg.add_mark(
            "/mnt/a",
            LinuxFanotifyMarkType::Mount,
            &g,
            LinuxFanotifyEvents::OPEN,
            false,
        );
        reg.flush(&g, LinuxFanotifyMarkType::Inode);
        reg.notify("/tmp/f", LinuxFanotifyEvents::OPEN, false, 7, 9);
        assert!(g.take(16).is_empty(), "inode marks were flushed");
        reg.notify("/mnt/a/f", LinuxFanotifyEvents::OPEN, false, 7, 9);
        assert_eq!(g.take(16).len(), 1, "the mount mark survived");
    }

    #[test]
    fn removing_the_last_bit_drops_the_mark_and_a_second_remove_reports_missing() {
        let reg = FanotifyRegistry::default();
        let g = group();
        reg.add_mark(
            "/tmp/f",
            LinuxFanotifyMarkType::Inode,
            &g,
            LinuxFanotifyEvents::OPEN,
            false,
        );
        assert!(reg.remove_mark(
            "/tmp/f",
            LinuxFanotifyMarkType::Inode,
            &g,
            LinuxFanotifyEvents::OPEN,
            false,
        ));
        assert!(reg.is_empty());
        assert!(
            !reg.remove_mark(
                "/tmp/f",
                LinuxFanotifyMarkType::Inode,
                &g,
                LinuxFanotifyEvents::OPEN,
                false,
            ),
            "removing from an unmarked object must lower to ENOENT"
        );
    }

    #[test]
    fn a_dead_group_stops_matching_and_its_marks_are_pruned() {
        let reg = FanotifyRegistry::default();
        let g = group();
        reg.add_mark(
            "/tmp/f",
            LinuxFanotifyMarkType::Inode,
            &g,
            LinuxFanotifyEvents::OPEN,
            false,
        );
        assert!(!reg.is_empty());
        drop(g);
        // The mark is still in the table but must no longer match; the sweep
        // the close path runs then removes it.
        reg.notify("/tmp/f", LinuxFanotifyEvents::OPEN, false, 7, 9);
        reg.prune_dead_groups();
        assert!(reg.is_empty());
    }

    #[test]
    fn a_forked_clone_of_the_registry_shares_marks_with_its_parent() {
        // The property `fanotify12` depends on: a child that closes its own
        // fanotify fd still generates events into the parent's group.
        let reg = FanotifyRegistry::default();
        let g = group();
        reg.add_mark(
            "/tmp/f",
            LinuxFanotifyMarkType::Inode,
            &g,
            LinuxFanotifyEvents::OPEN,
            false,
        );
        let child = reg.clone();
        child.notify("/tmp/f", LinuxFanotifyEvents::OPEN, false, 7, 9);
        assert_eq!(
            g.take(16).len(),
            1,
            "the child's operation reached the parent's group"
        );
    }

    #[test]
    fn queue_is_fifo_and_readiness_tracks_it() {
        let g = group();
        assert!(!g.has_events());
        for mask in [
            LinuxFanotifyEvents::OPEN,
            LinuxFanotifyEvents::MODIFY,
            LinuxFanotifyEvents::CLOSE_WRITE,
        ] {
            g.enqueue(PendingEvent {
                mask,
                path: "/tmp/f".to_owned(),
                pid: 1,
            });
        }
        assert!(g.has_events());
        let events = g.take(2);
        assert_eq!(events[0].mask, LinuxFanotifyEvents::OPEN);
        assert_eq!(events[1].mask, LinuxFanotifyEvents::MODIFY);
        assert!(g.has_events());
        g.requeue_front(events);
        let all = g.take(16);
        assert_eq!(all.len(), 3, "requeue restores the drained events in order");
        assert_eq!(all[0].mask, LinuxFanotifyEvents::OPEN);
        assert_eq!(all[2].mask, LinuxFanotifyEvents::CLOSE_WRITE);
        assert!(!g.has_events());
    }

    #[test]
    fn event_record_matches_the_fanotify_event_metadata_wire_layout() {
        let bytes = encode_event(LinuxFanotifyEvents::OPEN, 5, 4242);
        assert_eq!(bytes.len(), LINUX_FANOTIFY_EVENT_METADATA_LEN);
        assert_eq!(
            u32::from_ne_bytes(bytes[0..4].try_into().unwrap()),
            LINUX_FANOTIFY_EVENT_METADATA_LEN as u32,
            "event_len"
        );
        assert_eq!(bytes[4], LINUX_FANOTIFY_METADATA_VERSION, "vers");
        assert_eq!(bytes[5], 0, "reserved");
        assert_eq!(
            u16::from_ne_bytes(bytes[6..8].try_into().unwrap()),
            LINUX_FANOTIFY_EVENT_METADATA_LEN as u16,
            "metadata_len"
        );
        assert_eq!(
            u64::from_ne_bytes(bytes[8..16].try_into().unwrap()),
            LinuxFanotifyEvents::OPEN.bits(),
            "mask"
        );
        assert_eq!(
            i32::from_ne_bytes(bytes[16..20].try_into().unwrap()),
            5,
            "fd"
        );
        assert_eq!(
            i32::from_ne_bytes(bytes[20..24].try_into().unwrap()),
            4242,
            "pid"
        );
    }

    #[test]
    fn path_containment_compares_whole_components() {
        assert!(path_within("/", "/anything"));
        assert!(path_within("/mnt/a", "/mnt/a"));
        assert!(path_within("/mnt/a", "/mnt/a/b"));
        assert!(!path_within("/mnt/a", "/mnt/ab"));
        assert!(!path_within("/mnt/a", "/mnt"));
    }
}
