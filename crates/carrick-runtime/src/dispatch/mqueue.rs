//! Pure in-memory POSIX message queues (`mq_open`/`mq_unlink`/`mq_timedsend`/
//! `mq_timedreceive`/`mq_notify`/`mq_getsetattr`).
//!
//! Under Carrick's unified kernel model, all guest tasks live in a single host
//! process graph sharing [`MqueueRegistry`]. An in-memory queue structure
//! backed by `Mutex<MqueueState>` and `parking_lot::Condvar` provides exact
//! POSIX message queue semantics without creating host files under `/tmp` or
//! acquiring host OFD locks.

use super::*;
use crate::linux_abi::LinuxErrno;
use std::collections::HashMap;
use std::sync::Arc;

syscall_table! {
    /// Per-module syscall routing for the POSIX message-queue subsystem.
    /// `resolve_handler` in `dispatch/mod.rs` chains this with the other
    /// modules' tables. (x86_64 maps 240–245 → 180–185 at the GuestArch seam.)
    pub(crate) fn dispatch_mqueue;
    180 => mq_open,
    181 => mq_unlink,
    182 => mq_timedsend,
    183 => mq_timedreceive,
    184 => mq_notify,
    185 => mq_getsetattr,
}

/// Defaults from mq_overview(7) / the `/proc/sys/fs/mqueue` values carrick
/// advertises in `vfs/proc.rs`.
const DEFAULT_MAXMSG: u32 = 10;
const DEFAULT_MSGSIZE: u32 = 8192;

/// Upper bounds (queues_max-adjacent guard rails). A guest `mq_open` with an
/// `attr` exceeding these gets EINVAL, like Linux with no privilege.
const MAX_MAXMSG: u32 = 65_536;
const MAX_MSGSIZE: u32 = 16 * 1024 * 1024;

/// `NAME_MAX` for the queue name (mq_overview(7): a name is `/` + up to
/// `NAME_MAX` (255) further chars).
const NAME_MAX: usize = 255;

const NOTIFY_DATA_SIZE: usize = 32;

/// glibc's mq-notify helper distinguishes "message arrived" from
/// "registration removed" by the final byte in the 32-byte netlink record.
const MQ_NOTIFY_EVENT_MSG: u32 = 1;
const MQ_NOTIFY_EVENT_REMOVED: u32 = 2;

#[derive(Clone, Debug)]
pub struct MqueueMessage {
    pub prio: u32,
    #[allow(dead_code)]
    pub seq: u64,
    pub payload: Vec<u8>,
}

#[derive(Debug)]
pub enum MqueueNotifyTarget<KernelResource = (), HostResource = ()> {
    /// One exact Carrick-kernel task generation. A numeric guest pid is never
    /// allowed to escape this variant into a host pid-taking syscall.
    Kernel(crate::kernel::TaskKey, KernelResource),
    /// Legacy one-host-process-per-guest-process delivery. The pid is a host
    /// pid by construction and retains the established xsig/kill fallback.
    Host(libc::pid_t, HostResource),
}

impl<KernelResource, HostResource> MqueueNotifyTarget<KernelResource, HostResource> {
    fn same_owner<OtherKernel, OtherHost>(
        &self,
        other: &MqueueNotifyTarget<OtherKernel, OtherHost>,
    ) -> bool {
        match (self, other) {
            (Self::Kernel(left, _), MqueueNotifyTarget::Kernel(right, _)) => left == right,
            (Self::Host(left, _), MqueueNotifyTarget::Host(right, _)) => left == right,
            _ => false,
        }
    }
}

#[derive(Debug)]
pub struct RetainedNetlinkDescription {
    description: Arc<crate::kernel::FileDescription>,
}

impl RetainedNetlinkDescription {
    fn new(description: Arc<crate::kernel::FileDescription>) -> Self {
        description.retain_fd_ref();
        Self { description }
    }

    fn enqueue(&self, bytes: &[u8]) -> Result<(), LinuxErrno> {
        let mut open = self.description.write();
        let OpenDescription::Netlink { recv_queue, .. } = &mut *open else {
            return Err(LINUX_EBADF);
        };
        recv_queue.extend(bytes);
        Ok(())
    }
}

impl Drop for RetainedNetlinkDescription {
    fn drop(&mut self) {
        self.description.release_fd_ref();
    }
}

#[derive(Debug)]
pub enum MqueueNotify {
    Signal {
        registration: crate::kernel::FileDescriptionId,
        target: MqueueNotifyTarget,
        signo: i32,
        value: i64,
    },
    Thread {
        registration: crate::kernel::FileDescriptionId,
        /// The route and the resource it is allowed to use are one value, so a
        /// kernel TaskKey cannot accidentally be paired with a host fd (or a
        /// host pid with a retained kernel description).
        target: MqueueNotifyTarget<RetainedNetlinkDescription, i32>,
        data: [u8; NOTIFY_DATA_SIZE],
    },
}

impl MqueueNotify {
    fn registration(&self) -> crate::kernel::FileDescriptionId {
        match self {
            Self::Signal { registration, .. } | Self::Thread { registration, .. } => *registration,
        }
    }
}

#[derive(Debug)]
enum MqueueNotifySpec {
    Signal {
        target: MqueueNotifyTarget,
        signo: i32,
        value: i64,
    },
    Thread {
        target: MqueueNotifyTarget<RetainedNetlinkDescription, i32>,
        data: [u8; NOTIFY_DATA_SIZE],
    },
}

impl MqueueNotifySpec {
    fn bind(self, registration: crate::kernel::FileDescriptionId) -> MqueueNotify {
        match self {
            Self::Signal {
                target,
                signo,
                value,
            } => MqueueNotify::Signal {
                registration,
                target,
                signo,
                value,
            },
            Self::Thread { target, data } => MqueueNotify::Thread {
                registration,
                target,
                data,
            },
        }
    }
}

#[derive(Debug)]
pub struct MqueueState {
    pub messages: Vec<MqueueMessage>,
    pub max_msg: usize,
    pub msg_size: usize,
    pub creator_uid: u32,
    pub next_seq: u64,
    pub notify: Option<MqueueNotify>,
}

#[derive(Debug)]
pub struct MqueueInner {
    pub state: parking_lot::Mutex<MqueueState>,
    pub changed: parking_lot::Condvar,
}

impl MqueueInner {
    pub fn new(max_msg: usize, msg_size: usize, creator_uid: u32) -> Self {
        Self {
            state: parking_lot::Mutex::new(MqueueState {
                messages: Vec::new(),
                max_msg,
                msg_size,
                creator_uid,
                next_seq: 0,
                notify: None,
            }),
            changed: parking_lot::Condvar::new(),
        }
    }

    /// Remove only the registration owned by the exact open-file description
    /// whose final logical reference is closing. A different open of the same
    /// named queue is a different identity and must not disturb it.
    pub(crate) fn retire_notification_owner(
        &self,
        owner: crate::kernel::FileDescriptionId,
    ) -> Option<MqueueNotify> {
        let mut state = self.state.lock();
        if state
            .notify
            .as_ref()
            .is_some_and(|notification| notification.registration() == owner)
        {
            state.notify.take()
        } else {
            None
        }
    }
}

#[derive(Default, Debug)]
pub struct MqueueRegistry {
    pub queues: parking_lot::Mutex<HashMap<String, Arc<MqueueInner>>>,
}

/// Validate a guest mqueue name.
fn validate_mqueue_name(name: &str) -> Result<String, LinuxErrno> {
    if name.is_empty() {
        return Err(crate::linux_abi::LINUX_ENOENT);
    }
    if name.contains('/') || name == "." || name == ".." {
        return Err(crate::linux_abi::LINUX_EACCES);
    }
    if name.len() > NAME_MAX {
        return Err(crate::linux_abi::LINUX_ENAMETOOLONG);
    }
    Ok(name.to_owned())
}

struct MqDescription {
    base: OpenDescriptionBase,
    queue: Arc<MqueueInner>,
}

impl SyscallDispatcher {
    fn mqueue_notify_target(&self, context: &crate::kernel::KernelContext) -> MqueueNotifyTarget {
        if self.hvpatch_process().is_some() {
            MqueueNotifyTarget::Kernel(context.task().key(), ())
        } else {
            MqueueNotifyTarget::Host(std::process::id() as libc::pid_t, ())
        }
    }

    fn retain_netlink_description(
        &self,
        fd: i32,
    ) -> Result<RetainedNetlinkDescription, LinuxErrno> {
        if fd < 0 {
            return Err(LINUX_EBADF);
        }
        let files = self.captured_file_table();
        let open_files = files.read_open_files();
        let description = open_files
            .get(&fd)
            .map(crate::kernel::FileSlot::description)
            .ok_or(LINUX_EBADF)?;
        if !matches!(&*description.read(), OpenDescription::Netlink { .. }) {
            return Err(LINUX_EBADF);
        }
        // Retain while the fd-table read lock still prevents a concurrent
        // close from dropping the last functional reference and closing the
        // backing between validation and acquisition.
        Ok(RetainedNetlinkDescription::new(description))
    }

    fn mq_description(&self, fd: i32) -> Result<MqDescription, LinuxErrno> {
        let open_file = self.open_file(fd).ok_or(LINUX_EBADF)?;
        let open = open_file.description.read();
        match &*open {
            OpenDescription::Mqueue { base, queue } => Ok(MqDescription {
                base: base.clone(),
                queue: Arc::clone(queue),
            }),
            _ => Err(LINUX_EBADF),
        }
    }

    fn mqueue_file_description(
        &self,
        fd: i32,
    ) -> Result<Arc<crate::kernel::FileDescription>, LinuxErrno> {
        self.open_file(fd)
            .map(|slot| slot.description())
            .ok_or(LINUX_EBADF)
    }

    define_syscall! {
        /// mq_open(name, oflag, mode, attr). Opens (and optionally creates) a
        /// message queue and returns a `mqd_t` (a real guest fd).
        fn mq_open(this, cx, name: GuestPtr, oflag: u64, mode: u64, attr: GuestPtr) {
            let _ = mode;
            let name = match read_guest_c_string(&*cx.memory, name.0) {
                Ok(s) => s,
                Err(errno) => return Ok(DispatchOutcome::errno(errno)),
            };
            let queue_name = match validate_mqueue_name(&name) {
                Ok(p) => p,
                Err(errno) => return Ok(DispatchOutcome::errno(errno)),
            };

            let access = oflag & LINUX_O_ACCMODE;
            if access != LINUX_O_RDONLY && access != LINUX_O_WRONLY && access != LINUX_O_RDWR {
                return Ok(DispatchOutcome::errno(LINUX_EINVAL));
            }
            let open_flags = LinuxOpenFlags::from_bits_truncate(oflag);
            let create = open_flags.contains(LinuxOpenFlags::CREAT);
            let exclusive = open_flags.contains(LinuxOpenFlags::EXCL);

            let mut queues = this.mqueue.queues.lock();
            let queue = if let Some(existing) = queues.get(&queue_name) {
                if create && exclusive {
                    return Ok(DispatchOutcome::errno(crate::linux_abi::LINUX_EEXIST));
                }
                Arc::clone(existing)
            } else {
                if !create {
                    return Ok(DispatchOutcome::errno(LINUX_ENOENT));
                }
                let (mut maxmsg, mut msgsize) = (DEFAULT_MAXMSG, DEFAULT_MSGSIZE);
                if attr.0 != 0 {
                    let mq_attr: crate::linux_abi::LinuxMqAttr =
                        match read_kernel_struct(&*cx.memory, attr.0) {
                            Ok(a) => a,
                            Err(errno) => return Ok(DispatchOutcome::errno(errno)),
                        };
                    let req_max = mq_attr.mq_maxmsg;
                    let req_size = mq_attr.mq_msgsize;
                    if req_max <= 0 || req_size <= 0 {
                        return Ok(DispatchOutcome::errno(LINUX_EINVAL));
                    }
                    if req_max as u64 > MAX_MAXMSG as u64 || req_size as u64 > MAX_MSGSIZE as u64 {
                        return Ok(DispatchOutcome::errno(LINUX_EINVAL));
                    }
                    maxmsg = req_max as u32;
                    msgsize = req_size as u32;
                }
                let creator_uid = this.cred_snapshot().euid.raw();
                let inner = Arc::new(MqueueInner::new(maxmsg as usize, msgsize as usize, creator_uid));
                queues.insert(queue_name, Arc::clone(&inner));
                inner
            };
            drop(queues);

            let status_flags = access
                | if open_flags.contains(LinuxOpenFlags::NONBLOCK) {
                    LINUX_O_NONBLOCK
                } else {
                    0
                };
            let description = OpenDescription::Mqueue {
                base: OpenDescriptionBase::new(status_flags),
                queue,
            };
            let open_file = OpenFile::from_open_description(
                std::sync::Arc::new(parking_lot::RwLock::new(description)),
                linux_fd_flags_from_open_flags(oflag),
            );
            match this.install_fd_at_or_above(0, open_file) {
                Ok(fd) => Ok(DispatchOutcome::Returned { value: fd as i64 }),
                Err(_) => Ok(DispatchOutcome::errno(crate::dispatch::linux_errno::EMFILE)),
            }
        }

        /// mq_unlink(name). Remove the queue's name; the in-memory queue is
        /// removed from the registry. Existing open descriptors keep working.
        fn mq_unlink(this, cx, name: GuestPtr) {
            let name = match read_guest_c_string(&*cx.memory, name.0) {
                Ok(s) => s,
                Err(errno) => return Ok(DispatchOutcome::errno(errno)),
            };
            let queue_name = match validate_mqueue_name(&name) {
                Ok(p) => p,
                Err(errno) => return Ok(DispatchOutcome::errno(errno)),
            };

            let mut queues = this.mqueue.queues.lock();
            let Some(queue) = queues.get(&queue_name) else {
                return Ok(DispatchOutcome::errno(LINUX_ENOENT));
            };

            let euid = this.cred_snapshot().euid;
            if !euid.is_root() {
                let creator = queue.state.lock().creator_uid;
                if creator != euid.raw() {
                    return Ok(DispatchOutcome::errno(LINUX_EACCES));
                }
            }

            queues.remove(&queue_name);
            Ok(DispatchOutcome::Returned { value: 0 })
        }

        /// mq_timedsend(mqd, msg_ptr, msg_len, prio, abs_timeout). Enqueue a
        /// message. EBADF if the queue was opened O_RDONLY; EMSGSIZE if
        /// `msg_len > mq_msgsize`.
        fn mq_timedsend(this, cx, mqd: u64, msg_ptr: GuestPtr, msg_len: u64, prio: u64, abs_timeout: GuestPtr) {
            let mq = match this.mq_description(mqd as i32) {
                Ok(v) => v,
                Err(errno) => return Ok(DispatchOutcome::errno(errno)),
            };
            let access = mq.base.status_flags() & LINUX_O_ACCMODE;
            if access == LINUX_O_RDONLY {
                return Ok(DispatchOutcome::errno(LINUX_EBADF));
            }
            let len = msg_len as usize;
            let msg_size = mq.queue.state.lock().msg_size;
            if len > msg_size {
                return Ok(DispatchOutcome::errno(crate::linux_abi::LINUX_EMSGSIZE));
            }
            if prio >= 32768 {
                return Ok(DispatchOutcome::errno(LINUX_EINVAL));
            }
            let payload = match cx.memory.read_bytes(msg_ptr.0, len) {
                Ok(b) => b,
                Err(_) => return Ok(DispatchOutcome::errno(LINUX_EFAULT)),
            };

            let deadline = match read_abs_deadline(&*cx.memory, abs_timeout.0) {
                Ok(d) => d,
                Err(errno) => return Ok(DispatchOutcome::errno(errno)),
            };

            let nonblock = mq.base.is_nonblocking();
            let tid = cx.tid();
            loop {
                if mq_wait_interrupted(this, cx.kernel, tid) {
                    return Ok(DispatchOutcome::errno(LINUX_EINTR));
                }
                {
                    let mut state = mq.queue.state.lock();
                    if state.messages.len() < state.max_msg {
                        let was_empty = state.messages.is_empty();
                        let notify = if was_empty { state.notify.take() } else { None };
                        let seq = state.next_seq;
                        state.next_seq = state.next_seq.wrapping_add(1);
                        let pos = state
                            .messages
                            .iter()
                            .position(|m| m.prio < prio as u32)
                            .unwrap_or(state.messages.len());
                        state.messages.insert(
                            pos,
                            MqueueMessage {
                                prio: prio as u32,
                                seq,
                                payload,
                            },
                        );
                        drop(state);
                        mq.queue.changed.notify_all();
                        if let Some(delivery) = notify {
                            deliver_notify(this, cx.kernel, tid, delivery);
                        }
                        return Ok(DispatchOutcome::Returned { value: 0 });
                    }
                    if nonblock {
                        return Ok(DispatchOutcome::errno(LINUX_EAGAIN));
                    }
                    if deadline_expired(deadline) {
                        return Ok(DispatchOutcome::errno(LINUX_ETIMEDOUT));
                    }
                    mq.queue
                        .changed
                        .wait_for(&mut state, std::time::Duration::from_millis(10));
                }
            }
        }

        /// mq_timedreceive(mqd, buf_ptr, buf_len, prio_ptr, abs_timeout).
        /// Dequeue the highest-priority message.
        fn mq_timedreceive(this, cx, mqd: u64, buf_ptr: GuestPtr, buf_len: u64, prio_ptr: GuestPtr, abs_timeout: GuestPtr) {
            let mq = match this.mq_description(mqd as i32) {
                Ok(v) => v,
                Err(errno) => return Ok(DispatchOutcome::errno(errno)),
            };
            let access = mq.base.status_flags() & LINUX_O_ACCMODE;
            if access == LINUX_O_WRONLY {
                return Ok(DispatchOutcome::errno(LINUX_EBADF));
            }
            let msg_size = mq.queue.state.lock().msg_size;
            if (buf_len as usize) < msg_size {
                return Ok(DispatchOutcome::errno(crate::linux_abi::LINUX_EMSGSIZE));
            }
            let deadline = match read_abs_deadline(&*cx.memory, abs_timeout.0) {
                Ok(d) => d,
                Err(errno) => return Ok(DispatchOutcome::errno(errno)),
            };

            let nonblock = mq.base.is_nonblocking();
            let tid = cx.tid();
            loop {
                if mq_wait_interrupted(this, cx.kernel, tid) {
                    return Ok(DispatchOutcome::errno(LINUX_EINTR));
                }
                {
                    let mut state = mq.queue.state.lock();
                    if !state.messages.is_empty() {
                        let msg = state.messages.remove(0);
                        drop(state);
                        mq.queue.changed.notify_all();

                        if prio_ptr.0 != 0
                            && cx
                                .memory
                                .write_bytes(prio_ptr.0, &msg.prio.to_le_bytes())
                                .is_err()
                        {
                            return Ok(DispatchOutcome::errno(LINUX_EFAULT));
                        }
                        let n = msg.payload.len();
                        if !msg.payload.is_empty()
                            && cx.memory.write_bytes(buf_ptr.0, &msg.payload).is_err()
                        {
                            return Ok(DispatchOutcome::errno(LINUX_EFAULT));
                        }
                        return Ok(DispatchOutcome::Returned { value: n as i64 });
                    }
                    if nonblock {
                        return Ok(DispatchOutcome::errno(LINUX_EAGAIN));
                    }
                    if deadline_expired(deadline) {
                        return Ok(DispatchOutcome::errno(LINUX_ETIMEDOUT));
                    }
                    mq.queue
                        .changed
                        .wait_for(&mut state, std::time::Duration::from_millis(10));
                }
            }
        }

        /// mq_notify(mqd, sevp). Register (NULL → unregister) a one-shot
        /// notification for the empty→non-empty transition.
        fn mq_notify(this, cx, mqd: u64, sevp: GuestPtr) {
            let caller = this.mqueue_notify_target(cx.kernel);
            let mqd = match i32::try_from(mqd) {
                Ok(mqd) => mqd,
                Err(_) => return Ok(DispatchOutcome::errno(LINUX_EBADF)),
            };

            if sevp.0 == 0 {
                let description = match this.mqueue_file_description(mqd) {
                    Ok(description) => description,
                    Err(errno) => return Ok(DispatchOutcome::errno(errno)),
                };
                // Close takes description WRITE then queue. Keep the matching
                // READ->queue order until publication, so either unregister
                // wins before close (and close observes no record) or close
                // wins and this sees Closed/EBADF. There is no stale midpoint.
                let open = description.read();
                let OpenDescription::Mqueue { queue, .. } = &*open else {
                    return Ok(DispatchOutcome::errno(LINUX_EBADF));
                };
                let registration = description.id();
                let mut state = queue.state.lock();
                let delivery = match state.notify.take() {
                    Some(MqueueNotify::Signal {
                        registration: owner,
                        target,
                        ..
                    }) if owner == registration && target.same_owner(&caller) => None,
                    Some(MqueueNotify::Thread {
                        registration: owner,
                        target,
                        mut data,
                    }) if owner == registration && target.same_owner(&caller) => {
                        data[NOTIFY_DATA_SIZE - 1] = MQ_NOTIFY_EVENT_REMOVED as u8;
                        Some(MqueueNotify::Thread {
                            registration: owner,
                            target,
                            data,
                        })
                    }
                    other => {
                        state.notify = other;
                        None
                    }
                };
                drop(state);
                drop(open);
                if let Some(delivery) = delivery {
                    deliver_notify(this, cx.kernel, cx.tid(), delivery);
                }
                return Ok(DispatchOutcome::Returned { value: 0 });
            }

            let sev: crate::linux_abi::LinuxSigevent =
                match read_kernel_struct(&*cx.memory, sevp.0) {
                    Ok(s) => s,
                    Err(errno) => return Ok(DispatchOutcome::errno(errno)),
                };
            let sigev_notify = sev.sigev_notify;
            let sigev_value = sev.sigev_value;
            let notify_record = match sigev_notify {
                crate::linux_abi::LINUX_SIGEV_NONE => None,
                crate::linux_abi::LINUX_SIGEV_SIGNAL => {
                    let s = sev.sigev_signo;
                    if !(1..=64).contains(&s) {
                        return Ok(DispatchOutcome::errno(LINUX_EINVAL));
                    }
                    Some(MqueueNotifySpec::Signal {
                        target: caller,
                        signo: s,
                        value: sigev_value as i64,
                    })
                }
                crate::linux_abi::LINUX_SIGEV_THREAD => {
                    let fd = sev.sigev_signo;
                    let target = match caller {
                        MqueueNotifyTarget::Kernel(task, ()) => {
                            match this.retain_netlink_description(fd) {
                                Ok(description) => MqueueNotifyTarget::Kernel(task, description),
                                Err(errno) => return Ok(DispatchOutcome::errno(errno)),
                            }
                        }
                        MqueueNotifyTarget::Host(pid, ()) => {
                            if fd < 0 || !this.fd_is_netlink(fd) {
                                return Ok(DispatchOutcome::errno(LINUX_EBADF));
                            }
                            MqueueNotifyTarget::Host(pid, fd)
                        }
                    };
                    let bytes = match cx.memory.read_bytes(sigev_value, NOTIFY_DATA_SIZE) {
                        Ok(bytes) => bytes,
                        Err(_) => return Ok(DispatchOutcome::errno(LINUX_EFAULT)),
                    };
                    let mut data = [0u8; NOTIFY_DATA_SIZE];
                    data.copy_from_slice(&bytes);
                    data[NOTIFY_DATA_SIZE - 1] = MQ_NOTIFY_EVENT_MSG as u8;
                    Some(MqueueNotifySpec::Thread { target, data })
                }
                _ => return Ok(DispatchOutcome::errno(LINUX_EINVAL)),
            };

            let description = match this.mqueue_file_description(mqd) {
                Ok(description) => description,
                Err(errno) => return Ok(DispatchOutcome::errno(errno)),
            };
            // See unregister above: the read guard is the lifetime lease that
            // prevents last-close from turning the description into Closed
            // between validation and queue publication.
            let open = description.read();
            let OpenDescription::Mqueue { queue, .. } = &*open else {
                return Ok(DispatchOutcome::errno(LINUX_EBADF));
            };
            let notify_record = notify_record.map(|spec| spec.bind(description.id()));
            let mut state = queue.state.lock();
            if state.notify.is_some() {
                return Ok(DispatchOutcome::errno(crate::linux_abi::LINUX_EBUSY));
            }
            state.notify = notify_record;
            Ok(DispatchOutcome::Returned { value: 0 })
        }

        /// mq_getsetattr(mqd, newattr, oldattr).
        fn mq_getsetattr(this, cx, mqd: u64, newattr: GuestPtr, oldattr: GuestPtr) {
            let mq = match this.mq_description(mqd as i32) {
                Ok(v) => v,
                Err(errno) => return Ok(DispatchOutcome::errno(errno)),
            };

            if oldattr.0 != 0 {
                let state = mq.queue.state.lock();
                let out = crate::linux_abi::LinuxMqAttr {
                    mq_flags: if mq.base.is_nonblocking() { LINUX_O_NONBLOCK as i64 } else { 0 },
                    mq_maxmsg: state.max_msg as i64,
                    mq_msgsize: state.msg_size as i64,
                    mq_curmsgs: state.messages.len() as i64,
                    __reserved: [0; 4],
                };
                drop(state);
                if cx
                    .memory
                    .write_bytes(oldattr.0, zerocopy::IntoBytes::as_bytes(&out))
                    .is_err()
                {
                    return Ok(DispatchOutcome::errno(LINUX_EFAULT));
                }
            }

            if newattr.0 != 0 {
                let new_attr: crate::linux_abi::LinuxMqAttr =
                    match read_kernel_struct(&*cx.memory, newattr.0) {
                        Ok(a) => a,
                        Err(errno) => return Ok(DispatchOutcome::errno(errno)),
                    };
                let want_nonblock =
                    (new_attr.mq_flags as u64) & LinuxOpenFlags::NONBLOCK.bits() != 0;
                if let Some(open_file) = this.open_file(mqd as i32) {
                    let mut open = open_file.description.write();
                    let cur = open.status_flags();
                    let next = if want_nonblock {
                        cur | LINUX_O_NONBLOCK
                    } else {
                        cur & !LINUX_O_NONBLOCK
                    };
                    open.set_status_flags(next);
                }
            }

            Ok(DispatchOutcome::Returned { value: 0 })
        }
    }
}

fn deliver_notify(
    this: &SyscallDispatcher,
    context: &crate::kernel::KernelContext,
    tid: crate::thread::ThreadId,
    delivery: MqueueNotify,
) {
    match delivery {
        MqueueNotify::Signal {
            target,
            signo,
            value,
            ..
        } => match target {
            MqueueNotifyTarget::Kernel(target, ()) => {
                let Ok(signal) = crate::kernel::LinuxSignal::for_signal_number(signo) else {
                    return;
                };
                let info = crate::linux_abi::LinuxSiginfo::message_queue(
                    signo,
                    context.task().key().id.raw(),
                    context.resources().credentials().ruid().raw(),
                    value,
                );
                let _ = context
                    .kernel()
                    .post_signal_to_task_key(target, signal, Some(info));
            }
            MqueueNotifyTarget::Host(pid, ()) => {
                let info = crate::linux_abi::LinuxSiginfo::message_queue(
                    signo,
                    this.identity_pid() as i32,
                    this.cred_snapshot().ruid.raw(),
                    value,
                );
                let local_pid = this
                    .hvpatch_process()
                    .map(|_| context.task().key().id.raw())
                    .unwrap_or_else(|| std::process::id() as i32);
                if pid == local_pid {
                    this.record_pending_siginfo(context, tid, signo, info);
                    this.mark_signal_pending(context, tid, signo);
                    crate::host_signal::raise_for_self(signo);
                } else if crate::host_signal::xsig_enqueue(
                    pid,
                    signo,
                    crate::linux_abi::LINUX_SI_MESGQ,
                    this.identity_pid() as i32,
                    this.cred_snapshot().ruid.raw(),
                    value,
                    0,
                ) {
                    crate::host_signal::xsig_nudge(pid);
                } else {
                    let host_signo = crate::host_signal::linux_to_host_signum(signo);
                    unsafe { libc::kill(pid, host_signo) };
                }
            }
        },
        MqueueNotify::Thread { target, data, .. } => match target {
            MqueueNotifyTarget::Kernel(target, description) => {
                let _ = context
                    .kernel()
                    .publish_task_event_and_wake(target, || description.enqueue(&data).is_ok());
            }
            MqueueNotifyTarget::Host(pid, netlink_fd) => {
                let local_pid = this
                    .hvpatch_process()
                    .map(|_| context.task().key().id.raw())
                    .unwrap_or_else(|| std::process::id() as i32);
                if pid == local_pid {
                    let _ = this.enqueue_netlink_message(netlink_fd, &data);
                }
            }
        },
    }
}

fn mq_wait_interrupted(
    this: &SyscallDispatcher,
    context: &crate::kernel::KernelContext,
    tid: crate::thread::ThreadId,
) -> bool {
    this.has_deliverable_dispatch_pending_for_wait(context, tid, carrick_abi::WaitSigMask::NONE)
        || carrick_signal_core::xsig::xsig_has_unblocked_for_self(carrick_abi::SigBlockMask::NONE)
        || carrick_signal_core::has_pending_for(tid.raw())
}

fn read_abs_deadline(
    memory: &impl GuestMemory,
    addr: u64,
) -> Result<Option<(i64, i64)>, LinuxErrno> {
    if addr == 0 {
        return Ok(None);
    }
    let ts = read_timespec(memory, addr)?;
    if ts.tv_sec < 0 || ts.tv_nsec < 0 || ts.tv_nsec >= 1_000_000_000 {
        return Err(LINUX_EINVAL);
    }
    Ok(Some((ts.tv_sec, ts.tv_nsec)))
}

fn deadline_expired(deadline: Option<(i64, i64)>) -> bool {
    let Some((sec, nsec)) = deadline else {
        return false;
    };
    let mut now: libc::timespec = unsafe { core::mem::zeroed() };
    unsafe { libc::clock_gettime(libc::CLOCK_REALTIME, &mut now) };
    let now_sec = now.tv_sec as i64;
    let now_nsec = now.tv_nsec as i64;
    (now_sec, now_nsec) >= (sec, nsec)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    fn dispatch_call(
        dispatcher: &SyscallDispatcher,
        context: &crate::kernel::KernelContext,
        memory: &mut LinearMemory,
        number: u64,
        args: [u64; 6],
    ) -> DispatchOutcome {
        dispatcher
            .dispatch_normalized(
                context,
                SyscallRequest::new(number, SyscallArgs::from(args)),
                memory,
                &CompatReporter::default(),
                None,
            )
            .expect("mqueue test syscall must be routed")
            .expect("mqueue test syscall must dispatch")
    }

    fn returned_fd(outcome: DispatchOutcome) -> i32 {
        match outcome {
            DispatchOutcome::Returned { value } => i32::try_from(value).expect("fd fits i32"),
            other => panic!("expected fd, got {other:?}"),
        }
    }

    fn open_test_queue(
        dispatcher: &SyscallDispatcher,
        context: &crate::kernel::KernelContext,
        memory: &mut LinearMemory,
        name_address: u64,
        name: &[u8],
    ) -> i32 {
        memory.write_bytes(name_address, name).unwrap();
        returned_fd(dispatch_call(
            dispatcher,
            context,
            memory,
            180,
            [
                name_address,
                LINUX_O_RDWR | LINUX_O_CREAT | LINUX_O_EXCL,
                0o600,
                0,
                0,
                0,
            ],
        ))
    }

    fn open_existing_test_queue(
        dispatcher: &SyscallDispatcher,
        context: &crate::kernel::KernelContext,
        memory: &mut LinearMemory,
        name_address: u64,
        name: &[u8],
    ) -> i32 {
        memory.write_bytes(name_address, name).unwrap();
        returned_fd(dispatch_call(
            dispatcher,
            context,
            memory,
            180,
            [name_address, LINUX_O_RDWR, 0, 0, 0, 0],
        ))
    }

    fn open_test_netlink(
        dispatcher: &SyscallDispatcher,
        context: &crate::kernel::KernelContext,
        memory: &mut LinearMemory,
    ) -> i32 {
        returned_fd(dispatch_call(
            dispatcher,
            context,
            memory,
            198,
            [LINUX_AF_NETLINK as u64, LINUX_SOCK_DGRAM as u64, 0, 0, 0, 0],
        ))
    }

    fn register_thread_notification(
        dispatcher: &SyscallDispatcher,
        context: &crate::kernel::KernelContext,
        memory: &mut LinearMemory,
        mqd: i32,
        netlink_fd: i32,
        data: [u8; NOTIFY_DATA_SIZE],
    ) {
        use zerocopy::IntoBytes as _;

        let data_address = 0x1200;
        let sigevent_address = 0x1100;
        memory.write_bytes(data_address, &data).unwrap();
        let sigevent = crate::linux_abi::LinuxSigevent {
            sigev_value: data_address,
            sigev_signo: netlink_fd,
            sigev_notify: crate::linux_abi::LINUX_SIGEV_THREAD,
            _sigev_un: [0; 48],
        };
        memory
            .write_bytes(sigevent_address, sigevent.as_bytes())
            .unwrap();
        assert_eq!(
            dispatch_call(
                dispatcher,
                context,
                memory,
                184,
                [mqd as u64, sigevent_address, 0, 0, 0, 0],
            ),
            DispatchOutcome::Returned { value: 0 },
        );
    }

    fn register_signal_notification(
        dispatcher: &SyscallDispatcher,
        context: &crate::kernel::KernelContext,
        memory: &mut LinearMemory,
        mqd: i32,
        signo: i32,
        value: i64,
        sigevent_address: u64,
    ) {
        use zerocopy::IntoBytes as _;

        let sigevent = crate::linux_abi::LinuxSigevent {
            sigev_value: value as u64,
            sigev_signo: signo,
            sigev_notify: crate::linux_abi::LINUX_SIGEV_SIGNAL,
            _sigev_un: [0; 48],
        };
        memory
            .write_bytes(sigevent_address, sigevent.as_bytes())
            .unwrap();
        assert_eq!(
            dispatch_call(
                dispatcher,
                context,
                memory,
                184,
                [mqd as u64, sigevent_address, 0, 0, 0, 0],
            ),
            DispatchOutcome::Returned { value: 0 },
        );
    }

    fn send_test_message(
        dispatcher: &SyscallDispatcher,
        context: &crate::kernel::KernelContext,
        memory: &mut LinearMemory,
        mqd: i32,
        message_address: u64,
    ) {
        memory.write_bytes(message_address, b"x").unwrap();
        assert_eq!(
            dispatch_call(
                dispatcher,
                context,
                memory,
                182,
                [mqd as u64, message_address, 1, 0, 0, 0],
            ),
            DispatchOutcome::Returned { value: 0 },
        );
    }

    fn fork_test_task(
        parent: &crate::kernel::KernelContext,
        registry_id: i32,
        name: &str,
    ) -> crate::kernel::KernelContext {
        parent
            .kernel()
            .reserve_fork(
                parent,
                crate::kernel::ClonePlan::from_flags(carrick_abi::LinuxCloneFlags::empty())
                    .unwrap(),
                name.to_owned(),
                None,
            )
            .unwrap()
            .prepare_reference(crate::thread::ThreadId::synthetic_for_tests(registry_id))
            .unwrap()
            .commit()
            .unwrap()
            .into_parts()
            .unwrap()
            .0
    }

    fn file_description(
        dispatcher: &SyscallDispatcher,
        context: &crate::kernel::KernelContext,
        fd: i32,
    ) -> Arc<crate::kernel::FileDescription> {
        super::super::resources::with_captured_resources(context, || {
            dispatcher.open_file(fd).expect("open file").description()
        })
    }

    fn mqueue_description_and_queue(
        dispatcher: &SyscallDispatcher,
        context: &crate::kernel::KernelContext,
        fd: i32,
    ) -> (Arc<crate::kernel::FileDescription>, Arc<MqueueInner>) {
        let description = file_description(dispatcher, context, fd);
        let queue = {
            let open = description.read();
            let OpenDescription::Mqueue { queue, .. } = &*open else {
                panic!("fd {fd} is not an mqueue");
            };
            Arc::clone(queue)
        };
        (description, queue)
    }

    fn close_test_fd(
        dispatcher: &SyscallDispatcher,
        context: &crate::kernel::KernelContext,
        memory: &mut LinearMemory,
        fd: i32,
    ) {
        assert_eq!(
            dispatch_call(dispatcher, context, memory, 57, [fd as u64, 0, 0, 0, 0, 0],),
            DispatchOutcome::Returned { value: 0 },
        );
    }

    fn netlink_bytes(
        dispatcher: &SyscallDispatcher,
        context: &crate::kernel::KernelContext,
        fd: i32,
    ) -> Vec<u8> {
        super::super::resources::with_captured_resources(context, || {
            let open_file = dispatcher.open_file(fd).expect("netlink fd");
            let open = open_file.description.read();
            let OpenDescription::Netlink { recv_queue, .. } = &*open else {
                panic!("fd {fd} is not netlink");
            };
            recv_queue.iter().copied().collect()
        })
    }

    #[derive(Debug)]
    struct SignalObservingWaker {
        wakes: AtomicUsize,
        pending: Arc<crate::kernel::TaskPendingSignals>,
        pending_when_woken: AtomicUsize,
    }

    impl crate::kernel::TaskWaker for SignalObservingWaker {
        fn wake_task(&self) {
            self.pending_when_woken
                .store(self.pending.pending_count(), Ordering::SeqCst);
            self.wakes.fetch_add(1, Ordering::SeqCst);
        }
    }

    #[derive(Debug)]
    struct NetlinkObservingWaker {
        wakes: AtomicUsize,
        description: Arc<crate::kernel::FileDescription>,
        bytes_when_woken: AtomicUsize,
    }

    impl crate::kernel::TaskWaker for NetlinkObservingWaker {
        fn wake_task(&self) {
            let open = self.description.read();
            let queued = match &*open {
                OpenDescription::Netlink { recv_queue, .. } => recv_queue.len(),
                _ => 0,
            };
            self.bytes_when_woken.store(queued, Ordering::SeqCst);
            self.wakes.fetch_add(1, Ordering::SeqCst);
        }
    }

    #[test]
    fn validate_names() {
        assert_eq!(validate_mqueue_name("my_queue").unwrap(), "my_queue");
        assert_eq!(validate_mqueue_name("").unwrap_err(), LINUX_ENOENT);
        assert_eq!(validate_mqueue_name("/sub").unwrap_err(), LINUX_EACCES);
        assert_eq!(validate_mqueue_name(".").unwrap_err(), LINUX_EACCES);
        assert_eq!(validate_mqueue_name("..").unwrap_err(), LINUX_EACCES);
        assert_eq!(
            validate_mqueue_name(&"a".repeat(256)).unwrap_err(),
            LINUX_ENAMETOOLONG
        );
    }

    #[test]
    fn priority_ordering_and_fifo() {
        let queue = MqueueInner::new(10, 1024, 0);
        {
            let mut state = queue.state.lock();
            let messages: [(u32, u64, &[u8]); 4] = [
                (10, 0, b"prio10_first"),
                (5, 1, b"prio5_first"),
                (10, 2, b"prio10_second"),
                (20, 3, b"prio20_only"),
            ];
            for (prio, seq, payload) in messages {
                let pos = state
                    .messages
                    .iter()
                    .position(|m| m.prio < prio)
                    .unwrap_or(state.messages.len());
                state.messages.insert(
                    pos,
                    MqueueMessage {
                        prio,
                        seq,
                        payload: payload.to_vec(),
                    },
                );
            }
        }
        let mut state = queue.state.lock();
        assert_eq!(state.messages.remove(0).payload, b"prio20_only");
        assert_eq!(state.messages.remove(0).payload, b"prio10_first");
        assert_eq!(state.messages.remove(0).payload, b"prio10_second");
        assert_eq!(state.messages.remove(0).payload, b"prio5_first");
        assert!(state.messages.is_empty());
    }

    /// Characterize the non-HVPatch route before changing its target type. A
    /// local unregister still publishes glibc's REMOVED record through the
    /// caller's CURRENT fd number, exactly as the historical host path did.
    #[test]
    fn host_thread_unregister_route_is_unchanged() {
        let dispatcher = SyscallDispatcher::new();
        let context = dispatcher.capture_one_task_context().unwrap();
        let mut memory = LinearMemory::new(0x1000, vec![0u8; 0x5000]);
        let mqd = open_test_queue(&dispatcher, &context, &mut memory, 0x1000, b"host_notify\0");
        let netlink_fd = open_test_netlink(&dispatcher, &context, &mut memory);
        let data = [0x5au8; NOTIFY_DATA_SIZE];
        register_thread_notification(&dispatcher, &context, &mut memory, mqd, netlink_fd, data);

        assert_eq!(
            dispatch_call(
                &dispatcher,
                &context,
                &mut memory,
                184,
                [mqd as u64, 0, 0, 0, 0, 0],
            ),
            DispatchOutcome::Returned { value: 0 },
        );
        let mut expected = data;
        expected[NOTIFY_DATA_SIZE - 1] = MQ_NOTIFY_EVENT_REMOVED as u8;
        assert_eq!(netlink_bytes(&dispatcher, &context, netlink_fd), expected);

        register_signal_notification(&dispatcher, &context, &mut memory, mqd, 34, 0x1234, 0x1300);
        let mq = dispatcher.mq_description(mqd).unwrap();
        let state = mq.queue.state.lock();
        assert!(matches!(
            &state.notify,
            Some(MqueueNotify::Signal {
                target: MqueueNotifyTarget::Host(pid, ()),
                ..
            }) if *pid == std::process::id() as libc::pid_t
        ));
    }

    #[test]
    fn last_mqueue_description_close_clears_registration_for_replacement_generation() {
        let dispatcher = SyscallDispatcher::new();
        let (process, _) = crate::hvpatch::process_context_for_tests(83_010);
        dispatcher.bind_hvpatch_process(process);
        let owner = dispatcher.capture_one_task_context().unwrap();
        let mut memory = LinearMemory::new(0x1000, vec![0u8; 0x6000]);
        let name = b"close_owner\0";
        let mqd = open_test_queue(&dispatcher, &owner, &mut memory, 0x1000, name);
        let (_, queue) = mqueue_description_and_queue(&dispatcher, &owner, mqd);
        register_signal_notification(&dispatcher, &owner, &mut memory, mqd, 34, 7, 0x1100);
        assert!(queue.state.lock().notify.is_some());

        close_test_fd(&dispatcher, &owner, &mut memory, mqd);
        assert!(
            queue.state.lock().notify.is_none(),
            "last close must retire the description-owned registration"
        );

        let replacement = fork_test_task(&owner, 82_010, "replacement notify owner");
        let replacement_mqd =
            open_existing_test_queue(&dispatcher, &replacement, &mut memory, 0x1000, name);
        register_signal_notification(
            &dispatcher,
            &replacement,
            &mut memory,
            replacement_mqd,
            34,
            8,
            0x1100,
        );
        assert!(queue.state.lock().notify.is_some());
    }

    #[test]
    fn dup_keeps_registration_until_last_description_reference_closes() {
        let dispatcher = SyscallDispatcher::new();
        let (process, _) = crate::hvpatch::process_context_for_tests(83_011);
        dispatcher.bind_hvpatch_process(process);
        let owner = dispatcher.capture_one_task_context().unwrap();
        let mut memory = LinearMemory::new(0x1000, vec![0u8; 0x6000]);
        let mqd = open_test_queue(&dispatcher, &owner, &mut memory, 0x1000, b"dup_owner\0");
        let (_, queue) = mqueue_description_and_queue(&dispatcher, &owner, mqd);
        let duplicate = returned_fd(dispatch_call(
            &dispatcher,
            &owner,
            &mut memory,
            23,
            [mqd as u64, 0, 0, 0, 0, 0],
        ));
        register_signal_notification(&dispatcher, &owner, &mut memory, mqd, 34, 9, 0x1100);

        close_test_fd(&dispatcher, &owner, &mut memory, mqd);
        assert!(
            queue.state.lock().notify.is_some(),
            "a dup keeps the registering open description alive"
        );
        close_test_fd(&dispatcher, &owner, &mut memory, duplicate);
        assert!(
            queue.state.lock().notify.is_none(),
            "the final reference retires the registration"
        );
    }

    #[test]
    fn closing_thread_registration_releases_retained_netlink_reference() {
        let dispatcher = SyscallDispatcher::new();
        let (process, _) = crate::hvpatch::process_context_for_tests(83_012);
        dispatcher.bind_hvpatch_process(process);
        let owner = dispatcher.capture_one_task_context().unwrap();
        let mut memory = LinearMemory::new(0x1000, vec![0u8; 0x6000]);
        let mqd = open_test_queue(&dispatcher, &owner, &mut memory, 0x1000, b"thread_owner\0");
        let (_, queue) = mqueue_description_and_queue(&dispatcher, &owner, mqd);
        let netlink_fd = open_test_netlink(&dispatcher, &owner, &mut memory);
        let netlink = file_description(&dispatcher, &owner, netlink_fd);
        let refs_before = netlink.fd_ref_count();
        register_thread_notification(
            &dispatcher,
            &owner,
            &mut memory,
            mqd,
            netlink_fd,
            [0x31; NOTIFY_DATA_SIZE],
        );
        assert_eq!(netlink.fd_ref_count(), refs_before + 1);

        close_test_fd(&dispatcher, &owner, &mut memory, mqd);
        assert!(queue.state.lock().notify.is_none());
        assert_eq!(
            netlink.fd_ref_count(),
            refs_before,
            "retiring the registration drops its retained netlink reference"
        );
    }

    #[test]
    fn another_description_for_same_queue_cannot_unregister_owner() {
        let dispatcher = SyscallDispatcher::new();
        let (process, _) = crate::hvpatch::process_context_for_tests(83_013);
        dispatcher.bind_hvpatch_process(process);
        let owner = dispatcher.capture_one_task_context().unwrap();
        let mut memory = LinearMemory::new(0x1000, vec![0u8; 0x6000]);
        let name = b"wrong_description\0";
        let owner_mqd = open_test_queue(&dispatcher, &owner, &mut memory, 0x1000, name);
        let other_mqd = open_existing_test_queue(&dispatcher, &owner, &mut memory, 0x1000, name);
        let (_, queue) = mqueue_description_and_queue(&dispatcher, &owner, owner_mqd);
        register_signal_notification(&dispatcher, &owner, &mut memory, owner_mqd, 34, 10, 0x1100);

        assert_eq!(
            dispatch_call(
                &dispatcher,
                &owner,
                &mut memory,
                184,
                [other_mqd as u64, 0, 0, 0, 0, 0],
            ),
            DispatchOutcome::Returned { value: 0 },
        );
        assert!(
            queue.state.lock().notify.is_some(),
            "only the exact registering open description may unregister"
        );
    }

    #[test]
    fn registration_holds_description_read_lock_until_queue_publication() {
        let dispatcher = Arc::new(SyscallDispatcher::new());
        let (process, _) = crate::hvpatch::process_context_for_tests(83_014);
        dispatcher.bind_hvpatch_process(process);
        let owner = dispatcher.capture_one_task_context().unwrap();
        let close_context = dispatcher.capture_one_task_context().unwrap();
        let mut memory = LinearMemory::new(0x1000, vec![0u8; 0x6000]);
        let mqd = open_test_queue(&dispatcher, &owner, &mut memory, 0x1000, b"close_race\0");
        let (description, queue) = mqueue_description_and_queue(&dispatcher, &owner, mqd);
        use zerocopy::IntoBytes as _;
        let sigevent = crate::linux_abi::LinuxSigevent {
            sigev_value: 11,
            sigev_signo: 34,
            sigev_notify: crate::linux_abi::LINUX_SIGEV_SIGNAL,
            _sigev_un: [0; 48],
        };
        memory.write_bytes(0x1100, sigevent.as_bytes()).unwrap();

        let queue_guard = queue.state.lock();
        let registering_dispatcher = Arc::clone(&dispatcher);
        let register_thread = std::thread::spawn(move || {
            dispatch_call(
                &registering_dispatcher,
                &owner,
                &mut memory,
                184,
                [mqd as u64, 0x1100, 0, 0, 0, 0],
            )
        });

        let deadline = std::time::Instant::now() + std::time::Duration::from_millis(250);
        while description.try_write_for_test().is_some() {
            assert!(
                std::time::Instant::now() < deadline,
                "registration dropped the description read lock before queue publication"
            );
            std::thread::yield_now();
        }

        let closing_dispatcher = Arc::clone(&dispatcher);
        let close_thread = std::thread::spawn(move || {
            let mut close_memory = LinearMemory::new(0x1000, vec![0u8; 0x1000]);
            dispatch_call(
                &closing_dispatcher,
                &close_context,
                &mut close_memory,
                57,
                [mqd as u64, 0, 0, 0, 0, 0],
            )
        });
        drop(queue_guard);

        assert_eq!(
            register_thread.join().unwrap(),
            DispatchOutcome::Returned { value: 0 }
        );
        assert_eq!(
            close_thread.join().unwrap(),
            DispatchOutcome::Returned { value: 0 }
        );
        assert!(
            queue.state.lock().notify.is_none(),
            "close linearized after registration must retire that registration"
        );
    }

    #[test]
    fn hvpatch_cross_task_signal_targets_exact_registrant_with_sender_identity() {
        let dispatcher = SyscallDispatcher::new();
        let (process, _) = crate::hvpatch::process_context_for_tests(83_001);
        dispatcher.bind_hvpatch_process(process);
        let registrant = dispatcher.capture_one_task_context().unwrap();
        let mut memory = LinearMemory::new(0x1000, vec![0u8; 0x6000]);
        let mqd = open_test_queue(
            &dispatcher,
            &registrant,
            &mut memory,
            0x1000,
            b"kernel_signal\0",
        );
        let signo = 34;
        let value = 0x1234_5678_90ab_cdefu64 as i64;
        register_signal_notification(
            &dispatcher,
            &registrant,
            &mut memory,
            mqd,
            signo,
            value,
            0x1100,
        );
        let sender = fork_test_task(&registrant, 82_001, "mq sender");
        let sender = sender
            .kernel()
            .update_credentials(&sender, |credentials| {
                credentials.set_uid_triple(
                    carrick_abi::NsUid::new(1_234),
                    carrick_abi::NsUid::new(1_234),
                    carrick_abi::NsUid::new(1_234),
                );
            })
            .unwrap();

        let target_waker = Arc::new(SignalObservingWaker {
            wakes: AtomicUsize::new(0),
            pending: registrant.shared().pending_signals(),
            pending_when_woken: AtomicUsize::new(0),
        });
        let sender_waker = Arc::new(SignalObservingWaker {
            wakes: AtomicUsize::new(0),
            pending: sender.shared().pending_signals(),
            pending_when_woken: AtomicUsize::new(0),
        });
        registrant
            .task()
            .set_waker(Arc::clone(&target_waker) as Arc<dyn crate::kernel::TaskWaker>);
        sender
            .task()
            .set_waker(Arc::clone(&sender_waker) as Arc<dyn crate::kernel::TaskWaker>);

        send_test_message(&dispatcher, &sender, &mut memory, mqd, 0x1200);

        let entries = registrant.shared().pending_signals().snapshot_entries();
        assert_eq!(entries.len(), 1);
        let pending = entries[0];
        assert_eq!(pending.signal.raw(), signo);
        let info = pending.siginfo.expect("SI_MESGQ payload");
        let info_signo = info.si_signo;
        let info_code = info.si_code;
        let info_sender = info.si_addr as u32 as i32;
        let info_uid = (info.si_addr >> 32) as u32;
        let info_value = i64::from_le_bytes(info._pad[0..8].try_into().unwrap());
        assert_eq!(info_signo, signo);
        assert_eq!(info_code, crate::linux_abi::LINUX_SI_MESGQ);
        assert_eq!(info_sender, sender.task().key().id.raw());
        assert_eq!(info_uid, 1_234);
        assert_eq!(info_value, value);
        assert!(
            sender
                .shared()
                .pending_signals()
                .snapshot_entries()
                .is_empty()
        );
        assert_eq!(target_waker.wakes.load(Ordering::SeqCst), 1);
        assert_eq!(target_waker.pending_when_woken.load(Ordering::SeqCst), 1);
        assert_eq!(sender_waker.wakes.load(Ordering::SeqCst), 0);

        let mq = dispatcher.mq_description(mqd).unwrap();
        let state = mq.queue.state.lock();
        assert!(state.notify.is_none(), "notification is one-shot");
    }

    #[test]
    fn hvpatch_thread_notification_keeps_registrants_exact_netlink_description() {
        let dispatcher = SyscallDispatcher::new();
        let (process, _) = crate::hvpatch::process_context_for_tests(83_002);
        dispatcher.bind_hvpatch_process(process);
        let registrant = dispatcher.capture_one_task_context().unwrap();
        let mut memory = LinearMemory::new(0x1000, vec![0u8; 0x7000]);
        let mqd = open_test_queue(
            &dispatcher,
            &registrant,
            &mut memory,
            0x1000,
            b"kernel_thread\0",
        );
        let netlink_fd = open_test_netlink(&dispatcher, &registrant, &mut memory);
        let mut data = [0u8; NOTIFY_DATA_SIZE];
        for (index, byte) in data.iter_mut().enumerate() {
            *byte = u8::try_from(index).unwrap();
        }
        register_thread_notification(&dispatcher, &registrant, &mut memory, mqd, netlink_fd, data);

        let sender = fork_test_task(&registrant, 82_002, "mq thread sender");
        assert_eq!(
            dispatch_call(
                &dispatcher,
                &sender,
                &mut memory,
                57,
                [netlink_fd as u64, 0, 0, 0, 0, 0],
            ),
            DispatchOutcome::Returned { value: 0 },
        );
        let replacement = open_test_netlink(&dispatcher, &sender, &mut memory);
        assert_eq!(replacement, netlink_fd, "child must recycle the fd number");

        let registrant_description = file_description(&dispatcher, &registrant, netlink_fd);
        let target_waker = Arc::new(NetlinkObservingWaker {
            wakes: AtomicUsize::new(0),
            description: Arc::clone(&registrant_description),
            bytes_when_woken: AtomicUsize::new(0),
        });
        let sender_waker = Arc::new(SignalObservingWaker {
            wakes: AtomicUsize::new(0),
            pending: sender.shared().pending_signals(),
            pending_when_woken: AtomicUsize::new(0),
        });
        registrant
            .task()
            .set_waker(Arc::clone(&target_waker) as Arc<dyn crate::kernel::TaskWaker>);
        sender
            .task()
            .set_waker(Arc::clone(&sender_waker) as Arc<dyn crate::kernel::TaskWaker>);

        send_test_message(&dispatcher, &sender, &mut memory, mqd, 0x1300);

        data[NOTIFY_DATA_SIZE - 1] = MQ_NOTIFY_EVENT_MSG as u8;
        assert_eq!(netlink_bytes(&dispatcher, &registrant, netlink_fd), data);
        assert!(
            netlink_bytes(&dispatcher, &sender, replacement).is_empty(),
            "the sender's recycled fd must not receive the registrant's event",
        );
        assert_eq!(target_waker.wakes.load(Ordering::SeqCst), 1);
        assert_eq!(
            target_waker.bytes_when_woken.load(Ordering::SeqCst),
            NOTIFY_DATA_SIZE,
            "the record must be published before the exact target wakes",
        );
        assert_eq!(sender_waker.wakes.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn hvpatch_unregister_and_delivery_never_follow_reused_pid() {
        let dispatcher = SyscallDispatcher::new();
        let (process, _) = crate::hvpatch::process_context_for_tests(83_003);
        dispatcher.bind_hvpatch_process(process);
        let root = dispatcher.capture_one_task_context().unwrap();
        let root_binding = root.task_binding();
        let root_tid = root.thread().key().tid;
        let mut memory = LinearMemory::new(0x1000, vec![0u8; 0x6000]);
        let mqd = open_test_queue(
            &dispatcher,
            &root,
            &mut memory,
            0x1000,
            b"kernel_generation\0",
        );
        let registrant = fork_test_task(&root, 82_003, "old mq registrant");
        let old_key = registrant.task().key();
        register_signal_notification(
            &dispatcher,
            &registrant,
            &mut memory,
            mqd,
            34,
            0x55aa,
            0x1100,
        );
        {
            let mq = super::super::resources::with_captured_resources(&root, || {
                dispatcher.mq_description(mqd).unwrap()
            });
            let state = mq.queue.state.lock();
            assert!(matches!(
                &state.notify,
                Some(MqueueNotify::Signal {
                    target: MqueueNotifyTarget::Kernel(target, ()),
                    ..
                }) if *target == old_key
            ));
        }

        root.kernel()
            .exit_task_key_eventually(
                old_key,
                crate::kernel::LinuxWaitStatus::from_wait_encoding(0),
            )
            .unwrap();
        drop(registrant);
        assert!(matches!(
            root.kernel().wait_child(
                root.task().key().id,
                Some(old_key.id),
                crate::kernel::WaitMode::Consume,
            ),
            Ok(crate::kernel::WaitOutcome::Exited(_))
        ));
        root.kernel().sweep_retired_threads();
        root.kernel().ids().set_next_for_tests(old_key.id.raw());
        let fresh_root = root_binding.capture(root_tid).unwrap();
        let replacement = fork_test_task(&fresh_root, 82_004, "replacement mq task");
        assert_eq!(replacement.task().key().id, old_key.id);
        assert_ne!(replacement.task().key(), old_key);

        assert_eq!(
            dispatch_call(
                &dispatcher,
                &replacement,
                &mut memory,
                184,
                [mqd as u64, 0, 0, 0, 0, 0],
            ),
            DispatchOutcome::Returned { value: 0 },
        );
        {
            let mq = super::super::resources::with_captured_resources(&fresh_root, || {
                dispatcher.mq_description(mqd).unwrap()
            });
            let state = mq.queue.state.lock();
            assert!(
                matches!(
                    &state.notify,
                    Some(MqueueNotify::Signal {
                        target: MqueueNotifyTarget::Kernel(target, ()),
                        ..
                    }) if *target == old_key
                ),
                "the reused pid does not own the old generation's registration"
            );
        }

        let replacement_waker = Arc::new(SignalObservingWaker {
            wakes: AtomicUsize::new(0),
            pending: replacement.shared().pending_signals(),
            pending_when_woken: AtomicUsize::new(0),
        });
        replacement
            .task()
            .set_waker(Arc::clone(&replacement_waker) as Arc<dyn crate::kernel::TaskWaker>);
        send_test_message(&dispatcher, &fresh_root, &mut memory, mqd, 0x1200);
        assert!(
            replacement
                .shared()
                .pending_signals()
                .snapshot_entries()
                .is_empty()
        );
        assert_eq!(replacement_waker.wakes.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn mqueue_syscall_round_trip() {
        let dispatcher = SyscallDispatcher::new();
        let kernel = dispatcher.capture_one_task_context().unwrap();
        let reporter = CompatReporter::default();
        let mut memory = LinearMemory::new(0x1000, vec![0u8; 0x4000]);

        memory.write_bytes(0x1000, b"test_q\0").unwrap();

        let open_res = dispatcher
            .dispatch_normalized(
                &kernel,
                SyscallRequest::new(
                    180,
                    SyscallArgs::from([
                        0x1000,
                        LINUX_O_RDWR | LINUX_O_CREAT | LINUX_O_EXCL,
                        0o600,
                        0,
                        0,
                        0,
                    ]),
                ),
                &mut memory,
                &reporter,
                None,
            )
            .unwrap()
            .unwrap();
        let fd = match open_res {
            DispatchOutcome::Returned { value } => value as i32,
            other => panic!("expected fd, got {other:?}"),
        };
        assert!(fd >= 0);

        memory.write_bytes(0x1100, b"hello world").unwrap();

        let send_res = dispatcher
            .dispatch_normalized(
                &kernel,
                SyscallRequest::new(182, SyscallArgs::from([fd as u64, 0x1100, 11, 5, 0, 0])),
                &mut memory,
                &reporter,
                None,
            )
            .unwrap()
            .unwrap();
        assert_eq!(send_res, DispatchOutcome::Returned { value: 0 });

        let recv_res = dispatcher
            .dispatch_normalized(
                &kernel,
                SyscallRequest::new(
                    183,
                    SyscallArgs::from([fd as u64, 0x1200, 8192, 0x1300, 0, 0]),
                ),
                &mut memory,
                &reporter,
                None,
            )
            .unwrap()
            .unwrap();
        assert_eq!(recv_res, DispatchOutcome::Returned { value: 11 });

        let read_back = memory.read_bytes(0x1200, 11).unwrap();
        assert_eq!(read_back, b"hello world");
        let prio_bytes = memory.read_bytes(0x1300, 4).unwrap();
        let prio = u32::from_le_bytes([prio_bytes[0], prio_bytes[1], prio_bytes[2], prio_bytes[3]]);
        assert_eq!(prio, 5);

        let unlink_res = dispatcher
            .dispatch_normalized(
                &kernel,
                SyscallRequest::new(181, SyscallArgs::from([0x1000, 0, 0, 0, 0, 0])),
                &mut memory,
                &reporter,
                None,
            )
            .unwrap()
            .unwrap();
        assert_eq!(unlink_res, DispatchOutcome::Returned { value: 0 });
    }
}
