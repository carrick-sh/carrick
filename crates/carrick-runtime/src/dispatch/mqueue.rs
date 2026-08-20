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

#[derive(Clone, Debug)]
pub enum MqueueNotify {
    Signal {
        pid: i32,
        signo: i32,
        value: i64,
    },
    Thread {
        pid: i32,
        netlink_fd: i32,
        data: [u8; NOTIFY_DATA_SIZE],
    },
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
            let caller_pid = this
                .hvpatch_process()
                .map(|_| cx.kernel.task().key().id.raw())
                .unwrap_or_else(|| std::process::id() as i32);

            if sevp.0 == 0 {
                let mq = match this.mq_description(mqd as i32) {
                    Ok(v) => v,
                    Err(errno) => return Ok(DispatchOutcome::errno(errno)),
                };
                let mut state = mq.queue.state.lock();
                let delivery = match state.notify.take() {
                    Some(MqueueNotify::Signal { pid, .. }) if pid == caller_pid => None,
                    Some(MqueueNotify::Thread {
                        pid,
                        netlink_fd,
                        mut data,
                    }) if pid == caller_pid => {
                        data[NOTIFY_DATA_SIZE - 1] = MQ_NOTIFY_EVENT_REMOVED as u8;
                        Some(MqueueNotify::Thread {
                            pid,
                            netlink_fd,
                            data,
                        })
                    }
                    other => {
                        state.notify = other;
                        None
                    }
                };
                drop(state);
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
                    Some(MqueueNotify::Signal {
                        pid: caller_pid,
                        signo: s,
                        value: sigev_value as i64,
                    })
                }
                crate::linux_abi::LINUX_SIGEV_THREAD => {
                    let fd = sev.sigev_signo;
                    if fd < 0 || !this.fd_is_netlink(fd) {
                        return Ok(DispatchOutcome::errno(LINUX_EBADF));
                    }
                    let bytes = match cx.memory.read_bytes(sigev_value, NOTIFY_DATA_SIZE) {
                        Ok(bytes) => bytes,
                        Err(_) => return Ok(DispatchOutcome::errno(LINUX_EFAULT)),
                    };
                    let mut data = [0u8; NOTIFY_DATA_SIZE];
                    data.copy_from_slice(&bytes);
                    data[NOTIFY_DATA_SIZE - 1] = MQ_NOTIFY_EVENT_MSG as u8;
                    Some(MqueueNotify::Thread {
                        pid: caller_pid,
                        netlink_fd: fd,
                        data,
                    })
                }
                _ => return Ok(DispatchOutcome::errno(LINUX_EINVAL)),
            };

            let mq = match this.mq_description(mqd as i32) {
                Ok(v) => v,
                Err(errno) => return Ok(DispatchOutcome::errno(errno)),
            };
            let mut state = mq.queue.state.lock();
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
        MqueueNotify::Signal { pid, signo, value } => {
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
        MqueueNotify::Thread {
            pid,
            netlink_fd,
            data,
        } => {
            let local_pid = this
                .hvpatch_process()
                .map(|_| context.task().key().id.raw())
                .unwrap_or_else(|| std::process::id() as i32);
            if pid == local_pid {
                let _ = this.enqueue_netlink_message(netlink_fd, &data);
            }
        }
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
