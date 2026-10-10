//! In-ring System V IPC and POSIX message queue family.
use crate::abi::entry::SyscallResult;
use crate::lifecycle::UserCopy;
use carrick_guest_arch::UserVa;

pub const EPERM: i64 = -1;
pub const ENOENT: i64 = -2;
pub const ESRCH: i64 = -3;
pub const EINTR: i64 = -4;
pub const E2BIG: i64 = -7;
pub const EAGAIN: i64 = -11;
pub const EACCES: i64 = -13;
pub const EFAULT: i64 = -14;
pub const EEXIST: i64 = -17;
pub const EINVAL: i64 = -22;
pub const ENOSPC: i64 = -28;
pub const ERANGE: i64 = -34;
pub const ENOSYS: i64 = -38;
pub const ENOMSG: i64 = -42;
pub const EIDRM: i64 = -43;
pub const EMSGSIZE: i64 = -90;

pub const IPC_CREAT: i32 = 0o1000;
pub const IPC_EXCL: i32 = 0o2000;
pub const IPC_NOWAIT: i32 = 0o4000;

pub const IPC_RMID: i32 = 0;
pub const IPC_SET: i32 = 1;
pub const IPC_STAT: i32 = 2;
pub const IPC_INFO: i32 = 3;

pub const MSG_STAT: i32 = 11;
pub const MSG_INFO: i32 = 12;
pub const MSG_NOERROR: i32 = 0o10000;
pub const MSG_EXCEPT: i32 = 0o20000;

pub const SEM_STAT: i32 = 18;
pub const SEM_INFO: i32 = 19;
pub const GETPID: i32 = 11;
pub const GETVAL: i32 = 12;
pub const GETALL: i32 = 13;
pub const GETNCNT: i32 = 14;
pub const GETZCNT: i32 = 15;
pub const SETVAL: i32 = 16;
pub const SETALL: i32 = 17;

pub const SHM_STAT: i32 = 13;
pub const SHM_INFO: i32 = 14;
pub const SHM_RDONLY: i32 = 0o10000;
pub const SHM_RND: i32 = 0o20000;
pub const SHM_REMAP: i32 = 0o40000;

pub const O_RDONLY: i32 = 0;
pub const O_WRONLY: i32 = 1;
pub const O_RDWR: i32 = 2;
pub const O_CREAT: i32 = 64;
pub const O_EXCL: i32 = 128;
pub const O_NONBLOCK: i32 = 2048;

pub const MSGMAX: usize = 8192;
pub const MSGMNB: usize = 16384;
pub const MSGMNI: usize = 32000;

pub const SEMMSL: usize = 32000;
pub const SEMMNI: usize = 32000;
pub const SEMMNS: usize = 1024000000;
pub const SEMOPM: usize = 500;
pub const SEMVMX: u16 = 32767;

pub const SHMMIN: usize = 1;
pub const SHMMAX: usize = usize::MAX - 4096;
pub const SHMMNI: usize = 4096;
pub const SHMALL: usize = usize::MAX / 4096;

pub const MQ_MAXMSG: i64 = 32768;
pub const MQ_MSGSIZE: i64 = 1048576;
pub const MQ_PRIO_MAX: u32 = 32768;

#[repr(C)]
#[derive(Clone, Copy, Default, PartialEq, Eq)]
#[cfg_attr(test, derive(Debug))]
pub struct LinuxIpcPerm {
    pub key: i32,
    pub uid: u32,
    pub gid: u32,
    pub cuid: u32,
    pub cgid: u32,
    pub mode: u16,
    pub __pad1: u16,
    pub seq: u16,
    pub __pad2: u16,
    pub __glibc_reserved1: u64,
    pub __glibc_reserved2: u64,
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
#[cfg_attr(test, derive(Debug))]
pub struct LinuxMsqidDs {
    pub msg_perm: LinuxIpcPerm,
    pub msg_stime: i64,
    pub msg_rtime: i64,
    pub msg_ctime: i64,
    pub msg_cbytes: u64,
    pub msg_qnum: u64,
    pub msg_qbytes: u64,
    pub msg_lspid: i32,
    pub msg_lrpid: i32,
    pub __glibc_reserved4: u64,
    pub __glibc_reserved5: u64,
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
#[cfg_attr(test, derive(Debug))]
pub struct LinuxSemidDs {
    pub sem_perm: LinuxIpcPerm,
    pub sem_otime: i64,
    pub __glibc_reserved1: u64,
    pub sem_ctime: i64,
    pub __glibc_reserved2: u64,
    pub sem_nsems: u64,
    pub __glibc_reserved3: u64,
    pub __glibc_reserved4: u64,
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
#[cfg_attr(test, derive(Debug))]
pub struct LinuxShmidDs {
    pub shm_perm: LinuxIpcPerm,
    pub shm_segsz: u64,
    pub shm_atime: i64,
    pub shm_dtime: i64,
    pub shm_ctime: i64,
    pub shm_cpid: i32,
    pub shm_lpid: i32,
    pub shm_nattch: u64,
    pub __glibc_reserved4: u64,
    pub __glibc_reserved5: u64,
}

#[repr(C, packed)]
#[derive(Clone, Copy, Default)]
#[cfg_attr(test, derive(Debug))]
pub struct LinuxSembuf {
    pub sem_num: u16,
    pub sem_op: i16,
    pub sem_flg: i16,
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
#[cfg_attr(test, derive(Debug))]
pub struct LinuxMqAttr {
    pub mq_flags: i64,
    pub mq_maxmsg: i64,
    pub mq_msgsize: i64,
    pub mq_curmsgs: i64,
    pub __pad: [i64; 4],
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum IpcCall {
    MsgGet,
    MsgCtl,
    MsgRcv,
    Msgsnd,
    SemGet,
    SemCtl,
    SemTimedOp,
    SemOp,
    ShmGet,
    ShmCtl,
    ShmAt,
    ShmDt,
    MqOpen,
    MqUnlink,
    MqTimedSend,
    MqTimedReceive,
    MqNotify,
    MqGetSetAttr,
}

pub enum IpcOutcome {
    Returned(SyscallResult),
    Suspended,
}

pub trait ProcessIpcVenue {
    fn msgget(&mut self, key: i32, msgflg: i32) -> Result<i32, i64>;
    fn msgctl(&mut self, msqid: i32, cmd: i32, buf: Option<&mut LinuxMsqidDs>) -> Result<i64, i64>;
    fn msgsnd(&mut self, msqid: i32, mtype: i64, mtext: &[u8], msgflg: i32) -> Result<(), i64>;
    fn msgrcv(
        &mut self,
        msqid: i32,
        msgp: UserVa,
        mtext_out: &mut [u8],
        msgtyp: i64,
        msgflg: i32,
    ) -> Result<(i64, usize), i64>;

    fn semget(&mut self, key: i32, nsems: i32, semflg: i32) -> Result<i32, i64>;
    fn semctl(
        &mut self,
        semid: i32,
        semnum: i32,
        cmd: i32,
        arg: u64,
        ds_out: Option<&mut LinuxSemidDs>,
    ) -> Result<i64, i64>;
    fn semop(&mut self, semid: i32, sops: &[LinuxSembuf]) -> Result<(), i64>;

    fn shmget(&mut self, key: i32, size: usize, shmflg: i32) -> Result<i32, i64>;
    fn shmctl(&mut self, shmid: i32, cmd: i32, buf: Option<&mut LinuxShmidDs>) -> Result<i64, i64>;
    fn shmat(&mut self, shmid: i32, shmaddr: u64, shmflg: i32) -> Result<u64, i64>;
    fn shmdt(&mut self, shmaddr: u64) -> Result<(), i64>;

    fn mq_open(
        &mut self,
        name: &[u8],
        oflag: i32,
        mode: u32,
        attr: Option<&LinuxMqAttr>,
    ) -> Result<i32, i64>;
    fn mq_unlink(&mut self, name: &[u8]) -> Result<(), i64>;
    fn mq_timedsend(&mut self, mqdes: i32, msg_ptr: &[u8], msg_prio: u32) -> Result<(), i64>;
    fn mq_timedreceive(
        &mut self,
        mqdes: i32,
        msg_ptr_va: UserVa,
        msg_buf: &mut [u8],
        msg_prio: &mut u32,
        msg_prio_va: UserVa,
    ) -> Result<usize, i64>;
    fn mq_notify(&mut self, mqdes: i32, sevp: u64) -> Result<(), i64>;
    fn mq_getsetattr(
        &mut self,
        mqdes: i32,
        new_attr: Option<&LinuxMqAttr>,
        old_attr: Option<&mut LinuxMqAttr>,
    ) -> Result<(), i64>;

    fn suspend_current(&mut self) -> Result<IpcOutcome, i64>;
}

pub trait IpcNative<'a>: UserCopy {
    fn arguments(&self) -> [u64; 6];
    fn process_ipc(&mut self) -> Option<&mut dyn ProcessIpcVenue>;
}

#[inline(always)]
fn ret(code: i64) -> Option<IpcOutcome> {
    Some(IpcOutcome::Returned(SyscallResult::new(code)))
}

#[inline(always)]
fn ret_res(res: Result<i64, i64>) -> Option<IpcOutcome> {
    Some(IpcOutcome::Returned(SyscallResult::new(match res {
        Ok(v) => v,
        Err(e) => e,
    })))
}

fn copy_val_in<'a, T: Copy>(native: &mut dyn IpcNative<'a>, ptr: UserVa) -> Option<T> {
    let mut val = core::mem::MaybeUninit::<T>::uninit();
    let slice = unsafe {
        core::slice::from_raw_parts_mut(val.as_mut_ptr() as *mut u8, core::mem::size_of::<T>())
    };
    if !native.copy_in(slice, ptr) {
        None
    } else {
        Some(unsafe { val.assume_init() })
    }
}

fn copy_val_out<'a, T: Copy>(native: &mut dyn IpcNative<'a>, ptr: UserVa, val: &T) -> bool {
    let slice = unsafe {
        core::slice::from_raw_parts(val as *const T as *const u8, core::mem::size_of::<T>())
    };
    native.copy_out(ptr, slice)
}

fn alloc_zeroed_vec(len: usize) -> alloc::vec::Vec<u8> {
    alloc::vec![0u8; len]
}

fn copy_str_in<'a>(
    native: &mut dyn IpcNative<'a>,
    ptr: UserVa,
    buf: &mut [u8; 256],
) -> Result<usize, Option<()>> {
    if ptr.raw() == 0 {
        return Err(None);
    }
    let mut len = 0;
    while len < 256 {
        let mut b = [0u8; 1];
        if !native.copy_in(&mut b, UserVa::new(ptr.raw().wrapping_add(len as u64))) {
            return Err(Some(()));
        }
        if b[0] == 0 {
            break;
        }
        buf[len] = b[0];
        len += 1;
    }
    if len == 0 || len >= 256 {
        return Err(None);
    }
    Ok(len)
}

fn get_mq_name<'a>(
    native: &mut dyn IpcNative<'a>,
    va: u64,
    buf: &mut [u8; 256],
) -> Result<usize, Option<i64>> {
    match copy_str_in(native, UserVa::new(va), buf) {
        Ok(l) => Ok(l),
        Err(Some(())) => Err(None),
        Err(None) => Err(Some(if va == 0 { EFAULT } else { EINVAL })),
    }
}

fn invoke_msg<'a>(
    call: IpcCall,
    args: &[u64; 6],
    native: &mut dyn IpcNative<'a>,
) -> Option<IpcOutcome> {
    match call {
        IpcCall::MsgGet => {
            let venue = native.process_ipc()?;
            ret_res(
                venue
                    .msgget(args[0] as i32, args[1] as i32)
                    .map(|id| id as i64),
            )
        }
        IpcCall::MsgCtl => {
            let msqid = args[0] as i32;
            let cmd = args[1] as i32;
            let buf_ptr = UserVa::new(args[2]);
            if (cmd == IPC_SET || cmd == IPC_STAT) && buf_ptr.raw() == 0 {
                return ret(EFAULT);
            }
            let mut ds = if cmd == IPC_SET {
                copy_val_in::<LinuxMsqidDs>(native, buf_ptr)?
            } else {
                LinuxMsqidDs::default()
            };
            let venue = native.process_ipc()?;
            match venue.msgctl(msqid, cmd, Some(&mut ds)) {
                Ok(val) => {
                    if (cmd == IPC_STAT || cmd == MSG_STAT) && !copy_val_out(native, buf_ptr, &ds) {
                        return None;
                    }
                    ret(val)
                }
                Err(e) => ret(e),
            }
        }
        IpcCall::Msgsnd => {
            let msqid = args[0] as i32;
            let msgp = UserVa::new(args[1]);
            let msgsz = args[2] as usize;
            let msgflg = args[3] as i32;
            if msgp.raw() == 0 {
                return ret(EFAULT);
            }
            if msgsz > MSGMAX {
                return ret(EINVAL);
            }
            let mtype = copy_val_in::<i64>(native, msgp)?;
            if mtype <= 0 {
                return ret(EINVAL);
            }
            let text_va = UserVa::new(msgp.raw().wrapping_add(8));
            let mut mtext = alloc_zeroed_vec(msgsz);
            if msgsz > 0 && !native.copy_in(&mut mtext, text_va) {
                return None;
            }
            let venue = native.process_ipc()?;
            match venue.msgsnd(msqid, mtype, &mtext, msgflg) {
                Ok(()) => ret(0),
                Err(EAGAIN) if msgflg & IPC_NOWAIT == 0 => venue.suspend_current().ok(),
                Err(e) => ret(e),
            }
        }
        IpcCall::MsgRcv => {
            let msqid = args[0] as i32;
            let msgp = UserVa::new(args[1]);
            let msgsz = args[2] as usize;
            let msgtyp = args[3] as i64;
            let msgflg = args[4] as i32;
            if msgp.raw() == 0 {
                return ret(EFAULT);
            }
            let mut mtext = alloc_zeroed_vec(msgsz);
            let venue = native.process_ipc()?;
            match venue.msgrcv(msqid, msgp, &mut mtext, msgtyp, msgflg) {
                Ok((mtype, bytes_copied)) => {
                    if !copy_val_out(native, msgp, &mtype) {
                        return None;
                    }
                    let text_va = UserVa::new(msgp.raw().wrapping_add(8));
                    if bytes_copied > 0 && !native.copy_out(text_va, &mtext[..bytes_copied]) {
                        return None;
                    }
                    ret(bytes_copied as i64)
                }
                Err(ENOMSG) if msgflg & IPC_NOWAIT == 0 => venue.suspend_current().ok(),
                Err(e) => ret(e),
            }
        }
        _ => None,
    }
}

fn invoke_sem<'a>(
    call: IpcCall,
    args: &[u64; 6],
    native: &mut dyn IpcNative<'a>,
) -> Option<IpcOutcome> {
    match call {
        IpcCall::SemGet => {
            let venue = native.process_ipc()?;
            ret_res(
                venue
                    .semget(args[0] as i32, args[1] as i32, args[2] as i32)
                    .map(|id| id as i64),
            )
        }
        IpcCall::SemCtl => {
            let semid = args[0] as i32;
            let semnum = args[1] as i32;
            let cmd = args[2] as i32;
            let arg = args[3];
            let mut ds = LinuxSemidDs::default();
            let venue = native.process_ipc()?;
            match venue.semctl(semid, semnum, cmd, arg, Some(&mut ds)) {
                Ok(val) => {
                    if (cmd == IPC_STAT || cmd == SEM_STAT)
                        && arg != 0
                        && !copy_val_out(native, UserVa::new(arg), &ds)
                    {
                        return None;
                    }
                    ret(val)
                }
                Err(e) => ret(e),
            }
        }
        IpcCall::SemOp | IpcCall::SemTimedOp => {
            let semid = args[0] as i32;
            let sops_ptr = UserVa::new(args[1]);
            let nsops = args[2] as usize;
            if nsops == 0 || nsops > SEMOPM {
                return ret(EINVAL);
            }
            if sops_ptr.raw() == 0 {
                return ret(EFAULT);
            }
            let byte_len = nsops * core::mem::size_of::<LinuxSembuf>();
            let mut bytes = alloc_zeroed_vec(byte_len);
            if !native.copy_in(&mut bytes, sops_ptr) {
                return None;
            }
            let sops: &[LinuxSembuf] =
                unsafe { core::slice::from_raw_parts(bytes.as_ptr() as *const LinuxSembuf, nsops) };
            let venue = native.process_ipc()?;
            match venue.semop(semid, sops) {
                Ok(()) => ret(0),
                Err(EAGAIN) => {
                    let has_nowait = sops.iter().any(|s| (s.sem_flg as i32) & IPC_NOWAIT != 0);
                    if has_nowait {
                        ret(EAGAIN)
                    } else {
                        venue.suspend_current().ok()
                    }
                }
                Err(e) => ret(e),
            }
        }
        _ => None,
    }
}

fn invoke_shm<'a>(
    call: IpcCall,
    args: &[u64; 6],
    native: &mut dyn IpcNative<'a>,
) -> Option<IpcOutcome> {
    match call {
        IpcCall::ShmGet => {
            let venue = native.process_ipc()?;
            ret_res(
                venue
                    .shmget(args[0] as i32, args[1] as usize, args[2] as i32)
                    .map(|id| id as i64),
            )
        }
        IpcCall::ShmCtl => {
            let shmid = args[0] as i32;
            let cmd = args[1] as i32;
            let buf_ptr = UserVa::new(args[2]);
            let mut ds = LinuxShmidDs::default();
            let venue = native.process_ipc()?;
            match venue.shmctl(shmid, cmd, Some(&mut ds)) {
                Ok(val) => {
                    if (cmd == IPC_STAT || cmd == SHM_STAT)
                        && buf_ptr.raw() != 0
                        && !copy_val_out(native, buf_ptr, &ds)
                    {
                        return None;
                    }
                    ret(val)
                }
                Err(e) => ret(e),
            }
        }
        IpcCall::ShmAt => {
            let venue = native.process_ipc()?;
            ret_res(
                venue
                    .shmat(args[0] as i32, args[1], args[2] as i32)
                    .map(|a| a as i64),
            )
        }
        IpcCall::ShmDt => {
            let venue = native.process_ipc()?;
            ret_res(venue.shmdt(args[0]).map(|()| 0))
        }
        _ => None,
    }
}

fn invoke_mq<'a>(
    call: IpcCall,
    args: &[u64; 6],
    native: &mut dyn IpcNative<'a>,
) -> Option<IpcOutcome> {
    match call {
        IpcCall::MqOpen => {
            let mut name_buf = [0u8; 256];
            let len = match get_mq_name(native, args[0], &mut name_buf) {
                Ok(l) => l,
                Err(Some(e)) => return ret(e),
                Err(None) => return None,
            };
            let attr_ptr = UserVa::new(args[3]);
            let attr = if attr_ptr.raw() != 0 {
                Some(copy_val_in::<LinuxMqAttr>(native, attr_ptr)?)
            } else {
                None
            };
            let venue = native.process_ipc()?;
            ret_res(
                venue
                    .mq_open(
                        &name_buf[..len],
                        args[1] as i32,
                        args[2] as u32,
                        attr.as_ref(),
                    )
                    .map(|d| d as i64),
            )
        }
        IpcCall::MqUnlink => {
            let mut name_buf = [0u8; 256];
            let len = match get_mq_name(native, args[0], &mut name_buf) {
                Ok(l) => l,
                Err(Some(e)) => return ret(e),
                Err(None) => return None,
            };
            let venue = native.process_ipc()?;
            ret_res(venue.mq_unlink(&name_buf[..len]).map(|()| 0))
        }
        IpcCall::MqTimedSend => {
            let mqdes = args[0] as i32;
            let msg_ptr = UserVa::new(args[1]);
            let msg_len = args[2] as usize;
            let msg_prio = args[3] as u32;
            if msg_ptr.raw() == 0 {
                return ret(EFAULT);
            }
            let mut buf = alloc_zeroed_vec(msg_len);
            if msg_len > 0 && !native.copy_in(&mut buf, msg_ptr) {
                return None;
            }
            let venue = native.process_ipc()?;
            match venue.mq_timedsend(mqdes, &buf, msg_prio) {
                Ok(()) => ret(0),
                Err(EAGAIN) => match venue.suspend_current() {
                    Ok(outcome) => Some(outcome),
                    Err(_) => ret(EAGAIN),
                },
                Err(e) => ret(e),
            }
        }
        IpcCall::MqTimedReceive => {
            let mqdes = args[0] as i32;
            let msg_ptr = UserVa::new(args[1]);
            let msg_len = args[2] as usize;
            let prio_ptr = UserVa::new(args[3]);
            if msg_ptr.raw() == 0 {
                return ret(EFAULT);
            }
            let mut buf = alloc_zeroed_vec(msg_len);
            let mut prio = 0u32;
            let venue = native.process_ipc()?;
            match venue.mq_timedreceive(mqdes, msg_ptr, &mut buf, &mut prio, prio_ptr) {
                Ok(bytes) => {
                    if bytes > 0 && !native.copy_out(msg_ptr, &buf[..bytes]) {
                        return None;
                    }
                    if prio_ptr.raw() != 0 && !copy_val_out(native, prio_ptr, &prio) {
                        return None;
                    }
                    ret(bytes as i64)
                }
                Err(EAGAIN) => match venue.suspend_current() {
                    Ok(outcome) => Some(outcome),
                    Err(_) => ret(EAGAIN),
                },
                Err(e) => ret(e),
            }
        }
        IpcCall::MqNotify => {
            let venue = native.process_ipc()?;
            ret_res(venue.mq_notify(args[0] as i32, args[1]).map(|()| 0))
        }
        IpcCall::MqGetSetAttr => {
            let new_attr_ptr = UserVa::new(args[1]);
            let old_attr_ptr = UserVa::new(args[2]);
            let new_attr = if new_attr_ptr.raw() != 0 {
                Some(copy_val_in::<LinuxMqAttr>(native, new_attr_ptr)?)
            } else {
                None
            };
            let mut old_attr = LinuxMqAttr::default();
            let venue = native.process_ipc()?;
            match venue.mq_getsetattr(args[0] as i32, new_attr.as_ref(), Some(&mut old_attr)) {
                Ok(()) => {
                    if old_attr_ptr.raw() != 0 && !copy_val_out(native, old_attr_ptr, &old_attr) {
                        return None;
                    }
                    ret(0)
                }
                Err(e) => ret(e),
            }
        }
        _ => None,
    }
}

pub fn invoke<'a>(call: IpcCall, native: &mut dyn IpcNative<'a>) -> Option<IpcOutcome> {
    let args = native.arguments();
    match call {
        IpcCall::MsgGet | IpcCall::MsgCtl | IpcCall::Msgsnd | IpcCall::MsgRcv => {
            invoke_msg(call, &args, native)
        }
        IpcCall::SemGet | IpcCall::SemCtl | IpcCall::SemOp | IpcCall::SemTimedOp => {
            invoke_sem(call, &args, native)
        }
        IpcCall::ShmGet | IpcCall::ShmCtl | IpcCall::ShmAt | IpcCall::ShmDt => {
            invoke_shm(call, &args, native)
        }
        IpcCall::MqOpen
        | IpcCall::MqUnlink
        | IpcCall::MqTimedSend
        | IpcCall::MqTimedReceive
        | IpcCall::MqNotify
        | IpcCall::MqGetSetAttr => invoke_mq(call, &args, native),
    }
}
