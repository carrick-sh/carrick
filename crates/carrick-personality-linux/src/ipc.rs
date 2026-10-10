//! In-ring System V IPC family (SysV messages and semaphores).
extern crate alloc;

use alloc::vec::Vec;
use core::time::Duration;

use crate::abi::entry::SyscallResult;
use crate::lifecycle::UserCopy;
use carrick_guest_arch::UserVa;
pub use carrick_syscall_abi::ipc::{
    GETALL, GETNCNT, GETPID, GETVAL, GETZCNT, IPC_CREAT, IPC_EXCL, IPC_INFO, IPC_NOWAIT,
    IPC_PRIVATE, IPC_RMID, IPC_SET, IPC_STAT, LinuxIpcPerm, LinuxMsginfo, LinuxMsqidDs,
    LinuxSembuf, LinuxSemidDs, LinuxSeminfo, MSG_EXCEPT, MSG_INFO, MSG_NOERROR, MSG_STAT, MSGMAX,
    MSGMNB, MSGMNI, SEM_INFO, SEM_STAT, SEM_UNDO, SEMMNI, SEMMNS, SEMMSL, SEMOPM, SEMVMX, SETALL,
    SETVAL,
};
use carrick_syscall_abi::{LINUX_E2BIG, LINUX_EFAULT, LINUX_EINVAL, LINUX_ENOSYS, LinuxErrno};

#[repr(C)]
#[derive(Clone, Copy, Default, Debug)]
pub struct LinuxTimespec {
    pub tv_sec: i64,
    pub tv_nsec: i64,
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
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum IpcOutcome {
    Returned(SyscallResult),
    Suspended,
}

pub type MsgrcvMessage = (i64, Vec<u8>);
pub type MsgrcvResult = Result<(IpcOutcome, Option<MsgrcvMessage>), i64>;

pub trait ProcessIpcVenue {
    fn msgget(&mut self, key: i32, msgflg: i32) -> Result<i32, i64>;
    fn msgctl(&mut self, msqid: i32, cmd: i32, buf: Option<&mut LinuxMsqidDs>) -> Result<i64, i64>;
    fn msgctl_info(&mut self, cmd: i32, buf: &mut LinuxMsginfo) -> Result<i64, i64>;
    fn msgsnd(
        &mut self,
        msqid: i32,
        mtype: i64,
        mtext: &[u8],
        msgflg: i32,
    ) -> Result<IpcOutcome, i64>;
    fn msgrcv(
        &mut self,
        msqid: i32,
        msgp: UserVa,
        msgtyp: i64,
        msgflg: i32,
        msgsz: usize,
    ) -> MsgrcvResult;
    fn msgrcv_restore(&mut self, msqid: i32, mtype: i64, data: Vec<u8>) -> Result<(), i64>;

    fn semget(&mut self, key: i32, nsems: i32, semflg: i32) -> Result<i32, i64>;
    fn sem_nsems(&mut self, semid: i32) -> Result<usize, i64>;
    fn semctl_rmid(&mut self, semid: i32) -> Result<i64, i64>;
    fn semctl_stat(
        &mut self,
        semid: i32,
        semnum: i32,
        cmd: i32,
        ds: &mut LinuxSemidDs,
    ) -> Result<i64, i64>;
    fn semctl_set(&mut self, semid: i32, ds: &LinuxSemidDs) -> Result<i64, i64>;
    fn semctl_info(&mut self, cmd: i32, info: &mut LinuxSeminfo) -> Result<i64, i64>;
    fn semctl_getval(&mut self, semid: i32, semnum: i32) -> Result<i64, i64>;
    fn semctl_setval(&mut self, semid: i32, semnum: i32, val: u64) -> Result<i64, i64>;
    fn semctl_getpid(&mut self, semid: i32, semnum: i32) -> Result<i64, i64>;
    fn semctl_getncnt(&mut self, semid: i32, semnum: i32) -> Result<i64, i64>;
    fn semctl_getzcnt(&mut self, semid: i32, semnum: i32) -> Result<i64, i64>;
    fn semctl_getall(&mut self, semid: i32, out: &mut [u16]) -> Result<i64, i64>;
    fn semctl_setall(&mut self, semid: i32, vals: &[u16]) -> Result<i64, i64>;
    fn semop(
        &mut self,
        semid: i32,
        sops: &[LinuxSembuf],
        timeout: Option<Duration>,
    ) -> Result<IpcOutcome, i64>;
}

pub trait IpcNative<'a>: UserCopy {
    fn arguments(&self) -> [u64; 6];
    fn process_ipc(&mut self) -> Option<&mut dyn ProcessIpcVenue>;
}

#[inline(always)]
fn ret(code: i64) -> IpcOutcome {
    IpcOutcome::Returned(SyscallResult::new(code))
}

#[inline(always)]
fn ret_errno(errno: LinuxErrno) -> IpcOutcome {
    ret(errno.guest_retval())
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

fn invoke_msg<'a>(call: IpcCall, args: &[u64; 6], native: &mut dyn IpcNative<'a>) -> IpcOutcome {
    match call {
        IpcCall::MsgGet => {
            let Some(venue) = native.process_ipc() else {
                return ret_errno(LINUX_ENOSYS);
            };
            match venue.msgget(args[0] as i32, args[1] as i32) {
                Ok(id) => ret(id as i64),
                Err(e) => ret(e),
            }
        }
        IpcCall::MsgCtl => {
            let msqid = args[0] as i32;
            let cmd = args[1] as i32;
            let buf_ptr = UserVa::new(args[2]);
            match cmd {
                IPC_INFO | MSG_INFO => {
                    if buf_ptr.raw() == 0 {
                        return ret_errno(LINUX_EFAULT);
                    }
                    let mut info = LinuxMsginfo::default();
                    let res = {
                        let Some(venue) = native.process_ipc() else {
                            return ret_errno(LINUX_ENOSYS);
                        };
                        venue.msgctl_info(cmd, &mut info)
                    };
                    match res {
                        Ok(val) => {
                            if !copy_val_out(native, buf_ptr, &info) {
                                return ret_errno(LINUX_EFAULT);
                            }
                            ret(val)
                        }
                        Err(e) => ret(e),
                    }
                }
                IPC_STAT | MSG_STAT => {
                    if buf_ptr.raw() == 0 {
                        return ret_errno(LINUX_EFAULT);
                    }
                    let mut ds = LinuxMsqidDs::default();
                    let res = {
                        let Some(venue) = native.process_ipc() else {
                            return ret_errno(LINUX_ENOSYS);
                        };
                        venue.msgctl(msqid, cmd, Some(&mut ds))
                    };
                    match res {
                        Ok(val) => {
                            if !copy_val_out(native, buf_ptr, &ds) {
                                return ret_errno(LINUX_EFAULT);
                            }
                            ret(val)
                        }
                        Err(e) => ret(e),
                    }
                }
                IPC_SET => {
                    if buf_ptr.raw() == 0 {
                        return ret_errno(LINUX_EFAULT);
                    }
                    let Some(mut ds) = copy_val_in::<LinuxMsqidDs>(native, buf_ptr) else {
                        return ret_errno(LINUX_EFAULT);
                    };
                    let Some(venue) = native.process_ipc() else {
                        return ret_errno(LINUX_ENOSYS);
                    };
                    match venue.msgctl(msqid, cmd, Some(&mut ds)) {
                        Ok(val) => ret(val),
                        Err(e) => ret(e),
                    }
                }
                IPC_RMID => {
                    let Some(venue) = native.process_ipc() else {
                        return ret_errno(LINUX_ENOSYS);
                    };
                    match venue.msgctl(msqid, cmd, None) {
                        Ok(val) => ret(val),
                        Err(e) => ret(e),
                    }
                }
                _ => ret_errno(LINUX_EINVAL),
            }
        }
        IpcCall::Msgsnd => {
            let msqid = args[0] as i32;
            let msgp = UserVa::new(args[1]);
            let msgsz_raw = args[2];
            let msgflg = args[3] as i32;
            if msgp.raw() == 0 {
                return ret_errno(LINUX_EFAULT);
            }
            if (msgsz_raw as i64) < 0 || msgsz_raw > MSGMAX as u64 {
                return ret_errno(LINUX_EINVAL);
            }
            let msgsz = msgsz_raw as usize;
            let Some(mtype) = copy_val_in::<i64>(native, msgp) else {
                return ret_errno(LINUX_EFAULT);
            };
            if mtype <= 0 {
                return ret_errno(LINUX_EINVAL);
            }
            let text_va = UserVa::new(msgp.raw().wrapping_add(8));
            let mut mtext = alloc::vec![0u8; msgsz];
            if msgsz > 0 && !native.copy_in(&mut mtext, text_va) {
                return ret_errno(LINUX_EFAULT);
            }
            let Some(venue) = native.process_ipc() else {
                return ret_errno(LINUX_ENOSYS);
            };
            match venue.msgsnd(msqid, mtype, &mtext, msgflg) {
                Ok(outcome) => outcome,
                Err(e) => ret(e),
            }
        }
        IpcCall::MsgRcv => {
            let msqid = args[0] as i32;
            let msgp = UserVa::new(args[1]);
            let msgsz_raw = args[2];
            let msgtyp = args[3] as i64;
            let msgflg = args[4] as i32;
            if msgp.raw() == 0 {
                return ret_errno(LINUX_EFAULT);
            }
            if (msgsz_raw as i64) < 0 || msgsz_raw > MSGMAX as u64 {
                return ret_errno(LINUX_EINVAL);
            }
            let msgsz = msgsz_raw as usize;
            let res = {
                let Some(venue) = native.process_ipc() else {
                    return ret_errno(LINUX_ENOSYS);
                };
                venue.msgrcv(msqid, msgp, msgtyp, msgflg, msgsz)
            };
            match res {
                Ok((outcome, Some((mtype, data)))) => {
                    let text_va = UserVa::new(msgp.raw().wrapping_add(8));
                    let copy_ok = copy_val_out(native, msgp, &mtype)
                        && (data.is_empty() || native.copy_out(text_va, &data));
                    if !copy_ok {
                        // Restore message to head of queue so it is not lost!
                        if let Some(venue) = native.process_ipc() {
                            let _ = venue.msgrcv_restore(msqid, mtype, data);
                        }
                        return ret_errno(LINUX_EFAULT);
                    }
                    outcome
                }
                Ok((outcome, None)) => outcome,
                Err(e) => ret(e),
            }
        }
        _ => ret_errno(LINUX_ENOSYS),
    }
}

fn invoke_sem<'a>(call: IpcCall, args: &[u64; 6], native: &mut dyn IpcNative<'a>) -> IpcOutcome {
    match call {
        IpcCall::SemGet => {
            let Some(venue) = native.process_ipc() else {
                return ret_errno(LINUX_ENOSYS);
            };
            match venue.semget(args[0] as i32, args[1] as i32, args[2] as i32) {
                Ok(id) => ret(id as i64),
                Err(e) => ret(e),
            }
        }
        IpcCall::SemCtl => {
            let semid = args[0] as i32;
            let semnum = args[1] as i32;
            let cmd = args[2] as i32;
            let arg = args[3];
            match cmd {
                IPC_INFO | SEM_INFO => {
                    let arg_ptr = UserVa::new(arg);
                    if arg_ptr.raw() == 0 {
                        return ret_errno(LINUX_EFAULT);
                    }
                    let mut info = LinuxSeminfo::default();
                    let res = {
                        let Some(venue) = native.process_ipc() else {
                            return ret_errno(LINUX_ENOSYS);
                        };
                        venue.semctl_info(cmd, &mut info)
                    };
                    match res {
                        Ok(val) => {
                            if !copy_val_out(native, arg_ptr, &info) {
                                return ret_errno(LINUX_EFAULT);
                            }
                            ret(val)
                        }
                        Err(e) => ret(e),
                    }
                }
                IPC_STAT | SEM_STAT => {
                    let arg_ptr = UserVa::new(arg);
                    if arg_ptr.raw() == 0 {
                        return ret_errno(LINUX_EFAULT);
                    }
                    let mut ds = LinuxSemidDs::default();
                    let res = {
                        let Some(venue) = native.process_ipc() else {
                            return ret_errno(LINUX_ENOSYS);
                        };
                        venue.semctl_stat(semid, semnum, cmd, &mut ds)
                    };
                    match res {
                        Ok(val) => {
                            if !copy_val_out(native, arg_ptr, &ds) {
                                return ret_errno(LINUX_EFAULT);
                            }
                            ret(val)
                        }
                        Err(e) => ret(e),
                    }
                }
                IPC_SET => {
                    let arg_ptr = UserVa::new(arg);
                    if arg_ptr.raw() == 0 {
                        return ret_errno(LINUX_EFAULT);
                    }
                    let Some(ds) = copy_val_in::<LinuxSemidDs>(native, arg_ptr) else {
                        return ret_errno(LINUX_EFAULT);
                    };
                    let Some(venue) = native.process_ipc() else {
                        return ret_errno(LINUX_ENOSYS);
                    };
                    match venue.semctl_set(semid, &ds) {
                        Ok(val) => ret(val),
                        Err(e) => ret(e),
                    }
                }
                IPC_RMID => {
                    let Some(venue) = native.process_ipc() else {
                        return ret_errno(LINUX_ENOSYS);
                    };
                    match venue.semctl_rmid(semid) {
                        Ok(val) => ret(val),
                        Err(e) => ret(e),
                    }
                }
                GETVAL => {
                    let Some(venue) = native.process_ipc() else {
                        return ret_errno(LINUX_ENOSYS);
                    };
                    match venue.semctl_getval(semid, semnum) {
                        Ok(val) => ret(val),
                        Err(e) => ret(e),
                    }
                }
                SETVAL => {
                    let Some(venue) = native.process_ipc() else {
                        return ret_errno(LINUX_ENOSYS);
                    };
                    match venue.semctl_setval(semid, semnum, arg) {
                        Ok(val) => ret(val),
                        Err(e) => ret(e),
                    }
                }
                GETPID => {
                    let Some(venue) = native.process_ipc() else {
                        return ret_errno(LINUX_ENOSYS);
                    };
                    match venue.semctl_getpid(semid, semnum) {
                        Ok(val) => ret(val),
                        Err(e) => ret(e),
                    }
                }
                GETNCNT => {
                    let Some(venue) = native.process_ipc() else {
                        return ret_errno(LINUX_ENOSYS);
                    };
                    match venue.semctl_getncnt(semid, semnum) {
                        Ok(val) => ret(val),
                        Err(e) => ret(e),
                    }
                }
                GETZCNT => {
                    let Some(venue) = native.process_ipc() else {
                        return ret_errno(LINUX_ENOSYS);
                    };
                    match venue.semctl_getzcnt(semid, semnum) {
                        Ok(val) => ret(val),
                        Err(e) => ret(e),
                    }
                }
                GETALL => {
                    let arg_ptr = UserVa::new(arg);
                    if arg_ptr.raw() == 0 {
                        return ret_errno(LINUX_EFAULT);
                    }
                    let nsems = {
                        let Some(venue) = native.process_ipc() else {
                            return ret_errno(LINUX_ENOSYS);
                        };
                        match venue.sem_nsems(semid) {
                            Ok(n) => n,
                            Err(e) => return ret(e),
                        }
                    };
                    let mut vals = alloc::vec![0u16; nsems];
                    let res = {
                        let Some(venue) = native.process_ipc() else {
                            return ret_errno(LINUX_ENOSYS);
                        };
                        venue.semctl_getall(semid, &mut vals)
                    };
                    match res {
                        Ok(val) => {
                            let slice = unsafe {
                                core::slice::from_raw_parts(
                                    vals.as_ptr() as *const u8,
                                    vals.len() * core::mem::size_of::<u16>(),
                                )
                            };
                            if !native.copy_out(arg_ptr, slice) {
                                return ret_errno(LINUX_EFAULT);
                            }
                            ret(val)
                        }
                        Err(e) => ret(e),
                    }
                }
                SETALL => {
                    let arg_ptr = UserVa::new(arg);
                    if arg_ptr.raw() == 0 {
                        return ret_errno(LINUX_EFAULT);
                    }
                    let nsems = {
                        let Some(venue) = native.process_ipc() else {
                            return ret_errno(LINUX_ENOSYS);
                        };
                        match venue.sem_nsems(semid) {
                            Ok(n) => n,
                            Err(e) => return ret(e),
                        }
                    };
                    let byte_len = nsems * core::mem::size_of::<u16>();
                    let mut bytes = alloc::vec![0u8; byte_len];
                    if !native.copy_in(&mut bytes, arg_ptr) {
                        return ret_errno(LINUX_EFAULT);
                    }
                    let vals: &[u16] =
                        unsafe { core::slice::from_raw_parts(bytes.as_ptr() as *const u16, nsems) };
                    let Some(venue) = native.process_ipc() else {
                        return ret_errno(LINUX_ENOSYS);
                    };
                    match venue.semctl_setall(semid, vals) {
                        Ok(val) => ret(val),
                        Err(e) => ret(e),
                    }
                }
                _ => ret_errno(LINUX_EINVAL),
            }
        }
        IpcCall::SemOp | IpcCall::SemTimedOp => {
            let semid = args[0] as i32;
            let sops_ptr = UserVa::new(args[1]);
            let nsops = args[2] as usize;
            if nsops == 0 {
                return ret_errno(LINUX_EINVAL);
            }
            if nsops > SEMOPM {
                return ret_errno(LINUX_E2BIG);
            }
            if sops_ptr.raw() == 0 {
                return ret_errno(LINUX_EFAULT);
            }
            let byte_len = nsops * core::mem::size_of::<LinuxSembuf>();
            let mut bytes = alloc::vec![0u8; byte_len];
            if !native.copy_in(&mut bytes, sops_ptr) {
                return ret_errno(LINUX_EFAULT);
            }
            let sops: &[LinuxSembuf] =
                unsafe { core::slice::from_raw_parts(bytes.as_ptr() as *const LinuxSembuf, nsops) };

            let timeout = if call == IpcCall::SemTimedOp {
                let to_ptr = UserVa::new(args[3]);
                if to_ptr.raw() != 0 {
                    let Some(ts) = copy_val_in::<LinuxTimespec>(native, to_ptr) else {
                        return ret_errno(LINUX_EFAULT);
                    };
                    if ts.tv_sec < 0 || ts.tv_nsec < 0 || ts.tv_nsec >= 1_000_000_000 {
                        return ret_errno(LINUX_EINVAL);
                    }
                    Some(Duration::new(ts.tv_sec as u64, ts.tv_nsec as u32))
                } else {
                    None
                }
            } else {
                None
            };

            let Some(venue) = native.process_ipc() else {
                return ret_errno(LINUX_ENOSYS);
            };
            match venue.semop(semid, sops, timeout) {
                Ok(outcome) => outcome,
                Err(e) => ret(e),
            }
        }
        _ => ret_errno(LINUX_ENOSYS),
    }
}

pub fn invoke<'a>(call: IpcCall, native: &mut dyn IpcNative<'a>) -> IpcOutcome {
    let args = native.arguments();
    match call {
        IpcCall::MsgGet | IpcCall::MsgCtl | IpcCall::Msgsnd | IpcCall::MsgRcv => {
            invoke_msg(call, &args, native)
        }
        IpcCall::SemGet | IpcCall::SemCtl | IpcCall::SemOp | IpcCall::SemTimedOp => {
            invoke_sem(call, &args, native)
        }
    }
}
