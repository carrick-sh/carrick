//! In-ring System V IPC family (SysV messages and semaphores).
extern crate alloc;

use alloc::vec::Vec;
use core::time::Duration;

pub mod namespace;

use crate::abi::entry::SyscallResult;
use crate::lifecycle::{LifecycleOutcome, UserCopy};
use carrick_core::user_copy::{CopyOutcome, GuestCopyRequest};
use carrick_guest_arch::UserVa;
pub use carrick_syscall_abi::ipc::{
    GETALL, GETNCNT, GETPID, GETVAL, GETZCNT, IPC_CREAT, IPC_EXCL, IPC_INFO, IPC_NOWAIT,
    IPC_PRIVATE, IPC_RMID, IPC_SET, IPC_STAT, LinuxIpcPerm, LinuxMsginfo, LinuxMsqidDs,
    LinuxSembuf, LinuxSemidDs, LinuxSemidDsAarch64, LinuxSemidDsX86_64, LinuxSeminfo, LinuxShmidDs,
    MSG_EXCEPT, MSG_INFO, MSG_NOERROR, MSG_STAT, MSGMAX, MSGMNB, MSGMNI, SEM_INFO, SEM_STAT,
    SEM_UNDO, SEMMNI, SEMMNS, SEMMSL, SEMOPM, SEMVMX, SETALL, SETVAL,
};
use carrick_syscall_abi::{LINUX_E2BIG, LINUX_EFAULT, LINUX_EINVAL, LINUX_ENOSYS, LinuxErrno};

#[repr(C)]
#[derive(
    Clone,
    Copy,
    Default,
    Debug,
    zerocopy::FromBytes,
    zerocopy::IntoBytes,
    zerocopy::KnownLayout,
    zerocopy::Immutable,
)]
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
    Redispatch,
    HostCustody,
    ReturnedWithWork(SyscallResult),
    Transferred {
        progress: carrick_core_abi::Served,
        result: SyscallResult,
    },
}

impl IpcOutcome {
    pub fn from_lifecycle(outcome: LifecycleOutcome) -> Self {
        match outcome {
            LifecycleOutcome::Returned {
                result,
                work: false,
            } => Self::Returned(result),
            LifecycleOutcome::Returned { result, work: true } => Self::ReturnedWithWork(result),
            LifecycleOutcome::Redispatch => Self::Redispatch,
            LifecycleOutcome::Transferred {
                progress: carrick_core_abi::Served::Idle,
                ..
            } => Self::Suspended,
            LifecycleOutcome::Transferred { progress, result } => {
                Self::Transferred { progress, result }
            }
            LifecycleOutcome::HostCustody => Self::HostCustody,
        }
    }

    pub fn into_lifecycle(self) -> LifecycleOutcome {
        match self {
            Self::Returned(result) => LifecycleOutcome::Returned {
                result,
                work: false,
            },
            Self::Suspended => LifecycleOutcome::Transferred {
                progress: carrick_core_abi::Served::Idle,
                result: SyscallResult::new(0),
            },
            Self::Redispatch => LifecycleOutcome::Redispatch,
            Self::HostCustody => LifecycleOutcome::HostCustody,
            Self::ReturnedWithWork(result) => LifecycleOutcome::Returned { result, work: true },
            Self::Transferred { progress, result } => {
                LifecycleOutcome::Transferred { progress, result }
            }
        }
    }
}

/// A completed IPC answer, including the next unwritten byte and any message
/// removed from its queue. Memory contention must retain this exact answer.
pub struct IpcOutput {
    pub address: UserVa,
    pub bytes: Vec<u8>,
    pub offset: usize,
    pub result: SyscallResult,
    pub message: Option<(i32, usize, i64)>,
}

impl IpcOutput {
    fn new(address: UserVa, bytes: Vec<u8>, result: i64) -> Self {
        Self {
            address,
            bytes,
            offset: 0,
            result: SyscallResult::new(result),
            message: None,
        }
    }

    pub fn range(&self) -> Option<carrick_guest_arch::UserRange> {
        carrick_guest_arch::UserRange::checked(
            self.address,
            carrick_guest_arch::GuestLen::new(self.bytes.len() as u64),
        )
        .filter(|range| range.in_lower_half())
    }

    pub fn restore(&self, venue: &mut dyn ProcessIpcVenue) {
        if let Some((id, index, kind)) = self.message {
            let _ = venue.msgrcv_restore(id, index, kind, self.bytes[8..].to_vec());
        }
    }
}

/// Copy only page-bounded pieces: a successful prefix belongs to this answer,
/// and a refusal transfers its cursor to the memory owner's continuation.
pub fn finish_output<'a>(native: &mut dyn IpcNative<'a>, mut output: IpcOutput) -> IpcOutcome {
    if output.range().is_none() {
        if let Some(venue) = native.process_ipc() {
            output.restore(venue);
        }
        return ret_errno(LINUX_EFAULT);
    }

    while output.offset < output.bytes.len() {
        let Some(address) = output.address.raw().checked_add(output.offset as u64) else {
            if let Some(venue) = native.process_ipc() {
                output.restore(venue);
            }
            return ret_errno(LINUX_EFAULT);
        };
        let count = (4096 - (address as usize & 4095)).min(output.bytes.len() - output.offset);
        match native.copy_out(
            UserVa::new(address),
            &output.bytes[output.offset..output.offset + count],
        ) {
            CopyOutcome::Done => output.offset += count,
            CopyOutcome::Fault => {
                if let Some(venue) = native.process_ipc() {
                    output.restore(venue);
                }
                return ret_errno(LINUX_EFAULT);
            }
            CopyOutcome::NotYet(request) => return native.retain_output(request, output),
        }
    }
    IpcOutcome::Returned(output.result)
}

pub type MsgrcvMessage = (usize, i64, Vec<u8>);
pub type MsgrcvResult = Result<(IpcOutcome, Option<MsgrcvMessage>), i64>;

pub trait ProcessIpcVenue {
    fn complete_output(&mut self, output: IpcOutput) -> LifecycleOutcome;
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
    fn msgrcv_restore(
        &mut self,
        msqid: i32,
        original_idx: usize,
        mtype: i64,
        data: Vec<u8>,
    ) -> Result<(), i64>;

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
    fn retain_output(&mut self, request: GuestCopyRequest, output: IpcOutput) -> IpcOutcome;
    fn arguments(&self) -> [u64; 6];
    fn process_ipc(&mut self) -> Option<&mut dyn ProcessIpcVenue>;
    fn guest_isa(&self) -> carrick_guest_arch::GuestIsa {
        carrick_guest_arch::GuestIsa::Aarch64
    }
}

#[inline(always)]
fn ret(code: i64) -> IpcOutcome {
    IpcOutcome::Returned(SyscallResult::new(code))
}

#[inline(always)]
fn ret_errno(errno: LinuxErrno) -> IpcOutcome {
    ret(errno.guest_retval())
}

fn invoke_msg<'a>(
    call: IpcCall,
    args: &[u64; 6],
    mut native: &mut dyn IpcNative<'a>,
) -> IpcOutcome {
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
                        Ok(val) => finish_output(
                            native,
                            IpcOutput::new(
                                buf_ptr,
                                zerocopy::IntoBytes::as_bytes(&info).to_vec(),
                                val,
                            ),
                        ),
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
                        Ok(val) => finish_output(
                            native,
                            IpcOutput::new(
                                buf_ptr,
                                zerocopy::IntoBytes::as_bytes(&ds).to_vec(),
                                val,
                            ),
                        ),
                        Err(e) => ret(e),
                    }
                }
                IPC_SET => {
                    if buf_ptr.raw() == 0 {
                        return ret_errno(LINUX_EFAULT);
                    }
                    let Some(mut ds) = (&mut native).read_val::<LinuxMsqidDs>(buf_ptr) else {
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
            let Some(mtype) = (&mut native).read_val::<i64>(msgp) else {
                return ret_errno(LINUX_EFAULT);
            };
            if mtype <= 0 {
                return ret_errno(LINUX_EINVAL);
            }
            let text_va = UserVa::new(msgp.raw().wrapping_add(8));
            let mut mtext = alloc::vec![0u8; msgsz];
            if msgsz > 0 && !native.copy_in(&mut mtext, text_va).is_done() {
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
            if (msgsz_raw as i64) < 0 {
                return ret_errno(LINUX_EINVAL);
            }
            let msgsz = (msgsz_raw as usize).min(MSGMAX);
            let res = {
                let Some(venue) = native.process_ipc() else {
                    return ret_errno(LINUX_ENOSYS);
                };
                venue.msgrcv(msqid, msgp, msgtyp, msgflg, msgsz)
            };
            match res {
                Ok((IpcOutcome::Returned(result), Some((original_idx, mtype, data)))) => {
                    let mut bytes = mtype.to_ne_bytes().to_vec();
                    bytes.extend_from_slice(&data);
                    let mut output = IpcOutput::new(msgp, bytes, result.raw());
                    output.message = Some((msqid, original_idx, mtype));
                    finish_output(native, output)
                }
                Ok((outcome, _)) => outcome,
                Err(e) => ret(e),
            }
        }
        _ => ret_errno(LINUX_ENOSYS),
    }
}

fn invoke_sem<'a>(
    call: IpcCall,
    args: &[u64; 6],
    mut native: &mut dyn IpcNative<'a>,
) -> IpcOutcome {
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
                        Ok(val) => finish_output(
                            native,
                            IpcOutput::new(
                                arg_ptr,
                                zerocopy::IntoBytes::as_bytes(&info).to_vec(),
                                val,
                            ),
                        ),
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
                            let bytes = match native.guest_isa() {
                                carrick_guest_arch::GuestIsa::X86_64 => {
                                    zerocopy::IntoBytes::as_bytes(&ds).to_vec()
                                }
                                carrick_guest_arch::GuestIsa::Aarch64 => {
                                    zerocopy::IntoBytes::as_bytes(&ds.to_aarch64()).to_vec()
                                }
                            };
                            finish_output(native, IpcOutput::new(arg_ptr, bytes, val))
                        }
                        Err(e) => ret(e),
                    }
                }
                IPC_SET => {
                    let arg_ptr = UserVa::new(arg);
                    if arg_ptr.raw() == 0 {
                        return ret_errno(LINUX_EFAULT);
                    }
                    let ds = match native.guest_isa() {
                        carrick_guest_arch::GuestIsa::X86_64 => {
                            let Some(ds) = (&mut native).read_val::<LinuxSemidDsX86_64>(arg_ptr)
                            else {
                                return ret_errno(LINUX_EFAULT);
                            };
                            ds
                        }
                        carrick_guest_arch::GuestIsa::Aarch64 => {
                            let Some(ds) = (&mut native).read_val::<LinuxSemidDsAarch64>(arg_ptr)
                            else {
                                return ret_errno(LINUX_EFAULT);
                            };
                            ds.to_x86_64()
                        }
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
                        Ok(val) => finish_output(
                            native,
                            IpcOutput::new(
                                arg_ptr,
                                zerocopy::IntoBytes::as_bytes(vals.as_slice()).to_vec(),
                                val,
                            ),
                        ),
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
                    if !native.copy_in(&mut bytes, arg_ptr).is_done() {
                        return ret_errno(LINUX_EFAULT);
                    }
                    let vals: Vec<u16> = bytes
                        .as_chunks::<2>()
                        .0
                        .iter()
                        .copied()
                        .map(u16::from_ne_bytes)
                        .collect();
                    let Some(venue) = native.process_ipc() else {
                        return ret_errno(LINUX_ENOSYS);
                    };
                    match venue.semctl_setall(semid, &vals) {
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
            if !native.copy_in(&mut bytes, sops_ptr).is_done() {
                return ret_errno(LINUX_EFAULT);
            }
            let Ok(sops) = <[LinuxSembuf] as zerocopy::FromBytes>::ref_from_bytes(&bytes) else {
                return ret_errno(LINUX_EINVAL);
            };

            let timeout = if call == IpcCall::SemTimedOp {
                let to_ptr = UserVa::new(args[3]);
                if to_ptr.raw() != 0 {
                    let Some(ts) = (&mut native).read_val::<LinuxTimespec>(to_ptr) else {
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::TaskCredentials;
    use crate::ipc::namespace::IpcNamespace;
    use carrick_guest_arch::GuestIsa;

    const GUEST_BUF_VA: u64 = 0x1000_0000;

    #[inline(never)]
    fn poison_stack(depth: usize) -> u8 {
        let mut scratch = [0xa5_u8; 1024];
        core::hint::black_box(&mut scratch);
        if depth > 0 {
            scratch[0] ^= poison_stack(depth - 1);
        }
        core::hint::black_box(scratch[scratch.len() - 1])
    }

    #[inline(never)]
    fn invoke_with_poisoned_stack<'a>(call: IpcCall, native: &mut dyn IpcNative<'a>) -> IpcOutcome {
        core::hint::black_box(poison_stack(4));
        invoke(call, native)
    }

    struct TestVenue {
        ns: IpcNamespace,
        creds: TaskCredentials,
    }

    impl TestVenue {
        fn new() -> Self {
            Self {
                ns: IpcNamespace::new(),
                creds: TaskCredentials::ROOT,
            }
        }
    }

    impl ProcessIpcVenue for TestVenue {
        fn complete_output(&mut self, _: IpcOutput) -> LifecycleOutcome {
            unreachable!("test copy owner is TestNative")
        }
        fn msgget(&mut self, key: i32, msgflg: i32) -> Result<i32, i64> {
            self.ns
                .msgget(&self.creds, key, msgflg)
                .map_err(|e| e.guest_retval())
        }

        fn msgctl(
            &mut self,
            msqid: i32,
            cmd: i32,
            buf: Option<&mut LinuxMsqidDs>,
        ) -> Result<i64, i64> {
            core::hint::black_box(poison_stack(2));
            match cmd {
                IPC_STAT | MSG_STAT => {
                    let out = buf.ok_or_else(|| LINUX_EFAULT.guest_retval())?;
                    self.ns
                        .msgctl_stat(&self.creds, msqid, cmd, out)
                        .map_err(|e| e.guest_retval())
                }
                IPC_SET => {
                    let ds = buf.ok_or_else(|| LINUX_EFAULT.guest_retval())?;
                    self.ns
                        .msgctl_set(&self.creds, msqid, ds)
                        .map(|_| 0)
                        .map_err(|e| e.guest_retval())
                }
                IPC_RMID => self
                    .ns
                    .msgctl_rmid(&self.creds, msqid)
                    .map(|_| 0)
                    .map_err(|e| e.guest_retval()),
                _ => Err(LINUX_EINVAL.guest_retval()),
            }
        }

        fn msgctl_info(&mut self, _cmd: i32, buf: &mut LinuxMsginfo) -> Result<i64, i64> {
            core::hint::black_box(poison_stack(2));
            self.ns.msgctl_info(buf).map_err(|e| e.guest_retval())
        }

        fn msgsnd(
            &mut self,
            _msqid: i32,
            _mtype: i64,
            _mtext: &[u8],
            _msgflg: i32,
        ) -> Result<IpcOutcome, i64> {
            Err(LINUX_ENOSYS.guest_retval())
        }

        fn msgrcv(
            &mut self,
            _msqid: i32,
            _msgp: UserVa,
            _msgtyp: i64,
            _msgflg: i32,
            _msgsz: usize,
        ) -> MsgrcvResult {
            Err(LINUX_ENOSYS.guest_retval())
        }

        fn msgrcv_restore(
            &mut self,
            _msqid: i32,
            _original_idx: usize,
            _mtype: i64,
            _data: Vec<u8>,
        ) -> Result<(), i64> {
            Err(LINUX_ENOSYS.guest_retval())
        }

        fn semget(&mut self, key: i32, nsems: i32, semflg: i32) -> Result<i32, i64> {
            self.ns
                .semget(&self.creds, key, nsems, semflg)
                .map_err(|e| e.guest_retval())
        }

        fn sem_nsems(&mut self, semid: i32) -> Result<usize, i64> {
            self.ns
                .sem_set(semid)
                .map(|s| s.sems.len())
                .map_err(|e| e.guest_retval())
        }

        fn semctl_rmid(&mut self, semid: i32) -> Result<i64, i64> {
            self.ns
                .semctl_rmid(&self.creds, semid)
                .map(|_| 0)
                .map_err(|e| e.guest_retval())
        }

        fn semctl_stat(
            &mut self,
            semid: i32,
            _semnum: i32,
            cmd: i32,
            ds: &mut LinuxSemidDs,
        ) -> Result<i64, i64> {
            core::hint::black_box(poison_stack(2));
            self.ns
                .semctl_stat(&self.creds, semid, cmd, ds)
                .map_err(|e| e.guest_retval())
        }

        fn semctl_set(&mut self, semid: i32, ds: &LinuxSemidDs) -> Result<i64, i64> {
            self.ns
                .semctl_set(&self.creds, semid, ds)
                .map_err(|e| e.guest_retval())
        }

        fn semctl_info(&mut self, _cmd: i32, info: &mut LinuxSeminfo) -> Result<i64, i64> {
            self.ns.semctl_info(info).map_err(|e| e.guest_retval())
        }

        fn semctl_getval(&mut self, semid: i32, semnum: i32) -> Result<i64, i64> {
            self.ns
                .semctl_getval(&self.creds, semid, semnum)
                .map_err(|e| e.guest_retval())
        }

        fn semctl_setval(&mut self, semid: i32, semnum: i32, val: u64) -> Result<i64, i64> {
            self.ns
                .semctl_setval(&self.creds, 1, semid, semnum, val)
                .map(|_| 0)
                .map_err(|e| e.guest_retval())
        }

        fn semctl_getpid(&mut self, _semid: i32, _semnum: i32) -> Result<i64, i64> {
            Err(LINUX_ENOSYS.guest_retval())
        }

        fn semctl_getncnt(&mut self, _semid: i32, _semnum: i32) -> Result<i64, i64> {
            Err(LINUX_ENOSYS.guest_retval())
        }

        fn semctl_getzcnt(&mut self, _semid: i32, _semnum: i32) -> Result<i64, i64> {
            Err(LINUX_ENOSYS.guest_retval())
        }

        fn semctl_getall(&mut self, semid: i32, out: &mut [u16]) -> Result<i64, i64> {
            self.ns
                .semctl_getall(&self.creds, semid, out)
                .map_err(|e| e.guest_retval())
        }

        fn semctl_setall(&mut self, semid: i32, vals: &[u16]) -> Result<i64, i64> {
            self.ns
                .semctl_setall(&self.creds, 1, semid, vals)
                .map(|_| 0)
                .map_err(|e| e.guest_retval())
        }

        fn semop(
            &mut self,
            _semid: i32,
            _sops: &[LinuxSembuf],
            _timeout: Option<Duration>,
        ) -> Result<IpcOutcome, i64> {
            Err(LINUX_ENOSYS.guest_retval())
        }
    }

    struct TestNative<'v> {
        args: [u64; 6],
        isa: GuestIsa,
        guest_mem: Vec<u8>,
        base_va: u64,
        venue: &'v mut TestVenue,
        refuse_output: bool,
        pending_output: Option<IpcOutput>,
        fault_output: bool,
    }

    impl<'v> TestNative<'v> {
        fn new(venue: &'v mut TestVenue, isa: GuestIsa, args: [u64; 6], mem_len: usize) -> Self {
            Self {
                args,
                isa,
                guest_mem: alloc::vec![0xff_u8; mem_len],
                base_va: GUEST_BUF_VA,
                venue,
                refuse_output: false,
                pending_output: None,
                fault_output: false,
            }
        }
    }

    impl UserCopy for TestNative<'_> {
        fn copy_in(&mut self, dst: &mut [u8], src: UserVa) -> carrick_core::user_copy::CopyOutcome {
            let Some(off) = src.raw().checked_sub(self.base_va) else {
                return carrick_core::user_copy::CopyOutcome::Fault;
            };
            let off = off as usize;
            let Some(end) = off.checked_add(dst.len()) else {
                return carrick_core::user_copy::CopyOutcome::Fault;
            };
            if end > self.guest_mem.len() {
                return carrick_core::user_copy::CopyOutcome::Fault;
            }
            dst.copy_from_slice(&self.guest_mem[off..end]);
            carrick_core::user_copy::CopyOutcome::Done
        }

        fn copy_out(&mut self, dst: UserVa, src: &[u8]) -> carrick_core::user_copy::CopyOutcome {
            if self.fault_output {
                return CopyOutcome::Fault;
            }
            if core::mem::take(&mut self.refuse_output) {
                return carrick_core::user_copy::CopyOutcome::NotYet(
                    carrick_core::user_copy::GuestCopyRequest {
                        address: dst,
                        len: carrick_guest_arch::GuestLen::new(src.len() as u64),
                        access: carrick_guest_arch::Access::Write,
                    },
                );
            }
            let Some(off) = dst.raw().checked_sub(self.base_va) else {
                return carrick_core::user_copy::CopyOutcome::Fault;
            };
            let off = off as usize;
            let Some(end) = off.checked_add(src.len()) else {
                return carrick_core::user_copy::CopyOutcome::Fault;
            };
            if end > self.guest_mem.len() {
                return carrick_core::user_copy::CopyOutcome::Fault;
            }
            self.guest_mem[off..end].copy_from_slice(src);
            carrick_core::user_copy::CopyOutcome::Done
        }
    }

    impl<'a> IpcNative<'a> for TestNative<'_> {
        fn retain_output(&mut self, request: GuestCopyRequest, output: IpcOutput) -> IpcOutcome {
            assert_eq!(
                request.address.raw(),
                output.address.raw() + output.offset as u64
            );
            self.pending_output = Some(output);
            IpcOutcome::Suspended
        }
        fn arguments(&self) -> [u64; 6] {
            self.args
        }

        fn process_ipc(&mut self) -> Option<&mut dyn ProcessIpcVenue> {
            Some(self.venue)
        }

        fn guest_isa(&self) -> GuestIsa {
            self.isa
        }
    }

    #[test]
    fn ipc_output_owner_refusal_is_not_efault() {
        let mut venue = TestVenue::new();
        let id = venue.msgget(0x1234, IPC_CREAT | 0o644).unwrap();
        let mut native = TestNative::new(
            &mut venue,
            GuestIsa::X86_64,
            [id as u64, IPC_STAT as u64, GUEST_BUF_VA, 0, 0, 0],
            120,
        );
        native.refuse_output = true;
        assert_eq!(invoke(IpcCall::MsgCtl, &mut native), IpcOutcome::Suspended);
        let output = native.pending_output.take().expect("retained answer");
        assert_eq!(
            finish_output(&mut native, output),
            IpcOutcome::Returned(SyscallResult::new(0))
        );
        assert!(native.pending_output.is_none());
    }

    #[test]
    fn ipc_record_outputs_keep_frozen_answers_on_owner_wait_for_both_isas() {
        for isa in [GuestIsa::X86_64, GuestIsa::Aarch64] {
            let mut venue = TestVenue::new();
            let msg = venue.msgget(0x1234, IPC_CREAT | 0o644).unwrap();
            let sem = venue.semget(0x3456, 2, IPC_CREAT | 0o640).unwrap();
            let cases = [
                (
                    IpcCall::MsgCtl,
                    [msg as u64, IPC_STAT as u64, GUEST_BUF_VA, 0, 0, 0],
                ),
                (IpcCall::MsgCtl, [0, IPC_INFO as u64, GUEST_BUF_VA, 0, 0, 0]),
                (
                    IpcCall::SemCtl,
                    [sem as u64, 0, IPC_STAT as u64, GUEST_BUF_VA, 0, 0],
                ),
                (IpcCall::SemCtl, [0, 0, IPC_INFO as u64, GUEST_BUF_VA, 0, 0]),
                (
                    IpcCall::SemCtl,
                    [sem as u64, 0, GETALL as u64, GUEST_BUF_VA, 0, 0],
                ),
            ];
            for (call, args) in cases {
                let mut native = TestNative::new(&mut venue, isa, args, 128);
                let expected = invoke(call, &mut native);
                let expected_bytes = native.guest_mem.clone();
                native.guest_mem.fill(0xff);
                native.refuse_output = true;
                assert_eq!(invoke(call, &mut native), IpcOutcome::Suspended);
                let output = native.pending_output.take().expect("answer retained");
                assert_eq!(output.offset, 0);
                // The frozen bytes complete without repeating the namespace query.
                assert_eq!(finish_output(&mut native, output), expected);
                assert_eq!(native.guest_mem, expected_bytes);
                native.fault_output = true;
                assert_eq!(invoke(call, &mut native), ret_errno(LINUX_EFAULT));
            }
        }
    }

    #[test]
    fn msgctl_stat_zeroes_ipc_perm_padding_bytes() {
        let mut venue = TestVenue::new();
        let msqid = venue.msgget(0x1234, IPC_CREAT | 0o644).unwrap();

        for (cmd, id_or_idx) in [(IPC_STAT, msqid), (MSG_STAT, 0)] {
            let mut native = TestNative::new(
                &mut venue,
                GuestIsa::X86_64,
                [id_or_idx as u64, cmd as u64, GUEST_BUF_VA, 0, 0, 0],
                120,
            );
            let outcome = invoke_with_poisoned_stack(IpcCall::MsgCtl, &mut native);
            assert!(matches!(outcome, IpcOutcome::Returned(r) if r.raw() >= 0));
            // LinuxIpcPerm bytes 28..32 sit between __pad2 (26..28) and __glibc_reserved1 (32..40).
            assert_eq!(
                &native.guest_mem[28..32],
                &[0, 0, 0, 0],
                "msgctl(cmd={cmd}) leaked non-zero bytes in LinuxIpcPerm padding 28..32"
            );
            // High 16 bits of mode at 22..24 and __pad2 at 26..28 must also be zero.
            assert_eq!(&native.guest_mem[22..24], &[0, 0]);
            assert_eq!(&native.guest_mem[26..28], &[0, 0]);
        }
    }

    #[test]
    fn msgctl_info_zeroes_tail_padding_bytes() {
        let mut venue = TestVenue::new();
        let _msqid = venue.msgget(0x2345, IPC_CREAT | 0o600).unwrap();

        for cmd in [IPC_INFO, MSG_INFO] {
            let mut native = TestNative::new(
                &mut venue,
                GuestIsa::X86_64,
                [0, cmd as u64, GUEST_BUF_VA, 0, 0, 0],
                32,
            );
            let outcome = invoke_with_poisoned_stack(IpcCall::MsgCtl, &mut native);
            assert!(matches!(outcome, IpcOutcome::Returned(r) if r.raw() >= 0));
            // LinuxMsginfo fields end after msgseg: u16 at 28..30; 30..32 is tail padding.
            assert_eq!(
                &native.guest_mem[30..32],
                &[0, 0],
                "msgctl(cmd={cmd}) leaked non-zero bytes in LinuxMsginfo tail padding 30..32"
            );
        }
    }

    #[test]
    fn semctl_stat_zeroes_ipc_perm_padding_bytes_for_x86_64_and_aarch64() {
        let mut venue = TestVenue::new();
        let semid = venue.semget(0x3456, 2, IPC_CREAT | 0o640).unwrap();

        for (isa, expected_size) in [(GuestIsa::X86_64, 104usize), (GuestIsa::Aarch64, 88usize)] {
            for (cmd, id_or_idx) in [(IPC_STAT, semid), (SEM_STAT, 0)] {
                let mut native = TestNative::new(
                    &mut venue,
                    isa,
                    [id_or_idx as u64, 0, cmd as u64, GUEST_BUF_VA, 0, 0],
                    expected_size,
                );
                let outcome = invoke_with_poisoned_stack(IpcCall::SemCtl, &mut native);
                assert!(matches!(outcome, IpcOutcome::Returned(r) if r.raw() >= 0));
                assert_eq!(
                    &native.guest_mem[28..32],
                    &[0, 0, 0, 0],
                    "semctl(isa={isa:?}, cmd={cmd}) leaked non-zero bytes in LinuxIpcPerm padding 28..32"
                );
                assert_eq!(&native.guest_mem[22..24], &[0, 0]);
                assert_eq!(&native.guest_mem[26..28], &[0, 0]);
            }
        }
    }

    #[test]
    fn semctl_setall_and_getall_round_trip_unaligned_guest_bytes() {
        let mut venue = TestVenue::new();
        let semid = venue.semget(0x4567, 3, IPC_CREAT | 0o666).unwrap();
        let odd_va = GUEST_BUF_VA + 1;
        let expected = [0x1234_u16, 0x5678, 0x0abc];

        let mut native = TestNative::new(
            &mut venue,
            GuestIsa::X86_64,
            [semid as u64, 0, SETALL as u64, odd_va, 0, 0],
            16,
        );
        for (i, v) in expected.iter().enumerate() {
            let bytes = v.to_ne_bytes();
            native.guest_mem[1 + i * 2..1 + i * 2 + 2].copy_from_slice(&bytes);
        }
        let set_outcome = invoke(IpcCall::SemCtl, &mut native);
        assert_eq!(set_outcome, IpcOutcome::Returned(SyscallResult::new(0)));

        let out_va = GUEST_BUF_VA + 9;
        let mut native_get = TestNative::new(
            &mut venue,
            GuestIsa::X86_64,
            [semid as u64, 0, GETALL as u64, out_va, 0, 0],
            16,
        );
        let get_outcome = invoke(IpcCall::SemCtl, &mut native_get);
        assert_eq!(get_outcome, IpcOutcome::Returned(SyscallResult::new(0)));
        for (i, v) in expected.iter().enumerate() {
            let got = u16::from_ne_bytes([
                native_get.guest_mem[9 + i * 2],
                native_get.guest_mem[9 + i * 2 + 1],
            ]);
            assert_eq!(got, *v);
        }
    }
}
