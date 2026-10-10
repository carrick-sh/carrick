//! Canonical Linux System V IPC constants, types, and struct layouts.

pub const IPC_PRIVATE: i32 = 0;
pub const IPC_RMID: i32 = 0;
pub const IPC_SET: i32 = 1;
pub const IPC_STAT: i32 = 2;
pub const IPC_INFO: i32 = 3;

pub const IPC_CREAT: i32 = 0o1000;
pub const IPC_EXCL: i32 = 0o2000;
pub const IPC_NOWAIT: i32 = 0o4000;

// Message queues
pub const MSG_STAT: i32 = 11;
pub const MSG_INFO: i32 = 12;
pub const MSG_NOERROR: i32 = 0o10000;
pub const MSG_EXCEPT: i32 = 0o20000;

pub const MSGMAX: usize = 8192;
pub const MSGMNB: usize = 16384;
pub const MSGMNI: usize = 32000;

// Semaphores
pub const SEM_STAT: i32 = 18;
pub const SEM_INFO: i32 = 19;
pub const SEM_UNDO: i16 = 0x1000;

pub const GETPID: i32 = 11;
pub const GETVAL: i32 = 12;
pub const GETALL: i32 = 13;
pub const GETNCNT: i32 = 14;
pub const GETZCNT: i32 = 15;
pub const SETVAL: i32 = 16;
pub const SETALL: i32 = 17;

pub const SEMMNI: usize = 32000;
pub const SEMMSL: usize = 32000;
pub const SEMMNS: usize = 1024000000;
pub const SEMOPM: usize = 500;
pub const SEMVMX: u16 = 32767;

/// Linux IPC permissions structure (struct ipc64_perm).
#[repr(C)]
#[derive(Clone, Copy, Default, PartialEq, Eq, Debug)]
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

/// Linux System V message queue description (struct msqid64_ds).
#[repr(C)]
#[derive(Clone, Copy, Default, Debug)]
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

/// Linux System V semaphore set description (struct semid64_ds).
#[repr(C)]
#[derive(Clone, Copy, Default, Debug)]
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

/// Linux System V semaphore operation (struct sembuf).
#[repr(C, packed)]
#[derive(Clone, Copy, Default, Debug)]
pub struct LinuxSembuf {
    pub sem_num: u16,
    pub sem_op: i16,
    pub sem_flg: i16,
}

/// Linux System V msginfo (struct msginfo).
#[repr(C)]
#[derive(Clone, Copy, Default, Debug)]
pub struct LinuxMsginfo {
    pub msgpool: i32,
    pub msgmap: i32,
    pub msgmax: i32,
    pub msgmnb: i32,
    pub msgmni: i32,
    pub msgssz: i32,
    pub msgtql: i32,
    pub msgseg: u16,
}

/// Linux System V seminfo (struct seminfo).
#[repr(C)]
#[derive(Clone, Copy, Default, Debug)]
pub struct LinuxSeminfo {
    pub semmap: i32,
    pub semmni: i32,
    pub semmns: i32,
    pub semmnu: i32,
    pub semmsl: i32,
    pub semopm: i32,
    pub semume: i32,
    pub semusz: i32,
    pub semvmx: i32,
    pub semaem: i32,
}
