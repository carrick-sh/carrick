//! In-zone IPC namespace for System V IPC and POSIX message queues.
//!
//! Provides container-scoped IPC objects (messages, semaphores, shared memory,
//! POSIX message queues) owned by Carrick's kernel graph without host delegation.

extern crate alloc;

use alloc::string::String;
use alloc::vec::Vec;

use super::{LinuxCapabilitySet, TaskCredentials, TaskGid, TaskUid};

pub const IPC_PRIVATE: i32 = 0;
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

pub const SEMMNI: usize = 32000;
pub const SEMMSL: usize = 32000;
pub const SEMOPM: usize = 500;
pub const SEMVMX: u16 = 32767;

pub const SHMMNI: usize = 4096;
pub const SHMMAX: usize = 16 * 1024 * 1024 * 1024; // 16 GiB
pub const SHMMIN: usize = 1;

pub const MQ_MAXMSG_DEFAULT: i64 = 10;
pub const MQ_MSGSIZE_DEFAULT: i64 = 8192;

pub const ERR_PERM: i64 = -1;
pub const ERR_NOENT: i64 = -2;
pub const ERR_SRCH: i64 = -3;
pub const ERR_INTR: i64 = -4;
pub const ERR_2BIG: i64 = -7;
pub const ERR_BADF: i64 = -9;
pub const ERR_AGAIN: i64 = -11;
pub const ERR_NOMEM: i64 = -12;
pub const ERR_ACCES: i64 = -13;
pub const ERR_FAULT: i64 = -14;
pub const ERR_EXIST: i64 = -17;
pub const ERR_INVAL: i64 = -22;
pub const ERR_NOSPC: i64 = -28;
pub const ERR_RANGE: i64 = -34;
pub const ERR_NOSYS: i64 = -38;
pub const ERR_NOMSG: i64 = -42;
pub const ERR_IDRM: i64 = -43;
pub const ERR_MSGSIZE: i64 = -90;

const IPCMNI_MASK: i32 = 0x7fff;

#[derive(Clone, Copy, Eq, PartialEq)]
#[cfg_attr(test, derive(Debug))]
pub struct IpcPerm {
    pub key: i32,
    pub uid: TaskUid,
    pub gid: TaskGid,
    pub cuid: TaskUid,
    pub cgid: TaskGid,
    pub mode: u16,
    pub seq: u16,
}

impl IpcPerm {
    pub fn new(key: i32, mode: u16, seq: u16, creds: &TaskCredentials) -> Self {
        Self {
            key,
            uid: creds.euid,
            gid: creds.egid,
            cuid: creds.euid,
            cgid: creds.egid,
            mode: mode & 0o777,
            seq,
        }
    }

    /// Check if `creds` satisfy `req_mode` (0o400 for read, 0o200 for write).
    /// Follows Linux ipc(2) credential rules:
    /// - Privileged (CAP_IPC_OWNER or CAP_SYS_ADMIN) bypasses check.
    /// - If UID matches `perm.uid` or `perm.cuid`, ONLY owner bits are checked.
    /// - Else if GID matches `perm.gid` or `perm.cgid` or any supplementary group, ONLY group bits are checked.
    /// - Else other bits are checked.
    pub fn check_perm(&self, creds: &TaskCredentials, req_mode: u16) -> Result<(), i64> {
        if creds
            .cap_effective
            .contains(LinuxCapabilitySet::CAP_IPC_OWNER)
            || creds
                .cap_effective
                .contains(LinuxCapabilitySet::CAP_SYS_ADMIN)
        {
            return Ok(());
        }

        if creds.euid == self.uid || creds.euid == self.cuid {
            if req_mode & 0o400 != 0 && self.mode & 0o400 == 0 {
                return Err(ERR_ACCES);
            }
            if req_mode & 0o200 != 0 && self.mode & 0o200 == 0 {
                return Err(ERR_ACCES);
            }
            return Ok(());
        }

        let is_group = creds.egid == self.gid
            || creds.egid == self.cgid
            || creds
                .groups
                .iter()
                .any(|g| *g == self.gid || *g == self.cgid);

        if is_group {
            if req_mode & 0o400 != 0 && self.mode & 0o040 == 0 {
                return Err(ERR_ACCES);
            }
            if req_mode & 0o200 != 0 && self.mode & 0o020 == 0 {
                return Err(ERR_ACCES);
            }
            return Ok(());
        }

        if req_mode & 0o400 != 0 && self.mode & 0o004 == 0 {
            return Err(ERR_ACCES);
        }
        if req_mode & 0o200 != 0 && self.mode & 0o002 == 0 {
            return Err(ERR_ACCES);
        }
        Ok(())
    }

    pub fn check_admin(&self, creds: &TaskCredentials) -> Result<(), i64> {
        if creds
            .cap_effective
            .contains(LinuxCapabilitySet::CAP_SYS_ADMIN)
            || creds
                .cap_effective
                .contains(LinuxCapabilitySet::CAP_IPC_OWNER)
            || creds.euid == self.uid
            || creds.euid == self.cuid
        {
            Ok(())
        } else {
            Err(ERR_PERM)
        }
    }
}

fn make_id(index: i32, seq: u16) -> i32 {
    let seq_part = (seq as i32 & IPCMNI_MASK) << 15;
    let idx_part = index & IPCMNI_MASK;
    seq_part | idx_part
}

fn id_to_index(id: i32) -> i32 {
    id & IPCMNI_MASK
}

fn id_to_seq(id: i32) -> u16 {
    ((id >> 15) & IPCMNI_MASK) as u16
}

fn update_seq(seqs: &mut Vec<(i32, u16)>, id: i32) {
    let idx = id_to_index(id);
    let next_seq = (id_to_seq(id).wrapping_add(1)) & (IPCMNI_MASK as u16);
    if let Some(entry) = seqs.iter_mut().find(|(i, _)| *i == idx) {
        entry.1 = next_seq;
    } else {
        seqs.push((idx, next_seq));
    }
}

#[derive(Clone, Eq, PartialEq)]
#[cfg_attr(test, derive(Debug))]
pub struct SysvMessage {
    pub mtype: i64,
    pub data: Vec<u8>,
}

#[derive(Clone)]
#[cfg_attr(test, derive(Debug))]
pub struct SysvMsgQueue {
    pub id: i32,
    pub perm: IpcPerm,
    pub qbytes: usize,
    pub messages: Vec<SysvMessage>,
    pub lspid: u32,
    pub lrpid: u32,
    pub stime: u64,
    pub rtime: u64,
    pub ctime: u64,
    pub wait_channel: u64,
}

impl SysvMsgQueue {
    pub fn current_bytes(&self) -> usize {
        self.messages.iter().map(|m| m.data.len()).sum()
    }
}

#[derive(Clone, Copy)]
#[cfg_attr(test, derive(Debug))]
pub struct SysvSem {
    pub semval: u16,
    pub sempid: u32,
    pub semncnt: u16,
    pub semzcnt: u16,
}

#[derive(Clone)]
#[cfg_attr(test, derive(Debug))]
pub struct SysvSemSet {
    pub id: i32,
    pub perm: IpcPerm,
    pub sems: Vec<SysvSem>,
    pub otime: u64,
    pub ctime: u64,
    pub wait_channel: u64,
}

#[derive(Clone)]
#[cfg_attr(test, derive(Debug))]
pub struct SysvShmSegment {
    pub id: i32,
    pub perm: IpcPerm,
    pub size: usize,
    pub atime: u64,
    pub dtime: u64,
    pub ctime: u64,
    pub cpid: u32,
    pub lpid: u32,
    pub nattch: u64,
    pub marked_for_destruction: bool,
    pub base_va: Option<u64>,
}

#[derive(Clone)]
#[cfg_attr(test, derive(Debug))]
pub struct MqueueMsg {
    pub prio: u32,
    pub data: Vec<u8>,
}

#[derive(Clone)]
#[cfg_attr(test, derive(Debug))]
pub struct Mqueue {
    pub id: u32,
    pub name: String,
    pub flags: i32,
    pub maxmsg: i64,
    pub msgsize: i64,
    pub messages: Vec<MqueueMsg>, // Kept sorted by prio descending
    pub unlinked: bool,
    pub refcount: usize,
    pub mode: u32,
    pub uid: TaskUid,
    pub gid: TaskGid,
    pub wait_channel: u64,
}

#[derive(Clone)]
#[cfg_attr(test, derive(Debug))]
pub struct MqueueDesc {
    pub mqdes: i32,
    pub queue_id: u32,
    pub oflag: i32,
}

#[derive(Clone, Copy, Eq, PartialEq)]
#[cfg_attr(test, derive(Debug))]
pub enum SemopOutcome {
    Complete,
    Suspend,
}

#[derive(Clone, Copy, Eq, PartialEq)]
#[cfg_attr(test, derive(Debug))]
pub enum MsgsndOutcome {
    Complete,
    Suspend,
}

#[derive(Clone, Eq, PartialEq)]
#[cfg_attr(test, derive(Debug))]
pub enum MsgrcvOutcome {
    Complete(SysvMessage),
    Suspend,
}

#[derive(Clone, Copy, Eq, PartialEq)]
#[cfg_attr(test, derive(Debug))]
pub enum MqSendOutcome {
    Complete,
    Suspend,
}

#[derive(Clone, Eq, PartialEq)]
#[cfg_attr(test, derive(Debug))]
pub enum MqReceiveOutcome {
    Complete(Vec<u8>, u32),
    Suspend,
}

#[derive(Clone)]
#[cfg_attr(test, derive(Debug))]
pub struct IpcNamespace {
    msg_slots: Vec<SysvMsgQueue>,
    msg_seqs: Vec<(i32, u16)>,
    next_msg_idx: i32,

    sem_slots: Vec<SysvSemSet>,
    sem_seqs: Vec<(i32, u16)>,
    next_sem_idx: i32,

    shm_slots: Vec<SysvShmSegment>,
    shm_seqs: Vec<(i32, u16)>,
    next_shm_idx: i32,
    next_shm_va: u64,

    mqueues: Vec<Mqueue>,
    mq_descriptors: Vec<MqueueDesc>,
    next_mqdes: i32,
    next_mq_id: u32,

    next_channel_id: u64,
}

impl Default for IpcNamespace {
    fn default() -> Self {
        Self::new()
    }
}

impl IpcNamespace {
    pub fn new() -> Self {
        Self {
            msg_slots: Vec::new(),
            msg_seqs: Vec::new(),
            next_msg_idx: 0,

            sem_slots: Vec::new(),
            sem_seqs: Vec::new(),
            next_sem_idx: 0,

            shm_slots: Vec::new(),
            shm_seqs: Vec::new(),
            next_shm_idx: 0,
            next_shm_va: 0x0000_0064_0000_0000,

            mqueues: Vec::new(),
            mq_descriptors: Vec::new(),
            next_mqdes: 1000,
            next_mq_id: 1,

            next_channel_id: 1,
        }
    }

    fn alloc_channel_id(&mut self) -> u64 {
        let id = self.next_channel_id;
        self.next_channel_id = self.next_channel_id.wrapping_add(1);
        id
    }

    // ------------------------------------------------------------------------
    // System V Message Queues
    // ------------------------------------------------------------------------

    pub fn msgget(&mut self, creds: &TaskCredentials, key: i32, msgflg: i32) -> Result<i32, i64> {
        if key == IPC_PRIVATE {
            return self.create_msg_queue(creds, key, msgflg);
        }

        if let Some(queue) = self.msg_slots.iter().find(|q| q.perm.key == key) {
            if msgflg & IPC_CREAT != 0 && msgflg & IPC_EXCL != 0 {
                return Err(ERR_EXIST);
            }
            queue.perm.check_perm(creds, (msgflg & 0o777) as u16)?;
            return Ok(queue.id);
        }

        if msgflg & IPC_CREAT == 0 {
            return Err(ERR_NOENT);
        }

        self.create_msg_queue(creds, key, msgflg)
    }

    fn create_msg_queue(
        &mut self,
        creds: &TaskCredentials,
        key: i32,
        msgflg: i32,
    ) -> Result<i32, i64> {
        if self.msg_slots.len() >= MSGMNI {
            return Err(ERR_NOSPC);
        }
        let mut idx = self.next_msg_idx;
        let mut found = false;
        for _ in 0..=self.msg_slots.len() {
            if !self.msg_slots.iter().any(|q| id_to_index(q.id) == idx) {
                self.next_msg_idx = (idx + 1) & IPCMNI_MASK;
                found = true;
                break;
            }
            idx = (idx + 1) & IPCMNI_MASK;
        }
        if !found {
            return Err(ERR_NOSPC);
        }
        let seq = self
            .msg_seqs
            .iter()
            .find(|(i, _)| *i == idx)
            .map(|(_, s)| *s)
            .unwrap_or(0);
        let id = make_id(idx, seq);
        let perm = IpcPerm::new(key, (msgflg & 0o777) as u16, seq, creds);
        let channel = self.alloc_channel_id();

        let queue = SysvMsgQueue {
            id,
            perm,
            qbytes: MSGMNB,
            messages: Vec::new(),
            lspid: 0,
            lrpid: 0,
            stime: 0,
            rtime: 0,
            ctime: 0,
            wait_channel: channel,
        };

        self.msg_slots.push(queue);
        Ok(id)
    }

    pub fn msg_queue(&self, id: i32) -> Result<&SysvMsgQueue, i64> {
        self.msg_slots.iter().find(|q| q.id == id).ok_or(ERR_INVAL)
    }

    pub fn msg_queue_mut(&mut self, id: i32) -> Result<&mut SysvMsgQueue, i64> {
        self.msg_slots
            .iter_mut()
            .find(|q| q.id == id)
            .ok_or(ERR_INVAL)
    }

    pub fn msgctl_rmid(&mut self, creds: &TaskCredentials, msqid: i32) -> Result<u64, i64> {
        let pos = self
            .msg_slots
            .iter()
            .position(|q| q.id == msqid)
            .ok_or(ERR_INVAL)?;
        self.msg_slots[pos].perm.check_admin(creds)?;
        let channel = self.msg_slots[pos].wait_channel;
        self.msg_slots.swap_remove(pos);
        update_seq(&mut self.msg_seqs, msqid);
        Ok(channel)
    }

    pub fn msgctl_set(
        &mut self,
        creds: &TaskCredentials,
        msqid: i32,
        uid: TaskUid,
        gid: TaskGid,
        mode: u16,
        qbytes: usize,
    ) -> Result<(), i64> {
        let queue = self.msg_queue_mut(msqid)?;
        queue.perm.check_admin(creds)?;

        if qbytes > queue.qbytes
            && !creds
                .cap_effective
                .contains(LinuxCapabilitySet::CAP_SYS_RESOURCE)
        {
            return Err(ERR_PERM);
        }

        queue.perm.uid = uid;
        queue.perm.gid = gid;
        queue.perm.mode = mode & 0o777;
        queue.qbytes = qbytes;
        Ok(())
    }

    pub fn msgsnd(
        &mut self,
        creds: &TaskCredentials,
        caller_pid: u32,
        msqid: i32,
        mtype: i64,
        data: &[u8],
        msgflg: i32,
    ) -> Result<(MsgsndOutcome, u64), i64> {
        if mtype <= 0 {
            return Err(ERR_INVAL);
        }
        if data.len() > MSGMAX {
            return Err(ERR_INVAL);
        }

        let queue = self.msg_queue_mut(msqid)?;
        queue.perm.check_perm(creds, 0o200)?;

        let channel = queue.wait_channel;
        if queue.current_bytes() + data.len() > queue.qbytes {
            if msgflg & IPC_NOWAIT != 0 {
                return Err(ERR_AGAIN);
            }
            return Ok((MsgsndOutcome::Suspend, channel));
        }

        queue.messages.push(SysvMessage {
            mtype,
            data: data.to_vec(),
        });
        queue.lspid = caller_pid;
        Ok((MsgsndOutcome::Complete, channel))
    }

    pub fn msgrcv(
        &mut self,
        creds: &TaskCredentials,
        caller_pid: u32,
        msqid: i32,
        msgsz: usize,
        msgtyp: i64,
        msgflg: i32,
    ) -> Result<(MsgrcvOutcome, u64), i64> {
        let queue = self.msg_queue_mut(msqid)?;
        queue.perm.check_perm(creds, 0o400)?;
        let channel = queue.wait_channel;

        let target_idx = if msgtyp == 0 {
            if queue.messages.is_empty() {
                None
            } else {
                Some(0)
            }
        } else if msgtyp > 0 {
            let except = msgflg & MSG_EXCEPT != 0;
            queue
                .messages
                .iter()
                .position(|m| (m.mtype == msgtyp) ^ except)
        } else {
            let max_type = -msgtyp;
            queue
                .messages
                .iter()
                .enumerate()
                .filter(|(_, m)| m.mtype <= max_type)
                .min_by_key(|(_, m)| m.mtype)
                .map(|(idx, _)| idx)
        };

        let Some(idx) = target_idx else {
            if msgflg & IPC_NOWAIT != 0 {
                return Err(ERR_NOMSG);
            }
            return Ok((MsgrcvOutcome::Suspend, channel));
        };

        let msg = &queue.messages[idx];
        if msg.data.len() > msgsz && msgflg & MSG_NOERROR == 0 {
            return Err(ERR_2BIG);
        }

        let mut msg = queue.messages.remove(idx);
        if msg.data.len() > msgsz {
            msg.data.truncate(msgsz);
        }

        queue.lrpid = caller_pid;
        Ok((MsgrcvOutcome::Complete(msg), channel))
    }

    // ------------------------------------------------------------------------
    // System V Semaphores
    // ------------------------------------------------------------------------

    pub fn semget(
        &mut self,
        creds: &TaskCredentials,
        key: i32,
        nsems: i32,
        semflg: i32,
    ) -> Result<i32, i64> {
        if nsems < 0 || nsems as usize > SEMMSL {
            return Err(ERR_INVAL);
        }

        if key == IPC_PRIVATE {
            if nsems == 0 {
                return Err(ERR_INVAL);
            }
            return self.create_sem_set(creds, key, nsems as usize, semflg);
        }

        if let Some(sem_set) = self.sem_slots.iter().find(|s| s.perm.key == key) {
            if semflg & IPC_CREAT != 0 && semflg & IPC_EXCL != 0 {
                return Err(ERR_EXIST);
            }
            if nsems as usize > sem_set.sems.len() {
                return Err(ERR_INVAL);
            }
            sem_set.perm.check_perm(creds, (semflg & 0o777) as u16)?;
            return Ok(sem_set.id);
        }

        if semflg & IPC_CREAT == 0 {
            return Err(ERR_NOENT);
        }
        if nsems == 0 {
            return Err(ERR_INVAL);
        }

        self.create_sem_set(creds, key, nsems as usize, semflg)
    }

    fn create_sem_set(
        &mut self,
        creds: &TaskCredentials,
        key: i32,
        nsems: usize,
        semflg: i32,
    ) -> Result<i32, i64> {
        if self.sem_slots.len() >= SEMMNI {
            return Err(ERR_NOSPC);
        }
        let mut idx = self.next_sem_idx;
        let mut found = false;
        for _ in 0..=self.sem_slots.len() {
            if !self.sem_slots.iter().any(|s| id_to_index(s.id) == idx) {
                self.next_sem_idx = (idx + 1) & IPCMNI_MASK;
                found = true;
                break;
            }
            idx = (idx + 1) & IPCMNI_MASK;
        }
        if !found {
            return Err(ERR_NOSPC);
        }
        let seq = self
            .sem_seqs
            .iter()
            .find(|(i, _)| *i == idx)
            .map(|(_, s)| *s)
            .unwrap_or(0);
        let id = make_id(idx, seq);
        let perm = IpcPerm::new(key, (semflg & 0o777) as u16, seq, creds);
        let channel = self.alloc_channel_id();

        let sems = alloc::vec![
            SysvSem {
                semval: 0,
                sempid: 0,
                semncnt: 0,
                semzcnt: 0,
            };
            nsems
        ];

        let sem_set = SysvSemSet {
            id,
            perm,
            sems,
            otime: 0,
            ctime: 0,
            wait_channel: channel,
        };

        self.sem_slots.push(sem_set);
        Ok(id)
    }

    pub fn sem_set(&self, id: i32) -> Result<&SysvSemSet, i64> {
        self.sem_slots.iter().find(|s| s.id == id).ok_or(ERR_INVAL)
    }

    pub fn sem_set_mut(&mut self, id: i32) -> Result<&mut SysvSemSet, i64> {
        self.sem_slots
            .iter_mut()
            .find(|s| s.id == id)
            .ok_or(ERR_INVAL)
    }

    pub fn semctl_rmid(&mut self, creds: &TaskCredentials, semid: i32) -> Result<u64, i64> {
        let pos = self
            .sem_slots
            .iter()
            .position(|s| s.id == semid)
            .ok_or(ERR_INVAL)?;
        self.sem_slots[pos].perm.check_admin(creds)?;
        let channel = self.sem_slots[pos].wait_channel;
        self.sem_slots.swap_remove(pos);
        update_seq(&mut self.sem_seqs, semid);
        Ok(channel)
    }

    pub fn semctl_setval(
        &mut self,
        creds: &TaskCredentials,
        caller_pid: u32,
        semid: i32,
        semnum: usize,
        val: u16,
    ) -> Result<u64, i64> {
        if val > SEMVMX {
            return Err(ERR_RANGE);
        }
        let set = self.sem_set_mut(semid)?;
        set.perm.check_perm(creds, 0o200)?;
        if semnum >= set.sems.len() {
            return Err(ERR_INVAL);
        }

        set.sems[semnum].semval = val;
        set.sems[semnum].sempid = caller_pid;
        Ok(set.wait_channel)
    }

    pub fn semop(
        &mut self,
        creds: &TaskCredentials,
        caller_pid: u32,
        semid: i32,
        sops: &[(u16, i16, i16)], // (sem_num, sem_op, sem_flg)
    ) -> Result<(SemopOutcome, u64), i64> {
        if sops.is_empty() || sops.len() > SEMOPM {
            return Err(ERR_2BIG);
        }

        let set = self.sem_set_mut(semid)?;
        let channel = set.wait_channel;

        // Check bounds and permissions
        let mut req_mode = 0o400;
        for &(num, op, _) in sops {
            if num as usize >= set.sems.len() {
                return Err(ERR_INVAL);
            }
            if op != 0 {
                req_mode |= 0o200;
            }
        }
        set.perm.check_perm(creds, req_mode)?;

        let any_nowait = sops
            .iter()
            .any(|&(_, _, flg)| flg & (IPC_NOWAIT as i16) != 0);

        // Check if all operations can be applied simultaneously
        let mut can_apply = true;
        for &(num, op, _) in sops {
            let sem = &set.sems[num as usize];
            if op > 0 {
                if (sem.semval as i32) + (op as i32) > (SEMVMX as i32) {
                    return Err(ERR_RANGE);
                }
            } else if op < 0 {
                if (sem.semval as i32) + (op as i32) < 0 {
                    can_apply = false;
                    break;
                }
            } else if sem.semval != 0 {
                can_apply = false;
                break;
            }
        }

        if !can_apply {
            if any_nowait {
                return Err(ERR_AGAIN);
            }
            return Ok((SemopOutcome::Suspend, channel));
        }

        // Apply all operations atomically
        for &(num, op, _) in sops {
            let sem = &mut set.sems[num as usize];
            if op != 0 {
                sem.semval = ((sem.semval as i32) + (op as i32)) as u16;
            }
            sem.sempid = caller_pid;
        }

        Ok((SemopOutcome::Complete, channel))
    }

    // ------------------------------------------------------------------------
    // System V Shared Memory
    // ------------------------------------------------------------------------

    pub fn shmget(
        &mut self,
        creds: &TaskCredentials,
        caller_pid: u32,
        key: i32,
        size: usize,
        shmflg: i32,
    ) -> Result<i32, i64> {
        if !(SHMMIN..=SHMMAX).contains(&size) {
            return Err(ERR_INVAL);
        }
        let page_size = 4096;
        let rounded_size = (size + page_size - 1) & !(page_size - 1);

        if key == IPC_PRIVATE {
            return self.create_shm_segment(creds, caller_pid, key, rounded_size, shmflg);
        }

        if let Some(segment) = self.shm_slots.iter().find(|s| s.perm.key == key) {
            if shmflg & IPC_CREAT != 0 && shmflg & IPC_EXCL != 0 {
                return Err(ERR_EXIST);
            }
            if size > segment.size {
                return Err(ERR_INVAL);
            }
            segment.perm.check_perm(creds, (shmflg & 0o777) as u16)?;
            return Ok(segment.id);
        }

        if shmflg & IPC_CREAT == 0 {
            return Err(ERR_NOENT);
        }

        self.create_shm_segment(creds, caller_pid, key, rounded_size, shmflg)
    }

    fn create_shm_segment(
        &mut self,
        creds: &TaskCredentials,
        caller_pid: u32,
        key: i32,
        size: usize,
        shmflg: i32,
    ) -> Result<i32, i64> {
        if self.shm_slots.len() >= SHMMNI {
            return Err(ERR_NOSPC);
        }
        let mut idx = self.next_shm_idx;
        let mut found = false;
        for _ in 0..=self.shm_slots.len() {
            if !self.shm_slots.iter().any(|s| id_to_index(s.id) == idx) {
                self.next_shm_idx = (idx + 1) & IPCMNI_MASK;
                found = true;
                break;
            }
            idx = (idx + 1) & IPCMNI_MASK;
        }
        if !found {
            return Err(ERR_NOSPC);
        }
        let seq = self
            .shm_seqs
            .iter()
            .find(|(i, _)| *i == idx)
            .map(|(_, s)| *s)
            .unwrap_or(0);
        let id = make_id(idx, seq);
        let perm = IpcPerm::new(key, (shmflg & 0o777) as u16, seq, creds);

        let segment = SysvShmSegment {
            id,
            perm,
            size,
            atime: 0,
            dtime: 0,
            ctime: 0,
            cpid: caller_pid,
            lpid: 0,
            nattch: 0,
            marked_for_destruction: false,
            base_va: None,
        };

        self.shm_slots.push(segment);
        Ok(id)
    }

    pub fn shm_segment(&self, id: i32) -> Result<&SysvShmSegment, i64> {
        self.shm_slots.iter().find(|s| s.id == id).ok_or(ERR_INVAL)
    }

    pub fn shm_segment_mut(&mut self, id: i32) -> Result<&mut SysvShmSegment, i64> {
        self.shm_slots
            .iter_mut()
            .find(|s| s.id == id)
            .ok_or(ERR_INVAL)
    }

    pub fn shmat(
        &mut self,
        creds: &TaskCredentials,
        caller_pid: u32,
        shmid: i32,
        shmaddr: u64,
        shmflg: i32,
    ) -> Result<(u64, usize), i64> {
        let pos = self
            .shm_slots
            .iter()
            .position(|s| s.id == shmid)
            .ok_or(ERR_INVAL)?;
        let req_mode = if shmflg & SHM_RDONLY != 0 {
            0o400
        } else {
            0o600
        };
        self.shm_slots[pos].perm.check_perm(creds, req_mode)?;

        let size = self.shm_slots[pos].size;
        let existing_va = self.shm_slots[pos].base_va;

        let va = if shmaddr != 0 {
            if shmaddr & 4095 != 0 && shmflg & SHM_RND == 0 {
                return Err(ERR_INVAL);
            }
            if shmflg & SHM_RND != 0 {
                shmaddr & !4095
            } else {
                shmaddr
            }
        } else if let Some(base) = existing_va {
            base
        } else {
            let va = self.next_shm_va;
            let step = ((size as u64).max(0x1000) + 4095) & !4095;
            self.next_shm_va = self.next_shm_va.checked_add(step).ok_or(ERR_NOMEM)?;
            self.shm_slots[pos].base_va = Some(va);
            va
        };

        let segment = &mut self.shm_slots[pos];
        segment.nattch = segment.nattch.saturating_add(1);
        segment.lpid = caller_pid;
        Ok((va, size))
    }

    pub fn shmdt(&mut self, caller_pid: u32, shmaddr: u64) -> Result<(), i64> {
        let mut target_pos = None;
        for (pos, seg) in self.shm_slots.iter().enumerate() {
            if seg.base_va == Some(shmaddr) && seg.nattch > 0 {
                target_pos = Some(pos);
                break;
            }
        }

        let Some(pos) = target_pos else {
            return Err(ERR_INVAL);
        };

        let seg = &mut self.shm_slots[pos];
        seg.nattch = seg.nattch.saturating_sub(1);
        seg.lpid = caller_pid;

        if seg.marked_for_destruction && seg.nattch == 0 {
            let id = seg.id;
            self.shm_slots.swap_remove(pos);
            update_seq(&mut self.shm_seqs, id);
        }

        Ok(())
    }

    pub fn shmctl_rmid(&mut self, creds: &TaskCredentials, shmid: i32) -> Result<(), i64> {
        let pos = self
            .shm_slots
            .iter()
            .position(|s| s.id == shmid)
            .ok_or(ERR_INVAL)?;
        self.shm_slots[pos].perm.check_admin(creds)?;

        if self.shm_slots[pos].nattch == 0 {
            self.shm_slots.swap_remove(pos);
            update_seq(&mut self.shm_seqs, shmid);
        } else {
            self.shm_slots[pos].marked_for_destruction = true;
        }

        Ok(())
    }

    // ------------------------------------------------------------------------
    // POSIX Message Queues (mq_*)
    // ------------------------------------------------------------------------

    pub fn mq_open(
        &mut self,
        creds: &TaskCredentials,
        name: &str,
        oflag: i32,
        mode: u32,
        attr: Option<(i64, i64)>, // (maxmsg, msgsize)
    ) -> Result<i32, i64> {
        let norm_name = name.strip_prefix('/').unwrap_or(name);
        if norm_name.is_empty() {
            return Err(ERR_INVAL);
        }

        if let Some(queue) = self.mqueues.iter_mut().find(|q| q.name == norm_name) {
            if oflag & O_CREAT != 0 && oflag & O_EXCL != 0 {
                return Err(ERR_EXIST);
            }
            queue.refcount += 1;
            let queue_id = queue.id;
            let mqdes = self.next_mqdes;
            self.next_mqdes += 1;
            self.mq_descriptors.push(MqueueDesc {
                mqdes,
                queue_id,
                oflag,
            });
            return Ok(mqdes);
        }

        if oflag & O_CREAT == 0 {
            return Err(ERR_NOENT);
        }

        let (maxmsg, msgsize) = match attr {
            Some((max, size)) if max > 0 && size > 0 => (max, size),
            _ => (MQ_MAXMSG_DEFAULT, MQ_MSGSIZE_DEFAULT),
        };

        let channel = self.alloc_channel_id();
        let queue_id = self.next_mq_id;
        self.next_mq_id += 1;
        let queue = Mqueue {
            id: queue_id,
            name: String::from(norm_name),
            flags: oflag & O_NONBLOCK,
            maxmsg,
            msgsize,
            messages: Vec::new(),
            unlinked: false,
            refcount: 1,
            mode,
            uid: creds.euid,
            gid: creds.egid,
            wait_channel: channel,
        };

        self.mqueues.push(queue);
        let mqdes = self.next_mqdes;
        self.next_mqdes += 1;
        self.mq_descriptors.push(MqueueDesc {
            mqdes,
            queue_id,
            oflag,
        });
        Ok(mqdes)
    }

    pub fn mq_unlink(&mut self, _creds: &TaskCredentials, name: &str) -> Result<(), i64> {
        let norm_name = name.strip_prefix('/').unwrap_or(name);
        let pos = self
            .mqueues
            .iter()
            .position(|q| q.name == norm_name)
            .ok_or(ERR_NOENT)?;
        self.mqueues[pos].unlinked = true;
        if self.mqueues[pos].refcount == 0 {
            self.mqueues.swap_remove(pos);
        }
        Ok(())
    }

    pub fn mq_close(&mut self, mqdes: i32) -> Result<(), i64> {
        let desc_pos = self
            .mq_descriptors
            .iter()
            .position(|d| d.mqdes == mqdes)
            .ok_or(ERR_BADF)?;
        let desc = self.mq_descriptors.swap_remove(desc_pos);
        if let Some(queue_pos) = self.mqueues.iter().position(|q| q.id == desc.queue_id) {
            let queue = &mut self.mqueues[queue_pos];
            queue.refcount = queue.refcount.saturating_sub(1);
            if queue.refcount == 0 && queue.unlinked {
                self.mqueues.swap_remove(queue_pos);
            }
        }
        Ok(())
    }

    pub fn mq_timedsend(
        &mut self,
        _creds: &TaskCredentials,
        mqdes: i32,
        data: &[u8],
        prio: u32,
    ) -> Result<(MqSendOutcome, u64), i64> {
        let desc = self
            .mq_descriptors
            .iter()
            .find(|d| d.mqdes == mqdes)
            .ok_or(ERR_BADF)?;
        let queue = self
            .mqueues
            .iter_mut()
            .find(|q| q.id == desc.queue_id)
            .ok_or(ERR_BADF)?;

        if (desc.oflag & O_WRONLY == 0) && (desc.oflag & O_RDWR == 0) {
            return Err(ERR_BADF);
        }
        if data.len() as i64 > queue.msgsize {
            return Err(ERR_MSGSIZE);
        }

        let channel = queue.wait_channel;
        if queue.messages.len() as i64 >= queue.maxmsg {
            if desc.oflag & O_NONBLOCK != 0 {
                return Err(ERR_AGAIN);
            }
            return Ok((MqSendOutcome::Suspend, channel));
        }

        // Insert sorted by priority descending
        let pos = queue
            .messages
            .iter()
            .position(|m| m.prio < prio)
            .unwrap_or(queue.messages.len());
        queue.messages.insert(
            pos,
            MqueueMsg {
                prio,
                data: data.to_vec(),
            },
        );

        Ok((MqSendOutcome::Complete, channel))
    }

    pub fn mq_timedreceive(
        &mut self,
        _creds: &TaskCredentials,
        mqdes: i32,
        max_len: usize,
    ) -> Result<(MqReceiveOutcome, u64), i64> {
        let desc = self
            .mq_descriptors
            .iter()
            .find(|d| d.mqdes == mqdes)
            .ok_or(ERR_BADF)?;
        let queue = self
            .mqueues
            .iter_mut()
            .find(|q| q.id == desc.queue_id)
            .ok_or(ERR_BADF)?;

        if (desc.oflag & O_WRONLY != 0) && (desc.oflag & O_RDWR == 0) {
            return Err(ERR_BADF);
        }
        if (max_len as i64) < queue.msgsize {
            return Err(ERR_MSGSIZE);
        }

        let channel = queue.wait_channel;
        if queue.messages.is_empty() {
            if desc.oflag & O_NONBLOCK != 0 {
                return Err(ERR_AGAIN);
            }
            return Ok((MqReceiveOutcome::Suspend, channel));
        }

        let msg = queue.messages.remove(0);
        Ok((MqReceiveOutcome::Complete(msg.data, msg.prio), channel))
    }

    pub fn mq_getsetattr(
        &mut self,
        mqdes: i32,
        new_flags: Option<i32>,
    ) -> Result<(i32, i64, i64, i64), i64> {
        let desc = self
            .mq_descriptors
            .iter_mut()
            .find(|d| d.mqdes == mqdes)
            .ok_or(ERR_BADF)?;
        let queue = self
            .mqueues
            .iter()
            .find(|q| q.id == desc.queue_id)
            .ok_or(ERR_BADF)?;

        let old_flags = desc.oflag & O_NONBLOCK;
        let maxmsg = queue.maxmsg;
        let msgsize = queue.msgsize;
        let curmsgs = queue.messages.len() as i64;

        if let Some(flags) = new_flags {
            if flags & O_NONBLOCK != 0 {
                desc.oflag |= O_NONBLOCK;
            } else {
                desc.oflag &= !O_NONBLOCK;
            }
        }

        Ok((old_flags, maxmsg, msgsize, curmsgs))
    }

    pub fn mq_notify(&mut self, mqdes: i32, sevp: u64) -> Result<(), i64> {
        let desc = self
            .mq_descriptors
            .iter()
            .find(|d| d.mqdes == mqdes)
            .ok_or(ERR_BADF)?;
        let _queue = self
            .mqueues
            .iter_mut()
            .find(|q| q.id == desc.queue_id)
            .ok_or(ERR_BADF)?;
        if sevp == 0 {
            // Unregister notification
            Ok(())
        } else {
            // Asynchronous notification registration depends on the in-ring signal delivery lane.
            Err(ERR_NOSYS)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ipc_perm_rules() {
        let mut creds = TaskCredentials::ROOT;
        creds.euid = TaskUid::new(1000);
        creds.egid = TaskGid::new(1000);
        creds.cap_effective = LinuxCapabilitySet::empty();

        let perm = IpcPerm::new(1234, 0o600, 1, &creds);
        // Owner read and write allowed
        assert_eq!(perm.check_perm(&creds, 0o400), Ok(()));
        assert_eq!(perm.check_perm(&creds, 0o200), Ok(()));

        // Different user cannot access mode 0600
        let mut other_creds = TaskCredentials::ROOT;
        other_creds.euid = TaskUid::new(2000);
        other_creds.egid = TaskGid::new(2000);
        other_creds.cap_effective = LinuxCapabilitySet::empty();
        assert_eq!(perm.check_perm(&other_creds, 0o400), Err(ERR_ACCES));
        assert_eq!(perm.check_perm(&other_creds, 0o200), Err(ERR_ACCES));

        // Mode 0000 denies owner access
        let perm_zero = IpcPerm::new(1234, 0o000, 1, &creds);
        assert_eq!(perm_zero.check_perm(&creds, 0o200), Err(ERR_ACCES));

        // Privileged CAP_IPC_OWNER bypasses checks
        other_creds.cap_effective = LinuxCapabilitySet::CAP_IPC_OWNER;
        assert_eq!(perm.check_perm(&other_creds, 0o400), Ok(()));
    }

    #[test]
    fn test_sysv_msg_round_trip() {
        let creds = TaskCredentials::ROOT;
        let mut ns = IpcNamespace::new();
        let key = 1234;
        let msqid = ns.msgget(&creds, key, IPC_CREAT | 0o666).unwrap();

        let msg_data = b"hello world";
        let (outcome, _) = ns.msgsnd(&creds, 42, msqid, 1, msg_data, 0).unwrap();
        assert_eq!(outcome, MsgsndOutcome::Complete);

        let (rcv_outcome, _) = ns.msgrcv(&creds, 42, msqid, 100, 1, 0).unwrap();
        match rcv_outcome {
            MsgrcvOutcome::Complete(msg) => {
                assert_eq!(msg.mtype, 1);
                assert_eq!(msg.data, msg_data);
            }
            MsgrcvOutcome::Suspend => panic!("expected complete"),
        }

        // Now queue is empty, msgrcv with IPC_NOWAIT returns ERR_NOMSG
        assert_eq!(
            ns.msgrcv(&creds, 42, msqid, 100, 1, IPC_NOWAIT)
                .unwrap_err(),
            ERR_NOMSG
        );

        // Remove queue
        ns.msgctl_rmid(&creds, msqid).unwrap();
        assert_eq!(ns.msgget(&creds, key, 0).unwrap_err(), ERR_NOENT);
    }

    #[test]
    fn test_sysv_sem_operations() {
        let creds = TaskCredentials::ROOT;
        let mut ns = IpcNamespace::new();
        let semid = ns
            .semget(&creds, IPC_PRIVATE, 1, IPC_CREAT | 0o666)
            .unwrap();

        // Initially semval is 0
        assert_eq!(ns.sem_set(semid).unwrap().sems[0].semval, 0);

        // semop -1 without IPC_NOWAIT suspends
        let (outcome, _) = ns.semop(&creds, 42, semid, &[(0, -1, 0)]).unwrap();
        assert_eq!(outcome, SemopOutcome::Suspend);

        // semop -1 with IPC_NOWAIT returns ERR_AGAIN
        assert_eq!(
            ns.semop(&creds, 42, semid, &[(0, -1, IPC_NOWAIT as i16)])
                .unwrap_err(),
            ERR_AGAIN
        );

        // semop +1 completes
        let (outcome, _) = ns.semop(&creds, 42, semid, &[(0, 1, 0)]).unwrap();
        assert_eq!(outcome, SemopOutcome::Complete);
        assert_eq!(ns.sem_set(semid).unwrap().sems[0].semval, 1);

        // Now semop -1 completes
        let (outcome, _) = ns.semop(&creds, 42, semid, &[(0, -1, 0)]).unwrap();
        assert_eq!(outcome, SemopOutcome::Complete);
        assert_eq!(ns.sem_set(semid).unwrap().sems[0].semval, 0);

        ns.semctl_rmid(&creds, semid).unwrap();
    }

    #[test]
    fn test_posix_mqueue_round_trip() {
        let creds = TaskCredentials::ROOT;
        let mut ns = IpcNamespace::new();
        let name = "test_queue";
        let mqdes = ns
            .mq_open(&creds, name, O_RDWR | O_CREAT | O_NONBLOCK, 0o666, None)
            .unwrap();

        // Empty queue with O_NONBLOCK returns ERR_AGAIN
        assert_eq!(
            ns.mq_timedreceive(&creds, mqdes, 8192).unwrap_err(),
            ERR_AGAIN
        );

        // Send message
        let (outcome, _) = ns.mq_timedsend(&creds, mqdes, b"TEST", 5).unwrap();
        assert_eq!(outcome, MqSendOutcome::Complete);

        // Receive message
        let (rcv_outcome, _) = ns.mq_timedreceive(&creds, mqdes, 8192).unwrap();
        match rcv_outcome {
            MqReceiveOutcome::Complete(data, prio) => {
                assert_eq!(data, b"TEST");
                assert_eq!(prio, 5);
            }
            MqReceiveOutcome::Suspend => panic!("expected complete"),
        }

        // Empty again returns ERR_AGAIN
        assert_eq!(
            ns.mq_timedreceive(&creds, mqdes, 8192).unwrap_err(),
            ERR_AGAIN
        );

        ns.mq_unlink(&creds, name).unwrap();
        ns.mq_close(mqdes).unwrap();
    }
}
