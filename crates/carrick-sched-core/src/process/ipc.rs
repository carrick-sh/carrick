//! In-zone IPC namespace for System V IPC (messages and semaphores).
//!
//! Provides container-scoped IPC objects (messages and semaphores)
//! owned by Carrick's kernel graph without host delegation.

extern crate alloc;

use alloc::vec::Vec;

use super::{LinuxCapabilitySet, TaskCredentials, TaskGid, TaskUid};
pub use carrick_syscall_abi::ipc::{
    IPC_CREAT, IPC_EXCL, IPC_NOWAIT, IPC_PRIVATE, LinuxIpcPerm, LinuxMsginfo, LinuxMsqidDs,
    LinuxSembuf, LinuxSemidDs, LinuxSeminfo, MSG_EXCEPT, MSG_NOERROR, MSGMAX, MSGMNB, MSGMNI,
    SEM_UNDO, SEMMNI, SEMMNS, SEMMSL, SEMOPM, SEMVMX,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum IpcError {
    NotPermitted,
    NoEntity,
    Interrupted,
    Again,
    PermissionDenied,
    BadAddress,
    AlreadyExists,
    InvalidArgument,
    TooBig,
    NoSpace,
    Range,
    NoMsg,
    IdentifierRemoved,
}

impl IpcError {
    #[inline]
    pub const fn guest_retval(self) -> i64 {
        match self {
            Self::NotPermitted => -1,
            Self::NoEntity => -2,
            Self::Interrupted => -4,
            Self::Again => -11,
            Self::PermissionDenied => -13,
            Self::BadAddress => -14,
            Self::AlreadyExists => -17,
            Self::InvalidArgument => -22,
            Self::TooBig => -7,
            Self::NoSpace => -28,
            Self::Range => -34,
            Self::NoMsg => -42,
            Self::IdentifierRemoved => -43,
        }
    }
}

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

    /// Check if `creds` satisfy `req_mode`.
    /// Follows Linux ipc(2) credential rules:
    /// - Privileged (CAP_IPC_OWNER) bypasses access check.
    /// - Existing-key request mask is folded across u/g/o ((req >> 6) | (req >> 3) | req) & 0o7.
    /// - If UID matches `perm.uid` or `perm.cuid`, ONLY owner bits are checked.
    /// - Else if GID matches `perm.gid` or `perm.cgid` or any supplementary group, ONLY group bits are checked.
    /// - Else other bits are checked.
    pub fn check_perm(&self, creds: &TaskCredentials, req_mode: u16) -> Result<(), IpcError> {
        if creds
            .cap_effective
            .contains(LinuxCapabilitySet::CAP_IPC_OWNER)
        {
            return Ok(());
        }

        let req = ((req_mode >> 6) | (req_mode >> 3) | req_mode) & 0o7;
        let is_owner = creds.euid == self.uid || creds.euid == self.cuid;
        let is_group = creds.egid == self.gid
            || creds.egid == self.cgid
            || creds
                .groups
                .iter()
                .any(|g| *g == self.gid || *g == self.cgid);

        let granted = if is_owner {
            (self.mode >> 6) & 0o7
        } else if is_group {
            (self.mode >> 3) & 0o7
        } else {
            self.mode & 0o7
        };

        if (req & !granted) != 0 {
            return Err(IpcError::PermissionDenied);
        }
        Ok(())
    }

    /// Check administrative permissions for IPC_SET / IPC_RMID.
    /// Requires CAP_SYS_ADMIN or effective UID matching owner or creator UID.
    pub fn check_admin(&self, creds: &TaskCredentials) -> Result<(), IpcError> {
        if creds
            .cap_effective
            .contains(LinuxCapabilitySet::CAP_SYS_ADMIN)
            || creds.euid == self.uid
            || creds.euid == self.cuid
        {
            Ok(())
        } else {
            Err(IpcError::NotPermitted)
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
    pub stime: i64,
    pub rtime: i64,
    pub ctime: i64,
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
    pub otime: i64,
    pub ctime: i64,
    pub wait_channel: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MsgsndOutcome {
    Complete,
    Suspend,
}

#[derive(Clone, Eq, PartialEq)]
#[cfg_attr(test, derive(Debug))]
pub enum MsgrcvOutcome {
    Complete {
        msg: SysvMessage,
        original_idx: usize,
    },
    Suspend,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SemopOutcome {
    Complete,
    Suspend { sem_num: u16, is_zero: bool },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct SemUndoEntry {
    pid: u32,
    semid: i32,
    semnum: u16,
    adj: i16,
}

pub struct IpcNamespace {
    msg_slots: Vec<SysvMsgQueue>,
    msg_seqs: Vec<(i32, u16)>,
    next_msg_idx: i32,

    sem_slots: Vec<SysvSemSet>,
    sem_seqs: Vec<(i32, u16)>,
    next_sem_idx: i32,

    sem_undo: Vec<SemUndoEntry>,
    next_channel_id: u64,
    current_time: i64,
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

            sem_undo: Vec::new(),
            next_channel_id: 1,
            current_time: 1_700_000_000,
        }
    }

    fn tick_time(&mut self) -> i64 {
        let t = self.current_time;
        self.current_time = self.current_time.saturating_add(1);
        t
    }

    fn alloc_channel_id(&mut self) -> u64 {
        let id = self.next_channel_id;
        self.next_channel_id = self.next_channel_id.wrapping_add(1);
        id
    }

    // ------------------------------------------------------------------------
    // System V Message Queues
    // ------------------------------------------------------------------------

    pub fn msgget(
        &mut self,
        creds: &TaskCredentials,
        key: i32,
        msgflg: i32,
    ) -> Result<i32, IpcError> {
        if key == IPC_PRIVATE {
            return self.create_msg_queue(creds, key, msgflg);
        }

        if let Some(queue) = self.msg_slots.iter().find(|q| q.perm.key == key) {
            if msgflg & IPC_CREAT != 0 && msgflg & IPC_EXCL != 0 {
                return Err(IpcError::AlreadyExists);
            }
            queue.perm.check_perm(creds, (msgflg & 0o777) as u16)?;
            return Ok(queue.id);
        }

        if msgflg & IPC_CREAT == 0 {
            return Err(IpcError::NoEntity);
        }

        self.create_msg_queue(creds, key, msgflg)
    }

    fn create_msg_queue(
        &mut self,
        creds: &TaskCredentials,
        key: i32,
        msgflg: i32,
    ) -> Result<i32, IpcError> {
        if self.msg_slots.len() >= MSGMNI {
            return Err(IpcError::NoSpace);
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
            return Err(IpcError::NoSpace);
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
        let now = self.tick_time();

        let queue = SysvMsgQueue {
            id,
            perm,
            qbytes: MSGMNB,
            messages: Vec::new(),
            lspid: 0,
            lrpid: 0,
            stime: 0,
            rtime: 0,
            ctime: now,
            wait_channel: channel,
        };

        self.msg_slots.push(queue);
        Ok(id)
    }

    pub fn msg_queue(&self, id: i32) -> Result<&SysvMsgQueue, IpcError> {
        self.msg_slots
            .iter()
            .find(|q| q.id == id)
            .ok_or(IpcError::InvalidArgument)
    }

    pub fn msg_queue_mut(&mut self, id: i32) -> Result<&mut SysvMsgQueue, IpcError> {
        self.msg_slots
            .iter_mut()
            .find(|q| q.id == id)
            .ok_or(IpcError::InvalidArgument)
    }

    pub fn is_valid_msg_queue(&self, id: i32) -> bool {
        self.msg_slots.iter().any(|q| q.id == id)
    }

    pub fn msgctl_rmid(&mut self, creds: &TaskCredentials, msqid: i32) -> Result<u64, IpcError> {
        let pos = self
            .msg_slots
            .iter()
            .position(|q| q.id == msqid)
            .ok_or(IpcError::InvalidArgument)?;
        self.msg_slots[pos].perm.check_admin(creds)?;
        let channel = self.msg_slots[pos].wait_channel;
        self.msg_slots.swap_remove(pos);
        update_seq(&mut self.msg_seqs, msqid);
        Ok(channel)
    }

    pub fn msgctl_stat(
        &self,
        creds: &TaskCredentials,
        msqid: i32,
        out: &mut LinuxMsqidDs,
    ) -> Result<i64, IpcError> {
        let queue = self.msg_queue(msqid)?;
        queue.perm.check_perm(creds, 0o400)?;

        out.msg_perm = LinuxIpcPerm {
            key: queue.perm.key,
            uid: queue.perm.uid.raw(),
            gid: queue.perm.gid.raw(),
            cuid: queue.perm.cuid.raw(),
            cgid: queue.perm.cgid.raw(),
            mode: queue.perm.mode,
            __pad1: 0,
            seq: queue.perm.seq,
            __pad2: 0,
            __glibc_reserved1: 0,
            __glibc_reserved2: 0,
        };
        out.msg_stime = queue.stime;
        out.msg_rtime = queue.rtime;
        out.msg_ctime = queue.ctime;
        out.msg_cbytes = queue.current_bytes() as u64;
        out.msg_qnum = queue.messages.len() as u64;
        out.msg_qbytes = queue.qbytes as u64;
        out.msg_lspid = queue.lspid as i32;
        out.msg_lrpid = queue.lrpid as i32;
        out.__glibc_reserved4 = 0;
        out.__glibc_reserved5 = 0;

        Ok(0)
    }

    pub fn msgctl_set(
        &mut self,
        creds: &TaskCredentials,
        msqid: i32,
        ds: &LinuxMsqidDs,
    ) -> Result<(), IpcError> {
        let qbytes = ds.msg_qbytes as usize;
        let now = self.tick_time();
        let queue = self.msg_queue_mut(msqid)?;
        queue.perm.check_admin(creds)?;

        if qbytes > MSGMNB
            && !creds
                .cap_effective
                .contains(LinuxCapabilitySet::CAP_SYS_RESOURCE)
        {
            return Err(IpcError::NotPermitted);
        }

        queue.perm.uid = TaskUid::new(ds.msg_perm.uid);
        queue.perm.gid = TaskGid::new(ds.msg_perm.gid);
        queue.perm.mode = ds.msg_perm.mode & 0o777;
        queue.qbytes = qbytes;
        queue.ctime = now;
        Ok(())
    }

    pub fn msgctl_info(&self, out: &mut LinuxMsginfo) -> Result<i64, IpcError> {
        out.msgpool = 1024;
        out.msgmap = 1024;
        out.msgmax = MSGMAX as i32;
        out.msgmnb = MSGMNB as i32;
        out.msgmni = MSGMNI as i32;
        out.msgssz = 16;
        out.msgtql = 1024;
        out.msgseg = 0xffff;

        let max_idx = self
            .msg_slots
            .iter()
            .map(|q| id_to_index(q.id))
            .max()
            .unwrap_or(0);
        Ok(max_idx as i64)
    }

    pub fn msgsnd(
        &mut self,
        creds: &TaskCredentials,
        caller_pid: u32,
        msqid: i32,
        mtype: i64,
        data: &[u8],
        msgflg: i32,
    ) -> Result<(MsgsndOutcome, u64), IpcError> {
        if mtype <= 0 || data.len() > MSGMAX {
            return Err(IpcError::InvalidArgument);
        }

        let now = self.tick_time();
        let queue = self.msg_queue_mut(msqid)?;
        queue.perm.check_perm(creds, 0o200)?;

        let channel = queue.wait_channel;
        if queue.current_bytes() + data.len() > queue.qbytes
            || 1 + queue.messages.len() > queue.qbytes
        {
            if msgflg & IPC_NOWAIT != 0 {
                return Err(IpcError::Again);
            }
            return Ok((MsgsndOutcome::Suspend, channel));
        }

        queue.messages.push(SysvMessage {
            mtype,
            data: data.to_vec(),
        });
        queue.lspid = caller_pid;
        queue.stime = now;
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
    ) -> Result<(MsgrcvOutcome, u64), IpcError> {
        let now = self.tick_time();
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
                return Err(IpcError::NoMsg);
            }
            return Ok((MsgrcvOutcome::Suspend, channel));
        };

        let msg = &queue.messages[idx];
        if msg.data.len() > msgsz && msgflg & MSG_NOERROR == 0 {
            return Err(IpcError::TooBig);
        }

        let mut msg = queue.messages.remove(idx);
        if msg.data.len() > msgsz {
            msg.data.truncate(msgsz);
        }

        queue.lrpid = caller_pid;
        queue.rtime = now;
        Ok((
            MsgrcvOutcome::Complete {
                msg,
                original_idx: idx,
            },
            channel,
        ))
    }

    pub fn msgrcv_restore(
        &mut self,
        msqid: i32,
        original_idx: usize,
        mtype: i64,
        data: Vec<u8>,
    ) -> Result<u64, IpcError> {
        let queue = self.msg_queue_mut(msqid)?;
        let insert_idx = original_idx.min(queue.messages.len());
        queue
            .messages
            .insert(insert_idx, SysvMessage { mtype, data });
        Ok(queue.wait_channel)
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
    ) -> Result<i32, IpcError> {
        if nsems < 0 || nsems as usize > SEMMSL {
            return Err(IpcError::InvalidArgument);
        }

        if key == IPC_PRIVATE {
            if nsems == 0 {
                return Err(IpcError::InvalidArgument);
            }
            return self.create_sem_set(creds, key, nsems as usize, semflg);
        }

        if let Some(sem_set) = self.sem_slots.iter().find(|s| s.perm.key == key) {
            if semflg & IPC_CREAT != 0 && semflg & IPC_EXCL != 0 {
                return Err(IpcError::AlreadyExists);
            }
            if nsems as usize > sem_set.sems.len() {
                return Err(IpcError::InvalidArgument);
            }
            sem_set.perm.check_perm(creds, (semflg & 0o777) as u16)?;
            return Ok(sem_set.id);
        }

        if semflg & IPC_CREAT == 0 {
            return Err(IpcError::NoEntity);
        }
        if nsems == 0 {
            return Err(IpcError::InvalidArgument);
        }

        self.create_sem_set(creds, key, nsems as usize, semflg)
    }

    fn create_sem_set(
        &mut self,
        creds: &TaskCredentials,
        key: i32,
        nsems: usize,
        semflg: i32,
    ) -> Result<i32, IpcError> {
        if self.sem_slots.len() >= SEMMNI {
            return Err(IpcError::NoSpace);
        }
        let total_sems: usize = self.sem_slots.iter().map(|s| s.sems.len()).sum();
        if total_sems + nsems > SEMMNS {
            return Err(IpcError::NoSpace);
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
            return Err(IpcError::NoSpace);
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
        let now = self.tick_time();

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
            ctime: now,
            wait_channel: channel,
        };

        self.sem_slots.push(sem_set);
        Ok(id)
    }

    pub fn sem_set(&self, id: i32) -> Result<&SysvSemSet, IpcError> {
        self.sem_slots
            .iter()
            .find(|s| s.id == id)
            .ok_or(IpcError::InvalidArgument)
    }

    pub fn sem_set_mut(&mut self, id: i32) -> Result<&mut SysvSemSet, IpcError> {
        self.sem_slots
            .iter_mut()
            .find(|s| s.id == id)
            .ok_or(IpcError::InvalidArgument)
    }

    pub fn is_valid_sem_set(&self, id: i32) -> bool {
        self.sem_slots.iter().any(|s| s.id == id)
    }

    pub fn semctl_rmid(&mut self, creds: &TaskCredentials, semid: i32) -> Result<u64, IpcError> {
        let pos = self
            .sem_slots
            .iter()
            .position(|s| s.id == semid)
            .ok_or(IpcError::InvalidArgument)?;
        self.sem_slots[pos].perm.check_admin(creds)?;
        let channel = self.sem_slots[pos].wait_channel;
        self.sem_slots.swap_remove(pos);
        update_seq(&mut self.sem_seqs, semid);
        self.sem_undo.retain(|e| e.semid != semid);
        Ok(channel)
    }

    pub fn semctl_stat(
        &self,
        creds: &TaskCredentials,
        semid: i32,
        out: &mut LinuxSemidDs,
    ) -> Result<i64, IpcError> {
        let set = self.sem_set(semid)?;
        set.perm.check_perm(creds, 0o400)?;

        out.sem_perm = LinuxIpcPerm {
            key: set.perm.key,
            uid: set.perm.uid.raw(),
            gid: set.perm.gid.raw(),
            cuid: set.perm.cuid.raw(),
            cgid: set.perm.cgid.raw(),
            mode: set.perm.mode,
            __pad1: 0,
            seq: set.perm.seq,
            __pad2: 0,
            __glibc_reserved1: 0,
            __glibc_reserved2: 0,
        };
        out.sem_otime = set.otime;
        out.__glibc_reserved1 = 0;
        out.sem_ctime = set.ctime;
        out.__glibc_reserved2 = 0;
        out.sem_nsems = set.sems.len() as u64;
        out.__glibc_reserved3 = 0;
        out.__glibc_reserved4 = 0;

        Ok(0)
    }

    pub fn semctl_set(
        &mut self,
        creds: &TaskCredentials,
        semid: i32,
        ds: &LinuxSemidDs,
    ) -> Result<i64, IpcError> {
        let now = self.tick_time();
        let set = self.sem_set_mut(semid)?;
        set.perm.check_admin(creds)?;

        set.perm.uid = TaskUid::new(ds.sem_perm.uid);
        set.perm.gid = TaskGid::new(ds.sem_perm.gid);
        set.perm.mode = ds.sem_perm.mode & 0o777;
        set.ctime = now;
        Ok(0)
    }

    pub fn semctl_info(&self, out: &mut LinuxSeminfo) -> Result<i64, IpcError> {
        out.semmap = 1024;
        out.semmni = SEMMNI as i32;
        out.semmns = SEMMNS as i32;
        out.semmnu = 1024;
        out.semmsl = SEMMSL as i32;
        out.semopm = SEMOPM as i32;
        out.semume = 1024;
        out.semusz = 1024;
        out.semvmx = SEMVMX as i32;
        out.semaem = 1024;

        let max_idx = self
            .sem_slots
            .iter()
            .map(|s| id_to_index(s.id))
            .max()
            .unwrap_or(0);
        Ok(max_idx as i64)
    }

    pub fn semctl_getval(
        &self,
        creds: &TaskCredentials,
        semid: i32,
        semnum: i32,
    ) -> Result<i64, IpcError> {
        let set = self.sem_set(semid)?;
        set.perm.check_perm(creds, 0o400)?;
        if semnum < 0 || semnum as usize >= set.sems.len() {
            return Err(IpcError::InvalidArgument);
        }
        Ok(set.sems[semnum as usize].semval as i64)
    }

    pub fn semctl_setval(
        &mut self,
        creds: &TaskCredentials,
        caller_pid: u32,
        semid: i32,
        semnum: i32,
        val: u64,
    ) -> Result<u64, IpcError> {
        if val > SEMVMX as u64 {
            return Err(IpcError::Range);
        }
        let now = self.tick_time();
        let set = self.sem_set_mut(semid)?;
        set.perm.check_perm(creds, 0o200)?;
        if semnum < 0 || semnum as usize >= set.sems.len() {
            return Err(IpcError::InvalidArgument);
        }

        set.sems[semnum as usize].semval = val as u16;
        set.sems[semnum as usize].sempid = caller_pid;
        set.ctime = now;
        Ok(set.wait_channel)
    }

    pub fn semctl_getpid(
        &self,
        creds: &TaskCredentials,
        semid: i32,
        semnum: i32,
    ) -> Result<i64, IpcError> {
        let set = self.sem_set(semid)?;
        set.perm.check_perm(creds, 0o400)?;
        if semnum < 0 || semnum as usize >= set.sems.len() {
            return Err(IpcError::InvalidArgument);
        }
        Ok(set.sems[semnum as usize].sempid as i64)
    }

    pub fn semctl_getncnt(
        &self,
        creds: &TaskCredentials,
        semid: i32,
        semnum: i32,
    ) -> Result<i64, IpcError> {
        let set = self.sem_set(semid)?;
        set.perm.check_perm(creds, 0o400)?;
        if semnum < 0 || semnum as usize >= set.sems.len() {
            return Err(IpcError::InvalidArgument);
        }
        Ok(set.sems[semnum as usize].semncnt as i64)
    }

    pub fn semctl_getzcnt(
        &self,
        creds: &TaskCredentials,
        semid: i32,
        semnum: i32,
    ) -> Result<i64, IpcError> {
        let set = self.sem_set(semid)?;
        set.perm.check_perm(creds, 0o400)?;
        if semnum < 0 || semnum as usize >= set.sems.len() {
            return Err(IpcError::InvalidArgument);
        }
        Ok(set.sems[semnum as usize].semzcnt as i64)
    }

    pub fn semctl_getall(
        &self,
        creds: &TaskCredentials,
        semid: i32,
        out: &mut [u16],
    ) -> Result<i64, IpcError> {
        let set = self.sem_set(semid)?;
        set.perm.check_perm(creds, 0o400)?;
        if out.len() < set.sems.len() {
            return Err(IpcError::InvalidArgument);
        }
        for (i, sem) in set.sems.iter().enumerate() {
            out[i] = sem.semval;
        }
        Ok(0)
    }

    pub fn semctl_setall(
        &mut self,
        creds: &TaskCredentials,
        caller_pid: u32,
        semid: i32,
        vals: &[u16],
    ) -> Result<u64, IpcError> {
        for &v in vals {
            if v > SEMVMX {
                return Err(IpcError::Range);
            }
        }
        let now = self.tick_time();
        let set = self.sem_set_mut(semid)?;
        set.perm.check_perm(creds, 0o200)?;
        if vals.len() != set.sems.len() {
            return Err(IpcError::InvalidArgument);
        }
        for (i, &v) in vals.iter().enumerate() {
            set.sems[i].semval = v;
            set.sems[i].sempid = caller_pid;
        }
        set.ctime = now;
        Ok(set.wait_channel)
    }

    pub fn semop(
        &mut self,
        creds: &TaskCredentials,
        caller_pid: u32,
        semid: i32,
        sops: &[(u16, i16, i16)], // (sem_num, sem_op, sem_flg)
    ) -> Result<(SemopOutcome, u64), IpcError> {
        if sops.is_empty() || sops.len() > SEMOPM {
            return Err(IpcError::TooBig);
        }

        let set = self.sem_set_mut(semid)?;
        let channel = set.wait_channel;

        // Check bounds and permissions
        let mut req_mode = 0o400;
        for &(num, op, _) in sops {
            if num as usize >= set.sems.len() {
                return Err(IpcError::InvalidArgument);
            }
            if op != 0 {
                req_mode |= 0o200;
            }
        }
        set.perm.check_perm(creds, req_mode)?;

        // Cumulative evaluation against scratch buffer
        let mut scratch: Vec<i32> = set.sems.iter().map(|s| s.semval as i32).collect();

        for &(num, op, flg) in sops {
            let val = scratch[num as usize];
            if op > 0 {
                if val + (op as i32) > (SEMVMX as i32) {
                    return Err(IpcError::Range);
                }
                scratch[num as usize] = val + (op as i32);
            } else if op < 0 {
                if val + (op as i32) < 0 {
                    if flg & (IPC_NOWAIT as i16) != 0 {
                        return Err(IpcError::Again);
                    }
                    return Ok((
                        SemopOutcome::Suspend {
                            sem_num: num,
                            is_zero: false,
                        },
                        channel,
                    ));
                }
                scratch[num as usize] = val + (op as i32);
            } else if val != 0 {
                if flg & (IPC_NOWAIT as i16) != 0 {
                    return Err(IpcError::Again);
                }
                return Ok((
                    SemopOutcome::Suspend {
                        sem_num: num,
                        is_zero: true,
                    },
                    channel,
                ));
            }
        }

        // All ops can be applied atomically
        let mut undo_ops = Vec::new();
        for &(num, op, flg) in sops {
            if flg & (SEM_UNDO as i16) != 0 && op != 0 {
                undo_ops.push((num, op));
            }
        }

        let now = self.current_time;
        self.current_time = self.current_time.saturating_add(1);
        let set = self.sem_set_mut(semid)?;
        for &(num, _, _) in sops {
            set.sems[num as usize].semval = scratch[num as usize] as u16;
            set.sems[num as usize].sempid = caller_pid;
        }
        set.otime = now;
        let channel = set.wait_channel;

        for (num, op) in undo_ops {
            self.record_undo(caller_pid, semid, num, op);
        }

        Ok((SemopOutcome::Complete, channel))
    }

    pub fn semop_suspend_enter(&mut self, semid: i32, sem_num: u16, is_zero: bool) {
        let Ok(set) = self.sem_set_mut(semid) else {
            return;
        };
        if (sem_num as usize) < set.sems.len() {
            if is_zero {
                set.sems[sem_num as usize].semzcnt =
                    set.sems[sem_num as usize].semzcnt.saturating_add(1);
            } else {
                set.sems[sem_num as usize].semncnt =
                    set.sems[sem_num as usize].semncnt.saturating_add(1);
            }
        }
    }

    pub fn semop_suspend_exit(&mut self, semid: i32, sem_num: u16, is_zero: bool) {
        let Ok(set) = self.sem_set_mut(semid) else {
            return;
        };
        if (sem_num as usize) < set.sems.len() {
            if is_zero {
                set.sems[sem_num as usize].semzcnt =
                    set.sems[sem_num as usize].semzcnt.saturating_sub(1);
            } else {
                set.sems[sem_num as usize].semncnt =
                    set.sems[sem_num as usize].semncnt.saturating_sub(1);
            }
        }
    }

    fn record_undo(&mut self, pid: u32, semid: i32, semnum: u16, op: i16) {
        if let Some(entry) = self
            .sem_undo
            .iter_mut()
            .find(|e| e.pid == pid && e.semid == semid && e.semnum == semnum)
        {
            entry.adj = entry.adj.saturating_sub(op);
        } else {
            self.sem_undo.push(SemUndoEntry {
                pid,
                semid,
                semnum,
                adj: -op,
            });
        }
    }

    pub fn exit_process(&mut self, pid: u32) -> Vec<u64> {
        let mut channels_to_wake = Vec::new();
        let mut entries = Vec::new();
        self.sem_undo.retain(|e| {
            if e.pid == pid {
                entries.push(*e);
                false
            } else {
                true
            }
        });

        for entry in entries {
            let Ok(set) = self.sem_set_mut(entry.semid) else {
                continue;
            };
            if (entry.semnum as usize) < set.sems.len() {
                let sem = &mut set.sems[entry.semnum as usize];
                let new_val = (sem.semval as i32 + entry.adj as i32).clamp(0, SEMVMX as i32);
                sem.semval = new_val as u16;
                if !channels_to_wake.contains(&set.wait_channel) {
                    channels_to_wake.push(set.wait_channel);
                }
            }
        }
        channels_to_wake
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
        assert_eq!(
            perm.check_perm(&other_creds, 0o400),
            Err(IpcError::PermissionDenied)
        );
        assert_eq!(
            perm.check_perm(&other_creds, 0o200),
            Err(IpcError::PermissionDenied)
        );

        // Mode 0000 denies owner access
        let perm_zero = IpcPerm::new(1234, 0o000, 1, &creds);
        assert_eq!(
            perm_zero.check_perm(&creds, 0o200),
            Err(IpcError::PermissionDenied)
        );

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
            MsgrcvOutcome::Complete { msg, .. } => {
                assert_eq!(msg.mtype, 1);
                assert_eq!(msg.data, msg_data);
            }
            MsgrcvOutcome::Suspend => panic!("expected complete"),
        }

        // Now queue is empty, msgrcv with IPC_NOWAIT returns IpcError::NoMsg
        assert_eq!(
            ns.msgrcv(&creds, 42, msqid, 100, 1, IPC_NOWAIT)
                .unwrap_err(),
            IpcError::NoMsg
        );

        // MSG_NOERROR vs E2BIG
        ns.msgsnd(&creds, 42, msqid, 1, b"12345678", 0).unwrap();
        assert_eq!(
            ns.msgrcv(&creds, 42, msqid, 4, 1, 0).unwrap_err(),
            IpcError::TooBig
        );
        let (rcv_outcome, _) = ns.msgrcv(&creds, 42, msqid, 4, 1, MSG_NOERROR).unwrap();
        match rcv_outcome {
            MsgrcvOutcome::Complete { msg, .. } => {
                assert_eq!(msg.data, b"1234");
            }
            MsgrcvOutcome::Suspend => panic!("expected complete"),
        }

        // MSG_EXCEPT and negative type
        ns.msgsnd(&creds, 42, msqid, 2, b"type2", 0).unwrap();
        ns.msgsnd(&creds, 42, msqid, 1, b"type1", 0).unwrap();
        // MSG_EXCEPT: receive first msg where mtype != 2
        let (rcv_outcome, _) = ns.msgrcv(&creds, 42, msqid, 10, 2, MSG_EXCEPT).unwrap();
        match rcv_outcome {
            MsgrcvOutcome::Complete { msg, .. } => {
                assert_eq!(msg.mtype, 1);
            }
            MsgrcvOutcome::Suspend => panic!("expected complete"),
        }
        // Consume type 2
        let _ = ns.msgrcv(&creds, 42, msqid, 10, 2, 0).unwrap();

        // Negative type: receive lowest type <= |msgtyp|
        ns.msgsnd(&creds, 42, msqid, 5, b"type5", 0).unwrap();
        ns.msgsnd(&creds, 42, msqid, 3, b"type3", 0).unwrap();
        let (rcv_outcome, _) = ns.msgrcv(&creds, 42, msqid, 10, -4, 0).unwrap();
        match rcv_outcome {
            MsgrcvOutcome::Complete { msg, .. } => {
                assert_eq!(msg.mtype, 3);
            }
            MsgrcvOutcome::Suspend => panic!("expected complete"),
        }

        // Tombstone / validity check
        assert!(ns.is_valid_msg_queue(msqid));
        ns.msgctl_rmid(&creds, msqid).unwrap();
        assert!(!ns.is_valid_msg_queue(msqid));
        assert_eq!(ns.msgget(&creds, key, 0).unwrap_err(), IpcError::NoEntity);
    }

    #[test]
    fn test_sysv_sem_operations_and_cumulative_semantics() {
        let creds = TaskCredentials::ROOT;
        let mut ns = IpcNamespace::new();
        let semid = ns
            .semget(&creds, IPC_PRIVATE, 2, IPC_CREAT | 0o666)
            .unwrap();

        // Initially semval is 0
        assert_eq!(ns.sem_set(semid).unwrap().sems[0].semval, 0);

        // Cumulative test C6: [(0, +1), (0, -1)] on 0 succeeds!
        let (outcome, _) = ns
            .semop(&creds, 42, semid, &[(0, 1, 0), (0, -1, 0)])
            .unwrap();
        assert_eq!(outcome, SemopOutcome::Complete);
        assert_eq!(ns.sem_set(semid).unwrap().sems[0].semval, 0);

        // Set sem 0 to 1
        ns.semctl_setval(&creds, 42, semid, 0, 1).unwrap();
        assert_eq!(ns.sem_set(semid).unwrap().sems[0].semval, 1);

        // Cumulative test C6: [(0, -1), (0, -1)] on 1 blocks!
        let (outcome, _) = ns
            .semop(&creds, 42, semid, &[(0, -1, 0), (0, -1, 0)])
            .unwrap();
        assert_eq!(
            outcome,
            SemopOutcome::Suspend {
                sem_num: 0,
                is_zero: false
            }
        );
        // Ensure atomic: value was NOT changed to 0 or wrapped
        assert_eq!(ns.sem_set(semid).unwrap().sems[0].semval, 1);

        // Nowait per blocking op: if blocking op has IPC_NOWAIT, returns EAGAIN
        assert_eq!(
            ns.semop(&creds, 42, semid, &[(0, -1, 0), (0, -1, IPC_NOWAIT as i16)])
                .unwrap_err(),
            IpcError::Again
        );

        // SEMOPM limit: > SEMOPM gives E2BIG
        let huge_sops = alloc::vec![(0, 1, 0); SEMOPM + 1];
        assert_eq!(
            ns.semop(&creds, 42, semid, &huge_sops).unwrap_err(),
            IpcError::TooBig
        );

        // SETVAL bounds: val > SEMVMX gives ERANGE
        assert_eq!(
            ns.semctl_setval(&creds, 42, semid, 0, (SEMVMX as u64) + 1)
                .unwrap_err(),
            IpcError::Range
        );

        // SETALL bounds: any val > SEMVMX gives ERANGE without mutating
        assert_eq!(
            ns.semctl_setall(&creds, 42, semid, &[0, SEMVMX + 1])
                .unwrap_err(),
            IpcError::Range
        );
        assert_eq!(ns.sem_set(semid).unwrap().sems[0].semval, 1);

        // GETNCNT / GETZCNT tracking
        ns.semop_suspend_enter(semid, 0, false);
        assert_eq!(ns.semctl_getncnt(&creds, semid, 0).unwrap(), 1);
        ns.semop_suspend_exit(semid, 0, false);
        assert_eq!(ns.semctl_getncnt(&creds, semid, 0).unwrap(), 0);

        // SEM_UNDO on process exit
        ns.semctl_setval(&creds, 42, semid, 0, 5).unwrap();
        let (outcome, _) = ns
            .semop(&creds, 100, semid, &[(0, 2, SEM_UNDO as i16)])
            .unwrap();
        assert_eq!(outcome, SemopOutcome::Complete);
        assert_eq!(ns.sem_set(semid).unwrap().sems[0].semval, 7);

        // When process 100 exits, undo adjustment restores semval back to 5
        let woken = ns.exit_process(100);
        assert_eq!(woken.len(), 1);
        assert_eq!(ns.sem_set(semid).unwrap().sems[0].semval, 5);

        ns.semctl_rmid(&creds, semid).unwrap();
    }

    #[test]
    fn test_msgsnd_zero_length_quota_and_msgrcv_restore() {
        let creds = TaskCredentials::ROOT;
        let mut ns = IpcNamespace::new();
        let msqid = ns.msgget(&creds, IPC_PRIVATE, IPC_CREAT | 0o666).unwrap();

        // artifically set qbytes to 2
        let mut ds = LinuxMsqidDs::default();
        ns.msgctl_stat(&creds, msqid, &mut ds).unwrap();
        ds.msg_qbytes = 2;
        ns.msgctl_set(&creds, msqid, &ds).unwrap();

        // sending 2 zero-length messages succeeds (qnum=2, cbytes=0)
        assert!(ns.msgsnd(&creds, 1, msqid, 1, &[], 0).is_ok());
        assert!(ns.msgsnd(&creds, 1, msqid, 2, &[], 0).is_ok());

        // 3rd zero-length message hits 1 + qnum > qbytes (1 + 2 > 2) and fails with Again under IPC_NOWAIT
        assert_eq!(
            ns.msgsnd(&creds, 1, msqid, 3, &[], IPC_NOWAIT).unwrap_err(),
            IpcError::Again
        );

        // Test msgrcv_restore restores to original index
        let mut ns2 = IpcNamespace::new();
        let q2 = ns2.msgget(&creds, IPC_PRIVATE, IPC_CREAT | 0o666).unwrap();
        ns2.msgsnd(&creds, 1, q2, 1, b"first", 0).unwrap();
        ns2.msgsnd(&creds, 1, q2, 2, b"second", 0).unwrap();
        ns2.msgsnd(&creds, 1, q2, 3, b"third", 0).unwrap();

        // Receive msg at idx 1 (type 2)
        let (rcv, _) = ns2.msgrcv(&creds, 1, q2, 10, 2, 0).unwrap();
        if let MsgrcvOutcome::Complete { original_idx, msg } = rcv {
            assert_eq!(original_idx, 1);
            assert_eq!(msg.mtype, 2);
            // Simulate copy failure -> restore at original_idx
            ns2.msgrcv_restore(q2, original_idx, msg.mtype, msg.data)
                .unwrap();
        } else {
            panic!("expected complete");
        }

        // Verify message at index 1 is indeed type 2
        let (rcv_all1, _) = ns2.msgrcv(&creds, 1, q2, 10, 0, 0).unwrap();
        let (rcv_all2, _) = ns2.msgrcv(&creds, 1, q2, 10, 0, 0).unwrap();
        let (rcv_all3, _) = ns2.msgrcv(&creds, 1, q2, 10, 0, 0).unwrap();
        if let (
            MsgrcvOutcome::Complete { msg: m1, .. },
            MsgrcvOutcome::Complete { msg: m2, .. },
            MsgrcvOutcome::Complete { msg: m3, .. },
        ) = (rcv_all1, rcv_all2, rcv_all3)
        {
            assert_eq!(m1.mtype, 1);
            assert_eq!(m2.mtype, 2);
            assert_eq!(m3.mtype, 3);
        } else {
            panic!("expected all complete");
        }
    }
}
