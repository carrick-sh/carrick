//! Identity and process-relation syscall family.
use crate::abi::entry::SyscallResult;
use crate::lifecycle::UserCopy;
use carrick_guest_arch::UserVa;

pub const EPERM: i64 = -1;
pub const ESRCH: i64 = -3;
pub const EACCES: i64 = -13;
pub const EFAULT: i64 = -14;
pub const EINVAL: i64 = -22;

pub const LINUX_CAPABILITY_VERSION_1: u32 = 0x1998_0330;
pub const LINUX_CAPABILITY_VERSION_2: u32 = 0x2007_1026;
pub const LINUX_CAPABILITY_VERSION_3: u32 = 0x2008_0522;

pub const LINUX_PR_SET_PDEATHSIG: u64 = 1;
pub const LINUX_PR_GET_PDEATHSIG: u64 = 2;
pub const LINUX_PR_GET_DUMPABLE: u64 = 3;
pub const LINUX_PR_SET_DUMPABLE: u64 = 4;
pub const LINUX_PR_SET_NAME: u64 = 15;
pub const LINUX_PR_GET_NAME: u64 = 16;
pub const LINUX_PR_SET_CHILD_SUBREAPER: u64 = 36;
pub const LINUX_PR_GET_CHILD_SUBREAPER: u64 = 37;
pub const LINUX_PR_SET_NO_NEW_PRIVS: u64 = 38;
pub const LINUX_PR_GET_NO_NEW_PRIVS: u64 = 39;
pub const LINUX_NGROUPS_MAX: usize = 65536;

pub use carrick_syscall_abi::LinuxCapabilitySet;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TaskCapabilities {
    pub effective: LinuxCapabilitySet,
    pub permitted: LinuxCapabilitySet,
    pub inheritable: LinuxCapabilitySet,
}

impl TaskCapabilities {
    pub const FULL: Self = Self {
        effective: LinuxCapabilitySet::FULL,
        permitted: LinuxCapabilitySet::FULL,
        inheritable: LinuxCapabilitySet::empty(),
    };
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum IdentityCall {
    GetUid,
    GetEuid,
    GetGid,
    GetEgid,
    GetResUid,
    GetResGid,
    SetUid,
    SetGid,
    SetReUid,
    SetReGid,
    SetResUid,
    SetResGid,
    SetFsUid,
    SetFsGid,
    GetGroups,
    SetGroups,
    CapGet,
    CapSet,
    GetPpid,
    GetPgid,
    SetPgid,
    GetSid,
    SetSid,
    SetTidAddress,
    GetRobustList,
    Personality,
    Prctl,
}

pub trait ProcessIdentityVenue {
    fn get_uids(&self) -> (u32, u32, u32, u32);
    fn get_gids(&self) -> (u32, u32, u32, u32);
    fn set_resuid(&mut self, r: Option<u32>, e: Option<u32>, s: Option<u32>) -> Result<(), i64>;
    fn set_resgid(&mut self, r: Option<u32>, e: Option<u32>, s: Option<u32>) -> Result<(), i64>;
    fn set_reuid(&mut self, r: Option<u32>, e: Option<u32>) -> Result<(), i64>;
    fn set_regid(&mut self, r: Option<u32>, e: Option<u32>) -> Result<(), i64>;
    fn set_uid(&mut self, uid: u32) -> Result<(), i64>;
    fn set_gid(&mut self, gid: u32) -> Result<(), i64>;
    fn set_fsuid(&mut self, fsuid: u32) -> u32;
    fn set_fsgid(&mut self, fsgid: u32) -> u32;
    fn can_set_groups(&self) -> Result<(), i64>;
    fn get_groups_count(&self) -> usize;
    fn get_groups(&self, out: &mut alloc::vec::Vec<u32>);
    fn set_groups(&mut self, groups: &[u32]) -> Result<(), i64>;
    fn capget(&self, pid: i32) -> Result<TaskCapabilities, i64>;
    fn capset(&mut self, pid: i32, caps: TaskCapabilities) -> Result<(), i64>;
    fn get_ppid(&self) -> u32;
    fn get_pgid(&self, pid: i32) -> Result<u32, i64>;
    fn set_pgid(&mut self, pid: i32, pgid: i32) -> Result<(), i64>;
    fn get_sid(&self, pid: i32) -> Result<u32, i64>;
    fn set_sid(&mut self) -> Result<u32, i64>;
    fn personality(&mut self, persona: u64) -> u64;
    fn prctl_get_name(&self, buf: &mut [u8; 16]);
    fn prctl_set_name(&mut self, name: &[u8; 16]);
    fn prctl_get_pdeathsig(&self) -> u8;
    fn prctl_set_pdeathsig(&mut self, sig: u8) -> Result<(), i64>;
    fn prctl_get_dumpable(&self) -> u32;
    fn prctl_set_dumpable(&mut self, dumpable: u32) -> Result<(), i64>;
    fn prctl_get_no_new_privs(&self) -> bool;
    fn prctl_set_no_new_privs(&mut self, no_new_privs: bool) -> Result<(), i64>;
    fn prctl_get_child_subreaper(&self) -> bool;
    fn prctl_set_child_subreaper(&mut self, subreaper: bool);
}

pub trait IdentityNative<'a>: UserCopy {
    fn arguments(&self) -> [u64; 6];
    fn visible_tid(&self) -> Option<u32>;
    fn set_clear_child_tid(&mut self, address: u64) -> bool;
    fn robust_list_for(&self, tid: i32) -> Result<(u64, u32), i64>;
    fn process_identity(&mut self) -> Option<&mut dyn ProcessIdentityVenue>;
}

fn keep_or_id(raw: u64) -> Option<u32> {
    let id = raw as u32;
    if id == u32::MAX { None } else { Some(id) }
}

#[inline(never)]
pub fn invoke<'a>(
    call: IdentityCall,
    native: &mut dyn IdentityNative<'a>,
) -> Option<SyscallResult> {
    let args = native.arguments();
    match call {
        IdentityCall::SetTidAddress => {
            let addr = args[0];
            let tid = native.visible_tid().unwrap_or(1);
            native.set_clear_child_tid(addr);
            Some(SyscallResult::new(i64::from(tid)))
        }
        IdentityCall::GetRobustList => {
            let pid = args[0] as i32;
            let head_ptr = UserVa::new(args[1]);
            let len_ptr = UserVa::new(args[2]);

            // Validate both output pointers before writing anything
            let mut test_head = [0u8; 8];
            let mut test_len = [0u8; 8];
            if !native.copy_in(&mut test_head, head_ptr) || !native.copy_in(&mut test_len, len_ptr)
            {
                return Some(SyscallResult::new(EFAULT));
            }

            let (head, len) = match native.robust_list_for(pid) {
                Ok(pair) => pair,
                Err(e) => return Some(SyscallResult::new(e)),
            };

            let len_u64 = len as u64;
            if !native.copy_out(head_ptr, &head.to_ne_bytes())
                || !native.copy_out(len_ptr, &len_u64.to_ne_bytes())
            {
                return Some(SyscallResult::new(EFAULT));
            }
            Some(SyscallResult::new(0))
        }
        IdentityCall::GetUid => {
            let venue = native.process_identity()?;
            let (ruid, _, _, _) = venue.get_uids();
            Some(SyscallResult::new(i64::from(ruid)))
        }
        IdentityCall::GetEuid => {
            let venue = native.process_identity()?;
            let (_, euid, _, _) = venue.get_uids();
            Some(SyscallResult::new(i64::from(euid)))
        }
        IdentityCall::GetGid => {
            let venue = native.process_identity()?;
            let (rgid, _, _, _) = venue.get_gids();
            Some(SyscallResult::new(i64::from(rgid)))
        }
        IdentityCall::GetEgid => {
            let venue = native.process_identity()?;
            let (_, egid, _, _) = venue.get_gids();
            Some(SyscallResult::new(i64::from(egid)))
        }
        IdentityCall::GetResUid => {
            let (ruid, euid, suid) = {
                let venue = native.process_identity()?;
                let (r, e, s, _) = venue.get_uids();
                (r, e, s)
            };
            if args[0] != 0 && !native.copy_out(UserVa::new(args[0]), &ruid.to_ne_bytes()) {
                return Some(SyscallResult::new(EFAULT));
            }
            if args[1] != 0 && !native.copy_out(UserVa::new(args[1]), &euid.to_ne_bytes()) {
                return Some(SyscallResult::new(EFAULT));
            }
            if args[2] != 0 && !native.copy_out(UserVa::new(args[2]), &suid.to_ne_bytes()) {
                return Some(SyscallResult::new(EFAULT));
            }
            Some(SyscallResult::new(0))
        }
        IdentityCall::GetResGid => {
            let (rgid, egid, sgid) = {
                let venue = native.process_identity()?;
                let (r, e, s, _) = venue.get_gids();
                (r, e, s)
            };
            if args[0] != 0 && !native.copy_out(UserVa::new(args[0]), &rgid.to_ne_bytes()) {
                return Some(SyscallResult::new(EFAULT));
            }
            if args[1] != 0 && !native.copy_out(UserVa::new(args[1]), &egid.to_ne_bytes()) {
                return Some(SyscallResult::new(EFAULT));
            }
            if args[2] != 0 && !native.copy_out(UserVa::new(args[2]), &sgid.to_ne_bytes()) {
                return Some(SyscallResult::new(EFAULT));
            }
            Some(SyscallResult::new(0))
        }
        IdentityCall::SetUid => {
            let venue = native.process_identity()?;
            match venue.set_uid(args[0] as u32) {
                Ok(()) => Some(SyscallResult::new(0)),
                Err(err) => Some(SyscallResult::new(err)),
            }
        }
        IdentityCall::SetGid => {
            let venue = native.process_identity()?;
            match venue.set_gid(args[0] as u32) {
                Ok(()) => Some(SyscallResult::new(0)),
                Err(err) => Some(SyscallResult::new(err)),
            }
        }
        IdentityCall::SetReUid => {
            let venue = native.process_identity()?;
            match venue.set_reuid(keep_or_id(args[0]), keep_or_id(args[1])) {
                Ok(()) => Some(SyscallResult::new(0)),
                Err(err) => Some(SyscallResult::new(err)),
            }
        }
        IdentityCall::SetReGid => {
            let venue = native.process_identity()?;
            match venue.set_regid(keep_or_id(args[0]), keep_or_id(args[1])) {
                Ok(()) => Some(SyscallResult::new(0)),
                Err(err) => Some(SyscallResult::new(err)),
            }
        }
        IdentityCall::SetResUid => {
            let venue = native.process_identity()?;
            match venue.set_resuid(
                keep_or_id(args[0]),
                keep_or_id(args[1]),
                keep_or_id(args[2]),
            ) {
                Ok(()) => Some(SyscallResult::new(0)),
                Err(err) => Some(SyscallResult::new(err)),
            }
        }
        IdentityCall::SetResGid => {
            let venue = native.process_identity()?;
            match venue.set_resgid(
                keep_or_id(args[0]),
                keep_or_id(args[1]),
                keep_or_id(args[2]),
            ) {
                Ok(()) => Some(SyscallResult::new(0)),
                Err(err) => Some(SyscallResult::new(err)),
            }
        }
        IdentityCall::SetFsUid => {
            let venue = native.process_identity()?;
            let old = venue.set_fsuid(args[0] as u32);
            Some(SyscallResult::new(i64::from(old)))
        }
        IdentityCall::SetFsGid => {
            let venue = native.process_identity()?;
            let old = venue.set_fsgid(args[0] as u32);
            Some(SyscallResult::new(i64::from(old)))
        }
        IdentityCall::GetGroups => {
            let size = args[0] as usize;
            let list_ptr = UserVa::new(args[1]);
            let venue = native.process_identity()?;
            let count = venue.get_groups_count();
            if size == 0 {
                return Some(SyscallResult::new(count as i64));
            }
            if size < count {
                return Some(SyscallResult::new(EINVAL));
            }
            let mut groups = alloc::vec::Vec::new();
            venue.get_groups(&mut groups);
            let mut cur_addr = list_ptr.raw();
            for &gid in groups.iter().take(count) {
                if !native.copy_out(UserVa::new(cur_addr), &gid.to_ne_bytes()) {
                    return Some(SyscallResult::new(EFAULT));
                }
                cur_addr = cur_addr.wrapping_add(4);
            }
            Some(SyscallResult::new(count as i64))
        }
        IdentityCall::SetGroups => {
            let size = args[0] as usize;
            if size > LINUX_NGROUPS_MAX {
                return Some(SyscallResult::new(EINVAL));
            }
            {
                let venue = native.process_identity()?;
                if let Err(e) = venue.can_set_groups() {
                    return Some(SyscallResult::new(e));
                }
            }
            let list_ptr = UserVa::new(args[1]);
            let mut groups = alloc::vec::Vec::with_capacity(size);
            let mut cur_addr = list_ptr.raw();
            for _ in 0..size {
                let mut bytes = [0u8; 4];
                if !native.copy_in(&mut bytes, UserVa::new(cur_addr)) {
                    return Some(SyscallResult::new(EFAULT));
                }
                groups.push(u32::from_ne_bytes(bytes));
                cur_addr = cur_addr.wrapping_add(4);
            }
            let venue = native.process_identity()?;
            match venue.set_groups(&groups) {
                Ok(()) => Some(SyscallResult::new(0)),
                Err(e) => Some(SyscallResult::new(e)),
            }
        }
        IdentityCall::CapGet => {
            let hdr_ptr = UserVa::new(args[0]);
            let data_ptr = UserVa::new(args[1]);
            let mut hdr_bytes = [0u8; 8];
            if !native.copy_in(&mut hdr_bytes, hdr_ptr) {
                return Some(SyscallResult::new(EFAULT));
            }
            let version = u32::from_ne_bytes(hdr_bytes[0..4].try_into().unwrap_or([0; 4]));
            let pid = i32::from_ne_bytes(hdr_bytes[4..8].try_into().unwrap_or([0; 4]));
            if !matches!(
                version,
                LINUX_CAPABILITY_VERSION_1
                    | LINUX_CAPABILITY_VERSION_2
                    | LINUX_CAPABILITY_VERSION_3
            ) {
                let pref = LINUX_CAPABILITY_VERSION_3.to_ne_bytes();
                let _ = native.copy_out(hdr_ptr, &pref);
                return Some(SyscallResult::new(EINVAL));
            }
            if pid < 0 {
                return Some(SyscallResult::new(EINVAL));
            }
            let caps = {
                let venue = native.process_identity()?;
                match venue.capget(pid) {
                    Ok(c) => c,
                    Err(e) => return Some(SyscallResult::new(e)),
                }
            };
            if data_ptr.raw() == 0 {
                return Some(SyscallResult::new(0));
            }
            if version == LINUX_CAPABILITY_VERSION_1 {
                let mut data = [0u8; 12];
                data[0..4].copy_from_slice(&(caps.effective.bits() as u32).to_ne_bytes());
                data[4..8].copy_from_slice(&(caps.permitted.bits() as u32).to_ne_bytes());
                data[8..12].copy_from_slice(&(caps.inheritable.bits() as u32).to_ne_bytes());
                if !native.copy_out(data_ptr, &data) {
                    return Some(SyscallResult::new(EFAULT));
                }
            } else {
                let mut data = [0u8; 24];
                let eff = caps.effective.bits();
                let prm = caps.permitted.bits();
                let inh = caps.inheritable.bits();
                data[0..4].copy_from_slice(&(eff as u32).to_ne_bytes());
                data[4..8].copy_from_slice(&(prm as u32).to_ne_bytes());
                data[8..12].copy_from_slice(&(inh as u32).to_ne_bytes());
                data[12..16].copy_from_slice(&((eff >> 32) as u32).to_ne_bytes());
                data[16..20].copy_from_slice(&((prm >> 32) as u32).to_ne_bytes());
                data[20..24].copy_from_slice(&((inh >> 32) as u32).to_ne_bytes());
                if !native.copy_out(data_ptr, &data) {
                    return Some(SyscallResult::new(EFAULT));
                }
            }
            Some(SyscallResult::new(0))
        }
        IdentityCall::CapSet => {
            let hdr_ptr = UserVa::new(args[0]);
            let data_ptr = UserVa::new(args[1]);
            let mut hdr_bytes = [0u8; 8];
            if !native.copy_in(&mut hdr_bytes, hdr_ptr) {
                return Some(SyscallResult::new(EFAULT));
            }
            let version = u32::from_ne_bytes(hdr_bytes[0..4].try_into().unwrap_or([0; 4]));
            let pid = i32::from_ne_bytes(hdr_bytes[4..8].try_into().unwrap_or([0; 4]));
            if !matches!(
                version,
                LINUX_CAPABILITY_VERSION_1
                    | LINUX_CAPABILITY_VERSION_2
                    | LINUX_CAPABILITY_VERSION_3
            ) {
                let pref = LINUX_CAPABILITY_VERSION_3.to_ne_bytes();
                let _ = native.copy_out(hdr_ptr, &pref);
                return Some(SyscallResult::new(EINVAL));
            }
            if pid < 0 {
                return Some(SyscallResult::new(ESRCH));
            }
            let (eff_raw, prm_raw, inh_raw) = if version == LINUX_CAPABILITY_VERSION_1 {
                let mut data = [0u8; 12];
                if !native.copy_in(&mut data, data_ptr) {
                    return Some(SyscallResult::new(EFAULT));
                }
                (
                    u32::from_ne_bytes(data[0..4].try_into().unwrap_or([0; 4])) as u64,
                    u32::from_ne_bytes(data[4..8].try_into().unwrap_or([0; 4])) as u64,
                    u32::from_ne_bytes(data[8..12].try_into().unwrap_or([0; 4])) as u64,
                )
            } else {
                let mut data = [0u8; 24];
                if !native.copy_in(&mut data, data_ptr) {
                    return Some(SyscallResult::new(EFAULT));
                }
                let e_lo = u32::from_ne_bytes(data[0..4].try_into().unwrap_or([0; 4])) as u64;
                let p_lo = u32::from_ne_bytes(data[4..8].try_into().unwrap_or([0; 4])) as u64;
                let i_lo = u32::from_ne_bytes(data[8..12].try_into().unwrap_or([0; 4])) as u64;
                let e_hi = u32::from_ne_bytes(data[12..16].try_into().unwrap_or([0; 4])) as u64;
                let p_hi = u32::from_ne_bytes(data[16..20].try_into().unwrap_or([0; 4])) as u64;
                let i_hi = u32::from_ne_bytes(data[20..24].try_into().unwrap_or([0; 4])) as u64;
                (
                    e_lo | (e_hi << 32),
                    p_lo | (p_hi << 32),
                    i_lo | (i_hi << 32),
                )
            };
            if ((eff_raw | prm_raw | inh_raw) & !LinuxCapabilitySet::ALL_CAPS_MASK) != 0 {
                return Some(SyscallResult::new(EINVAL));
            }
            let eff = LinuxCapabilitySet::from_bits_retain(eff_raw);
            let prm = LinuxCapabilitySet::from_bits_retain(prm_raw);
            let inh = LinuxCapabilitySet::from_bits_retain(inh_raw);
            if !prm.contains(eff) {
                return Some(SyscallResult::new(EPERM));
            }
            let venue = native.process_identity()?;
            match venue.capset(
                pid,
                TaskCapabilities {
                    effective: eff,
                    permitted: prm,
                    inheritable: inh,
                },
            ) {
                Ok(()) => Some(SyscallResult::new(0)),
                Err(e) => Some(SyscallResult::new(e)),
            }
        }
        IdentityCall::GetPpid => {
            let venue = native.process_identity()?;
            Some(SyscallResult::new(i64::from(venue.get_ppid())))
        }
        IdentityCall::GetPgid => {
            let pid = args[0] as i32;
            let venue = native.process_identity()?;
            match venue.get_pgid(pid) {
                Ok(pgid) => Some(SyscallResult::new(i64::from(pgid))),
                Err(e) => Some(SyscallResult::new(e)),
            }
        }
        IdentityCall::SetPgid => {
            let pid = args[0] as i32;
            let pgid = args[1] as i32;
            let venue = native.process_identity()?;
            match venue.set_pgid(pid, pgid) {
                Ok(()) => Some(SyscallResult::new(0)),
                Err(e) => Some(SyscallResult::new(e)),
            }
        }
        IdentityCall::GetSid => {
            let pid = args[0] as i32;
            let venue = native.process_identity()?;
            match venue.get_sid(pid) {
                Ok(sid) => Some(SyscallResult::new(i64::from(sid))),
                Err(e) => Some(SyscallResult::new(e)),
            }
        }
        IdentityCall::SetSid => {
            let venue = native.process_identity()?;
            match venue.set_sid() {
                Ok(sid) => Some(SyscallResult::new(i64::from(sid))),
                Err(e) => Some(SyscallResult::new(e)),
            }
        }
        IdentityCall::Personality => {
            let persona = args[0];
            let venue = native.process_identity()?;
            let old = venue.personality(persona);
            Some(SyscallResult::new(old as i64))
        }
        IdentityCall::Prctl => {
            let option = args[0];
            let arg2 = args[1];
            let arg3 = args[2];
            let arg4 = args[3];
            let arg5 = args[4];
            match option {
                LINUX_PR_SET_NAME => {
                    let mut name = [0u8; 16];
                    let mut cur_addr = arg2;
                    for slot in name.iter_mut() {
                        let mut b = [0u8; 1];
                        if !native.copy_in(&mut b, UserVa::new(cur_addr)) {
                            return Some(SyscallResult::new(EFAULT));
                        }
                        *slot = b[0];
                        if b[0] == 0 {
                            break;
                        }
                        cur_addr = cur_addr.wrapping_add(1);
                    }
                    let venue = native.process_identity()?;
                    venue.prctl_set_name(&name);
                    Some(SyscallResult::new(0))
                }
                LINUX_PR_GET_NAME => {
                    let mut name = [0u8; 16];
                    {
                        let venue = native.process_identity()?;
                        venue.prctl_get_name(&mut name);
                    }
                    if !native.copy_out(UserVa::new(arg2), &name) {
                        return Some(SyscallResult::new(EFAULT));
                    }
                    Some(SyscallResult::new(0))
                }
                LINUX_PR_SET_PDEATHSIG => {
                    if arg2 > 64 {
                        return Some(SyscallResult::new(EINVAL));
                    }
                    let venue = native.process_identity()?;
                    match venue.prctl_set_pdeathsig(arg2 as u8) {
                        Ok(()) => Some(SyscallResult::new(0)),
                        Err(e) => Some(SyscallResult::new(e)),
                    }
                }
                LINUX_PR_GET_PDEATHSIG => {
                    let sig = {
                        let venue = native.process_identity()?;
                        venue.prctl_get_pdeathsig() as i32
                    };
                    if !native.copy_out(UserVa::new(arg2), &sig.to_ne_bytes()) {
                        return Some(SyscallResult::new(EFAULT));
                    }
                    Some(SyscallResult::new(0))
                }
                LINUX_PR_GET_DUMPABLE => {
                    let d = {
                        let venue = native.process_identity()?;
                        venue.prctl_get_dumpable()
                    };
                    Some(SyscallResult::new(i64::from(d)))
                }
                LINUX_PR_SET_DUMPABLE => {
                    if arg2 > 1 {
                        return Some(SyscallResult::new(EINVAL));
                    }
                    let venue = native.process_identity()?;
                    match venue.prctl_set_dumpable(arg2 as u32) {
                        Ok(()) => Some(SyscallResult::new(0)),
                        Err(e) => Some(SyscallResult::new(e)),
                    }
                }
                LINUX_PR_SET_NO_NEW_PRIVS => {
                    if arg2 != 1 || arg3 != 0 || arg4 != 0 || arg5 != 0 {
                        return Some(SyscallResult::new(EINVAL));
                    }
                    let venue = native.process_identity()?;
                    match venue.prctl_set_no_new_privs(true) {
                        Ok(()) => Some(SyscallResult::new(0)),
                        Err(e) => Some(SyscallResult::new(e)),
                    }
                }
                LINUX_PR_GET_NO_NEW_PRIVS => {
                    if arg2 != 0 || arg3 != 0 || arg4 != 0 || arg5 != 0 {
                        return Some(SyscallResult::new(EINVAL));
                    }
                    let nnp = {
                        let venue = native.process_identity()?;
                        venue.prctl_get_no_new_privs()
                    };
                    Some(SyscallResult::new(if nnp { 1 } else { 0 }))
                }
                LINUX_PR_SET_CHILD_SUBREAPER => {
                    let venue = native.process_identity()?;
                    venue.prctl_set_child_subreaper(arg2 != 0);
                    Some(SyscallResult::new(0))
                }
                LINUX_PR_GET_CHILD_SUBREAPER => {
                    let val: i32 = {
                        let venue = native.process_identity()?;
                        if venue.prctl_get_child_subreaper() {
                            1
                        } else {
                            0
                        }
                    };
                    if !native.copy_out(UserVa::new(arg2), &val.to_ne_bytes()) {
                        return Some(SyscallResult::new(EFAULT));
                    }
                    Some(SyscallResult::new(0))
                }
                _ => None,
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::collections::BTreeMap;

    struct MockNative {
        args: [u64; 6],
        tid: u32,
        clear_child_tid: u64,
        robust_head: u64,
        robust_len: u32,
        memory: BTreeMap<u64, u8>,
        venue: MockVenue,
    }

    impl MockNative {
        fn new() -> Self {
            Self {
                args: [0; 6],
                tid: 100,
                clear_child_tid: 0,
                robust_head: 0x5000,
                robust_len: 24,
                memory: BTreeMap::new(),
                venue: MockVenue::default(),
            }
        }
    }

    impl UserCopy for MockNative {
        fn copy_in(&mut self, dst: &mut [u8], src: UserVa) -> bool {
            let addr = src.raw();
            for (i, byte) in dst.iter_mut().enumerate() {
                if let Some(&b) = self.memory.get(&(addr + i as u64)) {
                    *byte = b;
                } else {
                    return false;
                }
            }
            true
        }

        fn copy_out(&mut self, dst: UserVa, src: &[u8]) -> bool {
            let addr = dst.raw();
            for (i, &byte) in src.iter().enumerate() {
                self.memory.insert(addr + i as u64, byte);
            }
            true
        }
    }

    impl<'a> IdentityNative<'a> for MockNative {
        fn arguments(&self) -> [u64; 6] {
            self.args
        }
        fn visible_tid(&self) -> Option<u32> {
            Some(self.tid)
        }
        fn set_clear_child_tid(&mut self, address: u64) -> bool {
            self.clear_child_tid = address;
            true
        }
        fn robust_list_for(&self, tid: i32) -> Result<(u64, u32), i64> {
            if tid == 0 || tid as u32 == self.tid {
                Ok((self.robust_head, self.robust_len))
            } else {
                Err(ESRCH)
            }
        }
        fn process_identity(&mut self) -> Option<&mut dyn ProcessIdentityVenue> {
            Some(&mut self.venue)
        }
    }

    #[derive(Default)]
    struct MockVenue {
        uids: (u32, u32, u32, u32),
        gids: (u32, u32, u32, u32),
        groups: alloc::vec::Vec<u32>,
        caps: Option<TaskCapabilities>,
        ppid: u32,
        pgid: u32,
        sid: u32,
        personality: u64,
        comm: [u8; 16],
        pdeathsig: u8,
        dumpable: u32,
        no_new_privs: bool,
        child_subreaper: bool,
        can_set_groups_error: Option<i64>,
    }

    impl ProcessIdentityVenue for MockVenue {
        fn get_uids(&self) -> (u32, u32, u32, u32) {
            self.uids
        }
        fn get_gids(&self) -> (u32, u32, u32, u32) {
            self.gids
        }
        fn set_resuid(
            &mut self,
            r: Option<u32>,
            e: Option<u32>,
            s: Option<u32>,
        ) -> Result<(), i64> {
            if let Some(r) = r {
                self.uids.0 = r;
            }
            if let Some(e) = e {
                self.uids.1 = e;
            }
            if let Some(s) = s {
                self.uids.2 = s;
            }
            Ok(())
        }
        fn set_resgid(
            &mut self,
            r: Option<u32>,
            e: Option<u32>,
            s: Option<u32>,
        ) -> Result<(), i64> {
            if let Some(r) = r {
                self.gids.0 = r;
            }
            if let Some(e) = e {
                self.gids.1 = e;
            }
            if let Some(s) = s {
                self.gids.2 = s;
            }
            Ok(())
        }
        fn set_reuid(&mut self, r: Option<u32>, e: Option<u32>) -> Result<(), i64> {
            if let Some(r) = r {
                self.uids.0 = r;
            }
            if let Some(e) = e {
                self.uids.1 = e;
            }
            Ok(())
        }
        fn set_regid(&mut self, r: Option<u32>, e: Option<u32>) -> Result<(), i64> {
            if let Some(r) = r {
                self.gids.0 = r;
            }
            if let Some(e) = e {
                self.gids.1 = e;
            }
            Ok(())
        }
        fn set_uid(&mut self, uid: u32) -> Result<(), i64> {
            if uid == u32::MAX {
                return Err(EINVAL);
            }
            self.uids.1 = uid;
            Ok(())
        }
        fn set_gid(&mut self, gid: u32) -> Result<(), i64> {
            if gid == u32::MAX {
                return Err(EINVAL);
            }
            self.gids.1 = gid;
            Ok(())
        }
        fn set_fsuid(&mut self, fsuid: u32) -> u32 {
            let prev = self.uids.3;
            if fsuid != u32::MAX {
                self.uids.3 = fsuid;
            }
            prev
        }
        fn set_fsgid(&mut self, fsgid: u32) -> u32 {
            let prev = self.gids.3;
            if fsgid != u32::MAX {
                self.gids.3 = fsgid;
            }
            prev
        }
        fn can_set_groups(&self) -> Result<(), i64> {
            if let Some(err) = self.can_set_groups_error {
                return Err(err);
            }
            Ok(())
        }
        fn get_groups_count(&self) -> usize {
            self.groups.len()
        }
        fn get_groups(&self, out: &mut alloc::vec::Vec<u32>) {
            out.clear();
            out.extend_from_slice(&self.groups);
        }
        fn set_groups(&mut self, groups: &[u32]) -> Result<(), i64> {
            self.groups = groups.to_vec();
            Ok(())
        }
        fn capget(&self, _pid: i32) -> Result<TaskCapabilities, i64> {
            Ok(self.caps.unwrap_or(TaskCapabilities::FULL))
        }
        fn capset(&mut self, _pid: i32, caps: TaskCapabilities) -> Result<(), i64> {
            self.caps = Some(caps);
            Ok(())
        }
        fn get_ppid(&self) -> u32 {
            self.ppid
        }
        fn get_pgid(&self, _pid: i32) -> Result<u32, i64> {
            Ok(self.pgid)
        }
        fn set_pgid(&mut self, _pid: i32, pgid: i32) -> Result<(), i64> {
            if pgid < 0 {
                return Err(EINVAL);
            }
            self.pgid = pgid as u32;
            Ok(())
        }
        fn get_sid(&self, _pid: i32) -> Result<u32, i64> {
            Ok(self.sid)
        }
        fn set_sid(&mut self) -> Result<u32, i64> {
            Ok(self.sid)
        }
        fn personality(&mut self, p: u64) -> u64 {
            let old = self.personality;
            if p != 0xffff_ffff {
                self.personality = p;
            }
            old
        }
        fn prctl_get_name(&self, buf: &mut [u8; 16]) {
            *buf = self.comm;
        }
        fn prctl_set_name(&mut self, name: &[u8; 16]) {
            self.comm = *name;
        }
        fn prctl_get_pdeathsig(&self) -> u8 {
            self.pdeathsig
        }
        fn prctl_set_pdeathsig(&mut self, sig: u8) -> Result<(), i64> {
            self.pdeathsig = sig;
            Ok(())
        }
        fn prctl_get_dumpable(&self) -> u32 {
            self.dumpable
        }
        fn prctl_set_dumpable(&mut self, d: u32) -> Result<(), i64> {
            self.dumpable = d;
            Ok(())
        }
        fn prctl_get_no_new_privs(&self) -> bool {
            self.no_new_privs
        }
        fn prctl_set_no_new_privs(&mut self, n: bool) -> Result<(), i64> {
            self.no_new_privs = n;
            Ok(())
        }
        fn prctl_get_child_subreaper(&self) -> bool {
            self.child_subreaper
        }
        fn prctl_set_child_subreaper(&mut self, s: bool) {
            self.child_subreaper = s;
        }
    }

    #[test]
    fn prctl_unmodelled_option_returns_none() {
        let mut mock = MockNative::new();
        mock.args[0] = 999; // unknown option
        assert_eq!(invoke(IdentityCall::Prctl, &mut mock), None);
    }

    #[test]
    fn prctl_set_name_bounded_copy_stops_at_nul() {
        let mut mock = MockNative::new();
        mock.args[0] = LINUX_PR_SET_NAME;
        mock.args[1] = 0x1000;
        // Place "test\0" in memory at 0x1000, and leave 0x1005 unmapped
        mock.memory.insert(0x1000, b't');
        mock.memory.insert(0x1001, b'e');
        mock.memory.insert(0x1002, b's');
        mock.memory.insert(0x1003, b't');
        mock.memory.insert(0x1004, 0);

        let res = invoke(IdentityCall::Prctl, &mut mock).unwrap();
        assert_eq!(res.raw(), 0);
        assert_eq!(&mock.venue.comm[..5], b"test\0");
        assert_eq!(&mock.venue.comm[5..], &[0; 11]);
    }

    #[test]
    fn setgroups_checks_permission_before_copy_in() {
        let mut mock = MockNative::new();
        mock.venue.can_set_groups_error = Some(EPERM);
        mock.args[0] = 2;
        mock.args[1] = 0xdead_beef; // unmapped memory!
        let res = invoke(IdentityCall::SetGroups, &mut mock).unwrap();
        assert_eq!(res.raw(), EPERM);
    }

    #[test]
    fn setgroups_exceeds_max_returns_einval() {
        let mut mock = MockNative::new();
        mock.args[0] = (LINUX_NGROUPS_MAX + 1) as u64;
        mock.args[1] = 0x1000;
        let res = invoke(IdentityCall::SetGroups, &mut mock).unwrap();
        assert_eq!(res.raw(), EINVAL);
    }

    #[test]
    fn setfsuid_minus_one_returns_previous_and_leaves_unchanged() {
        let mut mock = MockNative::new();
        mock.venue.uids.3 = 1000;
        mock.args[0] = u32::MAX as u64; // (uid_t)-1
        let res = invoke(IdentityCall::SetFsUid, &mut mock).unwrap();
        assert_eq!(res.raw(), 1000);
        assert_eq!(mock.venue.uids.3, 1000);
    }

    #[test]
    fn get_robust_list_validates_pointers() {
        let mut mock = MockNative::new();
        mock.args[0] = 0; // current thread
        mock.args[1] = 0x1000; // head ptr
        mock.args[2] = 0x2000; // len ptr
        // len ptr unmapped -> EFAULT
        let res = invoke(IdentityCall::GetRobustList, &mut mock).unwrap();
        assert_eq!(res.raw(), EFAULT);
    }
}
