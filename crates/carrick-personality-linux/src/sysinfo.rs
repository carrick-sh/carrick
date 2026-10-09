//! System-information and resource-limit syscall family.
use crate::abi::entry::SyscallResult;
use crate::lifecycle::UserCopy;
use carrick_guest_arch::UserVa;

pub const EPERM: i64 = -1;
pub const ESRCH: i64 = -3;
pub const EFAULT: i64 = -14;
pub const EINVAL: i64 = -22;

pub const LINUX_UTSNAME_FIELD_SIZE: usize = 65;

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct LinuxUtsname {
    pub sysname: [u8; LINUX_UTSNAME_FIELD_SIZE],
    pub nodename: [u8; LINUX_UTSNAME_FIELD_SIZE],
    pub release: [u8; LINUX_UTSNAME_FIELD_SIZE],
    pub version: [u8; LINUX_UTSNAME_FIELD_SIZE],
    pub machine: [u8; LINUX_UTSNAME_FIELD_SIZE],
    pub domainname: [u8; LINUX_UTSNAME_FIELD_SIZE],
}

fn copy_cstr(dst: &mut [u8], src: &[u8]) {
    let len = src.len().min(dst.len().saturating_sub(1));
    dst[..len].copy_from_slice(&src[..len]);
    dst[len] = 0;
}

impl LinuxUtsname {
    pub const fn empty() -> Self {
        Self {
            sysname: [0; LINUX_UTSNAME_FIELD_SIZE],
            nodename: [0; LINUX_UTSNAME_FIELD_SIZE],
            release: [0; LINUX_UTSNAME_FIELD_SIZE],
            version: [0; LINUX_UTSNAME_FIELD_SIZE],
            machine: [0; LINUX_UTSNAME_FIELD_SIZE],
            domainname: [0; LINUX_UTSNAME_FIELD_SIZE],
        }
    }

    pub fn carrick_x86_64() -> Self {
        let mut u = Self::empty();
        copy_cstr(&mut u.sysname, b"Linux");
        copy_cstr(&mut u.nodename, b"carrick");
        copy_cstr(&mut u.release, b"6.6.0-carrick");
        copy_cstr(&mut u.version, b"#1 SMP PREEMPT");
        copy_cstr(&mut u.machine, b"x86_64");
        copy_cstr(&mut u.domainname, b"(none)");
        u
    }

    pub fn carrick_aarch64() -> Self {
        let mut u = Self::empty();
        copy_cstr(&mut u.sysname, b"Linux");
        copy_cstr(&mut u.nodename, b"carrick");
        copy_cstr(&mut u.release, b"6.6.0-carrick");
        copy_cstr(&mut u.version, b"#1 SMP PREEMPT");
        copy_cstr(&mut u.machine, b"aarch64");
        copy_cstr(&mut u.domainname, b"(none)");
        u
    }

    pub fn set_nodename(&mut self, name: &[u8]) {
        self.nodename = [0; LINUX_UTSNAME_FIELD_SIZE];
        copy_cstr(&mut self.nodename, name);
    }

    pub fn set_domainname(&mut self, name: &[u8]) {
        self.domainname = [0; LINUX_UTSNAME_FIELD_SIZE];
        copy_cstr(&mut self.domainname, name);
    }

    pub fn to_bytes(&self) -> [u8; 390] {
        let mut buf = [0u8; 390];
        buf[0..65].copy_from_slice(&self.sysname);
        buf[65..130].copy_from_slice(&self.nodename);
        buf[130..195].copy_from_slice(&self.release);
        buf[195..260].copy_from_slice(&self.version);
        buf[260..325].copy_from_slice(&self.machine);
        buf[325..390].copy_from_slice(&self.domainname);
        buf
    }
}

pub use carrick_sched_core::process::LinuxRlimit;

#[repr(C, packed)]
#[derive(Clone, Copy, Debug)]
pub struct LinuxSysinfo {
    pub uptime: i64,
    pub loads: [u64; 3],
    pub totalram: u64,
    pub freeram: u64,
    pub sharedram: u64,
    pub bufferram: u64,
    pub totalswap: u64,
    pub freeswap: u64,
    pub procs: u16,
    pub pad: u16,
    pub _pad_align: [u8; 4],
    pub totalhigh: u64,
    pub freehigh: u64,
    pub mem_unit: u32,
    pub _f: [u8; 4],
}

impl LinuxSysinfo {
    pub const fn default_info() -> Self {
        Self {
            uptime: 0,
            loads: [0; 3],
            totalram: 16 * 1024 * 1024 * 1024,
            freeram: 16 * 1024 * 1024 * 1024,
            sharedram: 0,
            bufferram: 0,
            totalswap: 0,
            freeswap: 0,
            procs: 1,
            pad: 0,
            _pad_align: [0; 4],
            totalhigh: 0,
            freehigh: 0,
            mem_unit: 1,
            _f: [0; 4],
        }
    }

    pub fn to_bytes(&self) -> [u8; 112] {
        let mut buf = [0u8; 112];
        buf[0..8].copy_from_slice(&self.uptime.to_ne_bytes());
        buf[8..16].copy_from_slice(&self.loads[0].to_ne_bytes());
        buf[16..24].copy_from_slice(&self.loads[1].to_ne_bytes());
        buf[24..32].copy_from_slice(&self.loads[2].to_ne_bytes());
        buf[32..40].copy_from_slice(&self.totalram.to_ne_bytes());
        buf[40..48].copy_from_slice(&self.freeram.to_ne_bytes());
        buf[48..56].copy_from_slice(&self.sharedram.to_ne_bytes());
        buf[56..64].copy_from_slice(&self.bufferram.to_ne_bytes());
        buf[64..72].copy_from_slice(&self.totalswap.to_ne_bytes());
        buf[72..80].copy_from_slice(&self.freeswap.to_ne_bytes());
        buf[80..82].copy_from_slice(&self.procs.to_ne_bytes());
        buf[82..84].copy_from_slice(&self.pad.to_ne_bytes());
        buf[84..88].copy_from_slice(&self._pad_align);
        buf[88..96].copy_from_slice(&self.totalhigh.to_ne_bytes());
        buf[96..104].copy_from_slice(&self.freehigh.to_ne_bytes());
        buf[104..108].copy_from_slice(&self.mem_unit.to_ne_bytes());
        buf[108..112].copy_from_slice(&self._f);
        buf
    }
}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct LinuxTimeval {
    pub tv_sec: i64,
    pub tv_usec: i64,
}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct LinuxRusage {
    pub ru_utime: LinuxTimeval,
    pub ru_stime: LinuxTimeval,
    pub ru_maxrss: i64,
    pub ru_ixrss: i64,
    pub ru_idrss: i64,
    pub ru_isrss: i64,
    pub ru_minflt: i64,
    pub ru_majflt: i64,
    pub ru_nswap: i64,
    pub ru_inblock: i64,
    pub ru_oublock: i64,
    pub ru_msgsnd: i64,
    pub ru_msgrcv: i64,
    pub ru_nsignals: i64,
    pub ru_nvcsw: i64,
    pub ru_nivcsw: i64,
}

impl LinuxRusage {
    pub const fn zeroed() -> Self {
        Self {
            ru_utime: LinuxTimeval {
                tv_sec: 0,
                tv_usec: 0,
            },
            ru_stime: LinuxTimeval {
                tv_sec: 0,
                tv_usec: 0,
            },
            ru_maxrss: 0,
            ru_ixrss: 0,
            ru_idrss: 0,
            ru_isrss: 0,
            ru_minflt: 0,
            ru_majflt: 0,
            ru_nswap: 0,
            ru_inblock: 0,
            ru_oublock: 0,
            ru_msgsnd: 0,
            ru_msgrcv: 0,
            ru_nsignals: 0,
            ru_nvcsw: 0,
            ru_nivcsw: 0,
        }
    }

    pub fn to_bytes(&self) -> [u8; carrick_syscall_abi::LINUX_RUSAGE_BYTES] {
        let mut buf = [0u8; carrick_syscall_abi::LINUX_RUSAGE_BYTES];
        buf[0..8].copy_from_slice(&self.ru_utime.tv_sec.to_ne_bytes());
        buf[8..16].copy_from_slice(&self.ru_utime.tv_usec.to_ne_bytes());
        buf[16..24].copy_from_slice(&self.ru_stime.tv_sec.to_ne_bytes());
        buf[24..32].copy_from_slice(&self.ru_stime.tv_usec.to_ne_bytes());
        buf[32..40].copy_from_slice(&self.ru_maxrss.to_ne_bytes());
        buf[40..48].copy_from_slice(&self.ru_ixrss.to_ne_bytes());
        buf[48..56].copy_from_slice(&self.ru_idrss.to_ne_bytes());
        buf[56..64].copy_from_slice(&self.ru_isrss.to_ne_bytes());
        buf[64..72].copy_from_slice(&self.ru_minflt.to_ne_bytes());
        buf[72..80].copy_from_slice(&self.ru_majflt.to_ne_bytes());
        buf[80..88].copy_from_slice(&self.ru_nswap.to_ne_bytes());
        buf[88..96].copy_from_slice(&self.ru_inblock.to_ne_bytes());
        buf[96..104].copy_from_slice(&self.ru_oublock.to_ne_bytes());
        buf[104..112].copy_from_slice(&self.ru_msgsnd.to_ne_bytes());
        buf[112..120].copy_from_slice(&self.ru_msgrcv.to_ne_bytes());
        buf[120..128].copy_from_slice(&self.ru_nsignals.to_ne_bytes());
        buf[128..136].copy_from_slice(&self.ru_nvcsw.to_ne_bytes());
        buf[136..144].copy_from_slice(&self.ru_nivcsw.to_ne_bytes());
        buf
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SysinfoCall {
    Uname,
    SetHostname,
    SetDomainname,
    GetRlimit,
    SetRlimit,
    Prlimit64,
    Umask,
    GetRusage,
    Sysinfo,
}

pub trait ProcessSysinfoVenue {
    fn get_uts(&self) -> LinuxUtsname;
    fn can_set_hostname(&self) -> Result<(), i64>;
    fn set_hostname(&mut self, name: &[u8]) -> Result<(), i64>;
    fn can_set_domainname(&self) -> Result<(), i64>;
    fn set_domainname(&mut self, name: &[u8]) -> Result<(), i64>;
    fn get_rlimit(&self, resource: usize) -> Result<LinuxRlimit, i64>;
    fn set_rlimit(&mut self, resource: usize, limit: LinuxRlimit) -> Result<(), i64>;
    fn prlimit64(
        &mut self,
        pid: i32,
        resource: usize,
        new_limit: Option<LinuxRlimit>,
    ) -> Result<LinuxRlimit, i64>;
    fn umask(&mut self, mask: u32) -> u32;
    fn sysinfo(&self) -> LinuxSysinfo;
    fn getrusage(&self, who: i32) -> Result<LinuxRusage, i64>;
}

pub trait SysinfoNative<'a>: UserCopy {
    fn arguments(&self) -> [u64; 6];
    fn process_sysinfo(&mut self) -> Option<&mut dyn ProcessSysinfoVenue>;
}

#[inline(never)]
fn set_uts_string<'a>(
    ptr: UserVa,
    len: usize,
    native: &mut dyn SysinfoNative<'a>,
    is_domain: bool,
) -> Option<SyscallResult> {
    {
        let venue = native.process_sysinfo()?;
        let perm = if is_domain {
            venue.can_set_domainname()
        } else {
            venue.can_set_hostname()
        };
        if let Err(e) = perm {
            return Some(SyscallResult::new(e));
        }
        if len == 0 {
            let _ = if is_domain {
                venue.set_domainname(&[])
            } else {
                venue.set_hostname(&[])
            };
            return Some(SyscallResult::new(0));
        }
    }
    if len > 64 {
        return Some(SyscallResult::new(EINVAL));
    }
    if ptr.raw() == 0 {
        return Some(SyscallResult::new(EFAULT));
    }
    let mut buf = [0u8; 64];
    if !native.copy_in(&mut buf[..len], ptr) {
        return Some(SyscallResult::new(EFAULT));
    }
    let venue = native.process_sysinfo()?;
    let res = if is_domain {
        venue.set_domainname(&buf[..len])
    } else {
        venue.set_hostname(&buf[..len])
    };
    match res {
        Ok(()) => Some(SyscallResult::new(0)),
        Err(e) => Some(SyscallResult::new(e)),
    }
}

#[inline(never)]
pub fn invoke<'a>(call: SysinfoCall, native: &mut dyn SysinfoNative<'a>) -> Option<SyscallResult> {
    let args = native.arguments();
    match call {
        SysinfoCall::Uname => {
            let ptr = UserVa::new(args[0]);
            if ptr.raw() == 0 {
                return Some(SyscallResult::new(EFAULT));
            }
            let uts = {
                let venue = native.process_sysinfo()?;
                venue.get_uts()
            };
            if !native.copy_out(ptr, &uts.to_bytes()) {
                return Some(SyscallResult::new(EFAULT));
            }
            Some(SyscallResult::new(0))
        }
        SysinfoCall::SetHostname => {
            set_uts_string(UserVa::new(args[0]), args[1] as usize, native, false)
        }
        SysinfoCall::SetDomainname => {
            set_uts_string(UserVa::new(args[0]), args[1] as usize, native, true)
        }
        SysinfoCall::GetRlimit => {
            let resource = args[0] as usize;
            let ptr = UserVa::new(args[1]);
            if resource >= 16 {
                return Some(SyscallResult::new(EINVAL));
            }
            if ptr.raw() == 0 {
                return Some(SyscallResult::new(EFAULT));
            }
            let lim = {
                let venue = native.process_sysinfo()?;
                match venue.get_rlimit(resource) {
                    Ok(l) => l,
                    Err(e) => return Some(SyscallResult::new(e)),
                }
            };
            let mut bytes = [0u8; 16];
            bytes[0..8].copy_from_slice(&lim.rlim_cur.to_ne_bytes());
            bytes[8..16].copy_from_slice(&lim.rlim_max.to_ne_bytes());
            if !native.copy_out(ptr, &bytes) {
                return Some(SyscallResult::new(EFAULT));
            }
            Some(SyscallResult::new(0))
        }
        SysinfoCall::SetRlimit => {
            let resource = args[0] as usize;
            let ptr = UserVa::new(args[1]);
            if resource >= 16 {
                return Some(SyscallResult::new(EINVAL));
            }
            if ptr.raw() == 0 {
                return Some(SyscallResult::new(EFAULT));
            }
            let mut bytes = [0u8; 16];
            if !native.copy_in(&mut bytes, ptr) {
                return Some(SyscallResult::new(EFAULT));
            }
            let cur = u64::from_ne_bytes(bytes[0..8].try_into().unwrap_or([0; 8]));
            let max = u64::from_ne_bytes(bytes[8..16].try_into().unwrap_or([0; 8]));
            let venue = native.process_sysinfo()?;
            match venue.set_rlimit(resource, LinuxRlimit::new(cur, max)) {
                Ok(()) => Some(SyscallResult::new(0)),
                Err(e) => Some(SyscallResult::new(e)),
            }
        }
        SysinfoCall::Prlimit64 => {
            let pid = args[0] as i32;
            let resource = args[1] as usize;
            let new_limit_ptr = UserVa::new(args[2]);
            let old_limit_ptr = UserVa::new(args[3]);
            if resource >= 16 {
                return Some(SyscallResult::new(EINVAL));
            }
            let new_limit = if new_limit_ptr.raw() != 0 {
                let mut bytes = [0u8; 16];
                if !native.copy_in(&mut bytes, new_limit_ptr) {
                    return Some(SyscallResult::new(EFAULT));
                }
                let cur = u64::from_ne_bytes(bytes[0..8].try_into().unwrap_or([0; 8]));
                let max = u64::from_ne_bytes(bytes[8..16].try_into().unwrap_or([0; 8]));
                Some(LinuxRlimit::new(cur, max))
            } else {
                None
            };
            let old = {
                let venue = native.process_sysinfo()?;
                match venue.prlimit64(pid, resource, new_limit) {
                    Ok(l) => l,
                    Err(e) => return Some(SyscallResult::new(e)),
                }
            };
            if old_limit_ptr.raw() != 0 {
                let mut bytes = [0u8; 16];
                bytes[0..8].copy_from_slice(&old.rlim_cur.to_ne_bytes());
                bytes[8..16].copy_from_slice(&old.rlim_max.to_ne_bytes());
                if !native.copy_out(old_limit_ptr, &bytes) {
                    return Some(SyscallResult::new(EFAULT));
                }
            }
            Some(SyscallResult::new(0))
        }
        SysinfoCall::Umask => {
            let mask = args[0] as u32;
            let venue = native.process_sysinfo()?;
            let old = venue.umask(mask);
            Some(SyscallResult::new(i64::from(old)))
        }
        SysinfoCall::GetRusage => {
            let who = args[0] as i32;
            let ptr = UserVa::new(args[1]);
            if ptr.raw() == 0 {
                return Some(SyscallResult::new(EFAULT));
            }
            let rusage = {
                let venue = native.process_sysinfo()?;
                match venue.getrusage(who) {
                    Ok(r) => r,
                    Err(e) => return Some(SyscallResult::new(e)),
                }
            };
            if !native.copy_out(ptr, &rusage.to_bytes()) {
                return Some(SyscallResult::new(EFAULT));
            }
            Some(SyscallResult::new(0))
        }
        SysinfoCall::Sysinfo => {
            let ptr = UserVa::new(args[0]);
            if ptr.raw() == 0 {
                return Some(SyscallResult::new(EFAULT));
            }
            let info = {
                let venue = native.process_sysinfo()?;
                venue.sysinfo()
            };
            if !native.copy_out(ptr, &info.to_bytes()) {
                return Some(SyscallResult::new(EFAULT));
            }
            Some(SyscallResult::new(0))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::collections::BTreeMap;

    struct MockNative {
        args: [u64; 6],
        memory: BTreeMap<u64, u8>,
        venue: MockVenue,
    }

    impl MockNative {
        fn new() -> Self {
            Self {
                args: [0; 6],
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

    impl<'a> SysinfoNative<'a> for MockNative {
        fn arguments(&self) -> [u64; 6] {
            self.args
        }
        fn process_sysinfo(&mut self) -> Option<&mut dyn ProcessSysinfoVenue> {
            Some(&mut self.venue)
        }
    }

    struct MockVenue {
        uts: Option<LinuxUtsname>,
        hostname: alloc::vec::Vec<u8>,
        domainname: alloc::vec::Vec<u8>,
        can_set_host_error: Option<i64>,
        can_set_domain_error: Option<i64>,
        rlimits: [LinuxRlimit; 16],
    }

    impl Default for MockVenue {
        fn default() -> Self {
            Self {
                uts: None,
                hostname: alloc::vec::Vec::new(),
                domainname: alloc::vec::Vec::new(),
                can_set_host_error: None,
                can_set_domain_error: None,
                rlimits: [LinuxRlimit {
                    rlim_cur: LinuxRlimit::INFINITY,
                    rlim_max: LinuxRlimit::INFINITY,
                }; 16],
            }
        }
    }

    impl ProcessSysinfoVenue for MockVenue {
        fn get_uts(&self) -> LinuxUtsname {
            self.uts.unwrap_or_else(LinuxUtsname::carrick_x86_64)
        }
        fn can_set_hostname(&self) -> Result<(), i64> {
            if let Some(e) = self.can_set_host_error {
                return Err(e);
            }
            Ok(())
        }
        fn set_hostname(&mut self, name: &[u8]) -> Result<(), i64> {
            self.hostname = name.to_vec();
            Ok(())
        }
        fn can_set_domainname(&self) -> Result<(), i64> {
            if let Some(e) = self.can_set_domain_error {
                return Err(e);
            }
            Ok(())
        }
        fn set_domainname(&mut self, name: &[u8]) -> Result<(), i64> {
            self.domainname = name.to_vec();
            Ok(())
        }
        fn get_rlimit(&self, resource: usize) -> Result<LinuxRlimit, i64> {
            if resource >= 16 {
                return Err(EINVAL);
            }
            Ok(self.rlimits[resource])
        }
        fn set_rlimit(&mut self, resource: usize, limit: LinuxRlimit) -> Result<(), i64> {
            if resource >= 16 {
                return Err(EINVAL);
            }
            self.rlimits[resource] = limit;
            Ok(())
        }
        fn prlimit64(
            &mut self,
            _pid: i32,
            resource: usize,
            new_limit: Option<LinuxRlimit>,
        ) -> Result<LinuxRlimit, i64> {
            if resource >= 16 {
                return Err(EINVAL);
            }
            let old = self.rlimits[resource];
            if let Some(new) = new_limit {
                self.rlimits[resource] = new;
            }
            Ok(old)
        }
        fn umask(&mut self, mask: u32) -> u32 {
            mask
        }
        fn sysinfo(&self) -> LinuxSysinfo {
            LinuxSysinfo::default_info()
        }
        fn getrusage(&self, _who: i32) -> Result<LinuxRusage, i64> {
            Ok(LinuxRusage::zeroed())
        }
    }

    #[test]
    fn sethostname_checks_permission_before_copy_in() {
        let mut mock = MockNative::new();
        mock.venue.can_set_host_error = Some(EPERM);
        mock.args[0] = 0xdead_beef; // unmapped memory
        mock.args[1] = 5;
        let res = invoke(SysinfoCall::SetHostname, &mut mock).unwrap();
        assert_eq!(res.raw(), EPERM);
    }

    #[test]
    fn sethostname_len_zero_with_null_succeeds() {
        let mut mock = MockNative::new();
        mock.args[0] = 0; // NULL pointer
        mock.args[1] = 0; // len == 0
        let res = invoke(SysinfoCall::SetHostname, &mut mock).unwrap();
        assert_eq!(res.raw(), 0);
        assert_eq!(mock.venue.hostname, b"");
    }

    #[test]
    fn setdomainname_len_zero_with_null_succeeds() {
        let mut mock = MockNative::new();
        mock.args[0] = 0; // NULL pointer
        mock.args[1] = 0; // len == 0
        let res = invoke(SysinfoCall::SetDomainname, &mut mock).unwrap();
        assert_eq!(res.raw(), 0);
        assert_eq!(mock.venue.domainname, b"");
    }

    #[test]
    fn sethostname_len_exceeds_64_returns_einval() {
        let mut mock = MockNative::new();
        mock.args[0] = 0x1000;
        mock.args[1] = 65;
        let res = invoke(SysinfoCall::SetHostname, &mut mock).unwrap();
        assert_eq!(res.raw(), EINVAL);
    }

    #[test]
    fn sethostname_checks_permission_before_len_exceeds_64() {
        let mut mock = MockNative::new();
        mock.venue.can_set_host_error = Some(EPERM);
        mock.args[0] = 0x1000;
        mock.args[1] = 65; // len > 64
        let res = invoke(SysinfoCall::SetHostname, &mut mock).unwrap();
        assert_eq!(res.raw(), EPERM);
    }

    #[test]
    fn setdomainname_checks_permission_before_len_exceeds_64() {
        let mut mock = MockNative::new();
        mock.venue.can_set_domain_error = Some(EPERM);
        mock.args[0] = 0x1000;
        mock.args[1] = 65; // len > 64
        let res = invoke(SysinfoCall::SetDomainname, &mut mock).unwrap();
        assert_eq!(res.raw(), EPERM);
    }

    #[test]
    fn uname_copies_uts_record() {
        let mut mock = MockNative::new();
        mock.args[0] = 0x1000;
        let res = invoke(SysinfoCall::Uname, &mut mock).unwrap();
        assert_eq!(res.raw(), 0);
        // Verify sysname starts with "Linux\0"
        let sysname: alloc::vec::Vec<u8> = (0..6).map(|i| mock.memory[&(0x1000 + i)]).collect();
        assert_eq!(&sysname, b"Linux\0");
    }
}
