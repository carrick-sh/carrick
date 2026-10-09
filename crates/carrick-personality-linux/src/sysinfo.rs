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

    pub fn as_bytes(&self) -> &[u8] {
        // SAFETY: LinuxUtsname is #[repr(C)] containing only [u8; 65] arrays.
        unsafe {
            core::slice::from_raw_parts(
                (self as *const Self) as *const u8,
                core::mem::size_of::<Self>(),
            )
        }
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

    pub fn as_bytes(&self) -> &[u8] {
        // SAFETY: LinuxSysinfo is #[repr(C, packed)] Plain Old Data.
        unsafe {
            core::slice::from_raw_parts(
                (self as *const Self) as *const u8,
                core::mem::size_of::<Self>(),
            )
        }
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

    pub fn as_bytes(&self) -> &[u8] {
        // SAFETY: LinuxRusage is #[repr(C)] Plain Old Data.
        unsafe {
            core::slice::from_raw_parts(
                (self as *const Self) as *const u8,
                core::mem::size_of::<Self>(),
            )
        }
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
    fn set_hostname(&mut self, name: &[u8]) -> Result<(), i64>;
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
            if !native.copy_out(ptr, uts.as_bytes()) {
                return Some(SyscallResult::new(EFAULT));
            }
            Some(SyscallResult::new(0))
        }
        SysinfoCall::SetHostname => {
            let ptr = UserVa::new(args[0]);
            let len = args[1] as usize;
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
            match venue.set_hostname(&buf[..len]) {
                Ok(()) => Some(SyscallResult::new(0)),
                Err(e) => Some(SyscallResult::new(e)),
            }
        }
        SysinfoCall::SetDomainname => {
            let ptr = UserVa::new(args[0]);
            let len = args[1] as usize;
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
            match venue.set_domainname(&buf[..len]) {
                Ok(()) => Some(SyscallResult::new(0)),
                Err(e) => Some(SyscallResult::new(e)),
            }
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
            if !native.copy_out(ptr, rusage.as_bytes()) {
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
            if !native.copy_out(ptr, info.as_bytes()) {
                return Some(SyscallResult::new(EFAULT));
            }
            Some(SyscallResult::new(0))
        }
    }
}
