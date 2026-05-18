use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout, Unaligned};

pub const LINUX_S_IFMT: u32 = 0o170000;
pub const LINUX_S_IFDIR: u32 = 0o040000;
pub const LINUX_S_IFREG: u32 = 0o100000;
pub const LINUX_S_IFLNK: u32 = 0o120000;

pub const LINUX_DT_DIR: u8 = 4;
pub const LINUX_DT_REG: u8 = 8;
pub const LINUX_DT_LNK: u8 = 10;

pub const LINUX_AT_NULL: u64 = 0;
pub const LINUX_AT_PHDR: u64 = 3;
pub const LINUX_AT_PHENT: u64 = 4;
pub const LINUX_AT_PHNUM: u64 = 5;
pub const LINUX_AT_PAGESZ: u64 = 6;
pub const LINUX_AT_BASE: u64 = 7;
pub const LINUX_AT_ENTRY: u64 = 9;
pub const LINUX_PAGE_SIZE: u64 = 4096;
pub const LINUX_UTSNAME_FIELD_SIZE: usize = 65;
pub const LINUX_SIGSET_WORDS: usize = 16;

pub const LINUX_DIRENT64_HEADER_SIZE: usize = core::mem::size_of::<LinuxDirent64Header>();

#[repr(C, packed)]
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned,
)]
pub struct LinuxStat {
    pub st_dev: u64,
    pub st_ino: u64,
    pub st_mode: u32,
    pub st_nlink: u32,
    pub st_uid: u32,
    pub st_gid: u32,
    pub st_rdev: u64,
    pub __pad1: u64,
    pub st_size: i64,
    pub st_blksize: i32,
    pub __pad2: i32,
    pub st_blocks: i64,
    pub st_atime: i64,
    pub st_atime_nsec: u64,
    pub st_mtime: i64,
    pub st_mtime_nsec: u64,
    pub st_ctime: i64,
    pub st_ctime_nsec: u64,
    pub __unused4: u32,
    pub __unused5: u32,
}

#[repr(C, packed)]
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned,
)]
pub struct LinuxStatfs {
    pub f_type: i64,
    pub f_bsize: i64,
    pub f_blocks: u64,
    pub f_bfree: u64,
    pub f_bavail: u64,
    pub f_files: u64,
    pub f_ffree: u64,
    pub f_fsid: [i32; 2],
    pub f_namelen: i64,
    pub f_frsize: i64,
    pub f_flags: i64,
    pub f_spare: [i64; 4],
}

#[repr(C, packed)]
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned,
)]
pub struct LinuxWinsize {
    pub ws_row: u16,
    pub ws_col: u16,
    pub ws_xpixel: u16,
    pub ws_ypixel: u16,
}

impl LinuxWinsize {
    pub fn terminal_80x24() -> Self {
        Self {
            ws_row: 24,
            ws_col: 80,
            ws_xpixel: 0,
            ws_ypixel: 0,
        }
    }
}

#[repr(C, packed)]
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned,
)]
pub struct LinuxEventfdValue {
    pub value: u64,
}

#[repr(C, packed)]
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned,
)]
pub struct LinuxEpollEvent {
    pub events: u32,
    pub data: u64,
}

#[repr(C, packed)]
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned,
)]
pub struct LinuxPollFd {
    pub fd: i32,
    pub events: i16,
    pub revents: i16,
}

#[repr(C, packed)]
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned,
)]
pub struct LinuxCapabilityHeader {
    pub version: u32,
    pub pid: i32,
}

#[repr(C, packed)]
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned,
)]
pub struct LinuxCapabilityData {
    pub effective: u32,
    pub permitted: u32,
    pub inheritable: u32,
}

impl LinuxCapabilityData {
    pub const fn empty() -> Self {
        Self {
            effective: 0,
            permitted: 0,
            inheritable: 0,
        }
    }

    pub const fn is_empty(self) -> bool {
        self.effective == 0 && self.permitted == 0 && self.inheritable == 0
    }
}

#[repr(C, packed)]
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned,
)]
pub struct LinuxFdPair {
    pub read_fd: i32,
    pub write_fd: i32,
}

#[repr(C, packed)]
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned,
)]
pub struct LinuxDirent64Header {
    pub d_ino: u64,
    pub d_off: i64,
    pub d_reclen: u16,
    pub d_type: u8,
}

#[repr(C, packed)]
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned,
)]
pub struct LinuxAuxvEntry {
    pub a_type: u64,
    pub a_val: u64,
}

impl LinuxAuxvEntry {
    pub const fn new(a_type: u64, a_val: u64) -> Self {
        Self { a_type, a_val }
    }

    pub fn tag(self) -> u64 {
        self.a_type
    }

    pub fn value(self) -> u64 {
        self.a_val
    }
}

#[repr(C, packed)]
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned,
)]
pub struct LinuxIovec {
    pub iov_base: u64,
    pub iov_len: u64,
}

impl LinuxIovec {
    pub const fn new(iov_base: u64, iov_len: u64) -> Self {
        Self { iov_base, iov_len }
    }
}

#[repr(C, packed)]
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned,
)]
pub struct LinuxTimespec {
    pub tv_sec: i64,
    pub tv_nsec: i64,
}

impl LinuxTimespec {
    pub const fn new(tv_sec: i64, tv_nsec: i64) -> Self {
        Self { tv_sec, tv_nsec }
    }
}

#[repr(C, packed)]
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned,
)]
pub struct LinuxItimerspec {
    pub it_interval: LinuxTimespec,
    pub it_value: LinuxTimespec,
}

impl LinuxItimerspec {
    pub const fn new(it_interval: LinuxTimespec, it_value: LinuxTimespec) -> Self {
        Self {
            it_interval,
            it_value,
        }
    }
}

#[repr(C, packed)]
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned,
)]
pub struct LinuxTimerfdExpirations {
    pub expirations: u64,
}

#[repr(C, packed)]
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned,
)]
pub struct LinuxTimeval {
    pub tv_sec: i64,
    pub tv_usec: i64,
}

impl LinuxTimeval {
    pub const fn new(tv_sec: i64, tv_usec: i64) -> Self {
        Self { tv_sec, tv_usec }
    }
}

#[repr(C, packed)]
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned,
)]
pub struct LinuxTimezone {
    pub tz_minuteswest: i32,
    pub tz_dsttime: i32,
}

impl LinuxTimezone {
    pub const fn utc() -> Self {
        Self {
            tz_minuteswest: 0,
            tz_dsttime: 0,
        }
    }
}

#[repr(C, packed)]
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned,
)]
pub struct LinuxUtsname {
    pub sysname: [u8; LINUX_UTSNAME_FIELD_SIZE],
    pub nodename: [u8; LINUX_UTSNAME_FIELD_SIZE],
    pub release: [u8; LINUX_UTSNAME_FIELD_SIZE],
    pub version: [u8; LINUX_UTSNAME_FIELD_SIZE],
    pub machine: [u8; LINUX_UTSNAME_FIELD_SIZE],
    pub domainname: [u8; LINUX_UTSNAME_FIELD_SIZE],
}

impl LinuxUtsname {
    pub fn carrick_aarch64() -> Self {
        let mut utsname = Self {
            sysname: [0; LINUX_UTSNAME_FIELD_SIZE],
            nodename: [0; LINUX_UTSNAME_FIELD_SIZE],
            release: [0; LINUX_UTSNAME_FIELD_SIZE],
            version: [0; LINUX_UTSNAME_FIELD_SIZE],
            machine: [0; LINUX_UTSNAME_FIELD_SIZE],
            domainname: [0; LINUX_UTSNAME_FIELD_SIZE],
        };
        write_linux_c_field(&mut utsname.sysname, b"Linux");
        write_linux_c_field(&mut utsname.nodename, b"carrick");
        write_linux_c_field(&mut utsname.release, b"6.12.0-carrick");
        write_linux_c_field(&mut utsname.version, b"#1 Carrick");
        write_linux_c_field(&mut utsname.machine, b"aarch64");
        write_linux_c_field(&mut utsname.domainname, b"localdomain");
        utsname
    }
}

#[repr(C, packed)]
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned,
)]
pub struct LinuxRlimit {
    pub rlim_cur: u64,
    pub rlim_max: u64,
}

impl LinuxRlimit {
    pub const fn new(rlim_cur: u64, rlim_max: u64) -> Self {
        Self { rlim_cur, rlim_max }
    }
}

#[repr(C, packed)]
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned,
)]
pub struct LinuxSigaction {
    pub sa_handler: u64,
    pub sa_flags: u64,
    pub sa_restorer: u64,
    pub sa_mask: [u64; LINUX_SIGSET_WORDS],
}

impl LinuxSigaction {
    pub const fn empty() -> Self {
        Self {
            sa_handler: 0,
            sa_flags: 0,
            sa_restorer: 0,
            sa_mask: [0; LINUX_SIGSET_WORDS],
        }
    }
}

fn write_linux_c_field<const N: usize>(field: &mut [u8; N], value: &[u8]) {
    let len = value.len().min(N.saturating_sub(1));
    field[..len].copy_from_slice(&value[..len]);
}
