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
pub struct LinuxStatxTimestamp {
    pub tv_sec: i64,
    pub tv_nsec: u32,
    pub __reserved: i32,
}

impl LinuxStatxTimestamp {
    pub const fn zero() -> Self {
        Self {
            tv_sec: 0,
            tv_nsec: 0,
            __reserved: 0,
        }
    }
}

#[repr(C, packed)]
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned,
)]
pub struct LinuxStatx {
    pub stx_mask: u32,
    pub stx_blksize: u32,
    pub stx_attributes: u64,
    pub stx_nlink: u32,
    pub stx_uid: u32,
    pub stx_gid: u32,
    pub stx_mode: u16,
    pub __spare0: [u16; 1],
    pub stx_ino: u64,
    pub stx_size: u64,
    pub stx_blocks: u64,
    pub stx_attributes_mask: u64,
    pub stx_atime: LinuxStatxTimestamp,
    pub stx_btime: LinuxStatxTimestamp,
    pub stx_ctime: LinuxStatxTimestamp,
    pub stx_mtime: LinuxStatxTimestamp,
    pub stx_rdev_major: u32,
    pub stx_rdev_minor: u32,
    pub stx_dev_major: u32,
    pub stx_dev_minor: u32,
    pub stx_mnt_id: u64,
    pub stx_dio_mem_align: u32,
    pub stx_dio_offset_align: u32,
    pub stx_subvol: u64,
    pub stx_atomic_write_unit_min: u32,
    pub stx_atomic_write_unit_max: u32,
    pub stx_atomic_write_segments_max: u32,
    pub stx_dio_read_offset_align: u32,
    pub stx_atomic_write_unit_max_opt: u32,
    pub __spare2: [u32; 1],
    pub __spare3: [u64; 8],
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
pub struct LinuxTermios {
    pub c_iflag: u32,
    pub c_oflag: u32,
    pub c_cflag: u32,
    pub c_lflag: u32,
    pub c_line: u8,
    pub c_cc: [u8; 19],
    pub c_ispeed: u32,
    pub c_ospeed: u32,
}

impl LinuxTermios {
    pub fn default_cooked() -> Self {
        let mut c_cc = [0u8; 19];
        c_cc[0] = 0x03; // VINTR  (Ctrl+C)
        c_cc[1] = 0x1c; // VQUIT  (Ctrl+\)
        c_cc[2] = 0x7f; // VERASE (DEL)
        c_cc[3] = 0x15; // VKILL  (Ctrl+U)
        c_cc[4] = 0x04; // VEOF   (Ctrl+D)
        c_cc[5] = 0; // VTIME
        c_cc[6] = 1; // VMIN
        c_cc[7] = 0; // VSWTC
        c_cc[8] = 0x11; // VSTART  (Ctrl+Q)
        c_cc[9] = 0x13; // VSTOP   (Ctrl+S)
        c_cc[10] = 0x1a; // VSUSP   (Ctrl+Z)
        c_cc[11] = 0; // VEOL
        c_cc[12] = 0x12; // VREPRINT (Ctrl+R)
        c_cc[13] = 0x0f; // VDISCARD (Ctrl+O)
        c_cc[14] = 0x17; // VWERASE  (Ctrl+W)
        c_cc[15] = 0x16; // VLNEXT   (Ctrl+V)
        c_cc[16] = 0; // VEOL2
        // indices 17 and 18 reserved, remain 0
        Self {
            c_iflag: 0x4502,
            c_oflag: 0x0005,
            c_cflag: 0x04bf,
            c_lflag: 0x803b,
            c_line: 0,
            c_cc,
            c_ispeed: 38400,
            c_ospeed: 38400,
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
pub struct LinuxOpenHow {
    pub flags: u64,
    pub mode: u64,
    pub resolve: u64,
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
pub struct LinuxItimerval {
    pub it_interval: LinuxTimeval,
    pub it_value: LinuxTimeval,
}

impl LinuxItimerval {
    pub const fn new(it_interval: LinuxTimeval, it_value: LinuxTimeval) -> Self {
        Self {
            it_interval,
            it_value,
        }
    }

    pub const fn zeroed() -> Self {
        Self {
            it_interval: LinuxTimeval::new(0, 0),
            it_value: LinuxTimeval::new(0, 0),
        }
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
pub struct LinuxTms {
    pub tms_utime: i64,
    pub tms_stime: i64,
    pub tms_cutime: i64,
    pub tms_cstime: i64,
}

impl LinuxTms {
    pub const fn zeroed() -> Self {
        Self {
            tms_utime: 0,
            tms_stime: 0,
            tms_cutime: 0,
            tms_cstime: 0,
        }
    }
}

#[repr(C, packed)]
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned,
)]
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
            ru_utime: LinuxTimeval::new(0, 0),
            ru_stime: LinuxTimeval::new(0, 0),
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
}

#[repr(C, packed)]
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned,
)]
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
    pub _padding: [u8; 8],
    pub totalhigh: u64,
    pub freehigh: u64,
    pub mem_unit: u32,
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

#[repr(C, packed)]
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned,
)]
pub struct LinuxSigaltstack {
    pub ss_sp: u64,
    pub ss_flags: i32,
    pub __pad: u32,
    pub ss_size: u64,
}

impl LinuxSigaltstack {
    pub const fn empty() -> Self {
        Self {
            ss_sp: 0,
            ss_flags: 0,
            __pad: 0,
            ss_size: 0,
        }
    }

    pub const fn disabled() -> Self {
        Self {
            ss_sp: 0,
            ss_flags: 2, // SS_DISABLE
            __pad: 0,
            ss_size: 0,
        }
    }
}

fn write_linux_c_field<const N: usize>(field: &mut [u8; N], value: &[u8]) {
    let len = value.len().min(N.saturating_sub(1));
    field[..len].copy_from_slice(&value[..len]);
}
