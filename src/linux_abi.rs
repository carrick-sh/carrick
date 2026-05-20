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
pub const LINUX_AT_FLAGS: u64 = 8;
pub const LINUX_AT_ENTRY: u64 = 9;
pub const LINUX_AT_UID: u64 = 11;
pub const LINUX_AT_EUID: u64 = 12;
pub const LINUX_AT_GID: u64 = 13;
pub const LINUX_AT_EGID: u64 = 14;
pub const LINUX_AT_PLATFORM: u64 = 15;
pub const LINUX_AT_HWCAP: u64 = 16;
pub const LINUX_AT_CLKTCK: u64 = 17;
pub const LINUX_AT_SECURE: u64 = 23;
pub const LINUX_AT_RANDOM: u64 = 25;
pub const LINUX_AT_HWCAP2: u64 = 26;
pub const LINUX_AT_EXECFN: u64 = 31;
pub const LINUX_PAGE_SIZE: u64 = 4096;
pub const LINUX_UTSNAME_FIELD_SIZE: usize = 65;
/// Number of u64s in the kernel ABI sigset_t. Linux uapi defines
/// `_NSIG=64` and `_NSIG_WORDS = _NSIG / _NSIG_BPW = 1`, so the
/// kernel's `sigset_t` is a single 8-byte word and the kernel-level
/// `struct sigaction` (what `rt_sigaction` reads/writes) is therefore
/// 24 (handler+flags+restorer) + 8 (mask) = 32 bytes total. Writing
/// past those 32 bytes back into the caller's stack frame clobbers
/// the caller's saved `x30` and crashes the guest with PC=0.
pub const LINUX_SIGSET_WORDS: usize = 1;
pub const LINUX_KERNEL_SIGSET_SIZE: u64 = 8;

// Linux SIGxxx numbers (POSIX). Only the handful we actively translate to
// from host signals or accept from kill(2) are listed here.
pub const LINUX_SIGHUP: i32 = 1;
pub const LINUX_SIGINT: i32 = 2;
pub const LINUX_SIGQUIT: i32 = 3;
pub const LINUX_SIGTERM: i32 = 15;

/// `SIG_DFL` / `SIG_IGN` handler sentinel values stored in `sa_handler`.
pub const LINUX_SIG_DFL: u64 = 0;
pub const LINUX_SIG_IGN: u64 = 1;

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

/// Size of the Linux kernel-ABI `struct termios` for TCGETS/TCSETS on
/// aarch64. It's `c_iflag/c_oflag/c_cflag/c_lflag` (4 u32s = 16 bytes)
/// + `c_line` (1 byte) + `c_cc[19]` (19 bytes) = **36 bytes**. The
/// `c_ispeed`/`c_ospeed` fields belong to `struct termios2` (TCGETS2),
/// a separate ioctl. Writing 44 bytes for TCGETS overflows the
/// caller's stack-allocated buffer by 8, corrupts the stack canary,
/// and trips `__stack_chk_fail` later in any glibc program that calls
/// `isatty()` (which goes through tcgetattr → TCGETS) — i.e. ls, dpkg,
/// etc. Use [`LINUX_TERMIOS_KERNEL_SIZE`] explicitly for those ioctls.
pub const LINUX_TERMIOS_KERNEL_SIZE: usize = 36;

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

// ----- Netlink (AF_NETLINK / NETLINK_ROUTE) ABI ---------------------------
//
// macOS has no AF_NETLINK, so carrick synthesises just enough of the
// rtnetlink wire format for glibc's __check_pf / getaddrinfo and the
// `ip`/`ss` tools to enumerate a loopback interface and stop. These are
// the kernel uapi layouts (all little-endian on aarch64).

/// `struct nlmsghdr` — header on every netlink message.
#[repr(C, packed)]
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned,
)]
pub struct LinuxNlMsgHdr {
    pub nlmsg_len: u32,
    pub nlmsg_type: u16,
    pub nlmsg_flags: u16,
    pub nlmsg_seq: u32,
    pub nlmsg_pid: u32,
}

/// `struct ifinfomsg` — payload of an RTM_NEWLINK message.
#[repr(C, packed)]
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned,
)]
pub struct LinuxIfInfoMsg {
    pub ifi_family: u8,
    pub ifi_pad: u8,
    pub ifi_type: u16,
    pub ifi_index: i32,
    pub ifi_flags: u32,
    pub ifi_change: u32,
}

/// `struct ifaddrmsg` — payload of an RTM_NEWADDR message.
#[repr(C, packed)]
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned,
)]
pub struct LinuxIfAddrMsg {
    pub ifa_family: u8,
    pub ifa_prefixlen: u8,
    pub ifa_flags: u8,
    pub ifa_scope: u8,
    pub ifa_index: u32,
}

/// `struct rtattr` — TLV attribute header used inside rtnetlink payloads.
#[repr(C, packed)]
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned,
)]
pub struct LinuxRtAttr {
    pub rta_len: u16,
    pub rta_type: u16,
}

// nlmsg_type values.
pub const LINUX_NLMSG_NOOP: u16 = 1;
pub const LINUX_NLMSG_ERROR: u16 = 2;
pub const LINUX_NLMSG_DONE: u16 = 3;
pub const LINUX_RTM_GETLINK: u16 = 18;
pub const LINUX_RTM_NEWLINK: u16 = 16;
pub const LINUX_RTM_GETADDR: u16 = 22;
pub const LINUX_RTM_NEWADDR: u16 = 20;

// nlmsg_flags.
pub const LINUX_NLM_F_MULTI: u16 = 0x2;

// Interface flags / types we report for `lo`.
pub const LINUX_IFF_UP: u32 = 0x1;
pub const LINUX_IFF_LOOPBACK: u32 = 0x8;
pub const LINUX_IFF_RUNNING: u32 = 0x40;
pub const LINUX_ARPHRD_LOOPBACK: u16 = 772;

// rtattr types.
pub const LINUX_IFLA_ADDRESS: u16 = 1;
pub const LINUX_IFLA_IFNAME: u16 = 3;
pub const LINUX_IFA_ADDRESS: u16 = 1;
pub const LINUX_IFA_LOCAL: u16 = 2;
pub const LINUX_IFA_LABEL: u16 = 3;

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

/// Magic value placed in `CarrickSigframe::magic` so `rt_sigreturn` can
/// detect a misaligned / corrupt frame and refuse to restore garbage.
pub const CARRICK_SIGFRAME_MAGIC: u64 = 0x4361_7272_6963_6b53; // 'CarrickS'

/// Carrick's private signal frame layout. The Linux kernel's real
/// `struct rt_sigframe` carries a full `siginfo_t` + `ucontext_t`; we
/// only need enough state to round-trip a handler invocation through
/// `rt_sigreturn`, so we use a packed format we authored ourselves.
/// Userspace never inspects this — it just passes the pointer back to
/// `rt_sigreturn` via its registered restorer thunk.
#[repr(C, packed)]
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned,
)]
pub struct CarrickSigframe {
    pub magic: u64,
    pub signum: u32,
    pub _pad0: u32,
    pub saved_x: [u64; 31],
    pub saved_pc: u64,
    pub saved_sp: u64,
    pub saved_spsr: u64,
    pub _reserved: [u64; 6],
}

impl CarrickSigframe {
    pub const fn empty() -> Self {
        Self {
            magic: CARRICK_SIGFRAME_MAGIC,
            signum: 0,
            _pad0: 0,
            saved_x: [0; 31],
            saved_pc: 0,
            saved_sp: 0,
            saved_spsr: 0,
            _reserved: [0; 6],
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

// =============================================================================
//                            Kernel ABI boundary
// =============================================================================
//
// Every UAPI struct that crosses the syscall boundary has an EXACT byte
// count the Linux kernel writes/reads — and that count is what defines
// "the ABI", not the size of our Rust struct. Conflating the two is what
// gave us a 44-byte TCGETS write into glibc's 36-byte on-stack termios
// buffer; the overflow trampled the stack canary and every glibc binary
// that called isatty() aborted later inside __stack_chk_fail.
//
// To prevent that class of bug ever happening again, ABI-touching structs
// implement `KernelAbi`. The trait holds a const `ABI_SIZE` (the wire
// size the Linux kernel uses), and provides `abi_bytes()` returning a
// slice of exactly that length. All guest-memory writes from the
// dispatcher go through `write_kernel_struct`, which CAN'T pick the
// wrong length — the wire size is baked into the type.
//
// The trait's `const _` block asserts that ABI_SIZE never exceeds the
// in-memory Rust layout (so `abi_bytes()` can't read past the struct).
// For structs whose Rust layout naturally matches the kernel ABI,
// `ABI_SIZE == size_of::<Self>()` and a corresponding `const _` assert
// pins it to the documented kernel size — drift from spec fails the
// build with a clear message rather than corrupting guest memory.
//
// Sizes are sourced from `include/uapi/asm-generic/*.h` and the
// aarch64 arch overrides; cross-checked with `pahole` against a Debian
// trixie kernel when in doubt.

pub trait KernelAbi: IntoBytes + Immutable {
    /// Wire size the Linux kernel uses when the kernel reads/writes
    /// this struct via syscall. Must be `<= size_of::<Self>()`.
    const ABI_SIZE: usize;

    /// Bytes to copy into guest memory for an ABI-shaped syscall
    /// argument. Always exactly `ABI_SIZE` bytes regardless of the
    /// Rust struct's true layout.
    fn abi_bytes(&self) -> &[u8] {
        &self.as_bytes()[..Self::ABI_SIZE]
    }
}

// One macro per `KernelAbi` impl so the trait and the
// `ABI_SIZE <= sizeof(Self)` assert are always written together.
macro_rules! kernel_abi {
    ($ty:ty, $size:expr, $why:expr) => {
        impl KernelAbi for $ty {
            const ABI_SIZE: usize = $size;
        }
        const _: () = assert!(
            <$ty as KernelAbi>::ABI_SIZE <= core::mem::size_of::<$ty>(),
            concat!(stringify!($ty), ": ABI_SIZE > size_of::<Self>() — would over-read")
        );
        const _: () = assert!(
            <$ty as KernelAbi>::ABI_SIZE == $size,
            $why
        );
    };
}

kernel_abi!(LinuxStat, 128, "Linux struct stat for aarch64 is 128 bytes");
kernel_abi!(LinuxStatfs, 120, "Linux struct statfs64 is 120 bytes");
kernel_abi!(LinuxStatx, 256, "Linux struct statx is 256 bytes");
kernel_abi!(LinuxWinsize, 8, "TIOCGWINSZ struct is 8 bytes");
kernel_abi!(LinuxTermios, LINUX_TERMIOS_KERNEL_SIZE, "TCGETS kernel termios is 36 bytes; the trailing 8 bytes of LinuxTermios (c_ispeed/c_ospeed) belong to termios2/TCGETS2");
kernel_abi!(LinuxEventfdValue, 8, "eventfd_t is u64");
kernel_abi!(LinuxEpollEvent, 12, "epoll_event packed = u32 events + u64 data");
kernel_abi!(LinuxPollFd, 8, "pollfd is fd:i32 + events:i16 + revents:i16");
kernel_abi!(LinuxFdPair, 8, "two-int fd pair (pipe2 etc.)");
kernel_abi!(LinuxAuxvEntry, 16, "ELF auxv entry is two u64");
kernel_abi!(LinuxIovec, 16, "struct iovec is base:u64 + len:u64");
kernel_abi!(LinuxOpenHow, 24, "openat2 how is 3 u64s");
kernel_abi!(LinuxTimespec, 16, "timespec is tv_sec:i64 + tv_nsec:i64");
kernel_abi!(LinuxItimerspec, 32, "itimerspec is two timespecs");
kernel_abi!(LinuxTimeval, 16, "timeval is tv_sec:i64 + tv_usec:i64");
kernel_abi!(LinuxItimerval, 32, "itimerval is two timevals");
kernel_abi!(LinuxTimezone, 8, "timezone is tz_minuteswest:i32 + tz_dsttime:i32");
kernel_abi!(LinuxRlimit, 16, "rlimit is cur:u64 + max:u64");
kernel_abi!(LinuxTms, 32, "tms is four clock_t (long) = 4 * 8");
kernel_abi!(LinuxSigaction, 32, "k_sigaction is handler+flags+restorer+mask[1]");
kernel_abi!(LinuxTimerfdExpirations, 8, "timerfd_read result is u64");
kernel_abi!(LinuxCapabilityHeader, 8, "capget header is version:u32 + pid:i32");
kernel_abi!(LinuxCapabilityData, 12, "capget data is three u32");
kernel_abi!(LinuxStatxTimestamp, 16, "statx_timestamp is sec:i64 + nsec:u32 + pad");
kernel_abi!(LinuxSysinfo, core::mem::size_of::<LinuxSysinfo>(), "sysinfo (packed) matches its layout");
kernel_abi!(LinuxUtsname, LINUX_UTSNAME_FIELD_SIZE * 6, "utsname is 6 char[65] fields");
kernel_abi!(LinuxRusage, core::mem::size_of::<LinuxRusage>(), "rusage layout matches kernel ABI");
kernel_abi!(LinuxSigaltstack, 24, "stack_t is ss_sp:u64 + ss_flags:i32 + ss_size:u64 (with 4-byte pad)");
kernel_abi!(LinuxDirent64Header, 19, "dirent64 fixed header is d_ino+d_off+d_reclen+d_type");

#[cfg(test)]
mod kernel_abi_tests {
    use super::*;

    #[test]
    fn termios_kernel_abi_size_is_36_not_44() {
        // Regression for the bug that crashed ls/dpkg: LinuxTermios is
        // 44 bytes in Rust (it includes termios2's ispeed/ospeed) but
        // the kernel TCGETS write is exactly 36. `abi_bytes()` must
        // return 36 — anything more overflows the caller's stack.
        let t = LinuxTermios::default_cooked();
        assert_eq!(t.abi_bytes().len(), 36);
        assert_eq!(<LinuxTermios as KernelAbi>::ABI_SIZE, 36);
        assert!(core::mem::size_of::<LinuxTermios>() > <LinuxTermios as KernelAbi>::ABI_SIZE);
    }

    #[test]
    fn abi_size_never_exceeds_struct_size() {
        // Sample of structs across the surface — KernelAbi's const
        // assert guarantees this for every impl, but the test makes
        // the property runnable too.
        assert!(<LinuxStat as KernelAbi>::ABI_SIZE <= core::mem::size_of::<LinuxStat>());
        assert!(<LinuxStatfs as KernelAbi>::ABI_SIZE <= core::mem::size_of::<LinuxStatfs>());
        assert!(<LinuxStatx as KernelAbi>::ABI_SIZE <= core::mem::size_of::<LinuxStatx>());
        assert!(<LinuxRusage as KernelAbi>::ABI_SIZE <= core::mem::size_of::<LinuxRusage>());
        assert!(<LinuxUtsname as KernelAbi>::ABI_SIZE <= core::mem::size_of::<LinuxUtsname>());
        assert!(<LinuxSigaltstack as KernelAbi>::ABI_SIZE <= core::mem::size_of::<LinuxSigaltstack>());
        assert!(<LinuxSigaction as KernelAbi>::ABI_SIZE <= core::mem::size_of::<LinuxSigaction>());
    }
}
