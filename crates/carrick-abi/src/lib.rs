//! Linux AArch64 ABI constants and wire-format structs used by the dispatcher
//! and guest memory helpers.

use bitflags::bitflags;
use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout, Unaligned};

pub const LINUX_S_IFMT: u32 = 0o170000;
pub const LINUX_S_IFDIR: u32 = 0o040000;
pub const LINUX_S_IFREG: u32 = 0o100000;
pub const LINUX_S_IFLNK: u32 = 0o120000;
pub const LINUX_S_IFIFO: u32 = 0o010000;
pub const LINUX_S_IFCHR: u32 = 0o020000;
pub const LINUX_S_IFBLK: u32 = 0o060000;
pub const LINUX_S_IFSOCK: u32 = 0o140000;

pub const LINUX_DT_FIFO: u8 = 1;
pub const LINUX_DT_CHR: u8 = 2;
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
/// Base address of the kernel-provided vDSO ELF (carrick's fast clock page).
pub const LINUX_AT_SYSINFO_EHDR: u64 = 33;
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

/// `sa_flags` bit: the `sa_restorer` field is valid. When CLEAR the kernel
/// IGNORES `sa_restorer` (whatever garbage it holds) and returns from the
/// handler via the VDSO sigreturn trampoline. glibc on aarch64 never sets this
/// — so carrick must synthesise its own trampoline unless this bit is present.
pub const LINUX_SA_RESTORER: u64 = 0x0400_0000;

/// `SA_ONSTACK`: deliver this signal on the alternate signal stack installed
/// via `sigaltstack(2)`, if one is present. Go installs its runtime signal
/// handlers with this flag.
pub const LINUX_SA_ONSTACK: u64 = 0x0800_0000;

/// `SA_RESTART`: a blocking, restartable syscall interrupted by this handler is
/// transparently restarted (the kernel's `ERESTARTSYS` path) instead of failing
/// with `EINTR`. LTP's `tst_test` installs SA_RESTART handlers for its
/// SIGALRM/SIGUSR1 timeout+heartbeat, so the parent's `SAFE_WAITPID` reap must
/// restart when one fires — without this carrick surfaced EINTR and TBROK'd
/// nearly the whole suite.
pub const LINUX_SA_RESTART: u64 = 0x1000_0000;

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
/// + `c_line` (1 byte) + `c_cc[19]` (19 bytes) = **36 bytes**.
///
/// The `c_ispeed`/`c_ospeed` fields belong to `struct termios2` (TCGETS2),
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
    pub _pad: u32,
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
pub struct LinuxMsghdr {
    pub name: u64,
    pub namelen: u32,
    pub _pad0: u32,
    pub iov: u64,
    pub iovlen: u64,
    pub control: u64,
    pub controllen: u64,
    pub flags: u32,
    pub _pad1: u32,
}

#[repr(C, packed)]
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned,
)]
pub struct LinuxMmsghdr {
    pub msg_hdr: LinuxMsghdr,
    pub msg_len: u32,
    pub _pad: u32,
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

/// `struct rtmsg` — payload of an RTM_NEWROUTE message (a routing-table entry).
#[repr(C, packed)]
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned,
)]
pub struct LinuxRtMsg {
    pub rtm_family: u8,
    pub rtm_dst_len: u8,
    pub rtm_src_len: u8,
    pub rtm_tos: u8,
    pub rtm_table: u8,
    pub rtm_protocol: u8,
    pub rtm_scope: u8,
    pub rtm_type: u8,
    pub rtm_flags: u32,
}

/// `struct ndmsg` — payload of an RTM_NEWNEIGH message (a neighbour entry).
#[repr(C, packed)]
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned,
)]
pub struct LinuxNdMsg {
    pub ndm_family: u8,
    pub ndm_pad1: u8,
    pub ndm_pad2: u16,
    pub ndm_ifindex: i32,
    pub ndm_state: u16,
    pub ndm_flags: u8,
    pub ndm_type: u8,
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
pub const LINUX_RTM_NEWROUTE: u16 = 24;
pub const LINUX_RTM_GETROUTE: u16 = 26;
pub const LINUX_RTM_NEWNEIGH: u16 = 28;
pub const LINUX_RTM_GETNEIGH: u16 = 30;

// rtattr types inside an rtmsg (RTM_*ROUTE).
pub const LINUX_RTA_DST: u16 = 1;
pub const LINUX_RTA_OIF: u16 = 4;
// rtm_table / rtm_protocol / rtm_type / rtm_scope values for a connected route.
pub const LINUX_RT_TABLE_MAIN: u8 = 254;
pub const LINUX_RTPROT_KERNEL: u8 = 2;
pub const LINUX_RTN_UNICAST: u8 = 1;

// nlmsg_flags.
pub const LINUX_NLM_F_MULTI: u16 = 0x2;

// Interface flags / types we report for `lo`.
pub const LINUX_IFF_UP: u32 = 0x1;
pub const LINUX_IFF_BROADCAST: u32 = 0x2;
pub const LINUX_IFF_LOOPBACK: u32 = 0x8;
pub const LINUX_IFF_POINTOPOINT: u32 = 0x10;
pub const LINUX_IFF_RUNNING: u32 = 0x40;
pub const LINUX_IFF_MULTICAST: u32 = 0x1000;
pub const LINUX_ARPHRD_ETHER: u16 = 1;
pub const LINUX_ARPHRD_LOOPBACK: u16 = 772;
// rtnetlink address scopes (rtnetlink.h rt_scope_t).
pub const LINUX_RT_SCOPE_UNIVERSE: u8 = 0;
pub const LINUX_RT_SCOPE_LINK: u8 = 253;
pub const LINUX_RT_SCOPE_HOST: u8 = 254;

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
pub struct LinuxCloneArgs {
    pub flags: u64,
    pub pidfd: u64,
    pub child_tid: u64,
    pub parent_tid: u64,
    pub exit_signal: u64,
    pub stack: u64,
    pub stack_size: u64,
    pub tls: u64,
    pub set_tid: u64,
    pub set_tid_size: u64,
    pub cgroup: u64,
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
    // Reproduce the naturally-aligned kernel `struct sysinfo` (aarch64) under
    // repr(C,packed): a 2-byte explicit pad after `procs` + 4 implicit-alignment
    // bytes before the next u64, then a 4-byte trailing pad. The old single
    // `_padding: [u8; 8]` shifted totalhigh/freehigh/mem_unit by 2 bytes (the
    // guest read mem_unit as 65536). Size is now 112, matching Linux. (audit M4)
    pub pad: u16,
    pub _pad_align: [u8; 4],
    pub totalhigh: u64,
    pub freehigh: u64,
    pub mem_unit: u32,
    pub _f: [u8; 4],
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

pub const LINUX_SIGINFO_SIZE: usize = 128;
pub const LINUX_UCONTEXT_SIGMASK_PAD_BYTES: usize = 120;
pub const LINUX_AARCH64_SIGCONTEXT_RESERVED_BYTES: usize = 4096;

pub const LINUX_SI_USER: i32 = 0;

#[repr(C, packed)]
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned,
)]
pub struct LinuxSiginfo {
    pub si_signo: i32,
    pub si_errno: i32,
    pub si_code: i32,
    pub _pad0: i32,
    pub si_addr: u64,
    pub _pad: [u8; LINUX_SIGINFO_SIZE - 24],
}

impl LinuxSiginfo {
    pub const fn empty() -> Self {
        Self {
            si_signo: 0,
            si_errno: 0,
            si_code: 0,
            _pad0: 0,
            si_addr: 0,
            _pad: [0; LINUX_SIGINFO_SIZE - 24],
        }
    }
}

#[repr(C, packed)]
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned,
)]
pub struct LinuxSignalStack {
    pub ss_sp: u64,
    pub ss_flags: i32,
    pub _pad0: u32,
    pub ss_size: u64,
}

impl LinuxSignalStack {
    pub const fn empty() -> Self {
        Self {
            ss_sp: 0,
            ss_flags: 0,
            _pad0: 0,
            ss_size: 0,
        }
    }
}

#[repr(C, packed)]
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned,
)]
pub struct LinuxSignalContext {
    pub fault_address: u64,
    pub regs: [u64; 31],
    pub sp: u64,
    pub pc: u64,
    pub pstate: u64,
    pub _pad: [u8; 8],
    pub __reserved: [u8; LINUX_AARCH64_SIGCONTEXT_RESERVED_BYTES],
}

impl LinuxSignalContext {
    pub const fn empty() -> Self {
        Self {
            fault_address: 0,
            regs: [0; 31],
            sp: 0,
            pc: 0,
            pstate: 0,
            _pad: [0; 8],
            __reserved: [0; LINUX_AARCH64_SIGCONTEXT_RESERVED_BYTES],
        }
    }
}

#[repr(C, packed)]
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned,
)]
pub struct LinuxUcontext {
    pub uc_flags: u64,
    pub uc_link: u64,
    pub uc_stack: LinuxSignalStack,
    pub uc_sigmask: u64,
    pub _pad: [u8; LINUX_UCONTEXT_SIGMASK_PAD_BYTES],
    pub _pad2: [u8; 8],
    pub uc_mcontext: LinuxSignalContext,
}

impl LinuxUcontext {
    pub const fn empty() -> Self {
        Self {
            uc_flags: 0,
            uc_link: 0,
            uc_stack: LinuxSignalStack::empty(),
            uc_sigmask: 0,
            _pad: [0; LINUX_UCONTEXT_SIGMASK_PAD_BYTES],
            _pad2: [0; 8],
            uc_mcontext: LinuxSignalContext::empty(),
        }
    }
}

/// `_aarch64_ctx.magic` for the FP/SIMD context record the kernel places in
/// `sigcontext.__reserved`. The guest's signal handler and `rt_sigreturn` rely
/// on V0–V31 + FPSR/FPCR being saved here and restored, exactly as Linux does
/// (`arch/arm64/include/uapi/asm/sigcontext.h`). Without it, a handler that
/// touches SIMD (e.g. aarch64 `memcpy`) silently corrupts the interrupted
/// thread's vector state.
pub const LINUX_FPSIMD_MAGIC: u32 = 0x4650_8001;

/// AArch64 `struct fpsimd_context`: the FP/SIMD register record stored at the
/// start of `sigcontext.__reserved`. `vregs` holds V0–V31 as 128-bit values.
/// `#[repr(C, packed)]` matches the kernel's contiguous layout (head 8 + fpsr 4
/// + fpcr 4 + vregs 512 = 528 bytes; `vregs` at offset 16).
#[repr(C, packed)]
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned,
)]
pub struct LinuxFpsimdContext {
    pub magic: u32,
    pub size: u32,
    pub fpsr: u32,
    pub fpcr: u32,
    pub vregs: [u128; 32],
}

impl LinuxFpsimdContext {
    pub const fn empty() -> Self {
        Self {
            magic: LINUX_FPSIMD_MAGIC,
            size: core::mem::size_of::<Self>() as u32,
            fpsr: 0,
            fpcr: 0,
            vregs: [0; 32],
        }
    }
}

/// Magic value placed in `CarrickSigframe::magic` so `rt_sigreturn` can
/// detect a misaligned / corrupt frame and refuse to restore garbage.
pub const CARRICK_SIGFRAME_MAGIC: u64 = 0x4361_7272_6963_6b53; // 'CarrickS'

/// Carrick's signal frame layout. The leading fields are private so
/// `rt_sigreturn` can authenticate and restore the frame. The embedded
/// `siginfo_t` and AArch64 `ucontext_t` are Linux-shaped because SA_SIGINFO
/// handlers can inspect or mutate the saved register context.
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
    pub siginfo: LinuxSiginfo,
    pub ucontext: LinuxUcontext,
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
            siginfo: LinuxSiginfo::empty(),
            ucontext: LinuxUcontext::empty(),
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
            concat!(
                stringify!($ty),
                ": ABI_SIZE > size_of::<Self>() — would over-read"
            )
        );
        const _: () = assert!(<$ty as KernelAbi>::ABI_SIZE == $size, $why);
    };
}

kernel_abi!(LinuxStat, 128, "Linux struct stat for aarch64 is 128 bytes");
kernel_abi!(LinuxStatfs, 120, "Linux struct statfs64 is 120 bytes");
kernel_abi!(LinuxStatx, 256, "Linux struct statx is 256 bytes");
kernel_abi!(LinuxWinsize, 8, "TIOCGWINSZ struct is 8 bytes");
kernel_abi!(
    LinuxTermios,
    LINUX_TERMIOS_KERNEL_SIZE,
    "TCGETS kernel termios is 36 bytes; the trailing 8 bytes of LinuxTermios (c_ispeed/c_ospeed) belong to termios2/TCGETS2"
);
kernel_abi!(LinuxEventfdValue, 8, "eventfd_t is u64");
kernel_abi!(
    LinuxEpollEvent,
    16,
    "aarch64 epoll_event = u32 events + u32 pad + u64 data"
);
kernel_abi!(
    LinuxPollFd,
    8,
    "pollfd is fd:i32 + events:i16 + revents:i16"
);
kernel_abi!(
    LinuxMsghdr,
    56,
    "msghdr is name+namelen+pad+iov+iovlen+control+controllen+flags+pad"
);
kernel_abi!(
    LinuxMmsghdr,
    64,
    "mmsghdr is msghdr plus msg_len:u32 plus pad:u32"
);
kernel_abi!(LinuxFdPair, 8, "two-int fd pair (pipe2 etc.)");
kernel_abi!(LinuxAuxvEntry, 16, "ELF auxv entry is two u64");
kernel_abi!(LinuxIovec, 16, "struct iovec is base:u64 + len:u64");
kernel_abi!(LinuxOpenHow, 24, "openat2 how is 3 u64s");
kernel_abi!(LinuxCloneArgs, 88, "clone_args has eleven u64 fields");
kernel_abi!(LinuxTimespec, 16, "timespec is tv_sec:i64 + tv_nsec:i64");
kernel_abi!(LinuxItimerspec, 32, "itimerspec is two timespecs");
kernel_abi!(LinuxTimeval, 16, "timeval is tv_sec:i64 + tv_usec:i64");
kernel_abi!(LinuxItimerval, 32, "itimerval is two timevals");
kernel_abi!(
    LinuxTimezone,
    8,
    "timezone is tz_minuteswest:i32 + tz_dsttime:i32"
);
kernel_abi!(LinuxRlimit, 16, "rlimit is cur:u64 + max:u64");
kernel_abi!(LinuxTms, 32, "tms is four clock_t (long) = 4 * 8");
kernel_abi!(
    LinuxSigaction,
    32,
    "k_sigaction is handler+flags+restorer+mask[1]"
);
kernel_abi!(LinuxTimerfdExpirations, 8, "timerfd_read result is u64");
kernel_abi!(
    LinuxCapabilityHeader,
    8,
    "capget header is version:u32 + pid:i32"
);
kernel_abi!(LinuxCapabilityData, 12, "capget data is three u32");
kernel_abi!(
    LinuxStatxTimestamp,
    16,
    "statx_timestamp is sec:i64 + nsec:u32 + pad"
);
kernel_abi!(
    LinuxSysinfo,
    core::mem::size_of::<LinuxSysinfo>(),
    "sysinfo (packed) matches its layout"
);
kernel_abi!(
    LinuxUtsname,
    LINUX_UTSNAME_FIELD_SIZE * 6,
    "utsname is 6 char[65] fields"
);
kernel_abi!(
    LinuxRusage,
    core::mem::size_of::<LinuxRusage>(),
    "rusage layout matches kernel ABI"
);
kernel_abi!(
    LinuxSigaltstack,
    24,
    "stack_t is ss_sp:u64 + ss_flags:i32 + ss_size:u64 (with 4-byte pad)"
);
kernel_abi!(
    LinuxDirent64Header,
    19,
    "dirent64 fixed header is d_ino+d_off+d_reclen+d_type"
);

// ===== ABI constants moved from dispatch.rs (Goal #3, pub set) =====
pub const LINUX_EPERM: i32 = 1;
pub const LINUX_ENOENT: i32 = 2;
pub const LINUX_ESRCH: i32 = 3;
/// No such device or address — e.g. `open("/dev/tty")` with no controlling tty.
pub const LINUX_ENXIO: i32 = 6;
pub const LINUX_EBADF: i32 = 9;
pub const LINUX_ECHILD: i32 = 10;
pub const LINUX_EAGAIN: i32 = 11;
pub const LINUX_EINTR: i32 = 4;
/// Non-blocking `connect(2)` in progress / already in progress / completed.
pub const LINUX_EINPROGRESS: i32 = 115;
pub const LINUX_EALREADY: i32 = 114;
pub const LINUX_EISCONN: i32 = 106;
pub const LINUX_ENOMEM: i32 = 12;
pub const LINUX_EACCES: i32 = 13;
pub const LINUX_EFAULT: i32 = 14;
pub const LINUX_EEXIST: i32 = 17;
pub const LINUX_EPIPE: i32 = 32;
pub const LINUX_ESPIPE: i32 = 29;
pub const LINUX_EROFS: i32 = 30;
pub const LINUX_ENOTSUP: i32 = 95;
pub const LINUX_ENOTSOCK: i32 = 88;
pub const LINUX_ENOPROTOOPT: i32 = 92;
pub const LINUX_ESOCKTNOSUPPORT: i32 = 94;
// Linux's `type & SOCK_NONBLOCK` and `& SOCK_CLOEXEC` bits sit in the
// type argument to socket(2)/socketpair(2)/accept4(2). macOS doesn't
// have these; we strip them before calling libc and apply the effect
// (O_NONBLOCK, FD_CLOEXEC) by hand.
pub const LINUX_SOCK_NONBLOCK: i32 = 0o4000;
pub const LINUX_SOCK_CLOEXEC: i32 = 0o2000000;
// Linux `sockaddr_storage` is 128 bytes. We use the same upper bound
// when round-tripping addresses through host syscalls.
pub const LINUX_SOCKADDR_STORAGE_SIZE: usize = 128;
pub const LINUX_FALLOC_FL_KEEP_SIZE: u64 = 0x01;
pub const LINUX_FALLOC_FL_PUNCH_HOLE: u64 = 0x02;
pub const LINUX_FALLOC_FL_COLLAPSE_RANGE: u64 = 0x08;
pub const LINUX_FALLOC_FL_ZERO_RANGE: u64 = 0x10;
pub const LINUX_FALLOC_FL_INSERT_RANGE: u64 = 0x20;
pub const LINUX_FALLOC_FL_UNSHARE_RANGE: u64 = 0x40;
pub const LINUX_FALLOC_FL_SUPPORTED: u64 = LINUX_FALLOC_FL_KEEP_SIZE
    | LINUX_FALLOC_FL_PUNCH_HOLE
    | LINUX_FALLOC_FL_COLLAPSE_RANGE
    | LINUX_FALLOC_FL_ZERO_RANGE
    | LINUX_FALLOC_FL_INSERT_RANGE
    | LINUX_FALLOC_FL_UNSHARE_RANGE;
pub const LINUX_ENOTDIR: i32 = 20;
pub const LINUX_EISDIR: i32 = 21;
pub const LINUX_EINVAL: i32 = 22;
pub const LINUX_ENOTTY: i32 = 25;
pub const LINUX_EFBIG: i32 = 27;
pub const LINUX_ERANGE: i32 = 34;
pub const LINUX_ENAMETOOLONG: i32 = 36;
pub const LINUX_ENOSYS: i32 = 38;
pub const LINUX_ENOTEMPTY: i32 = 39;
pub const LINUX_ENODATA: i32 = 61;
pub const LINUX_E2BIG: i32 = 7;
// Remaining Linux UAPI errno values (asm-generic/errno-base.h + errno.h),
// canonical home for the `linux_errno` re-export table in dispatch/mod.rs.
pub const LINUX_EIO: i32 = 5;
pub const LINUX_ENOEXEC: i32 = 8;
pub const LINUX_ENOTBLK: i32 = 15;
pub const LINUX_EBUSY: i32 = 16;
pub const LINUX_EXDEV: i32 = 18;
pub const LINUX_ENODEV: i32 = 19;
pub const LINUX_ENFILE: i32 = 23;
pub const LINUX_EMFILE: i32 = 24;
pub const LINUX_ETXTBSY: i32 = 26;
pub const LINUX_ENOSPC: i32 = 28;
pub const LINUX_EMLINK: i32 = 31;
pub const LINUX_EDOM: i32 = 33;
// ----- Linux SysV-style codes; macOS diverges -----
pub const LINUX_EDEADLK: i32 = 35;
pub const LINUX_ENOLCK: i32 = 37;
pub const LINUX_ELOOP: i32 = 40;
pub const LINUX_ENOMSG: i32 = 42;
pub const LINUX_EIDRM: i32 = 43;
pub const LINUX_ENOLINK: i32 = 67;
pub const LINUX_EBADMSG: i32 = 74;
pub const LINUX_EOVERFLOW: i32 = 75;
pub const LINUX_EILSEQ: i32 = 84;
pub const LINUX_EDESTADDRREQ: i32 = 89;
pub const LINUX_EMSGSIZE: i32 = 90;
pub const LINUX_EPROTOTYPE: i32 = 91;
pub const LINUX_EPROTONOSUPPORT: i32 = 93;
pub const LINUX_EOPNOTSUPP: i32 = 95; // ≡ ENOTSUP
pub const LINUX_EPFNOSUPPORT: i32 = 96;
pub const LINUX_EADDRINUSE: i32 = 98;
pub const LINUX_EADDRNOTAVAIL: i32 = 99;
pub const LINUX_ENETDOWN: i32 = 100;
pub const LINUX_ENETUNREACH: i32 = 101;
pub const LINUX_ENETRESET: i32 = 102;
pub const LINUX_ECONNABORTED: i32 = 103;
pub const LINUX_ECONNRESET: i32 = 104;
pub const LINUX_ENOBUFS: i32 = 105;
pub const LINUX_ENOTCONN: i32 = 107;
pub const LINUX_ESHUTDOWN: i32 = 108;
pub const LINUX_ETOOMANYREFS: i32 = 109;
pub const LINUX_ECONNREFUSED: i32 = 111;
pub const LINUX_EHOSTDOWN: i32 = 112;
pub const LINUX_EHOSTUNREACH: i32 = 113;
pub const LINUX_ESTALE: i32 = 116;
pub const LINUX_EUCLEAN: i32 = 117;
pub const LINUX_EREMOTE: i32 = 121;
pub const LINUX_EDQUOT: i32 = 122;
pub const LINUX_ECANCELED: i32 = 125;
// Linux setxattr(2) flags. Same semantics as the macOS XATTR_CREATE/
// XATTR_REPLACE options (which carry different numeric values).
pub const LINUX_XATTR_CREATE: i32 = 0x1;
pub const LINUX_XATTR_REPLACE: i32 = 0x2;
pub const LINUX_ETIMEDOUT: i32 = 110;

/// Map a Linux (aarch64 generic) errno number to its symbolic name, for
/// human-readable trace/diagnostic output. Returns None for unknown values.
/// Numbers follow asm-generic/errno{,-base}.h, which aarch64 uses verbatim.
pub fn errno_name(e: u32) -> Option<&'static str> {
    Some(match e as i32 {
        LINUX_EPERM => "EPERM",
        LINUX_ENOENT => "ENOENT",
        LINUX_ESRCH => "ESRCH",
        LINUX_EINTR => "EINTR",
        LINUX_EIO => "EIO",
        LINUX_ENXIO => "ENXIO",
        7 => "E2BIG",
        LINUX_ENOEXEC => "ENOEXEC",
        LINUX_EBADF => "EBADF",
        LINUX_ECHILD => "ECHILD",
        LINUX_EAGAIN => "EAGAIN",
        LINUX_ENOMEM => "ENOMEM",
        LINUX_EACCES => "EACCES",
        LINUX_EFAULT => "EFAULT",
        LINUX_ENOTBLK => "ENOTBLK",
        LINUX_EBUSY => "EBUSY",
        LINUX_EEXIST => "EEXIST",
        LINUX_EXDEV => "EXDEV",
        LINUX_ENODEV => "ENODEV",
        LINUX_ENOTDIR => "ENOTDIR",
        LINUX_EISDIR => "EISDIR",
        LINUX_EINVAL => "EINVAL",
        LINUX_ENFILE => "ENFILE",
        LINUX_EMFILE => "EMFILE",
        LINUX_ENOTTY => "ENOTTY",
        LINUX_ETXTBSY => "ETXTBSY",
        LINUX_EFBIG => "EFBIG",
        LINUX_ENOSPC => "ENOSPC",
        LINUX_ESPIPE => "ESPIPE",
        LINUX_EROFS => "EROFS",
        LINUX_EMLINK => "EMLINK",
        LINUX_EPIPE => "EPIPE",
        LINUX_EDOM => "EDOM",
        LINUX_ERANGE => "ERANGE",
        LINUX_EDEADLK => "EDEADLK",
        LINUX_ENAMETOOLONG => "ENAMETOOLONG",
        LINUX_ENOLCK => "ENOLCK",
        LINUX_ENOSYS => "ENOSYS",
        LINUX_ENOTEMPTY => "ENOTEMPTY",
        LINUX_ELOOP => "ELOOP",
        LINUX_ENOMSG => "ENOMSG",
        LINUX_EIDRM => "EIDRM",
        LINUX_ENODATA => "ENODATA",
        LINUX_ENOLINK => "ENOLINK",
        LINUX_EBADMSG => "EBADMSG",
        LINUX_EOVERFLOW => "EOVERFLOW",
        LINUX_EILSEQ => "EILSEQ",
        LINUX_ENOTSOCK => "ENOTSOCK",
        LINUX_EDESTADDRREQ => "EDESTADDRREQ",
        LINUX_EMSGSIZE => "EMSGSIZE",
        LINUX_EPROTOTYPE => "EPROTOTYPE",
        LINUX_ENOPROTOOPT => "ENOPROTOOPT",
        LINUX_EPROTONOSUPPORT => "EPROTONOSUPPORT",
        LINUX_ESOCKTNOSUPPORT => "ESOCKTNOSUPPORT",
        LINUX_EOPNOTSUPP => "EOPNOTSUPP",
        LINUX_EPFNOSUPPORT => "EPFNOSUPPORT",
        LINUX_EADDRINUSE => "EADDRINUSE",
        LINUX_EADDRNOTAVAIL => "EADDRNOTAVAIL",
        LINUX_ENETDOWN => "ENETDOWN",
        LINUX_ENETUNREACH => "ENETUNREACH",
        LINUX_ENETRESET => "ENETRESET",
        LINUX_ECONNABORTED => "ECONNABORTED",
        LINUX_ECONNRESET => "ECONNRESET",
        LINUX_ENOBUFS => "ENOBUFS",
        LINUX_EISCONN => "EISCONN",
        LINUX_ENOTCONN => "ENOTCONN",
        LINUX_ESHUTDOWN => "ESHUTDOWN",
        LINUX_ETOOMANYREFS => "ETOOMANYREFS",
        LINUX_ETIMEDOUT => "ETIMEDOUT",
        LINUX_ECONNREFUSED => "ECONNREFUSED",
        LINUX_EHOSTDOWN => "EHOSTDOWN",
        LINUX_EHOSTUNREACH => "EHOSTUNREACH",
        LINUX_EALREADY => "EALREADY",
        LINUX_EINPROGRESS => "EINPROGRESS",
        LINUX_ESTALE => "ESTALE",
        LINUX_EUCLEAN => "EUCLEAN",
        LINUX_EREMOTE => "EREMOTE",
        LINUX_EDQUOT => "EDQUOT",
        LINUX_ECANCELED => "ECANCELED",
        _ => return None,
    })
}
pub const LINUX_AT_FDCWD: u64 = (-100_i64) as u64;
pub const LINUX_AT_SYMLINK_NOFOLLOW: u64 = 0x100;
pub const LINUX_AT_SYMLINK_FOLLOW: u64 = 0x400;
pub const LINUX_AT_EACCESS: u64 = 0x200;
pub const LINUX_AT_EMPTY_PATH: u64 = 0x1000;
pub const LINUX_AT_REMOVEDIR: u64 = 0x200;
pub const LINUX_AT_NO_AUTOMOUNT: u64 = 0x800;
pub const LINUX_AT_STATX_FORCE_SYNC: u64 = 0x2000;
pub const LINUX_AT_STATX_DONT_SYNC: u64 = 0x4000;
pub const LINUX_UTIME_NOW: i64 = (1 << 30) - 1;
pub const LINUX_UTIME_OMIT: i64 = (1 << 30) - 2;
pub const LINUX_R_OK: u64 = 4;
pub const LINUX_W_OK: u64 = 2;
pub const LINUX_X_OK: u64 = 1;
pub const LINUX_F_DUPFD: u64 = 0;
pub const LINUX_F_GETFD: u64 = 1;
pub const LINUX_F_SETFD: u64 = 2;
pub const LINUX_F_GETFL: u64 = 3;
pub const LINUX_F_SETFL: u64 = 4;
pub const LINUX_F_GETLK: u64 = 5;
pub const LINUX_F_SETLK: u64 = 6;
pub const LINUX_F_SETLKW: u64 = 7;
pub const LINUX_F_OFD_GETLK: u64 = 36;
pub const LINUX_F_OFD_SETLK: u64 = 37;
pub const LINUX_F_OFD_SETLKW: u64 = 38;
pub const LINUX_F_SETLEASE: u64 = 1024;
pub const LINUX_F_GETLEASE: u64 = 1025;
/// fcntl lock/lease type args (also l_type in struct flock).
pub const LINUX_F_RDLCK: i32 = 0;
pub const LINUX_F_WRLCK: i32 = 1;
pub const LINUX_F_UNLCK: i32 = 2;
pub const LINUX_F_DUPFD_CLOEXEC: u64 = 1030;
pub const LINUX_F_GETPIPE_SZ: u64 = 1032;
pub const LINUX_F_ADD_SEALS: u64 = 1033;
pub const LINUX_F_GET_SEALS: u64 = 1034;
pub const LINUX_FD_CLOEXEC: u64 = 1;
pub const LINUX_SEEK_SET: u64 = 0;
pub const LINUX_SEEK_CUR: u64 = 1;
pub const LINUX_SEEK_END: u64 = 2;
pub const LINUX_O_ACCMODE: u64 = 0b11;
pub const LINUX_O_RDONLY: u64 = 0;
pub const LINUX_O_WRONLY: u64 = 1;
pub const LINUX_O_RDWR: u64 = 2;
pub const LINUX_O_NONBLOCK: u64 = 0o4000;
pub const LINUX_O_CLOEXEC: u64 = 0o2000000;
pub const LINUX_O_CREAT: u64 = 0o100;
pub const LINUX_O_EXCL: u64 = 0o200;
pub const LINUX_O_TRUNC: u64 = 0o1000;
pub const LINUX_O_APPEND: u64 = 0o2000;
// aarch64 fcntl flag values (asm-generic): O_DIRECTORY=0o40000,
// O_NOFOLLOW=0o100000, O_DIRECT=0o200000, O_LARGEFILE=0o400000. carrick had
// O_DIRECTORY/O_DIRECT swapped (and O_NOFOLLOW wrong), so O_DIRECTORY never
// triggered the directory-required path and an O_DIRECT open was mistaken for
// it. Verified against a real aarch64-musl binary.
pub const LINUX_O_DIRECTORY: u64 = 0o40000;
pub const LINUX_O_NOFOLLOW: u64 = 0o100000;
/// `__O_TMPFILE` — the distinguishing bit of `O_TMPFILE` (which is
/// `__O_TMPFILE | O_DIRECTORY`). The `pathname` names the parent directory and
/// the kernel returns an unnamed regular file in it.
pub const LINUX_O_TMPFILE: u64 = 0o20000000;
pub const LINUX_PROT_READ: u64 = 0x1;
pub const LINUX_PROT_WRITE: u64 = 0x2;
pub const LINUX_PROT_EXEC: u64 = 0x4;
pub const LINUX_MAP_SHARED: u64 = 0x01;
pub const LINUX_MAP_PRIVATE: u64 = 0x02;
pub const LINUX_MAP_FIXED: u64 = 0x10;
pub const LINUX_MAP_ANONYMOUS: u64 = 0x20;
// Advisory mmap flags. On Linux these are placement/swap/perf hints that the
// kernel honours best-effort and that do not change the observable *contents*
// of an anonymous or file mapping; software relies on the kernel accepting
// them rather than failing. carrick accepts them and treats them as no-ops
// (see `LINUX_MAP_HINT_MASK`).
pub const LINUX_MAP_GROWSDOWN: u64 = 0x0100;
pub const LINUX_MAP_DENYWRITE: u64 = 0x0800;
pub const LINUX_MAP_EXECUTABLE: u64 = 0x1000;
pub const LINUX_MAP_LOCKED: u64 = 0x2000;
pub const LINUX_MAP_NORESERVE: u64 = 0x4000;
pub const LINUX_MAP_POPULATE: u64 = 0x8000;
pub const LINUX_MAP_NONBLOCK: u64 = 0x1_0000;
pub const LINUX_MAP_STACK: u64 = 0x2_0000;
pub const LINUX_MAP_HUGETLB: u64 = 0x4_0000;
/// `MAP_FIXED_NOREPLACE`: like `MAP_FIXED` but the kernel refuses (EEXIST) to
/// clobber an existing mapping. carrick honours the requested address exactly
/// as it does for `MAP_FIXED` (the bootstrap FIXED path never clobbers an
/// existing stage-2 mapping — it returns the address and relies on a
/// pre-existing mapping or an on-access fault), so it is normalised to
/// `MAP_FIXED` at dispatch.
pub const LINUX_MAP_FIXED_NOREPLACE: u64 = 0x10_0000;
/// Advisory hint flags carrick accepts and ignores (no observable effect on
/// the mapping's contents): stack/grows-down placement, swap reservation,
/// prefault, page-locking and huge-page hints. Rust std's stack-overflow
/// guard maps `MAP_STACK`, the Go runtime maps `MAP_STACK|MAP_NORESERVE`, and
/// glibc uses `MAP_DENYWRITE|MAP_EXECUTABLE` — all previously rejected with a
/// spurious EINVAL.
pub const LINUX_MAP_HINT_MASK: u64 = LINUX_MAP_GROWSDOWN
    | LINUX_MAP_DENYWRITE
    | LINUX_MAP_EXECUTABLE
    | LINUX_MAP_LOCKED
    | LINUX_MAP_NORESERVE
    | LINUX_MAP_POPULATE
    | LINUX_MAP_NONBLOCK
    | LINUX_MAP_STACK
    | LINUX_MAP_HUGETLB;
pub const LINUX_MADV_NORMAL: u64 = 0;
pub const LINUX_MADV_RANDOM: u64 = 1;
pub const LINUX_MADV_SEQUENTIAL: u64 = 2;
pub const LINUX_MADV_WILLNEED: u64 = 3;
pub const LINUX_MADV_DONTNEED: u64 = 4;
pub const LINUX_MADV_FREE: u64 = 8;
// Transparent-huge-page advisory hints. carrick presents 4 KiB guest pages and
// cannot promote a range to a huge page, but these advices are purely advisory:
// real Linux returns 0 for them whenever THP is built in (the common
// `always`/`madvise` modes), so accepting them as a success no-op matches the
// kernel and keeps allocators (Go runtime, jemalloc, glibc) from treating a
// spurious EINVAL as a hard error.
pub const LINUX_MADV_HUGEPAGE: u64 = 14;
pub const LINUX_MADV_NOHUGEPAGE: u64 = 15;
pub const LINUX_MADV_COLLAPSE: u64 = 25;
pub const LINUX_MREMAP_MAYMOVE: u64 = 0x01;
pub const LINUX_MREMAP_FIXED: u64 = 0x02;
pub const LINUX_MREMAP_DONTUNMAP: u64 = 0x04;
pub const LINUX_MS_ASYNC: u64 = 0x01;
pub const LINUX_MS_INVALIDATE: u64 = 0x02;
pub const LINUX_MS_SYNC: u64 = 0x04;
pub const LINUX_MCL_CURRENT: u64 = 0x01;
pub const LINUX_MCL_FUTURE: u64 = 0x02;
pub const LINUX_MCL_ONFAULT: u64 = 0x04;
pub const LINUX_PRIO_PROCESS: u64 = 0;
pub const LINUX_PRIO_PGRP: u64 = 1;
pub const LINUX_PRIO_USER: u64 = 2;
pub const LINUX_DEFAULT_UMASK: u32 = 0o022;
pub const LINUX_RLIM_INFINITY: u64 = u64::MAX;
pub const LINUX_RUSAGE_SELF: i32 = 0;
pub const LINUX_RUSAGE_CHILDREN: i32 = -1;
pub const LINUX_RUSAGE_THREAD: i32 = 1;
pub const LINUX_CLK_TCK: i64 = 100;
pub const LINUX_OVERLAYFS_SUPER_MAGIC: i64 = 0x794c7630;
pub const LINUX_EAFNOSUPPORT: i32 = 97;

// ===== ABI constants moved from dispatch.rs (Goal #3, private set, now pub) =====
pub const LINUX_EFD_SEMAPHORE: u64 = 0x1;
pub const LINUX_EFD_NONBLOCK: u64 = LINUX_O_NONBLOCK;
pub const LINUX_EFD_CLOEXEC: u64 = LINUX_O_CLOEXEC;
pub const LINUX_EPOLL_CLOEXEC: u64 = LINUX_O_CLOEXEC;
pub const LINUX_EPOLL_CTL_ADD: u64 = 1;
pub const LINUX_EPOLL_CTL_DEL: u64 = 2;
pub const LINUX_EPOLL_CTL_MOD: u64 = 3;
pub const LINUX_EPOLLIN: u32 = 0x001;
pub const LINUX_EPOLLPRI: u32 = 0x002;
pub const LINUX_EPOLLOUT: u32 = 0x004;
pub const LINUX_EPOLLERR: u32 = 0x008;
pub const LINUX_EPOLLHUP: u32 = 0x010;
pub const LINUX_EPOLLRDHUP: u32 = 0x2000;
pub const LINUX_EPOLLET: u32 = 0x8000_0000;
pub const LINUX_EPOLLONESHOT: u32 = 0x4000_0000;
pub const LINUX_EPOLLEXCLUSIVE: u32 = 0x1000_0000;
pub const LINUX_LOCK_SH: u64 = 1;
pub const LINUX_LOCK_EX: u64 = 2;
pub const LINUX_LOCK_NB: u64 = 4;
pub const LINUX_LOCK_UN: u64 = 8;
pub const LINUX_POLLIN: i16 = 0x0001;
pub const LINUX_POLLOUT: i16 = 0x0004;
pub const LINUX_POLLERR: i16 = 0x0008;
pub const LINUX_POLLHUP: i16 = 0x0010;
pub const LINUX_POLLNVAL: i16 = 0x0020;
pub const LINUX_TFD_NONBLOCK: u64 = LINUX_O_NONBLOCK;
pub const LINUX_TFD_CLOEXEC: u64 = LINUX_O_CLOEXEC;
pub const LINUX_TIMER_ABSTIME: u64 = 0x1;
pub const LINUX_SPLICE_F_MOVE: u64 = 0x1;
pub const LINUX_SPLICE_F_NONBLOCK: u64 = 0x2;
pub const LINUX_SPLICE_F_MORE: u64 = 0x4;
pub const LINUX_SPLICE_F_GIFT: u64 = 0x8;
pub const LINUX_SPLICE_SUPPORTED_FLAGS: u64 =
    LINUX_SPLICE_F_MOVE | LINUX_SPLICE_F_NONBLOCK | LINUX_SPLICE_F_MORE | LINUX_SPLICE_F_GIFT;
pub const LINUX_FUTEX_WAIT: u64 = 0;
pub const LINUX_FUTEX_WAKE: u64 = 1;
pub const LINUX_FUTEX_REQUEUE: u64 = 3;
pub const LINUX_FUTEX_CMP_REQUEUE: u64 = 4;
pub const LINUX_FUTEX_CMD_MASK: u64 = 0x7f;
pub const LINUX_FUTEX_PRIVATE_FLAG: u64 = 128;
pub const LINUX_FUTEX_CLOCK_REALTIME: u64 = 256;
pub const LINUX_MEMBARRIER_CMD_QUERY: u64 = 0;
pub const LINUX_TCGETS: u64 = 0x5401;
pub const LINUX_TCSETS: u64 = 0x5402;
pub const LINUX_TCSETSW: u64 = 0x5403;
pub const LINUX_TCSETSF: u64 = 0x5404;
pub const LINUX_TIOCSCTTY: u64 = 0x540E;
pub const LINUX_TIOCGPGRP: u64 = 0x540F;
pub const LINUX_TIOCSPGRP: u64 = 0x5410;
pub const LINUX_TIOCGWINSZ: u64 = 0x5413;
pub const LINUX_TIOCSWINSZ: u64 = 0x5414;
pub const LINUX_TIOCGPTN: u64 = 0x8004_5430;
pub const LINUX_TIOCSPTLCK: u64 = 0x4004_5431;
pub const LINUX_FIONREAD: u64 = 0x541B;
pub const LINUX_FIONBIO: u64 = 0x5421;
pub const LINUX_TIOCNOTTY: u64 = 0x5422;
pub const LINUX_TIOCGSID: u64 = 0x5429;
pub const LINUX_BOOTSTRAP_PGID: i32 = 1;
pub const LINUX_BOOTSTRAP_SID: i32 = 1;
pub const LINUX_PIPE_BUF_SIZE: i64 = 65_536;
pub const LINUX_RT_SIGSET_SIZE: u64 = 8;
pub const LINUX_MAX_SIGNUM: u64 = 64;
pub const LINUX_SIGKILL: i32 = 9;
pub const LINUX_SIGSTOP: i32 = 19;
/// Signals whose DEFAULT disposition is "ignore" (Linux `man 7 signal`: the
/// `Ign` action) — SIGCHLD, SIGURG, SIGWINCH. A no-handler instance of these is
/// silently dropped, NOT a terminating default action. (aarch64/generic nums.)
pub const LINUX_SIGCHLD: i32 = 17;
pub const LINUX_SIGURG: i32 = 23;
pub const LINUX_SIGWINCH: i32 = 28;
/// Timer-expiry signals: ITIMER_REAL→SIGALRM, ITIMER_VIRTUAL→SIGVTALRM,
/// ITIMER_PROF→SIGPROF (aarch64/generic numbering).
pub const LINUX_SIGALRM: i32 = 14;
pub const LINUX_SIGVTALRM: i32 = 26;
pub const LINUX_SIGPROF: i32 = 27;
/// `how` argument values for `rt_sigprocmask`.
pub const LINUX_SIG_BLOCK: u64 = 0;
pub const LINUX_SIG_UNBLOCK: u64 = 1;
pub const LINUX_SIG_SETMASK: u64 = 2;
pub const LINUX_BOOTSTRAP_PID: u64 = 1;
pub const LINUX_SS_ONSTACK: u64 = 1;
pub const LINUX_SS_DISABLE: u64 = 2;
pub const LINUX_MINSIGSTKSZ: u64 = 2048;
pub const LINUX_CLOCK_REALTIME: u64 = 0;
pub const LINUX_CLOCK_MONOTONIC: u64 = 1;
pub const LINUX_CLOCK_PROCESS_CPUTIME_ID: u64 = 2;
pub const LINUX_CLOCK_THREAD_CPUTIME_ID: u64 = 3;
pub const LINUX_CLOCK_MONOTONIC_RAW: u64 = 4;
pub const LINUX_CLOCK_REALTIME_COARSE: u64 = 5;
pub const LINUX_CLOCK_MONOTONIC_COARSE: u64 = 6;
pub const LINUX_CLOCK_BOOTTIME: u64 = 7;
pub const LINUX_CLOCK_REALTIME_ALARM: u64 = 8;
pub const LINUX_CLOCK_BOOTTIME_ALARM: u64 = 9;
pub const LINUX_CLOCK_TAI: u64 = 11;
pub const LINUX_CLOCK_RESOLUTION_NSEC: i64 = 1_000_000;
pub const LINUX_ITIMER_REAL: u64 = 0;
pub const LINUX_ITIMER_VIRTUAL: u64 = 1;
pub const LINUX_ITIMER_PROF: u64 = 2;
pub const LINUX_TASK_COMM_LEN: usize = 16;
pub const LINUX_CAPABILITY_VERSION_1: u32 = 0x1998_0330;
pub const LINUX_CAPABILITY_VERSION_2: u32 = 0x2007_1026;
pub const LINUX_CAPABILITY_VERSION_3: u32 = 0x2008_0522;
pub const LINUX_PERSONALITY_QUERY: u64 = 0xffff_ffff;
pub const LINUX_PR_SET_PDEATHSIG: u64 = 1;
pub const LINUX_PR_GET_PDEATHSIG: u64 = 2;
pub const LINUX_PR_GET_DUMPABLE: u64 = 3;
pub const LINUX_PR_SET_DUMPABLE: u64 = 4;
pub const LINUX_PR_SET_NAME: u64 = 15;
pub const LINUX_PR_GET_NAME: u64 = 16;
/// `prctl(PR_GET_MEM_MODEL, …)` / `prctl(PR_SET_MEM_MODEL, …)` — query or set
/// the CPU memory-ordering model. Apple Rosetta 2 issues
/// `PR_SET_MEM_MODEL(PR_SET_MEM_MODEL_TSO)` at startup to request hardware
/// x86_64 TSO ordering. These are the magic ASCII ("mMDL"/"MMDL") option values
/// from the Apple-Silicon/Asahi downstream kernel ABI that Apple's Rosetta was
/// built against — NOT small integers (the spec's "70/71" guess collides with
/// upstream PR_RISCV_V_* / PR_SET_MEMORY_CONSISTENCY_MODEL).
pub const LINUX_PR_GET_MEM_MODEL: u64 = 0x6d4d444c;
pub const LINUX_PR_SET_MEM_MODEL: u64 = 0x4d4d444c;
/// `arg2` values for PR_SET_MEM_MODEL.
pub const LINUX_PR_SET_MEM_MODEL_DEFAULT: u64 = 0;
pub const LINUX_PR_SET_MEM_MODEL_TSO: u64 = 1;
pub const LINUX_P_ALL: u64 = 0;
pub const LINUX_P_PID: u64 = 1;
pub const LINUX_P_PGID: u64 = 2;
pub const LINUX_P_PIDFD: u64 = 3;
pub const LINUX_WNOHANG: u64 = 1;
pub const LINUX_WUNTRACED: u64 = 2;
pub const LINUX_WSTOPPED: u64 = 2;
pub const LINUX_WEXITED: u64 = 4;
pub const LINUX_WCONTINUED: u64 = 8;
pub const LINUX_WNOWAIT: u64 = 0x0100_0000;
pub const LINUX_WAITID_STATE_MASK: u64 = LINUX_WEXITED | LINUX_WSTOPPED | LINUX_WCONTINUED;
pub const LINUX_WAITID_SUPPORTED_FLAGS: u64 =
    LINUX_WAITID_STATE_MASK | LINUX_WNOHANG | LINUX_WNOWAIT;
pub const LINUX_WCLONE: u64 = 0x8000_0000;
pub const LINUX_WALL: u64 = 0x4000_0000;
pub const LINUX_WNOTHREAD: u64 = 0x2000_0000;
pub const LINUX_WAIT4_SUPPORTED_FLAGS: u64 = LINUX_WNOHANG
    | LINUX_WUNTRACED
    | LINUX_WCONTINUED
    | LINUX_WCLONE
    | LINUX_WALL
    | LINUX_WNOTHREAD;
pub const LINUX_STATX_BASIC_STATS: u32 = 0x7ff;
pub const LINUX_STATX_RESERVED: u64 = 0x8000_0000;
pub const LINUX_IOV_MAX: usize = 1024;
pub const LINUX_OPEN_HOW_SIZE: u64 = core::mem::size_of::<LinuxOpenHow>() as u64;
/// Linux AF_* values for the families we support. Linux constants happen
/// to overlap with macOS's only for AF_UNSPEC / AF_UNIX / AF_INET — the
/// AF_INET6 numeric value differs (Linux: 10, macOS: 30).
pub const LINUX_AF_UNSPEC: i32 = 0;
pub const LINUX_AF_UNIX: i32 = 1;
pub const LINUX_AF_INET: i32 = 2;
pub const LINUX_AF_INET6: i32 = 10;
pub const LINUX_AF_NETLINK: i32 = 16;
pub const LINUX_AF_PACKET: i32 = 17;
pub const LINUX_SOCK_STREAM: i32 = 1;
pub const LINUX_SOCK_DGRAM: i32 = 2;
pub const LINUX_SOCK_RAW: i32 = 3;
pub const LINUX_SOCK_SEQPACKET: i32 = 5;

pub const LINUX_CLONE_VM: u64 = 0x0000_0100;
pub const LINUX_CLONE_FS: u64 = 0x0000_0200;
pub const LINUX_CLONE_FILES: u64 = 0x0000_0400;
pub const LINUX_CLONE_SIGHAND: u64 = 0x0000_0800;
pub const LINUX_CLONE_THREAD: u64 = 0x0001_0000;
pub const LINUX_CLONE_SETTLS: u64 = 0x0008_0000;
pub const LINUX_CLONE_PARENT_SETTID: u64 = 0x0010_0000;
pub const LINUX_CLONE_CHILD_CLEARTID: u64 = 0x0020_0000;
pub const LINUX_CLONE_CHILD_SETTID: u64 = 0x0100_0000;

bitflags! {
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct LinuxOpenFlags: u64 {
        const CREAT = LINUX_O_CREAT;
        const EXCL = LINUX_O_EXCL;
        const NOCTTY = 0o400;
        const TRUNC = LINUX_O_TRUNC;
        const APPEND = LINUX_O_APPEND;
        const NONBLOCK = LINUX_O_NONBLOCK;
        const DSYNC = 0o10000;
        const ASYNC = 0o20000;
        const DIRECT = 0o200000;
        const LARGEFILE = 0o400000;
        const DIRECTORY = LINUX_O_DIRECTORY;
        const NOFOLLOW = LINUX_O_NOFOLLOW;
        const NOATIME = 0o1000000;
        const CLOEXEC = LINUX_O_CLOEXEC;
        const SYNC = 0o4010000;
        const PATH = 0o010000000;
        const TMPFILE = 0o020000000;
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct LinuxAtFlags: u64 {
        const SYMLINK_NOFOLLOW = LINUX_AT_SYMLINK_NOFOLLOW;
        const EACCESS = LINUX_AT_EACCESS;
        const REMOVEDIR = LINUX_AT_REMOVEDIR;
        const NO_AUTOMOUNT = LINUX_AT_NO_AUTOMOUNT;
        const EMPTY_PATH = LINUX_AT_EMPTY_PATH;
        const STATX_FORCE_SYNC = LINUX_AT_STATX_FORCE_SYNC;
        const STATX_DONT_SYNC = LINUX_AT_STATX_DONT_SYNC;
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct LinuxMmapFlags: u64 {
        const SHARED = LINUX_MAP_SHARED;
        const PRIVATE = LINUX_MAP_PRIVATE;
        const FIXED = LINUX_MAP_FIXED;
        const ANONYMOUS = LINUX_MAP_ANONYMOUS;
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct LinuxFutexFlags: u64 {
        const PRIVATE = LINUX_FUTEX_PRIVATE_FLAG;
        const CLOCK_REALTIME = LINUX_FUTEX_CLOCK_REALTIME;
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct LinuxCloneFlags: u64 {
        const VM = LINUX_CLONE_VM;
        const FS = LINUX_CLONE_FS;
        const FILES = LINUX_CLONE_FILES;
        const SIGHAND = LINUX_CLONE_SIGHAND;
        /// Allocate a pidfd for the child. Legacy clone(2) returns it via the
        /// parent_tid pointer (arg2); clone3 via clone_args.pidfd.
        const PIDFD = 0x0000_1000;
        const THREAD = LINUX_CLONE_THREAD;
        const SETTLS = LINUX_CLONE_SETTLS;
        const PARENT_SETTID = LINUX_CLONE_PARENT_SETTID;
        const CHILD_CLEARTID = LINUX_CLONE_CHILD_CLEARTID;
        const CHILD_SETTID = LINUX_CLONE_CHILD_SETTID;
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct LinuxSocketTypeFlags: i32 {
        const NONBLOCK = LINUX_SOCK_NONBLOCK;
        const CLOEXEC = LINUX_SOCK_CLOEXEC;
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct LinuxFdFlags: u64 {
        const CLOEXEC = LINUX_FD_CLOEXEC;
    }
}

impl LinuxOpenFlags {
    pub const SUPPORTED_MASK: u64 = LINUX_O_ACCMODE | Self::all().bits();
}

impl LinuxAtFlags {
    pub const STATX_SYNC_AS_STAT: u64 = 0x800;
    pub const STATX_SUPPORTED_MASK: u64 = Self::EMPTY_PATH.bits()
        | Self::SYMLINK_NOFOLLOW.bits()
        | Self::NO_AUTOMOUNT.bits()
        | Self::STATX_SYNC_AS_STAT
        | Self::STATX_FORCE_SYNC.bits()
        | Self::STATX_DONT_SYNC.bits()
        | 0x6000;
}

impl LinuxMmapFlags {
    pub const SUPPORTED_MASK: u64 = Self::SHARED.bits()
        | Self::PRIVATE.bits()
        | Self::FIXED.bits()
        | Self::ANONYMOUS.bits()
        | LINUX_MAP_HINT_MASK
        | LINUX_MAP_FIXED_NOREPLACE;
}

impl LinuxFutexFlags {
    pub const SUPPORTED_MASK: u64 = Self::PRIVATE.bits() | Self::CLOCK_REALTIME.bits();
}

impl LinuxCloneFlags {
    pub const THREAD_MASK: u64 = Self::VM.bits()
        | Self::FS.bits()
        | Self::FILES.bits()
        | Self::SIGHAND.bits()
        | Self::THREAD.bits();
}

impl LinuxSocketTypeFlags {
    pub const SUPPORTED_MASK: i32 = Self::NONBLOCK.bits() | Self::CLOEXEC.bits();
}

pub const LINUX_SOCKET_TYPE_SUPPORTED_MASK: u64 = LinuxSocketTypeFlags::SUPPORTED_MASK as u64
    | LINUX_SOCK_STREAM as u64
    | LINUX_SOCK_DGRAM as u64
    | LINUX_SOCK_RAW as u64
    | LINUX_SOCK_SEQPACKET as u64;

pub const LINUX_MSG_OOB: i32 = 0x0001;
pub const LINUX_MSG_PEEK: i32 = 0x0002;
pub const LINUX_MSG_DONTROUTE: i32 = 0x0004;
pub const LINUX_MSG_TRUNC: i32 = 0x0020;
pub const LINUX_MSG_DONTWAIT: i32 = 0x0040;
pub const LINUX_MSG_EOR: i32 = 0x0080;
pub const LINUX_MSG_CTRUNC: i32 = 0x0008;
pub const LINUX_MSG_WAITALL: i32 = 0x0100;
pub const LINUX_MSG_NOSIGNAL: i32 = 0x4000;
pub const LINUX_MSG_CMSG_CLOEXEC: i32 = 0x4000_0000_u32 as i32;
// Linux socket option levels and names. Linux numbers them as small
// integers (SOL_SOCKET=1) while macOS reuses the IPPROTO/SO scheme
// (SOL_SOCKET=0xffff). We translate explicitly for the most common
// options the guest will throw at us. Anything we don't recognise
// returns `None` and the caller surfaces ENOPROTOOPT.
pub const LINUX_SOL_SOCKET: i32 = 1;
pub const LINUX_SOL_IP: i32 = 0; // IPPROTO_IP
pub const LINUX_SOL_TCP: i32 = 6; // IPPROTO_TCP
pub const LINUX_SOL_UDP: i32 = 17; // IPPROTO_UDP
pub const LINUX_SOL_IPV6: i32 = 41; // IPPROTO_IPV6

// IPPROTO_IP / IPPROTO_IPV6 option numbers differ from macOS, so they must be
// translated (not passed through). Linux uapi values (include/uapi/linux/in.h,
// in6.h):
pub const LINUX_IP_TOS: i32 = 1;
pub const LINUX_IP_TTL: i32 = 2;
pub const LINUX_IP_HDRINCL: i32 = 3;
pub const LINUX_IP_OPTIONS: i32 = 4;
pub const LINUX_IP_RECVTOS: i32 = 13;
pub const LINUX_IP_RECVTTL: i32 = 12;
pub const LINUX_IP_PKTINFO: i32 = 8;
pub const LINUX_IP_MULTICAST_IF: i32 = 32;
pub const LINUX_IP_MULTICAST_TTL: i32 = 33;
pub const LINUX_IP_MULTICAST_LOOP: i32 = 34;
pub const LINUX_IP_ADD_MEMBERSHIP: i32 = 35;
pub const LINUX_IP_DROP_MEMBERSHIP: i32 = 36;

pub const LINUX_IPV6_UNICAST_HOPS: i32 = 16;
pub const LINUX_IPV6_MULTICAST_IF: i32 = 17;
pub const LINUX_IPV6_MULTICAST_HOPS: i32 = 18;
pub const LINUX_IPV6_MULTICAST_LOOP: i32 = 19;
pub const LINUX_IPV6_JOIN_GROUP: i32 = 20;
pub const LINUX_IPV6_LEAVE_GROUP: i32 = 21;
pub const LINUX_IPV6_V6ONLY: i32 = 26;
pub const LINUX_IPV6_RECVPKTINFO: i32 = 49;
pub const LINUX_IPV6_PKTINFO: i32 = 50;
pub const LINUX_IPV6_RECVHOPLIMIT: i32 = 51;
pub const LINUX_IPV6_HOPLIMIT: i32 = 52;
pub const LINUX_IPV6_RECVTCLASS: i32 = 66;
pub const LINUX_IPV6_TCLASS: i32 = 67;

pub const LINUX_TCP_NODELAY: i32 = 1;
pub const LINUX_TCP_MAXSEG: i32 = 2;
pub const LINUX_TCP_CORK: i32 = 3;
pub const LINUX_TCP_KEEPIDLE: i32 = 4;
pub const LINUX_TCP_KEEPINTVL: i32 = 5;
pub const LINUX_TCP_KEEPCNT: i32 = 6;

pub const LINUX_SO_DEBUG: i32 = 1;
pub const LINUX_SO_REUSEADDR: i32 = 2;
pub const LINUX_SO_TYPE: i32 = 3;
pub const LINUX_SO_ERROR: i32 = 4;
pub const LINUX_SO_DONTROUTE: i32 = 5;
pub const LINUX_SO_BROADCAST: i32 = 6;
pub const LINUX_SO_SNDBUF: i32 = 7;
pub const LINUX_SO_RCVBUF: i32 = 8;
pub const LINUX_SO_KEEPALIVE: i32 = 9;
pub const LINUX_SO_OOBINLINE: i32 = 10;
pub const LINUX_SO_LINGER: i32 = 13;
pub const LINUX_SO_REUSEPORT: i32 = 15;
pub const LINUX_SO_PEERCRED: i32 = 17;
pub const LINUX_SO_RCVTIMEO: i32 = 20;
pub const LINUX_SO_SNDTIMEO: i32 = 21;
pub const LINUX_SO_ACCEPTCONN: i32 = 30;

/// Wire size of Linux `struct ucred { pid_t pid; uid_t uid; gid_t gid; }`
/// (three u32s). What `getsockopt(SOL_SOCKET, SO_PEERCRED)` returns.
pub const LINUX_UCRED_SIZE: usize = 12;

// ===== io_uring (WS-H4-B1) =====
// The submission/completion-queue-entry ABI is fixed (the guest fills SQEs and
// reads CQEs), so these structs must match the kernel byte-for-byte. The ring
// region offsets are flexible — carrick reports its own layout via the
// io_sqring/io_cqring offsets in io_uring_params.

/// `struct io_uring_sqe` — a 64-byte submission-queue entry. The kernel uses
/// unions for several fields; we flatten to the members carrick's phase-1
/// opcodes touch (`off`/`addr`/`len`/`op_flags` cover the rw + fsync ops).
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, FromBytes, IntoBytes, KnownLayout, Immutable)]
pub struct LinuxIoUringSqe {
    pub opcode: u8,
    pub flags: u8,
    pub ioprio: u16,
    pub fd: i32,
    pub off: u64,  // union: off / addr2
    pub addr: u64, // union: addr / splice_off_in
    pub len: u32,
    pub op_flags: u32, // union: rw_flags / fsync_flags / poll_events / …
    pub user_data: u64,
    pub buf_index: u16, // union: buf_index / buf_group
    pub personality: u16,
    pub splice_fd_in: i32, // union: splice_fd_in / file_index
    pub pad2: [u64; 2],
}

/// `struct io_uring_cqe` — a 16-byte completion-queue entry.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, FromBytes, IntoBytes, KnownLayout, Immutable)]
pub struct LinuxIoUringCqe {
    pub user_data: u64,
    pub res: i32,
    pub flags: u32,
}

/// `struct io_sqring_offsets` — where each SQ-ring field sits in the mmapped
/// SQ region, reported back to the guest by `io_uring_setup`.
#[repr(C)]
#[derive(
    Debug, Clone, Copy, Default, PartialEq, Eq, FromBytes, IntoBytes, KnownLayout, Immutable,
)]
pub struct LinuxIoSqringOffsets {
    pub head: u32,
    pub tail: u32,
    pub ring_mask: u32,
    pub ring_entries: u32,
    pub flags: u32,
    pub dropped: u32,
    pub array: u32,
    pub resv1: u32,
    pub resv2: u64,
}

/// `struct io_cqring_offsets`.
#[repr(C)]
#[derive(
    Debug, Clone, Copy, Default, PartialEq, Eq, FromBytes, IntoBytes, KnownLayout, Immutable,
)]
pub struct LinuxIoCqringOffsets {
    pub head: u32,
    pub tail: u32,
    pub ring_mask: u32,
    pub ring_entries: u32,
    pub overflow: u32,
    pub cqes: u32,
    pub flags: u32,
    pub resv1: u32,
    pub resv2: u64,
}

/// `struct io_uring_params` — in/out argument of `io_uring_setup`.
#[repr(C)]
#[derive(
    Debug, Clone, Copy, Default, PartialEq, Eq, FromBytes, IntoBytes, KnownLayout, Immutable,
)]
pub struct LinuxIoUringParams {
    pub sq_entries: u32,
    pub cq_entries: u32,
    pub flags: u32,
    pub sq_thread_cpu: u32,
    pub sq_thread_idle: u32,
    pub features: u32,
    pub wq_fd: u32,
    pub resv: [u32; 3],
    pub sq_off: LinuxIoSqringOffsets,
    pub cq_off: LinuxIoCqringOffsets,
}

// io_uring opcodes (subset carrick phase 1 services; others → CQE -EINVAL).
pub const LINUX_IORING_OP_NOP: u8 = 0;
pub const LINUX_IORING_OP_READV: u8 = 1;
pub const LINUX_IORING_OP_WRITEV: u8 = 2;
pub const LINUX_IORING_OP_FSYNC: u8 = 3;
pub const LINUX_IORING_OP_READ: u8 = 22;
pub const LINUX_IORING_OP_WRITE: u8 = 23;
pub const LINUX_IORING_OP_CLOSE: u8 = 19;
// Async (readiness-driven) ops — serviced via the kqueue/ThreadWaiter wait path.
pub const LINUX_IORING_OP_POLL_ADD: u8 = 6;
pub const LINUX_IORING_OP_ACCEPT: u8 = 13;
pub const LINUX_IORING_OP_CONNECT: u8 = 16;
pub const LINUX_IORING_OP_SENDMSG: u8 = 9;
pub const LINUX_IORING_OP_RECVMSG: u8 = 10;
pub const LINUX_IORING_OP_SEND: u8 = 26;
pub const LINUX_IORING_OP_RECV: u8 = 27;

// io_uring_enter `flags` bits Linux defines (uapi <linux/io_uring.h>). Any flag
// bit outside FLAGS_MASK is rejected with EINVAL at syscall entry. (audit M4)
pub const LINUX_IORING_ENTER_GETEVENTS: u32 = 1 << 0;
pub const LINUX_IORING_ENTER_SQ_WAKEUP: u32 = 1 << 1;
pub const LINUX_IORING_ENTER_SQ_WAIT: u32 = 1 << 2;
pub const LINUX_IORING_ENTER_EXT_ARG: u32 = 1 << 3;
pub const LINUX_IORING_ENTER_REGISTERED_RING: u32 = 1 << 4;
pub const LINUX_IORING_ENTER_ABS_TIMER: u32 = 1 << 5;
pub const LINUX_IORING_ENTER_EXT_ARG_REG: u32 = 1 << 6;
pub const LINUX_IORING_ENTER_FLAGS_MASK: u32 = LINUX_IORING_ENTER_GETEVENTS
    | LINUX_IORING_ENTER_SQ_WAKEUP
    | LINUX_IORING_ENTER_SQ_WAIT
    | LINUX_IORING_ENTER_EXT_ARG
    | LINUX_IORING_ENTER_REGISTERED_RING
    | LINUX_IORING_ENTER_ABS_TIMER
    | LINUX_IORING_ENTER_EXT_ARG_REG;

// mmap offsets the guest passes to map each ring region off the io_uring fd.
pub const LINUX_IORING_OFF_SQ_RING: u64 = 0;
pub const LINUX_IORING_OFF_CQ_RING: u64 = 0x0800_0000;
pub const LINUX_IORING_OFF_SQES: u64 = 0x1000_0000;

// io_uring_params.features bits carrick advertises.
pub const LINUX_IORING_FEAT_SINGLE_MMAP: u32 = 1 << 0;
pub const LINUX_IORING_FEAT_NODROP: u32 = 1 << 1;

#[cfg(test)]
mod kernel_abi_tests {
    use super::*;

    #[test]
    fn io_uring_struct_sizes_match_kernel_abi() {
        // The guest fills SQEs and reads CQEs/params at these exact sizes; a
        // mismatch silently corrupts the ring. (Linux: sqe 64, cqe 16,
        // sqring/cqring offsets 40, params 120.)
        assert_eq!(core::mem::size_of::<LinuxIoUringSqe>(), 64);
        assert_eq!(core::mem::size_of::<LinuxIoUringCqe>(), 16);
        assert_eq!(core::mem::size_of::<LinuxIoSqringOffsets>(), 40);
        assert_eq!(core::mem::size_of::<LinuxIoCqringOffsets>(), 40);
        assert_eq!(core::mem::size_of::<LinuxIoUringParams>(), 120);
    }

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
        assert!(
            <LinuxSigaltstack as KernelAbi>::ABI_SIZE <= core::mem::size_of::<LinuxSigaltstack>()
        );
        assert!(<LinuxSigaction as KernelAbi>::ABI_SIZE <= core::mem::size_of::<LinuxSigaction>());
    }

    #[test]
    fn message_and_clone_abi_structs_match_aarch64_layouts() {
        assert_eq!(core::mem::size_of::<LinuxMsghdr>(), 56);
        assert_eq!(<LinuxMsghdr as KernelAbi>::ABI_SIZE, 56);
        assert_eq!(core::mem::offset_of!(LinuxMsghdr, name), 0);
        assert_eq!(core::mem::offset_of!(LinuxMsghdr, namelen), 8);
        assert_eq!(core::mem::offset_of!(LinuxMsghdr, iov), 16);
        assert_eq!(core::mem::offset_of!(LinuxMsghdr, iovlen), 24);
        assert_eq!(core::mem::offset_of!(LinuxMsghdr, control), 32);
        assert_eq!(core::mem::offset_of!(LinuxMsghdr, controllen), 40);
        assert_eq!(core::mem::offset_of!(LinuxMsghdr, flags), 48);

        assert_eq!(core::mem::size_of::<LinuxMmsghdr>(), 64);
        assert_eq!(<LinuxMmsghdr as KernelAbi>::ABI_SIZE, 64);
        assert_eq!(core::mem::offset_of!(LinuxMmsghdr, msg_hdr), 0);
        assert_eq!(core::mem::offset_of!(LinuxMmsghdr, msg_len), 56);

        assert_eq!(core::mem::size_of::<LinuxCloneArgs>(), 88);
        assert_eq!(<LinuxCloneArgs as KernelAbi>::ABI_SIZE, 88);
        assert_eq!(core::mem::offset_of!(LinuxCloneArgs, flags), 0);
        assert_eq!(core::mem::offset_of!(LinuxCloneArgs, child_tid), 16);
        assert_eq!(core::mem::offset_of!(LinuxCloneArgs, parent_tid), 24);
        assert_eq!(core::mem::offset_of!(LinuxCloneArgs, stack), 40);
        assert_eq!(core::mem::offset_of!(LinuxCloneArgs, stack_size), 48);
        assert_eq!(core::mem::offset_of!(LinuxCloneArgs, tls), 56);
    }

    #[test]
    fn linux_flag_groups_pin_supported_and_rejected_masks() {
        assert_ne!(LinuxOpenFlags::SUPPORTED_MASK & LINUX_O_CREAT, 0);
        assert_ne!(LinuxOpenFlags::SUPPORTED_MASK & LINUX_O_NONBLOCK, 0);
        assert_eq!(LinuxOpenFlags::SUPPORTED_MASK & (1u64 << 63), 0);

        assert_ne!(LinuxAtFlags::STATX_SUPPORTED_MASK & LINUX_AT_EMPTY_PATH, 0);
        assert_ne!(
            LinuxAtFlags::STATX_SUPPORTED_MASK & LinuxAtFlags::STATX_SYNC_AS_STAT,
            0
        );
        assert_eq!(LinuxAtFlags::STATX_SUPPORTED_MASK & (1u64 << 63), 0);

        assert_ne!(LinuxMmapFlags::SUPPORTED_MASK & LINUX_MAP_PRIVATE, 0);
        assert_eq!(LinuxMmapFlags::SUPPORTED_MASK & 0x8000_0000, 0);
        // Advisory hint flags must be accepted (Rust std maps MAP_STACK, Go
        // maps MAP_STACK|MAP_NORESERVE) — rejecting them is a spurious EINVAL.
        for hint in [
            LINUX_MAP_STACK,
            LINUX_MAP_NORESERVE,
            LINUX_MAP_POPULATE,
            LINUX_MAP_DENYWRITE,
            LINUX_MAP_EXECUTABLE,
            LINUX_MAP_GROWSDOWN,
            LINUX_MAP_LOCKED,
            LINUX_MAP_NONBLOCK,
            LINUX_MAP_HUGETLB,
            LINUX_MAP_FIXED_NOREPLACE,
        ] {
            assert_ne!(
                LinuxMmapFlags::SUPPORTED_MASK & hint,
                0,
                "mmap hint flag {hint:#x} must be accepted"
            );
        }

        assert_ne!(
            LinuxFutexFlags::SUPPORTED_MASK & LINUX_FUTEX_PRIVATE_FLAG,
            0
        );
        assert_eq!(LinuxFutexFlags::SUPPORTED_MASK & 0x8000_0000, 0);

        assert_ne!(LinuxCloneFlags::THREAD_MASK & LINUX_CLONE_THREAD, 0);
        assert_eq!(LinuxCloneFlags::THREAD_MASK & (1u64 << 63), 0);

        assert_ne!(
            LinuxSocketTypeFlags::SUPPORTED_MASK & LINUX_SOCK_NONBLOCK,
            0
        );
        assert_eq!(LinuxSocketTypeFlags::SUPPORTED_MASK & (1_i32 << 30), 0);

        assert_eq!(LinuxFdFlags::CLOEXEC.bits(), LINUX_FD_CLOEXEC);
    }

    #[test]
    fn signal_frame_embeds_linux_aarch64_siginfo_and_ucontext_layout() {
        assert_eq!(core::mem::size_of::<LinuxSiginfo>(), 128);
        assert_eq!(core::mem::offset_of!(LinuxSiginfo, si_addr), 16);

        assert_eq!(core::mem::offset_of!(LinuxSignalContext, regs), 8);
        assert_eq!(core::mem::offset_of!(LinuxSignalContext, sp), 256);
        assert_eq!(core::mem::offset_of!(LinuxSignalContext, pc), 264);
        assert_eq!(core::mem::offset_of!(LinuxSignalContext, pstate), 272);
        assert_eq!(core::mem::offset_of!(LinuxSignalContext, __reserved), 288);
        assert_eq!(core::mem::size_of::<LinuxSignalContext>(), 4384);

        assert_eq!(core::mem::offset_of!(LinuxUcontext, uc_stack), 16);
        assert_eq!(core::mem::offset_of!(LinuxUcontext, uc_sigmask), 40);
        assert_eq!(core::mem::offset_of!(LinuxUcontext, _pad), 48);
        assert_eq!(core::mem::offset_of!(LinuxUcontext, _pad2), 168);
        assert_eq!(core::mem::offset_of!(LinuxUcontext, uc_mcontext), 176);
    }

    #[test]
    fn fpsimd_context_matches_linux_aarch64_layout() {
        // struct fpsimd_context: head{magic,size}=8, fpsr=4, fpcr=4, vregs[32]
        // of __uint128_t = 512; total 528, vregs at offset 16.
        assert_eq!(core::mem::offset_of!(LinuxFpsimdContext, fpsr), 8);
        assert_eq!(core::mem::offset_of!(LinuxFpsimdContext, fpcr), 12);
        assert_eq!(core::mem::offset_of!(LinuxFpsimdContext, vregs), 16);
        assert_eq!(core::mem::size_of::<LinuxFpsimdContext>(), 528);
        let fp = LinuxFpsimdContext::empty();
        let (magic, size) = (fp.magic, fp.size);
        assert_eq!(magic, LINUX_FPSIMD_MAGIC);
        assert_eq!(size, 528);
        // Must fit at the start of sigcontext.__reserved with room for the
        // null terminator record the guest expects after it.
        assert!(LINUX_AARCH64_SIGCONTEXT_RESERVED_BYTES >= 528 + 8);
    }
}
