//! Linux `stat(2)`/`statx(2)` ABI: file-type bits, the records, and the
//! one encoding of a file's stat facts every carrick venue shares (the
//! dispatcher and the ring alike).

pub const LINUX_S_IFMT: u32 = 0o170000;
pub const LINUX_S_IFDIR: u32 = 0o040000;
pub const LINUX_S_IFREG: u32 = 0o100000;
pub const LINUX_S_IFLNK: u32 = 0o120000;
pub const LINUX_S_IFIFO: u32 = 0o010000;
pub const LINUX_S_IFCHR: u32 = 0o020000;
pub const LINUX_S_IFBLK: u32 = 0o060000;
pub const LINUX_S_IFSOCK: u32 = 0o140000;

pub const LINUX_PAGE_SIZE: u64 = 4096;

pub const LINUX_STATX_TYPE: u32 = 0x0001;
pub const LINUX_STATX_MODE: u32 = 0x0002;
pub const LINUX_STATX_NLINK: u32 = 0x0004;
pub const LINUX_STATX_UID: u32 = 0x0008;
pub const LINUX_STATX_GID: u32 = 0x0010;
pub const LINUX_STATX_ATIME: u32 = 0x0020;
pub const LINUX_STATX_MTIME: u32 = 0x0040;
pub const LINUX_STATX_CTIME: u32 = 0x0080;
pub const LINUX_STATX_INO: u32 = 0x0100;
pub const LINUX_STATX_SIZE: u32 = 0x0200;
pub const LINUX_STATX_BLOCKS: u32 = 0x0400;
pub const LINUX_STATX_BASIC_STATS: u32 = 0x7ff;
pub const LINUX_STATX_BTIME: u32 = 0x0800;
pub const LINUX_STATX_MNT_ID: u32 = 0x1000;
pub const LINUX_STATX_DIOALIGN: u32 = 0x2000;
pub const LINUX_STATX_MNT_ID_UNIQUE: u32 = 0x4000;
pub const LINUX_STATX_ALL: u32 = 0x0fff;
pub const LINUX_STATX_RESERVED: u64 = 0x8000_0000;

#[repr(C, packed)]
#[derive(
    ::core::fmt::Debug,
    ::core::clone::Clone,
    ::core::marker::Copy,
    ::core::cmp::PartialEq,
    ::core::cmp::Eq,
    ::zerocopy::FromBytes,
    ::zerocopy::IntoBytes,
    ::zerocopy::KnownLayout,
    ::zerocopy::Immutable,
    ::zerocopy::Unaligned,
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

/// The facts `stat(2)` and `statx(2)` report for one file, independent of
/// how a kernel stores them: the single source both Linux encodings
/// ([`LinuxStat::from_fields`], [`LinuxStatx::from_fields`]) derive from.
#[derive(
    ::core::fmt::Debug,
    ::core::clone::Clone,
    ::core::marker::Copy,
    ::core::cmp::PartialEq,
    ::core::cmp::Eq,
)]
pub struct LinuxStatFields {
    pub ino: u64,
    pub mode: u32,
    pub nlink: u32,
    pub uid: u32,
    pub gid: u32,
    /// Device this node represents (`st_rdev`); zero for ordinary files.
    pub rdev: u64,
    pub size: u64,
    /// 512-byte blocks; `None` derives them from `size`.
    pub blocks: Option<u64>,
    pub atime: (i64, i64),
    pub mtime: (i64, i64),
    pub ctime: (i64, i64),
}

/// The synthetic inode carrick reports for an object named by `label`
/// (FNV-1a over its bytes, never zero), such as a pipe or an anonymous
/// inode, which Linux numbers in a pseudo filesystem.
pub const fn linux_synthetic_inode(label: &[u8]) -> u64 {
    let mut hash = 0xcbf2_9ce4_8422_2325_u64;
    let mut index = 0;
    while index < label.len() {
        hash ^= label[index] as u64;
        hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
        index += 1;
    }
    if hash == 0 { 1 } else { hash }
}

/// 512-byte blocks a file of `size` bytes reports when its store keeps no
/// allocation count.
pub const fn linux_blocks_512(size: u64) -> u64 {
    size.div_ceil(512)
}

/// Decode the major number from a raw Linux `dev_t` (the glibc `gnu_dev_major`
/// encoding documented in makedev(3)): the major occupies bits 8..20 and 32..64,
/// the minor bits 0..8 and 20..64 (interleaved so a 32-bit dev_t stays
/// compatible). `stat`/`mknod` carry the raw `dev_t` verbatim; only `statx`
/// reports the split fields. Clean-room from the man page, not glibc source.
pub const fn linux_dev_major(dev: u64) -> u32 {
    (((dev >> 8) & 0xfff) | ((dev >> 32) & !0xfff)) as u32
}

/// Decode the minor number from a raw Linux `dev_t` (see [`linux_dev_major`]).
pub const fn linux_dev_minor(dev: u64) -> u32 {
    ((dev & 0xff) | ((dev >> 12) & !0xff)) as u32
}

impl LinuxStatFields {
    /// An object carrick names by `label` with no backing file: one link,
    /// owned by root, empty, never written.
    pub const fn synthetic(label: &[u8], mode: u32) -> Self {
        Self {
            ino: linux_synthetic_inode(label),
            mode,
            nlink: 1,
            uid: 0,
            gid: 0,
            rdev: 0,
            size: 0,
            blocks: None,
            atime: (0, 0),
            mtime: (0, 0),
            ctime: (0, 0),
        }
    }

    /// Every carrick pipe end, in the dispatcher and in the ring alike.
    pub const CARRICK_PIPE: Self = Self::synthetic(b"pipe:[carrick]", LINUX_S_IFIFO | 0o600);
    /// Every carrick eventfd.
    pub const CARRICK_EVENTFD: Self = Self::synthetic(b"anon_inode:[eventfd]", 0o600);
    /// Every carrick epoll instance.
    pub const CARRICK_EPOLL: Self = Self::synthetic(b"anon_inode:[eventpoll]", 0o600);

    pub const fn blocks(&self) -> u64 {
        match self.blocks {
            Some(blocks) => blocks,
            None => linux_blocks_512(self.size),
        }
    }
}

impl LinuxStat {
    /// The canonical (asm-generic/aarch64) `struct stat` for `fields`.
    pub const fn from_fields(fields: &LinuxStatFields) -> Self {
        Self {
            st_dev: 1,
            st_ino: fields.ino,
            st_mode: fields.mode,
            st_nlink: fields.nlink,
            st_uid: fields.uid,
            st_gid: fields.gid,
            st_rdev: fields.rdev,
            __pad1: 0,
            st_size: fields.size as i64,
            st_blksize: LINUX_PAGE_SIZE as i32,
            __pad2: 0,
            st_blocks: fields.blocks() as i64,
            st_atime: fields.atime.0,
            st_atime_nsec: fields.atime.1 as u64,
            st_mtime: fields.mtime.0,
            st_mtime_nsec: fields.mtime.1 as u64,
            st_ctime: fields.ctime.0,
            st_ctime_nsec: fields.ctime.1 as u64,
            __unused4: 0,
            __unused5: 0,
        }
    }
}

#[repr(C, packed)]
#[derive(
    ::core::fmt::Debug,
    ::core::clone::Clone,
    ::core::marker::Copy,
    ::core::cmp::PartialEq,
    ::core::cmp::Eq,
    ::zerocopy::FromBytes,
    ::zerocopy::IntoBytes,
    ::zerocopy::KnownLayout,
    ::zerocopy::Immutable,
    ::zerocopy::Unaligned,
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

impl LinuxStatx {
    /// The `struct statx` carrick reports for `fields` (basic stats only).
    pub const fn from_fields(fields: &LinuxStatFields) -> Self {
        const fn stamp(time: (i64, i64)) -> LinuxStatxTimestamp {
            LinuxStatxTimestamp {
                tv_sec: time.0,
                tv_nsec: time.1 as u32,
                __reserved: 0,
            }
        }
        Self {
            stx_mask: LINUX_STATX_BASIC_STATS,
            stx_blksize: LINUX_PAGE_SIZE as u32,
            stx_attributes: 0,
            stx_nlink: fields.nlink,
            stx_uid: fields.uid,
            stx_gid: fields.gid,
            stx_mode: fields.mode as u16,
            __spare0: [0; 1],
            stx_ino: fields.ino,
            stx_size: fields.size,
            stx_blocks: fields.blocks(),
            stx_attributes_mask: 0,
            stx_atime: stamp(fields.atime),
            stx_btime: LinuxStatxTimestamp::zero(),
            stx_ctime: stamp(fields.ctime),
            stx_mtime: stamp(fields.mtime),
            stx_rdev_major: linux_dev_major(fields.rdev),
            stx_rdev_minor: linux_dev_minor(fields.rdev),
            stx_dev_major: 0,
            stx_dev_minor: 1,
            stx_mnt_id: 1,
            stx_dio_mem_align: 0,
            stx_dio_offset_align: 0,
            stx_subvol: 0,
            stx_atomic_write_unit_min: 0,
            stx_atomic_write_unit_max: 0,
            stx_atomic_write_segments_max: 0,
            stx_dio_read_offset_align: 0,
            stx_atomic_write_unit_max_opt: 0,
            __spare2: [0; 1],
            __spare3: [0; 8],
        }
    }
}

#[repr(C, packed)]
#[derive(
    ::core::fmt::Debug,
    ::core::clone::Clone,
    ::core::marker::Copy,
    ::core::cmp::PartialEq,
    ::core::cmp::Eq,
    ::zerocopy::FromBytes,
    ::zerocopy::IntoBytes,
    ::zerocopy::KnownLayout,
    ::zerocopy::Immutable,
    ::zerocopy::Unaligned,
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
