use std::collections::HashMap;
use std::path::Path;

use crate::compat::{CompatEvent, CompatReporter, SyscallArgs};
use crate::linux_abi::{
    LINUX_DIRENT64_HEADER_SIZE, LINUX_DT_DIR, LINUX_DT_LNK, LINUX_DT_REG, LINUX_S_IFDIR,
    LINUX_S_IFLNK, LINUX_S_IFREG, LinuxDirent64Header, LinuxStat,
};
use crate::rootfs::{RootFs, RootFsDirEntry, RootFsEntryKind, RootFsError, RootFsMetadata};
use crate::syscall::lookup_aarch64;
use serde::Serialize;
use thiserror::Error;
use zerocopy::IntoBytes;

pub const LINUX_ENOENT: i32 = 2;
pub const LINUX_EBADF: i32 = 9;
pub const LINUX_EACCES: i32 = 13;
pub const LINUX_EFAULT: i32 = 14;
pub const LINUX_ENOTDIR: i32 = 20;
pub const LINUX_EISDIR: i32 = 21;
pub const LINUX_EINVAL: i32 = 22;
pub const LINUX_ERANGE: i32 = 34;
pub const LINUX_ENAMETOOLONG: i32 = 36;
pub const LINUX_ENOSYS: i32 = 38;
pub const LINUX_AT_FDCWD: u64 = (-100_i64) as u64;
pub const LINUX_AT_EMPTY_PATH: u64 = 0x1000;
pub const LINUX_R_OK: u64 = 4;
pub const LINUX_W_OK: u64 = 2;
pub const LINUX_X_OK: u64 = 1;
pub const LINUX_SEEK_SET: u64 = 0;
pub const LINUX_SEEK_CUR: u64 = 1;
pub const LINUX_SEEK_END: u64 = 2;
const MAX_GUEST_PATH: usize = 4096;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct SyscallRequest {
    pub number: u64,
    pub args: SyscallArgs,
}

#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct Aarch64SyscallFrame {
    pub x0: u64,
    pub x1: u64,
    pub x2: u64,
    pub x3: u64,
    pub x4: u64,
    pub x5: u64,
    pub x8: u64,
}

impl SyscallRequest {
    pub fn new(number: u64, args: SyscallArgs) -> Self {
        Self { number, args }
    }

    pub fn arg(&self, index: usize) -> u64 {
        self.args.0[index]
    }

    pub fn from_aarch64_frame(frame: Aarch64SyscallFrame) -> Self {
        Self {
            number: frame.x8,
            args: SyscallArgs::from([frame.x0, frame.x1, frame.x2, frame.x3, frame.x4, frame.x5]),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DispatchOutcome {
    Returned { value: i64 },
    Errno { errno: i32 },
    Exit { code: i32 },
}

impl DispatchOutcome {
    fn retval_errno(&self) -> (i64, Option<i32>) {
        match *self {
            DispatchOutcome::Returned { value } => (value, None),
            DispatchOutcome::Errno { errno } => (-(errno as i64), Some(errno)),
            DispatchOutcome::Exit { code } => (code as i64, None),
        }
    }
}

pub trait GuestMemory {
    fn read_bytes(&self, address: u64, length: usize) -> Result<Vec<u8>, MemoryError>;
    fn write_bytes(&mut self, address: u64, bytes: &[u8]) -> Result<(), MemoryError>;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LinearMemory {
    base: u64,
    bytes: Vec<u8>,
}

impl LinearMemory {
    pub fn new(base: u64, bytes: Vec<u8>) -> Self {
        Self { base, bytes }
    }
}

impl GuestMemory for LinearMemory {
    fn read_bytes(&self, address: u64, length: usize) -> Result<Vec<u8>, MemoryError> {
        let offset = address
            .checked_sub(self.base)
            .ok_or(MemoryError::OutOfBounds { address, length })?;
        let offset =
            usize::try_from(offset).map_err(|_| MemoryError::OutOfBounds { address, length })?;
        let end = offset
            .checked_add(length)
            .ok_or(MemoryError::OutOfBounds { address, length })?;
        if end > self.bytes.len() {
            return Err(MemoryError::OutOfBounds { address, length });
        }
        Ok(self.bytes[offset..end].to_vec())
    }

    fn write_bytes(&mut self, address: u64, bytes: &[u8]) -> Result<(), MemoryError> {
        let offset = address
            .checked_sub(self.base)
            .ok_or(MemoryError::OutOfBounds {
                address,
                length: bytes.len(),
            })?;
        let offset = usize::try_from(offset).map_err(|_| MemoryError::OutOfBounds {
            address,
            length: bytes.len(),
        })?;
        let end = offset
            .checked_add(bytes.len())
            .ok_or(MemoryError::OutOfBounds {
                address,
                length: bytes.len(),
            })?;
        if end > self.bytes.len() {
            return Err(MemoryError::OutOfBounds {
                address,
                length: bytes.len(),
            });
        }
        self.bytes[offset..end].copy_from_slice(bytes);
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum MemoryError {
    #[error("guest memory read is out of bounds at 0x{address:x} for {length} bytes")]
    OutOfBounds { address: u64, length: usize },
}

#[derive(Debug, Error)]
pub enum DispatchError {
    #[error("guest memory read length does not fit this host: {0}")]
    LengthTooLarge(u64),
}

pub struct SyscallDispatcher {
    stdout: Vec<u8>,
    stderr: Vec<u8>,
    rootfs: Option<RootFs>,
    open_files: HashMap<i32, OpenDescription>,
    next_fd: i32,
    cwd: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum OpenDescription {
    File {
        path: String,
        metadata: RootFsMetadata,
        contents: Vec<u8>,
        offset: usize,
    },
    Directory {
        path: String,
        metadata: RootFsMetadata,
        entries: Vec<RootFsDirEntry>,
        offset: usize,
    },
}

impl Default for SyscallDispatcher {
    fn default() -> Self {
        Self::new()
    }
}

impl SyscallDispatcher {
    pub fn new() -> Self {
        Self {
            stdout: Vec::new(),
            stderr: Vec::new(),
            rootfs: None,
            open_files: HashMap::new(),
            next_fd: 3,
            cwd: "/".to_owned(),
        }
    }

    pub fn with_rootfs(rootfs: RootFs) -> Self {
        Self {
            rootfs: Some(rootfs),
            ..Self::new()
        }
    }

    pub fn stdout(&self) -> &[u8] {
        &self.stdout
    }

    pub fn stderr(&self) -> &[u8] {
        &self.stderr
    }

    pub fn cwd(&self) -> &str {
        &self.cwd
    }

    pub fn dispatch(
        &mut self,
        request: SyscallRequest,
        memory: &mut impl GuestMemory,
        reporter: &mut CompatReporter,
    ) -> Result<DispatchOutcome, DispatchError> {
        let syscall = lookup_aarch64(request.number);
        let name = syscall.map_or("unknown", |syscall| syscall.name);

        reporter.record(CompatEvent::SyscallEntry {
            number: request.number,
            name: name.to_owned(),
            args: request.args,
        });

        let outcome = match request.number {
            17 => self.getcwd(request, memory)?,
            48 => self.faccessat(request, memory)?,
            49 => self.chdir(request, memory)?,
            50 => self.fchdir(request),
            56 => self.openat(request, memory)?,
            57 => self.close(request),
            61 => self.getdents64(request, memory)?,
            62 => self.lseek(request),
            63 => self.read(request, memory)?,
            64 => self.write(request, memory)?,
            79 => self.newfstatat(request, memory)?,
            80 => self.fstat(request, memory),
            93 => self.exit(request),
            _ => {
                reporter.record(CompatEvent::unhandled_syscall(
                    request.number,
                    name,
                    request.args,
                ));
                DispatchOutcome::Errno {
                    errno: LINUX_ENOSYS,
                }
            }
        };

        let (retval, errno) = outcome.retval_errno();
        reporter.record(CompatEvent::SyscallReturn {
            number: request.number,
            name: name.to_owned(),
            retval,
            errno,
        });

        Ok(outcome)
    }

    fn getcwd(
        &self,
        request: SyscallRequest,
        memory: &mut impl GuestMemory,
    ) -> Result<DispatchOutcome, DispatchError> {
        let address = request.arg(0);
        let size = usize::try_from(request.arg(1))
            .map_err(|_| DispatchError::LengthTooLarge(request.arg(1)))?;
        let mut bytes = self.cwd.as_bytes().to_vec();
        bytes.push(0);
        if bytes.len() > size {
            return Ok(DispatchOutcome::Errno {
                errno: LINUX_ERANGE,
            });
        }
        if memory.write_bytes(address, &bytes).is_err() {
            return Ok(DispatchOutcome::Errno {
                errno: LINUX_EFAULT,
            });
        }
        Ok(DispatchOutcome::Returned {
            value: address as i64,
        })
    }

    fn faccessat(
        &self,
        request: SyscallRequest,
        memory: &impl GuestMemory,
    ) -> Result<DispatchOutcome, DispatchError> {
        let dirfd = request.arg(0);
        let pathname = request.arg(1);
        let mode = request.arg(2);
        let flags = request.arg(3);
        if mode & !(LINUX_R_OK | LINUX_W_OK | LINUX_X_OK) != 0 || flags != 0 {
            return Ok(DispatchOutcome::Errno {
                errno: LINUX_EINVAL,
            });
        }

        let path = match read_guest_c_string(memory, pathname) {
            Ok(path) => path,
            Err(errno) => return Ok(DispatchOutcome::Errno { errno }),
        };
        let path = match self.resolve_at_path(dirfd, &path) {
            Ok(path) => path,
            Err(errno) => return Ok(DispatchOutcome::Errno { errno }),
        };
        let Some(rootfs) = &self.rootfs else {
            return Ok(DispatchOutcome::Errno {
                errno: LINUX_ENOENT,
            });
        };
        let metadata = match rootfs.metadata(path) {
            Ok(metadata) => metadata,
            Err(errno) => {
                return Ok(DispatchOutcome::Errno {
                    errno: rootfs_errno(errno),
                });
            }
        };

        if mode & LINUX_W_OK != 0 {
            return Ok(DispatchOutcome::Errno {
                errno: LINUX_EACCES,
            });
        }
        if mode & LINUX_R_OK != 0
            && metadata.kind == RootFsEntryKind::File
            && metadata.mode & 0o444 == 0
        {
            return Ok(DispatchOutcome::Errno {
                errno: LINUX_EACCES,
            });
        }
        if mode & LINUX_X_OK != 0
            && metadata.kind == RootFsEntryKind::File
            && metadata.mode & 0o111 == 0
        {
            return Ok(DispatchOutcome::Errno {
                errno: LINUX_EACCES,
            });
        }

        Ok(DispatchOutcome::Returned { value: 0 })
    }

    fn chdir(
        &mut self,
        request: SyscallRequest,
        memory: &impl GuestMemory,
    ) -> Result<DispatchOutcome, DispatchError> {
        let pathname = request.arg(0);
        let path = match read_guest_c_string(memory, pathname) {
            Ok(path) => path,
            Err(errno) => return Ok(DispatchOutcome::Errno { errno }),
        };
        let path = match self.resolve_at_path(LINUX_AT_FDCWD, &path) {
            Ok(path) => path,
            Err(errno) => return Ok(DispatchOutcome::Errno { errno }),
        };
        let Some(rootfs) = &self.rootfs else {
            return Ok(DispatchOutcome::Errno {
                errno: LINUX_ENOENT,
            });
        };
        let metadata = match rootfs.metadata(path) {
            Ok(metadata) => metadata,
            Err(errno) => {
                return Ok(DispatchOutcome::Errno {
                    errno: rootfs_errno(errno),
                });
            }
        };
        if metadata.kind != RootFsEntryKind::Directory {
            return Ok(DispatchOutcome::Errno {
                errno: LINUX_ENOTDIR,
            });
        }
        self.cwd = display_rootfs_path(&metadata.path);
        Ok(DispatchOutcome::Returned { value: 0 })
    }

    fn fchdir(&mut self, request: SyscallRequest) -> DispatchOutcome {
        let fd = request.arg(0) as i32;
        let Some(open) = self.open_files.get(&fd) else {
            return DispatchOutcome::Errno { errno: LINUX_EBADF };
        };
        match open {
            OpenDescription::Directory { metadata, .. } => {
                self.cwd = display_rootfs_path(&metadata.path);
                DispatchOutcome::Returned { value: 0 }
            }
            OpenDescription::File { .. } => DispatchOutcome::Errno {
                errno: LINUX_ENOTDIR,
            },
        }
    }

    fn openat(
        &mut self,
        request: SyscallRequest,
        memory: &impl GuestMemory,
    ) -> Result<DispatchOutcome, DispatchError> {
        let dirfd = request.arg(0);
        let pathname = request.arg(1);
        let flags = request.arg(2);
        if flags & 0b11 != 0 {
            return Ok(DispatchOutcome::Errno {
                errno: LINUX_EINVAL,
            });
        }

        let path = match read_guest_c_string(memory, pathname) {
            Ok(path) => path,
            Err(errno) => return Ok(DispatchOutcome::Errno { errno }),
        };
        let path = match self.resolve_at_path(dirfd, &path) {
            Ok(path) => path,
            Err(errno) => return Ok(DispatchOutcome::Errno { errno }),
        };

        let Some(rootfs) = &self.rootfs else {
            return Ok(DispatchOutcome::Errno {
                errno: LINUX_ENOENT,
            });
        };
        let metadata = match rootfs.metadata(&path) {
            Ok(metadata) => metadata,
            Err(errno) => {
                return Ok(DispatchOutcome::Errno {
                    errno: rootfs_errno(errno),
                });
            }
        };

        let description = match metadata.kind {
            RootFsEntryKind::File => {
                let contents = match rootfs.read(&path) {
                    Ok(contents) => contents,
                    Err(errno) => {
                        return Ok(DispatchOutcome::Errno {
                            errno: rootfs_errno(errno),
                        });
                    }
                };
                OpenDescription::File {
                    path,
                    metadata,
                    contents,
                    offset: 0,
                }
            }
            RootFsEntryKind::Directory => {
                let entries = match rootfs.directory_entries(&path) {
                    Ok(entries) => entries,
                    Err(errno) => {
                        return Ok(DispatchOutcome::Errno {
                            errno: rootfs_errno(errno),
                        });
                    }
                };
                OpenDescription::Directory {
                    path,
                    metadata,
                    entries,
                    offset: 0,
                }
            }
            RootFsEntryKind::Symlink => {
                return Ok(DispatchOutcome::Errno {
                    errno: LINUX_EINVAL,
                });
            }
        };

        let fd = self.next_fd;
        self.next_fd += 1;
        self.open_files.insert(fd, description);
        Ok(DispatchOutcome::Returned { value: fd as i64 })
    }

    fn close(&mut self, request: SyscallRequest) -> DispatchOutcome {
        let fd = request.arg(0) as i32;
        if self.open_files.remove(&fd).is_some() {
            DispatchOutcome::Returned { value: 0 }
        } else {
            DispatchOutcome::Errno { errno: LINUX_EBADF }
        }
    }

    fn getdents64(
        &mut self,
        request: SyscallRequest,
        memory: &mut impl GuestMemory,
    ) -> Result<DispatchOutcome, DispatchError> {
        let fd = request.arg(0) as i32;
        let address = request.arg(1);
        let length = usize::try_from(request.arg(2))
            .map_err(|_| DispatchError::LengthTooLarge(request.arg(2)))?;
        let Some(OpenDescription::Directory {
            entries, offset, ..
        }) = self.open_files.get_mut(&fd)
        else {
            return Ok(DispatchOutcome::Errno { errno: LINUX_EBADF });
        };

        let mut out = Vec::new();
        while *offset < entries.len() {
            let record = dirent64_record(&entries[*offset], *offset + 1);
            if record.len() > length {
                return Ok(DispatchOutcome::Errno {
                    errno: LINUX_EINVAL,
                });
            }
            if out.len() + record.len() > length {
                break;
            }
            out.extend_from_slice(&record);
            *offset += 1;
        }

        if memory.write_bytes(address, &out).is_err() {
            return Ok(DispatchOutcome::Errno {
                errno: LINUX_EFAULT,
            });
        }

        Ok(DispatchOutcome::Returned {
            value: out.len() as i64,
        })
    }

    fn lseek(&mut self, request: SyscallRequest) -> DispatchOutcome {
        let fd = request.arg(0) as i32;
        let offset = request.arg(1) as i64;
        let whence = request.arg(2);
        let Some(open) = self.open_files.get_mut(&fd) else {
            return DispatchOutcome::Errno { errno: LINUX_EBADF };
        };

        let (current, end) = match open {
            OpenDescription::File {
                contents, offset, ..
            } => (*offset as i64, contents.len() as i64),
            OpenDescription::Directory {
                entries, offset, ..
            } => (*offset as i64, entries.len() as i64),
        };
        let next = match whence {
            LINUX_SEEK_SET => offset,
            LINUX_SEEK_CUR => current.saturating_add(offset),
            LINUX_SEEK_END => end.saturating_add(offset),
            _ => {
                return DispatchOutcome::Errno {
                    errno: LINUX_EINVAL,
                };
            }
        };
        if next < 0 {
            return DispatchOutcome::Errno {
                errno: LINUX_EINVAL,
            };
        }

        match open {
            OpenDescription::File { offset, .. } | OpenDescription::Directory { offset, .. } => {
                *offset = next as usize;
            }
        }
        DispatchOutcome::Returned { value: next }
    }

    fn read(
        &mut self,
        request: SyscallRequest,
        memory: &mut impl GuestMemory,
    ) -> Result<DispatchOutcome, DispatchError> {
        let fd = request.arg(0) as i32;
        let address = request.arg(1);
        let length = usize::try_from(request.arg(2))
            .map_err(|_| DispatchError::LengthTooLarge(request.arg(2)))?;
        let Some(open) = self.open_files.get_mut(&fd) else {
            return Ok(DispatchOutcome::Errno { errno: LINUX_EBADF });
        };
        let OpenDescription::File {
            contents, offset, ..
        } = open
        else {
            return Ok(DispatchOutcome::Errno {
                errno: LINUX_EISDIR,
            });
        };
        let remaining = &contents[*offset..];
        let read_len = remaining.len().min(length);
        let bytes = &remaining[..read_len];
        if memory.write_bytes(address, bytes).is_err() {
            return Ok(DispatchOutcome::Errno {
                errno: LINUX_EFAULT,
            });
        }
        *offset += read_len;
        Ok(DispatchOutcome::Returned {
            value: read_len as i64,
        })
    }

    fn write(
        &mut self,
        request: SyscallRequest,
        memory: &impl GuestMemory,
    ) -> Result<DispatchOutcome, DispatchError> {
        let fd = request.arg(0);
        let address = request.arg(1);
        let length = usize::try_from(request.arg(2))
            .map_err(|_| DispatchError::LengthTooLarge(request.arg(2)))?;
        let bytes = match memory.read_bytes(address, length) {
            Ok(bytes) => bytes,
            Err(_) => {
                return Ok(DispatchOutcome::Errno {
                    errno: LINUX_EFAULT,
                });
            }
        };

        match fd {
            1 => self.stdout.extend_from_slice(&bytes),
            2 => self.stderr.extend_from_slice(&bytes),
            _ => {
                return Ok(DispatchOutcome::Errno { errno: LINUX_EBADF });
            }
        }

        Ok(DispatchOutcome::Returned {
            value: length as i64,
        })
    }

    fn newfstatat(
        &self,
        request: SyscallRequest,
        memory: &mut impl GuestMemory,
    ) -> Result<DispatchOutcome, DispatchError> {
        let dirfd = request.arg(0);
        let pathname = request.arg(1);
        let statbuf = request.arg(2);
        let flags = request.arg(3);
        let path = match read_guest_c_string(memory, pathname) {
            Ok(path) => path,
            Err(errno) => return Ok(DispatchOutcome::Errno { errno }),
        };

        if path.is_empty() && flags & LINUX_AT_EMPTY_PATH != 0 {
            return Ok(self.write_fd_stat(dirfd as i32, statbuf, memory));
        }

        let path = match self.resolve_at_path(dirfd, &path) {
            Ok(path) => path,
            Err(errno) => return Ok(DispatchOutcome::Errno { errno }),
        };
        let Some(rootfs) = &self.rootfs else {
            return Ok(DispatchOutcome::Errno {
                errno: LINUX_ENOENT,
            });
        };
        let metadata = match rootfs.metadata(path) {
            Ok(metadata) => metadata,
            Err(errno) => {
                return Ok(DispatchOutcome::Errno {
                    errno: rootfs_errno(errno),
                });
            }
        };
        Ok(write_stat(memory, statbuf, &metadata))
    }

    fn fstat(&self, request: SyscallRequest, memory: &mut impl GuestMemory) -> DispatchOutcome {
        self.write_fd_stat(request.arg(0) as i32, request.arg(1), memory)
    }

    fn write_fd_stat(
        &self,
        fd: i32,
        statbuf: u64,
        memory: &mut impl GuestMemory,
    ) -> DispatchOutcome {
        let Some(open) = self.open_files.get(&fd) else {
            return DispatchOutcome::Errno { errno: LINUX_EBADF };
        };
        let metadata = match open {
            OpenDescription::File { metadata, .. }
            | OpenDescription::Directory { metadata, .. } => metadata,
        };
        write_stat(memory, statbuf, metadata)
    }

    fn exit(&self, request: SyscallRequest) -> DispatchOutcome {
        DispatchOutcome::Exit {
            code: request.arg(0) as i32,
        }
    }

    fn resolve_at_path(&self, dirfd: u64, path: &str) -> Result<String, i32> {
        if path.is_empty() || Path::new(path).is_absolute() {
            return Ok(path.to_owned());
        }
        if dirfd == LINUX_AT_FDCWD {
            return Ok(join_rootfs_path(&self.cwd, path));
        }

        match self.open_files.get(&(dirfd as i32)) {
            Some(OpenDescription::Directory { path: dir, .. }) => Ok(join_rootfs_path(dir, path)),
            Some(OpenDescription::File { .. }) => Err(LINUX_ENOTDIR),
            None => Err(LINUX_EBADF),
        }
    }
}

fn write_stat(
    memory: &mut impl GuestMemory,
    statbuf: u64,
    metadata: &RootFsMetadata,
) -> DispatchOutcome {
    let stat = LinuxStat {
        st_dev: 1,
        st_ino: inode_for_path(&metadata.path),
        st_mode: linux_mode(metadata),
        st_nlink: if metadata.kind == RootFsEntryKind::Directory {
            2
        } else {
            1
        },
        st_uid: 0,
        st_gid: 0,
        st_rdev: 0,
        __pad1: 0,
        st_size: metadata.size as i64,
        st_blksize: 4096,
        __pad2: 0,
        st_blocks: blocks_512(metadata.size),
        st_atime: 0,
        st_atime_nsec: 0,
        st_mtime: 0,
        st_mtime_nsec: 0,
        st_ctime: 0,
        st_ctime_nsec: 0,
        __unused4: 0,
        __unused5: 0,
    };

    if memory.write_bytes(statbuf, stat.as_bytes()).is_err() {
        DispatchOutcome::Errno {
            errno: LINUX_EFAULT,
        }
    } else {
        DispatchOutcome::Returned { value: 0 }
    }
}

fn linux_mode(metadata: &RootFsMetadata) -> u32 {
    let kind = match metadata.kind {
        RootFsEntryKind::File => LINUX_S_IFREG,
        RootFsEntryKind::Directory => LINUX_S_IFDIR,
        RootFsEntryKind::Symlink => LINUX_S_IFLNK,
    };
    kind | (metadata.mode & 0o7777)
}

fn blocks_512(size: usize) -> i64 {
    if size == 0 {
        0
    } else {
        size.div_ceil(512) as i64
    }
}

fn dirent64_record(entry: &RootFsDirEntry, next_offset: usize) -> Vec<u8> {
    let name = entry.name.as_bytes();
    let record_len = align_to(LINUX_DIRENT64_HEADER_SIZE + name.len() + 1, 8);
    let header = LinuxDirent64Header {
        d_ino: inode_for_path(&entry.metadata.path),
        d_off: next_offset as i64,
        d_reclen: record_len as u16,
        d_type: linux_dirent_type(entry.metadata.kind),
    };

    let mut out = vec![0; record_len];
    out[..LINUX_DIRENT64_HEADER_SIZE].copy_from_slice(header.as_bytes());
    out[LINUX_DIRENT64_HEADER_SIZE..LINUX_DIRENT64_HEADER_SIZE + name.len()].copy_from_slice(name);
    out
}

fn linux_dirent_type(kind: RootFsEntryKind) -> u8 {
    match kind {
        RootFsEntryKind::File => LINUX_DT_REG,
        RootFsEntryKind::Directory => LINUX_DT_DIR,
        RootFsEntryKind::Symlink => LINUX_DT_LNK,
    }
}

fn align_to(value: usize, alignment: usize) -> usize {
    value.div_ceil(alignment) * alignment
}

fn inode_for_path(path: &Path) -> u64 {
    let mut hash = 0xcbf29ce484222325_u64;
    for byte in path.as_os_str().as_encoded_bytes() {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(0x100000001b3);
    }
    hash.max(1)
}

fn join_rootfs_path(base: &str, path: &str) -> String {
    if base == "/" {
        format!("/{path}")
    } else {
        format!("{}/{path}", base.trim_end_matches('/'))
    }
}

fn display_rootfs_path(path: &Path) -> String {
    if path.as_os_str().is_empty() {
        "/".to_owned()
    } else {
        format!("/{}", path.display())
    }
}

fn rootfs_errno(error: RootFsError) -> i32 {
    match error {
        RootFsError::NotFound(_) => LINUX_ENOENT,
        RootFsError::UnsafePath(_) | RootFsError::Utf8(_) | RootFsError::TooManySymlinks(_) => {
            LINUX_EINVAL
        }
        RootFsError::Io(_) => LINUX_EINVAL,
    }
}

fn read_guest_c_string(memory: &impl GuestMemory, address: u64) -> Result<String, i32> {
    let mut bytes = Vec::new();
    for offset in 0..MAX_GUEST_PATH {
        let address = address
            .checked_add(offset as u64)
            .ok_or(LINUX_ENAMETOOLONG)?;
        let byte = memory
            .read_bytes(address, 1)
            .map_err(|_| LINUX_EFAULT)?
            .into_iter()
            .next()
            .ok_or(LINUX_EFAULT)?;
        if byte == 0 {
            return String::from_utf8(bytes).map_err(|_| LINUX_EINVAL);
        }
        bytes.push(byte);
    }
    Err(LINUX_ENAMETOOLONG)
}
