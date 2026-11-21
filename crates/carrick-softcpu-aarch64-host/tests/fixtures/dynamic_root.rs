//! Read-only test fixture answering `HVC #2` syscalls (`brk`, `mmap`,
//! `mprotect`, `munmap`, files, clocks, `futex`, signals) for the soft-CPU
//! engine witnesses in `boot_probe.rs`. Replies here do not come from the
//! production `carrick-kernel` / `carrick-personality-linux` dispatch.
use super::{PAGE, Pages, bind_host_fixture_fd, read_cstr};
use carrick_el1_abi::{
    DELEGATED_FLAG_READABLE, DELEGATED_FLAG_WRITABLE, HostBoundFd, HostObjectBinding,
};
use carrick_mem::{
    linux_abi::*,
    memory::{LINUX_HEAP_BASE, LINUX_MMAP_BASE, LINUX_STACK_SIZE},
};
use carrick_softcpu_aarch64::state::VirtualAddress;
use std::{
    cell::{Cell, RefCell},
    collections::{BTreeMap, VecDeque},
    ffi::OsString,
    fs::{self, File, Metadata},
    io::{self, Read, Seek, SeekFrom},
    os::unix::{
        ffi::{OsStrExt, OsStringExt},
        fs::{FileExt, MetadataExt},
    },
    path::{Component, Path, PathBuf},
    rc::Rc,
    time::{Instant, SystemTime, UNIX_EPOCH},
};

const MAX_MAPPING: u64 = 128 * 1024 * 1024;
const MAX_IO: u64 = 16 * 1024 * 1024;
const FD_LIMIT: u32 = 256;
const CWD: &[u8] = b"/\0";

/// Resolve inside a static, worker-owned checkout of an image. Absolute link
/// targets restart at the guest root. The root and its ancestors must remain
/// immutable throughout a run.
#[derive(Debug)]
pub(super) struct FixtureRoot(PathBuf);

impl FixtureRoot {
    pub(super) fn new(root: PathBuf) -> Self {
        Self(root.canonicalize().expect("canonical fixture root"))
    }

    fn resolve(&self, base: &Path, path: &Path, follow: bool) -> io::Result<PathBuf> {
        let mut pending: VecDeque<OsString> = path
            .components()
            .map(|c| c.as_os_str().to_owned())
            .collect();
        let mut resolved = base.to_owned();
        let mut links = 0;
        while let Some(part) = pending.pop_front() {
            match Path::new(&part).components().next().unwrap() {
                Component::RootDir => resolved.clear(),
                Component::ParentDir => {
                    resolved.pop();
                }
                Component::CurDir => {}
                Component::Normal(_) => {
                    resolved.push(part);
                    let candidate = self.0.join(&resolved);
                    let meta = fs::symlink_metadata(&candidate)?;
                    if meta.is_symlink() && (follow || !pending.is_empty()) {
                        links += 1;
                        if links > 40 {
                            return Err(io::Error::from_raw_os_error(LINUX_ELOOP.get()));
                        }
                        let target = fs::read_link(candidate)?;
                        resolved.pop();
                        for component in target.components().rev() {
                            pending.push_front(component.as_os_str().to_owned());
                        }
                    } else if !pending.is_empty() && !meta.is_dir() {
                        return Err(io::Error::from_raw_os_error(LINUX_ENOTDIR.get()));
                    }
                }
                Component::Prefix(_) => unreachable!("Unix paths"),
            }
        }
        Ok(resolved)
    }

    pub(super) fn read(&self, path: &str) -> io::Result<Vec<u8>> {
        let path = self.resolve(Path::new(""), Path::new(path), true)?;
        fs::read(self.0.join(path))
    }
}

enum Object {
    Stdio(u32),
    File(RefCell<File>),
    Directory {
        records: Vec<Vec<u8>>,
        cursor: Cell<usize>,
    },
}

struct OpenFile {
    path: PathBuf,
    object: Object,
    fields: LinuxStatFields,
    status: Cell<u64>,
}

struct Descriptor {
    file: Rc<OpenFile>,
    cloexec: bool,
}

struct Mapping {
    start: u64,
    offset: u64,
    len: u64,
    path: PathBuf,
}

/// Test-side `HVC #2` syscall responder for single-task startup witnesses
/// (answers 523 of CPython 3.12.16's 545 syscalls, not the production kernel).
pub(super) struct DynamicRoot {
    root: FixtureRoot,
    executable: &'static str,
    executable_link: PathBuf,
    fds: BTreeMap<u32, Descriptor>,
    next_map: u64,
    program_break: u64,
    exec_maps: Vec<Mapping>,
    opened: BTreeMap<PathBuf, u64>,
    pub(super) answered: u64,
    pub(super) stdout: Vec<u8>,
    started: Instant,
    signal_actions: BTreeMap<u64, [u8; size_of::<LinuxSigaction>()]>,
    signal_mask: u64,
    altstack: [u8; size_of::<LinuxSigaltstack>()],
}

fn fields(meta: &Metadata) -> LinuxStatFields {
    LinuxStatFields {
        ino: meta.ino(),
        mode: meta.mode(),
        nlink: meta.nlink() as u32,
        uid: meta.uid(),
        gid: meta.gid(),
        rdev: meta.rdev(),
        size: meta.size(),
        blocks: Some(meta.blocks()),
        atime: (meta.atime(), meta.atime_nsec()),
        mtime: (meta.mtime(), meta.mtime_nsec()),
        ctime: (meta.ctime(), meta.ctime_nsec()),
    }
}

fn errno(error: io::Error) -> i64 {
    -i64::from(error.raw_os_error().unwrap_or(LINUX_EIO.get()))
}

fn copy(memory: &mut Pages, address: u64, bytes: &[u8]) -> i64 {
    use carrick_softcpu_aarch64::handler::GuestMemory;
    match memory.write(VirtualAddress(address), bytes) {
        Ok(()) => 0,
        Err(_) => LINUX_EFAULT.guest_retval(),
    }
}

impl DynamicRoot {
    pub(super) fn new(root: FixtureRoot, executable: &'static str) -> Self {
        let fds = (0..=2)
            .map(|fd| {
                (
                    fd,
                    Descriptor {
                        file: Rc::new(OpenFile {
                            path: PathBuf::new(),
                            object: Object::Stdio(fd),
                            fields: LinuxStatFields::synthetic(
                                [b"stdin".as_slice(), b"stdout", b"stderr"][fd as usize],
                                LINUX_S_IFIFO | 0o600,
                            ),
                            status: Cell::new(u64::from(fd != 0)),
                        }),
                        cloexec: false,
                    },
                )
            })
            .collect();
        let executable_link = Path::new("/").join(
            root.resolve(Path::new(""), Path::new(executable), true)
                .unwrap(),
        );
        Self {
            root,
            executable,
            executable_link,
            fds,
            next_map: LINUX_MMAP_BASE,
            program_break: LINUX_HEAP_BASE,
            exec_maps: Vec::new(),
            opened: BTreeMap::new(),
            answered: 0,
            stdout: Vec::new(),
            started: Instant::now(),
            signal_actions: BTreeMap::new(),
            signal_mask: 0,
            altstack: LinuxSigaltstack::disabled().abi_bytes().try_into().unwrap(),
        }
    }

    fn fd(&self, fd: u64) -> io::Result<&Descriptor> {
        self.fds
            .get(&(fd as u32))
            .ok_or_else(|| io::Error::from_raw_os_error(LINUX_EBADF.get()))
    }

    fn resolve(&self, dir: u64, path: &[u8], follow: bool) -> io::Result<PathBuf> {
        if path.is_empty() {
            return Err(io::Error::from_raw_os_error(LINUX_ENOENT.get()));
        }
        let path = Path::new(std::ffi::OsStr::from_bytes(path));
        let base = if path.is_absolute() || dir as u32 == LINUX_AT_FDCWD as u32 {
            Path::new("")
        } else {
            let file = &self.fd(dir)?.file;
            if !matches!(file.object, Object::Directory { .. }) {
                return Err(io::Error::from_raw_os_error(LINUX_ENOTDIR.get()));
            }
            &file.path
        };
        self.root.resolve(base, path, follow)
    }

    fn install(&mut self, memory: &mut Pages, min: u32, descriptor: Descriptor) -> i64 {
        let Some(fd) = (min..FD_LIMIT).find(|fd| !self.fds.contains_key(fd)) else {
            return LINUX_EMFILE.guest_retval();
        };
        let flags = if matches!(descriptor.file.object, Object::Stdio(1 | 2)) {
            DELEGATED_FLAG_WRITABLE
        } else {
            DELEGATED_FLAG_READABLE
        };
        bind_host_fixture_fd(
            memory,
            fd,
            flags,
            HostObjectBinding::from_host_fd(HostBoundFd::new(fd as i32).unwrap()),
            descriptor.cloexec,
        );
        self.fds.insert(fd, descriptor);
        i64::from(fd)
    }

    fn open(&mut self, memory: &mut Pages, dir: u64, path: &[u8], flags: u64) -> io::Result<i64> {
        if flags & (LINUX_O_ACCMODE | LINUX_O_CREAT | LINUX_O_TRUNC) != 0 {
            return Err(io::Error::from_raw_os_error(LINUX_EROFS.get()));
        }
        let path = self.resolve(dir, path, flags & LINUX_O_NOFOLLOW == 0)?;
        let host = self.root.0.join(&path);
        let meta = fs::symlink_metadata(&host)?;
        let object = if meta.is_dir() {
            Object::Directory {
                records: dirents(&host, &self.root.0)?,
                cursor: Cell::new(0),
            }
        } else if flags & LINUX_O_DIRECTORY != 0 {
            return Err(io::Error::from_raw_os_error(LINUX_ENOTDIR.get()));
        } else if meta.is_file() {
            Object::File(RefCell::new(File::open(host)?))
        } else {
            return Err(io::Error::from_raw_os_error(LINUX_ELOOP.get()));
        };
        let descriptor = Descriptor {
            file: Rc::new(OpenFile {
                path: path.clone(),
                object,
                fields: fields(&meta),
                status: Cell::new(flags & !(LINUX_O_CLOEXEC | LINUX_O_NOFOLLOW)),
            }),
            cloexec: flags & LINUX_O_CLOEXEC != 0,
        };
        let fd = self.install(memory, 0, descriptor);
        if fd >= 0 {
            *self.opened.entry(path).or_default() += 1;
        }
        Ok(fd)
    }

    fn stat(&self, dir: u64, path: &[u8], flags: u64) -> io::Result<LinuxStatFields> {
        if path.is_empty() && flags & LINUX_AT_EMPTY_PATH != 0 {
            if dir as u32 == LINUX_AT_FDCWD as u32 {
                return fs::metadata(&self.root.0).map(|meta| fields(&meta));
            }
            return Ok(self.fd(dir)?.file.fields);
        }
        let path = self.resolve(dir, path, flags & LINUX_AT_SYMLINK_NOFOLLOW == 0)?;
        fs::symlink_metadata(self.root.0.join(path)).map(|meta| fields(&meta))
    }

    fn read(
        &self,
        memory: &mut Pages,
        fd: u64,
        dst: u64,
        len: u64,
        offset: Option<u64>,
    ) -> io::Result<i64> {
        let file = &self.fd(fd)?.file;
        let Object::File(file) = &file.object else {
            return match file.object {
                Object::Stdio(0) => Ok(0),
                Object::Stdio(_) => Ok(LINUX_EBADF.guest_retval()),
                _ => Ok(LINUX_EISDIR.guest_retval()),
            };
        };
        let mut bytes = vec![0; len.min(MAX_IO) as usize];
        let n = match offset {
            Some(at) => file.borrow().read_at(&mut bytes, at)?,
            None => file.borrow_mut().read(&mut bytes)?,
        };
        Ok(copy_count(memory, dst, &bytes[..n]))
    }

    fn getdents(&self, memory: &mut Pages, fd: u64, dst: u64, len: u64) -> io::Result<i64> {
        let file = &self.fd(fd)?.file;
        let Object::Directory { records, cursor } = &file.object else {
            return Ok(LINUX_ENOTDIR.guest_retval());
        };
        let start = cursor.get();
        let mut bytes = Vec::new();
        let mut end = start;
        for record in &records[start..] {
            if bytes.len() as u64 + record.len() as u64 > len.min(MAX_IO) {
                if end == start {
                    return Ok(LINUX_EINVAL.guest_retval());
                }
                break;
            }
            bytes.extend_from_slice(record);
            end += 1;
        }
        let result = copy_count(memory, dst, &bytes);
        if result >= 0 {
            cursor.set(end);
        }
        Ok(result)
    }

    fn seek(&self, fd: u64, offset: u64, whence: u64) -> io::Result<i64> {
        let file = &self.fd(fd)?.file;
        match &file.object {
            Object::File(file) => {
                let from = match whence {
                    LINUX_SEEK_SET if offset as i64 >= 0 => SeekFrom::Start(offset),
                    LINUX_SEEK_CUR => SeekFrom::Current(offset as i64),
                    LINUX_SEEK_END => SeekFrom::End(offset as i64),
                    _ => return Ok(LINUX_EINVAL.guest_retval()),
                };
                file.borrow_mut().seek(from).map(|position| position as i64)
            }
            Object::Directory { records, cursor }
                if whence == LINUX_SEEK_SET && offset <= records.len() as u64 =>
            {
                cursor.set(offset as usize);
                Ok(offset as i64)
            }
            Object::Directory { .. } => Ok(LINUX_EINVAL.guest_retval()),
            Object::Stdio(_) => Ok(LINUX_ESPIPE.guest_retval()),
        }
    }

    fn fcntl(&mut self, memory: &mut Pages, fd: u64, operation: u64, arg: u64) -> io::Result<i64> {
        let entry = self.fd(fd)?;
        Ok(match operation {
            LINUX_F_DUPFD | LINUX_F_DUPFD_CLOEXEC if arg < u64::from(FD_LIMIT) => {
                let descriptor = Descriptor {
                    file: Rc::clone(&entry.file),
                    cloexec: operation == LINUX_F_DUPFD_CLOEXEC,
                };
                self.install(memory, arg as u32, descriptor)
            }
            LINUX_F_GETFD => i64::from(entry.cloexec),
            LINUX_F_GETFL => entry.file.status.get() as i64,
            LINUX_F_SETFL => {
                let mutable = LINUX_O_APPEND | LINUX_O_NONBLOCK;
                entry
                    .file
                    .status
                    .set((entry.file.status.get() & !mutable) | (arg & mutable));
                0
            }
            LINUX_F_SETFD => {
                self.fds.get_mut(&(fd as u32)).unwrap().cloexec = arg & LINUX_FD_CLOEXEC != 0;
                0
            }
            _ => LINUX_EINVAL.guest_retval(),
        })
    }

    fn mmap(&mut self, memory: &mut Pages, args: [u64; 6]) -> io::Result<i64> {
        let [hint, len, prot, flags, fd, offset] = args;
        // A read-only shared file can use the same snapshot of the static root.
        if len == 0
            || len > MAX_MAPPING
            || !offset.is_multiple_of(PAGE)
            || !matches!(
                flags & (LINUX_MAP_PRIVATE | LINUX_MAP_SHARED),
                LINUX_MAP_PRIVATE | LINUX_MAP_SHARED
            )
            || (flags & LINUX_MAP_SHARED != 0
                && (flags & LINUX_MAP_ANONYMOUS != 0 || prot & LINUX_PROT_WRITE != 0))
        {
            return Ok(LINUX_EINVAL.guest_retval());
        }
        let len = len.next_multiple_of(PAGE);
        let fixed = flags & LINUX_MAP_FIXED != 0;
        let addr = if fixed { hint } else { self.next_map };
        let Some(end) = addr
            .checked_add(len)
            .filter(|end| *end <= LINUX_MMAP_BASE + MAX_MAPPING)
        else {
            return Ok(LINUX_ENOMEM.guest_retval());
        };
        if !addr.is_multiple_of(PAGE) || addr < LINUX_MMAP_BASE || (fixed && end > self.next_map) {
            return Ok(LINUX_EINVAL.guest_retval());
        }
        let data = if flags & LINUX_MAP_ANONYMOUS == 0 {
            let file = &self.fd(fd)?.file;
            let Object::File(source) = &file.object else {
                return Ok(LINUX_ENODEV.guest_retval());
            };
            let mut bytes = vec![0; len.min(file.fields.size.saturating_sub(offset)) as usize];
            source.borrow().read_exact_at(&mut bytes, offset)?;
            Some((file.path.clone(), bytes))
        } else {
            None
        };
        if !fixed {
            self.next_map = end;
        }
        for page in (addr..end).step_by(PAGE as usize) {
            memory.unmap(page);
            memory.map_zero(page);
        }
        if let Some((path, bytes)) = data {
            memory.load(addr, &bytes);
            if prot & LINUX_PROT_EXEC != 0 {
                self.exec_maps.push(Mapping {
                    start: addr,
                    len,
                    offset,
                    path,
                });
            }
        }
        protect(memory, addr, len, prot);
        Ok(addr as i64)
    }

    fn brk(&mut self, memory: &mut Pages, requested: u64) -> i64 {
        if (LINUX_HEAP_BASE..=LINUX_HEAP_BASE + MAX_MAPPING).contains(&requested) {
            let old_end = self.program_break.next_multiple_of(PAGE);
            let new_end = requested.next_multiple_of(PAGE);
            if new_end > old_end {
                for page in (old_end..new_end).step_by(PAGE as usize) {
                    memory.map_zero(page);
                }
                protect(memory, old_end, new_end - old_end, LINUX_PROT_WRITE);
            } else if new_end < old_end {
                protect(memory, new_end, old_end - new_end, 0);
                for page in (new_end..old_end).step_by(PAGE as usize) {
                    memory.unmap(page);
                }
            }
            self.program_break = requested;
        }
        self.program_break as i64
    }

    fn readlink(
        &self,
        memory: &mut Pages,
        dir: u64,
        path: &[u8],
        dst: u64,
        len: u64,
    ) -> io::Result<i64> {
        if len == 0 {
            return Ok(LINUX_EINVAL.guest_retval());
        }
        let path = if path == b"/proc/self/exe" {
            self.executable_link.clone()
        } else {
            let path = self.resolve(dir, path, false)?;
            fs::read_link(self.root.0.join(path))?
        };
        let bytes = path.as_os_str().as_bytes();
        Ok(copy_count(
            memory,
            dst,
            &bytes[..bytes.len().min(len as usize)],
        ))
    }

    fn write(&mut self, memory: &mut Pages, fd: u64, addr: u64, len: u64) -> io::Result<i64> {
        use carrick_softcpu_aarch64::handler::GuestMemory;
        let file = &self.fd(fd)?.file;
        let Object::Stdio(stream @ (1 | 2)) = file.object else {
            return Ok(LINUX_EBADF.guest_retval());
        };
        let mut bytes = vec![0; len.min(MAX_IO) as usize];
        if memory.read(VirtualAddress(addr), &mut bytes).is_err() {
            return Ok(LINUX_EFAULT.guest_retval());
        }
        if stream == 1 {
            self.stdout.extend_from_slice(&bytes);
        } else {
            println!("guest stderr={:?}", String::from_utf8_lossy(&bytes));
        }
        Ok(bytes.len() as i64)
    }

    fn clock(&self, memory: &mut Pages, clock: u64, dst: u64) -> i64 {
        let t = match clock {
            0 | 5 => SystemTime::now().duration_since(UNIX_EPOCH).unwrap(),
            1 | 4 | 6 | 7 => self.started.elapsed(),
            _ => return LINUX_EINVAL.guest_retval(),
        };
        copy(
            memory,
            dst,
            LinuxTimespec::new(t.as_secs() as i64, i64::from(t.subsec_nanos())).abi_bytes(),
        )
    }

    fn signal(&mut self, memory: &mut Pages, name: &str, args: [u64; 6]) -> i64 {
        use carrick_softcpu_aarch64::handler::GuestMemory;
        let [a, b, c, d, ..] = args;
        match name {
            "rt_sigaction" if (1..=64).contains(&a) && d == LINUX_RT_SIGSET_SIZE => {
                let mut next = [0; size_of::<LinuxSigaction>()];
                if b != 0 {
                    if matches!(a as i32, LINUX_SIGKILL | LINUX_SIGSTOP) {
                        return LINUX_EINVAL.guest_retval();
                    }
                    if memory.read(VirtualAddress(b), &mut next).is_err() {
                        return LINUX_EFAULT.guest_retval();
                    }
                }
                let current = self
                    .signal_actions
                    .get(&a)
                    .unwrap_or(&[0; size_of::<LinuxSigaction>()]);
                if c != 0 && copy(memory, c, current) != 0 {
                    return LINUX_EFAULT.guest_retval();
                }
                if b != 0 {
                    self.signal_actions.insert(a, next);
                }
            }
            "rt_sigprocmask" if d == LINUX_RT_SIGSET_SIZE => {
                let mut next = self.signal_mask;
                if b != 0 {
                    let mut bytes = [0; 8];
                    if memory.read(VirtualAddress(b), &mut bytes).is_err() {
                        return LINUX_EFAULT.guest_retval();
                    }
                    let bits = u64::from_le_bytes(bytes);
                    next = match a {
                        LINUX_SIG_BLOCK => next | bits,
                        LINUX_SIG_UNBLOCK => next & !bits,
                        LINUX_SIG_SETMASK => bits,
                        _ => return LINUX_EINVAL.guest_retval(),
                    };
                }
                if c != 0 && copy(memory, c, &self.signal_mask.to_le_bytes()) != 0 {
                    return LINUX_EFAULT.guest_retval();
                }
                self.signal_mask =
                    next & !((1 << (LINUX_SIGKILL - 1)) | (1 << (LINUX_SIGSTOP - 1)));
            }
            "sigaltstack" => {
                let mut next = self.altstack;
                if a != 0 && memory.read(VirtualAddress(a), &mut next).is_err() {
                    return LINUX_EFAULT.guest_retval();
                }
                if b != 0 && copy(memory, b, &self.altstack) != 0 {
                    return LINUX_EFAULT.guest_retval();
                }
                self.altstack = next;
            }
            _ => return LINUX_EINVAL.guest_retval(),
        }
        0
    }

    fn sysinfo(&self) -> LinuxSysinfo {
        LinuxSysinfo {
            uptime: self.started.elapsed().as_secs() as i64,
            loads: [0; 3],
            totalram: 512 * 1024 * 1024,
            freeram: 256 * 1024 * 1024,
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

    pub(super) fn reply(
        &mut self,
        memory: &mut Pages,
        name: &str,
        args: [u64; 6],
    ) -> Result<i64, String> {
        let [a, b, c, d, e, _] = args;
        let result = match name {
            "brk" => Ok(self.brk(memory, a)),
            "mmap" => self.mmap(memory, args),
            "mprotect" | "munmap" => {
                if !a.is_multiple_of(PAGE)
                    || b == 0
                    || b > MAX_MAPPING
                    || a.checked_add(b).is_none()
                {
                    return Ok(LINUX_EINVAL.guest_retval());
                }
                if name == "munmap" {
                    protect(memory, a, b, 0);
                    for page in (a..a + b).step_by(PAGE as usize) {
                        memory.unmap(page);
                    }
                } else {
                    protect(memory, a, b, c);
                }
                Ok(0)
            }
            "openat" => {
                let path = read_cstr(memory, b, 4096);
                println!("  openat path={:?}", String::from_utf8_lossy(&path));
                self.open(memory, a, &path, c)
            }
            "read" | "pread64" => self.read(memory, a, b, c, (name == "pread64").then_some(d)),
            "getdents64" => self.getdents(memory, a, b, c),
            "lseek" => self.seek(a, b, c),
            "fstat" => self.fd(a).map(|fd| {
                copy(
                    memory,
                    b,
                    LinuxStat::from_fields(&fd.file.fields).abi_bytes(),
                )
            }),
            "newfstatat" | "statx" => {
                let path = if b == 0 && name == "statx" && c & LINUX_AT_EMPTY_PATH != 0 {
                    Vec::new()
                } else {
                    read_cstr(memory, b, 4096)
                };
                if name == "statx" {
                    self.stat(a, &path, c)
                        .map(|fields| copy(memory, e, LinuxStatx::from_fields(&fields).abi_bytes()))
                } else {
                    self.stat(a, &path, d)
                        .map(|fields| copy(memory, c, LinuxStat::from_fields(&fields).abi_bytes()))
                }
            }
            "close" => {
                let closed = self.fds.remove(&(a as u32));
                if closed.is_some() {
                    super::unbind_host_fixture_fd(memory, a as u32);
                }
                Ok(if closed.is_some() {
                    0
                } else {
                    LINUX_EBADF.guest_retval()
                })
            }
            "faccessat" | "faccessat2" => {
                let path = read_cstr(memory, b, 4096);
                self.stat(a, &path, if name == "faccessat2" { d } else { 0 })
                    .map(|fields| {
                        if c & 2 != 0 || (c & 1 != 0 && fields.mode & 0o111 == 0) {
                            LINUX_EACCES.guest_retval()
                        } else {
                            0
                        }
                    })
            }
            // CPython may try to create a __pycache__ alongside a source import.
            "mkdirat" | "renameat" | "renameat2" | "unlinkat" => Ok(LINUX_EROFS.guest_retval()),
            "readlinkat" => {
                let path = read_cstr(memory, b, 4096);
                self.readlink(memory, a, &path, c, d)
            }
            "getcwd" => Ok(if b < CWD.len() as u64 {
                LINUX_ERANGE.guest_retval()
            } else {
                copy_count(memory, a, CWD)
            }),
            "ioctl" if b == LINUX_TCGETS => self.fd(a).map(|_| LINUX_ENOTTY.guest_retval()),
            "fcntl" => self.fcntl(memory, a, b, c),
            "dup" => self.fcntl(memory, a, LINUX_F_DUPFD, 0),
            "getpid" | "gettid" | "set_tid_address" => Ok(1),
            "getuid" | "geteuid" | "getgid" | "getegid" => Ok(0),
            "set_robust_list" => Ok(0),
            "rseq" => Ok(LINUX_ENOSYS.guest_retval()),
            "prlimit64" if a == 0 && c == 0 => {
                let limit = match b {
                    LINUX_RLIMIT_STACK => LinuxRlimit::new(LINUX_STACK_SIZE, u64::MAX),
                    LINUX_RLIMIT_NOFILE => {
                        LinuxRlimit::new(u64::from(FD_LIMIT), u64::from(FD_LIMIT))
                    }
                    _ => return Err(format!("unlisted {name} resource {b} args={args:x?}")),
                };
                Ok(copy(memory, d, limit.abi_bytes()))
            }
            "getrandom" => Ok(copy_count(memory, a, &vec![0x9d; b.min(MAX_IO) as usize])),
            "clock_gettime" => Ok(self.clock(memory, a, b)),
            "futex" if b & !LINUX_FUTEX_PRIVATE_FLAG == LINUX_FUTEX_WAKE => Ok(0),
            "rt_sigaction" | "rt_sigprocmask" | "sigaltstack" => {
                Ok(self.signal(memory, name, args))
            }
            "sysinfo" => Ok(copy(memory, a, self.sysinfo().abi_bytes())),
            "uname" => Ok(copy(memory, a, LinuxUtsname::carrick_aarch64().abi_bytes())),
            "write" => self.write(memory, a, b, c),
            _ => return Err(format!("unlisted mailbox syscall {name} {args:x?}")),
        };
        self.answered += 1;
        Ok(result.unwrap_or_else(errno))
    }

    pub(super) fn count_terminal_exit(&mut self) {
        self.answered += 1;
    }

    /// Report resolved IFUNC imports by reading the applied ELF relocations.
    pub(super) fn report_ifuncs(
        &self,
        memory: &mut Pages,
        program: &carrick_mem::elf::ElfProgram<'_>,
    ) -> usize {
        use carrick_softcpu_aarch64::handler::GuestMemory;
        use goblin::elf::{Elf, program_header::PT_LOAD, sym::STT_GNU_IFUNC};

        let Some(libc) = self
            .exec_maps
            .iter()
            .find(|map| map.path.ends_with("libc.so.6"))
        else {
            return 0;
        };
        let libc_bytes = fs::read(self.root.0.join(&libc.path)).unwrap();
        let libc_elf = Elf::parse(&libc_bytes).unwrap();
        let ifuncs: std::collections::BTreeSet<_> = libc_elf
            .dynsyms
            .iter()
            .filter(|sym| sym.st_type() == STT_GNU_IFUNC)
            .filter_map(|sym| libc_elf.dynstrtab.get_at(sym.st_name))
            .collect();
        let mut count = 0;
        let mut inspect = |image: &Path, bytes: &[u8], bias: u64| {
            let elf = Elf::parse(bytes).unwrap();
            for rel in elf.pltrelocs.iter().chain(elf.dynrelas.iter()) {
                let Some(name) = elf
                    .dynsyms
                    .get(rel.r_sym)
                    .and_then(|sym| elf.dynstrtab.get_at(sym.st_name))
                    .filter(|name| ifuncs.contains(name))
                else {
                    continue;
                };
                let mut bytes = [0; 8];
                if memory
                    .read(VirtualAddress(bias + rel.r_offset), &mut bytes)
                    .is_err()
                {
                    continue;
                }
                let target = u64::from_le_bytes(bytes);
                let Some((source, offset)) = self.image_at(target) else {
                    continue;
                };
                if source == libc.path && source != image {
                    println!(
                        "IFUNC /{} {name}: guest={target:#x} libc file offset={offset:#x}",
                        image.display()
                    );
                    count += 1;
                }
            }
        };
        inspect(
            Path::new(self.executable.trim_start_matches('/')),
            program.executable_bytes,
            program.executable.load_bias,
        );
        for map in &self.exec_maps {
            if map.path == libc.path {
                continue;
            }
            let bytes = fs::read(self.root.0.join(&map.path)).unwrap();
            let Ok(elf) = Elf::parse(&bytes) else {
                continue;
            };
            if let Some(segment) = elf.program_headers.iter().find(|ph| {
                ph.p_type == PT_LOAD
                    && ph.p_flags & 1 != 0
                    && ph.p_offset / PAGE == map.offset / PAGE
            }) {
                let bias = map.start - segment.p_vaddr / PAGE * PAGE;
                inspect(&map.path, &bytes, bias);
            }
        }
        count
    }

    pub(super) fn retire_ring_close(&mut self, fd: u64) {
        self.fds.remove(&(fd as u32));
    }

    pub(super) fn report_opens(&self) {
        for (path, count) in &self.opened {
            println!("opened {count} /{}", path.display());
        }
    }

    pub(super) fn image_at(&self, pc: u64) -> Option<(&Path, u64)> {
        let map = self
            .exec_maps
            .iter()
            .rev()
            .find(|map| (map.start..map.start + map.len).contains(&pc))?;
        Some((&map.path, pc - map.start + map.offset))
    }
}

fn copy_count(memory: &mut Pages, dst: u64, bytes: &[u8]) -> i64 {
    if copy(memory, dst, bytes) < 0 {
        LINUX_EFAULT.guest_retval()
    } else {
        bytes.len() as i64
    }
}

fn dirents(host: &Path, root: &Path) -> io::Result<Vec<Vec<u8>>> {
    let mut entries = vec![
        (OsString::from("."), fs::symlink_metadata(host)?),
        (
            OsString::from(".."),
            fs::symlink_metadata(
                host.parent()
                    .filter(|parent| parent.starts_with(root))
                    .unwrap_or(root),
            )?,
        ),
    ];
    for item in fs::read_dir(host)? {
        let item = item?;
        entries.push((item.file_name(), fs::symlink_metadata(item.path())?));
    }
    entries[2..].sort_by(|a, b| a.0.cmp(&b.0));
    Ok(entries
        .into_iter()
        .enumerate()
        .map(|(i, (name, meta))| {
            let name = name.into_vec();
            let len = (size_of::<LinuxDirent64Header>() + name.len() + 1).next_multiple_of(8);
            let file_type = meta.file_type();
            let kind = if file_type.is_dir() {
                LINUX_DT_DIR
            } else if file_type.is_symlink() {
                LINUX_DT_LNK
            } else if file_type.is_file() {
                LINUX_DT_REG
            } else {
                0
            };
            let header = LinuxDirent64Header {
                d_ino: meta.ino(),
                d_off: (i + 1) as i64,
                d_reclen: len as u16,
                d_type: kind,
            };
            let mut record = Vec::with_capacity(len);
            record.extend_from_slice(header.abi_bytes());
            record.extend_from_slice(&name);
            record.resize(len, 0);
            record
        })
        .collect())
}

fn protect(memory: &mut Pages, addr: u64, len: u64, prot: u64) {
    use carrick_mem::memory::{
        AARCH64_LINUX_PAGE_TABLE_LAYOUT, LINUX_PAGE_TABLES_BASE, LINUX_PAGE_TABLES_SIZE,
    };
    use carrick_mmu_core::aarch64::PageTableManager;
    use carrick_softcpu_aarch64::handler::GuestMemory;
    let mut raw = vec![0; LINUX_PAGE_TABLES_SIZE as usize];
    memory
        .read(VirtualAddress(LINUX_PAGE_TABLES_BASE), &mut raw)
        .unwrap();
    let mut tables =
        PageTableManager::new(raw, LINUX_PAGE_TABLES_BASE, AARCH64_LINUX_PAGE_TABLE_LAYOUT);
    let len = len.next_multiple_of(PAGE) as usize;
    let exec = prot & LINUX_PROT_EXEC != 0;
    match prot {
        0 => tables.set_prot_none(addr, len, None),
        p if p & LINUX_PROT_WRITE != 0 => tables.set_rw(addr, len, exec, None),
        _ => tables.set_readonly(addr, len, exec, None),
    }
    .unwrap();
    memory.load(
        LINUX_PAGE_TABLES_BASE,
        &tables.into_occupied_bytes().unwrap(),
    );
}
