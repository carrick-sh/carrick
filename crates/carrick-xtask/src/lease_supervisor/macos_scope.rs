//! Darwin has no child subreaper. Session or kernel pipe identity selects work.
//! A detached descendant closing every inherited writer escapes this scope;
//! the ignored close-all-fds regression pins that unsupported topology.
//! Process start time is rechecked before signaling. The final proc_pidinfo to
//! kill window remains: Darwin's PID-only kill is not an atomic incarnation API.

use super::ProcessIncarnation;
use std::collections::BTreeMap;
use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};

// libc exposes proc_pidfdinfo and vinfo_stat, but not these sys/proc_info.h
// layouts or PROC_PIDFDPIPEINFO. Keep the native ABI here, outside guest ABI.
#[repr(C)]
struct FileInfo {
    open_flags: u32,
    status: u32,
    offset: libc::off_t,
    kind: i32,
    guard_flags: u32,
}

#[repr(C)]
struct PipeInfo {
    stat: libc::vinfo_stat,
    handle: u64,
    peer_handle: u64,
    status: i32,
    reserved: i32,
}

#[repr(C)]
struct PipeFdInfo {
    file: FileInfo,
    pipe: PipeInfo,
}

fn pipe_info(pid: libc::pid_t, fd: libc::c_int) -> io::Result<PipeFdInfo> {
    let mut info = std::mem::MaybeUninit::<PipeFdInfo>::zeroed();
    let size = size_of::<PipeFdInfo>() as libc::c_int;
    // SAFETY: matching sys/proc_info.h pipe_fdinfo output, valid buffer size.
    let got = unsafe { libc::proc_pidfdinfo(pid, fd, 6, info.as_mut_ptr().cast(), size) };
    if got != size {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: full structure was initialized by libproc.
    Ok(unsafe { info.assume_init() })
}

pub(super) struct PipeWriter(u64);

impl PipeWriter {
    pub(super) fn from_reader(fd: libc::c_int) -> io::Result<Self> {
        Ok(Self(
            pipe_info(std::process::id() as libc::pid_t, fd)?
                .pipe
                .peer_handle,
        ))
    }

    fn owns_writer(&self, pid: libc::pid_t) -> bool {
        // SAFETY: libproc size query with no output buffer.
        let size =
            unsafe { libc::proc_pidinfo(pid, libc::PROC_PIDLISTFDS, 0, std::ptr::null_mut(), 0) };
        if size <= 0 {
            return false;
        }
        let mut capacity = size as usize / size_of::<libc::proc_fdinfo>() + 16;
        loop {
            let mut fds = vec![
                libc::proc_fdinfo {
                    proc_fd: 0,
                    proc_fdtype: 0
                };
                capacity
            ];
            let bytes = match i32::try_from(capacity * size_of::<libc::proc_fdinfo>()) {
                Ok(bytes) => bytes,
                Err(_) => return false,
            };
            // SAFETY: owned, correctly sized descriptor-info output storage.
            let got = unsafe {
                libc::proc_pidinfo(
                    pid,
                    libc::PROC_PIDLISTFDS,
                    0,
                    fds.as_mut_ptr().cast(),
                    bytes,
                )
            };
            if got <= 0 {
                return false;
            }
            if got == bytes {
                capacity *= 2;
                continue;
            }
            return fds[..got as usize / size_of::<libc::proc_fdinfo>()]
                .iter()
                .any(|fd| {
                    fd.proc_fdtype == libc::PROX_FDTYPE_PIPE as u32
                        && pipe_info(pid, fd.proc_fd).is_ok_and(|info| info.pipe.handle == self.0)
                });
        }
    }

    pub(super) fn cancel(
        &self,
        session: libc::pid_t,
        members: &mut BTreeMap<ProcessIncarnation, ProcessWatch>,
        deadline: &super::CleanupDeadline,
    ) -> io::Result<()> {
        loop {
            deadline.remaining()?;
            let mut changed = false;
            for pid in all_pids()? {
                if pid <= 0 || (unsafe { libc::getsid(pid) } != session && !self.owns_writer(pid)) {
                    continue;
                }
                let Some(info) = process_info(pid)? else {
                    continue;
                };
                let identity = info.identity;
                // SAFETY: native session query. Pipe identity covers setsid
                // while at least one scope descriptor remains open.
                if pid > 0
                    && (unsafe { libc::getsid(pid) } == session || self.owns_writer(pid))
                    && let std::collections::btree_map::Entry::Vacant(entry) =
                        members.entry(identity)
                    && let Some(process) = ProcessWatch::new(identity)?
                {
                    entry.insert(process);
                    changed = true;
                }
            }
            let mut pending = false;
            for process in members.values_mut() {
                if !process.exited()? {
                    pending = true;
                    process.cancel()?;
                }
            }
            // Another census after all known members exited closes forks made
            // before SIGKILL delivery. No SIGSTOP is issued: EPERM helpers keep
            // running to natural exit while exclusion and exit watches stay live.
            if !changed && !pending {
                return Ok(());
            }
            deadline.next_observation(std::time::Duration::from_millis(10))?;
        }
    }
}

pub(super) struct ProcessWatch {
    identity: ProcessIncarnation,
    queue: Option<OwnedFd>,
    permission_reported: bool,
}

impl ProcessWatch {
    fn new(identity: ProcessIncarnation) -> io::Result<Option<Self>> {
        // SAFETY: uniquely owned kqueue; process exit events bind to the
        // registered process, rather than a later occupant of its numeric PID.
        let fd = unsafe { libc::kqueue() };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        let queue = unsafe { OwnedFd::from_raw_fd(fd) };
        if unsafe { libc::fcntl(fd, libc::F_SETFD, libc::FD_CLOEXEC) } < 0 {
            return Err(io::Error::last_os_error());
        }
        let mut event = unsafe { std::mem::zeroed::<libc::kevent>() };
        event.ident = identity.pid as _;
        event.filter = libc::EVFILT_PROC;
        event.flags = libc::EV_ADD | libc::EV_ENABLE;
        event.fflags = libc::NOTE_EXIT;
        let queue = if unsafe {
            libc::kevent(fd, &event, 1, std::ptr::null_mut(), 0, std::ptr::null())
        } < 0
        {
            let error = io::Error::last_os_error();
            if !matches!(error.raw_os_error(), Some(libc::ESRCH) | Some(libc::EPERM)) {
                return Err(error);
            }
            // Privileged helpers can deny the exit watch as well as signaling.
            // Native start-time/status observations still keep exclusion held.
            None
        } else {
            Some(queue)
        };
        if !identity.present(observe(identity.pid)?) {
            return Ok(None);
        }
        Ok(Some(Self {
            identity,
            queue,
            permission_reported: false,
        }))
    }

    fn cancel(&mut self) -> io::Result<()> {
        let result = self.identity.signal(libc::SIGKILL, observe, |pid, signal| {
            // SAFETY: incarnation checked immediately before this PID-only
            // call. The documented final query-to-kill window remains.
            if unsafe { libc::kill(pid, signal) } == 0 {
                Ok(())
            } else {
                Err(io::Error::last_os_error())
            }
        });
        match result {
            Err(error) if error.raw_os_error() == Some(libc::EPERM) => {
                if !self.permission_reported {
                    eprintln!(
                        "host-lease: privileged descendant {} refused cancellation; awaiting its exit with exclusion held",
                        self.identity.pid
                    );
                    self.permission_reported = true;
                }
                Ok(())
            }
            Err(error) if error.raw_os_error() == Some(libc::ESRCH) => Ok(()),
            result => result,
        }
    }

    fn exited(&self) -> io::Result<bool> {
        if let Some(queue) = &self.queue {
            let mut event = unsafe { std::mem::zeroed::<libc::kevent>() };
            let timeout = libc::timespec {
                tv_sec: 0,
                tv_nsec: 0,
            };
            let result = unsafe {
                libc::kevent(
                    queue.as_raw_fd(),
                    std::ptr::null(),
                    0,
                    &mut event,
                    1,
                    &timeout,
                )
            };
            if result < 0 {
                return Err(io::Error::last_os_error());
            }
            if result > 0 && event.fflags & libc::NOTE_EXIT != 0 {
                return Ok(true);
            }
        }
        let Some(info) = process_info(self.identity.pid)? else {
            return Ok(true);
        };
        Ok(!self.identity.present(Some(info.identity)) || info.status == libc::SZOMB)
    }

    pub(super) fn reaped(&self) -> io::Result<bool> {
        // A replacement is never waited upon or signaled with kill(pid, 0).
        Ok(!self.identity.present(observe(self.identity.pid)?))
    }
}

struct NativeProcessInfo {
    identity: ProcessIncarnation,
    status: u32,
}

fn observe(pid: libc::pid_t) -> io::Result<Option<ProcessIncarnation>> {
    Ok(process_info(pid)?.map(|info| info.identity))
}

// Native proc_info_private.h API layout (56 bytes), absent from libc. Unlike
// full BSD info, unique identity and SHORTBSDINFO do not require matching UID.
#[repr(C)]
struct UniqueInfo {
    _executable_uuid: [u8; 16],
    unique_id: u64,
    _parent_unique_id: u64,
    _pid_version: i32,
    _original_parent_version: i32,
    _reserved: [u64; 2],
}
const _: () = assert!(size_of::<UniqueInfo>() == 56);

// Native sys/proc_info.h public short-BSD layout, added to newer libc versions
// than this workspace pins. Keep its ABI qualification beside the unique ID.
#[repr(C)]
struct ShortInfo {
    _pid: u32,
    _parent: u32,
    _group: u32,
    status: u32,
    _name: [libc::c_char; 16],
    _flags: u32,
    _uids_and_gids: [u32; 6],
    _reserved: u32,
}
const _: () = assert!(size_of::<ShortInfo>() == 64);

fn unique_info(pid: libc::pid_t) -> io::Result<Option<UniqueInfo>> {
    let mut info = std::mem::MaybeUninit::<UniqueInfo>::zeroed();
    let size = size_of::<UniqueInfo>() as libc::c_int;
    // SAFETY: matching native PROC_PIDUNIQIDENTIFIERINFO (17) ABI output.
    // arg=1 includes zombies: exit alone must not certify completed reaping.
    let got = unsafe { libc::proc_pidinfo(pid, 17, 1, info.as_mut_ptr().cast(), size) };
    if got == size {
        return Ok(Some(unsafe { info.assume_init() }));
    }
    let error = io::Error::last_os_error();
    if matches!(error.raw_os_error(), Some(libc::ESRCH) | Some(libc::ENOENT)) {
        return Ok(None);
    }
    Err(error)
}

fn process_info(pid: libc::pid_t) -> io::Result<Option<NativeProcessInfo>> {
    if pid <= 0 {
        return Ok(None);
    }
    let Some(unique) = unique_info(pid)? else {
        return Ok(None);
    };
    let mut info = std::mem::MaybeUninit::<libc::proc_bsdinfo>::zeroed();
    let size = size_of::<libc::proc_bsdinfo>() as libc::c_int;
    // SAFETY: correctly sized native process-info output.
    let got = unsafe {
        libc::proc_pidinfo(
            pid,
            libc::PROC_PIDTBSDINFO,
            1, // Include zombies until their parent's actual wait/reap.
            info.as_mut_ptr().cast(),
            size,
        )
    };
    let (start, status) = if got == size {
        // SAFETY: full matching native output initialized by libproc.
        let info = unsafe { info.assume_init() };
        (
            Some((info.pbi_start_tvsec, info.pbi_start_tvusec)),
            info.pbi_status,
        )
    } else {
        let error = io::Error::last_os_error();
        if matches!(error.raw_os_error(), Some(libc::ESRCH) | Some(libc::ENOENT)) {
            return Ok(None);
        }
        if error.raw_os_error() != Some(libc::EPERM) {
            return Err(error);
        }
        let mut info = std::mem::MaybeUninit::<ShortInfo>::zeroed();
        let size = size_of::<ShortInfo>() as libc::c_int;
        // SAFETY: UID-independent native status query for privileged helpers.
        let got = unsafe {
            libc::proc_pidinfo(
                pid,
                13, // PROC_PIDT_SHORTBSDINFO
                1,  // Include privileged zombies as well as live helpers.
                info.as_mut_ptr().cast(),
                size,
            )
        };
        if got != size {
            let error = io::Error::last_os_error();
            if matches!(error.raw_os_error(), Some(libc::ESRCH) | Some(libc::ENOENT)) {
                return Ok(None);
            }
            return Err(error);
        }
        (None, unsafe { info.assume_init() }.status)
    };
    // Metadata must belong to the same kernel incarnation across the queries.
    if unique_info(pid)?.is_none_or(|current| current.unique_id != unique.unique_id) {
        return Ok(None);
    }
    Ok(Some(NativeProcessInfo {
        identity: ProcessIncarnation {
            pid,
            unique_id: unique.unique_id,
            start,
        },
        status,
    }))
}

fn all_pids() -> io::Result<Vec<libc::pid_t>> {
    // SAFETY: PROC_ALL_PIDS count query, then correctly sized pid output.
    let size = unsafe { libc::proc_listpids(1, 0, std::ptr::null_mut(), 0) };
    if size < 0 {
        return Err(io::Error::last_os_error());
    }
    let mut capacity = size as usize / size_of::<libc::pid_t>() + 1024;
    loop {
        let mut pids = vec![0; capacity];
        let bytes = i32::try_from(capacity * size_of::<libc::pid_t>())
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
        let got = unsafe { libc::proc_listpids(1, 0, pids.as_mut_ptr().cast(), bytes) };
        if got < 0 {
            return Err(io::Error::last_os_error());
        }
        if got == bytes {
            capacity *= 2;
            continue;
        }
        pids.truncate(got as usize / size_of::<libc::pid_t>());
        return Ok(pids);
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn exited_child_is_not_reaped_until_waitpid() {
        use std::process::{Command, Stdio};
        let mut child = Command::new("/bin/cat")
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .spawn()
            .unwrap();
        let identity = super::observe(child.id() as libc::pid_t).unwrap().unwrap();
        let process = super::ProcessWatch::new(identity).unwrap().unwrap();
        drop(child.stdin.take());
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        while !process.exited().unwrap() {
            if std::time::Instant::now() >= deadline {
                child.kill().unwrap();
                child.wait().unwrap();
                panic!("child exit watch timed out");
            }
            std::thread::sleep(std::time::Duration::from_millis(1));
        }
        let prematurely_reaped = process.reaped().unwrap();
        // Always reap the fixture before asserting, including on the red path.
        assert!(child.wait().unwrap().success());
        assert!(!prematurely_reaped, "unreaped zombie certified as reaped");
        assert!(process.reaped().unwrap());
    }

    #[test]
    fn privileged_identity_is_observable_without_signal_permission() {
        // Read-only qualification against root-owned launchd. No signal is
        // sent; its incarnation must remain observable to cleanup after EPERM.
        assert!(
            super::observe(1)
                .expect("privileged exit observation denied")
                .is_some()
        );
    }
}
