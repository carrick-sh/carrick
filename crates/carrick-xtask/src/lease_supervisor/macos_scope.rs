//! Darwin has no child subreaper. Authenticate even detached descendants by
//! the kernel identity of the inherited scope pipe, then stop, kill and observe
//! launchd reaping them before releasing exclusion.

use std::collections::BTreeSet;
use std::io;

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

    pub(super) fn cancel(&self, session: libc::pid_t) -> io::Result<Vec<libc::pid_t>> {
        let mut stopped = BTreeSet::new();
        loop {
            let mut changed = false;
            for pid in all_pids()? {
                // SAFETY: native session query. Pipe identity covers setsid.
                if pid > 0
                    && (unsafe { libc::getsid(pid) } == session || self.owns_writer(pid))
                    && stopped.insert(pid)
                {
                    signal(pid, libc::SIGSTOP)?;
                    changed = true;
                }
            }
            // Stop delivery is asynchronous. Require a native stopped/exited
            // state before the final census, so no parent can fork past it.
            if !changed && stopped.iter().all(|&pid| stopped_or_exited(pid)) {
                break;
            }
            std::thread::yield_now();
        }
        for &pid in &stopped {
            signal(pid, libc::SIGKILL)?;
        }
        Ok(stopped.into_iter().collect())
    }
}

fn signal(pid: libc::pid_t, signal: libc::c_int) -> io::Result<()> {
    // SAFETY: only an authenticated, scoped process is targeted.
    if unsafe { libc::kill(pid, signal) } < 0 {
        let error = io::Error::last_os_error();
        if error.raw_os_error() != Some(libc::ESRCH) {
            return Err(error);
        }
    }
    Ok(())
}

fn stopped_or_exited(pid: libc::pid_t) -> bool {
    let mut info = std::mem::MaybeUninit::<libc::proc_bsdinfo>::zeroed();
    let size = size_of::<libc::proc_bsdinfo>() as libc::c_int;
    // SAFETY: correctly sized native process-info output.
    let got = unsafe {
        libc::proc_pidinfo(
            pid,
            libc::PROC_PIDTBSDINFO,
            0,
            info.as_mut_ptr().cast(),
            size,
        )
    };
    if got != size {
        return io::Error::last_os_error().raw_os_error() == Some(libc::ESRCH);
    }
    // SAFETY: libproc initialized the entire structure.
    matches!(
        unsafe { info.assume_init() }.pbi_status,
        libc::SSTOP | libc::SZOMB
    )
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
