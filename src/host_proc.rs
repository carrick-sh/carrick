//! Host-process introspection for synthesising `/proc/<pid>/` of carrick guest
//! processes. carrick forks each guest process as a real macOS process and the
//! guest pid IS the host pid (the trees mirror), so the host kernel — queried
//! via libproc `proc_pidinfo` — is the source of truth for another guest
//! process's state and identity. We never expose a process that is not one of
//! our own descendants (validated by walking the ppid chain up to this
//! process), so a guest can't probe arbitrary host processes.

/// Identity + state of a guest process, read from the host kernel.
#[derive(Debug, Clone)]
pub struct GuestProcInfo {
    /// Linux `/proc/<pid>/stat` state char (`R`/`S`/`T`/`Z`).
    pub state: char,
    pub ppid: u32,
    pub pgid: u32,
    pub uid: u32,
    pub gid: u32,
    /// Short command name (max 15 chars, like Linux `comm`).
    pub comm: String,
}

#[cfg(target_os = "macos")]
mod imp {
    use super::GuestProcInfo;

    /// Map a macOS process status (`pbi_status`) to the Linux stat state char.
    /// The tests only distinguish "sleeping in a syscall" (`S`) from "running"
    /// (`R`); a guest blocked in pause()/futex parks carrick's run loop in a
    /// host syscall, so the host reports `SSLEEP`.
    fn state_char(pbi_status: u32) -> char {
        // libc's S* status constants vary in signedness across versions; widen
        // both sides so the comparison is type-agnostic.
        let s = pbi_status as i64;
        if s == libc::SSLEEP as i64 {
            'S'
        } else if s == libc::SSTOP as i64 {
            'T'
        } else if s == libc::SZOMB as i64 {
            'Z'
        } else {
            // SRUN and SIDL (and anything unexpected) → running.
            'R'
        }
    }

    fn comm_from(buf: &[libc::c_char]) -> String {
        let bytes: Vec<u8> = buf
            .iter()
            .take_while(|&&c| c != 0)
            .map(|&c| c as u8)
            .collect();
        String::from_utf8_lossy(&bytes).into_owned()
    }

    /// Fetch a pid's BSD info via `proc_pidinfo(PROC_PIDTBSDINFO)`. `None` if the
    /// pid doesn't exist or isn't inspectable.
    fn bsdinfo(pid: u32) -> Option<libc::proc_bsdinfo> {
        let mut info: libc::proc_bsdinfo = unsafe { std::mem::zeroed() };
        let size = std::mem::size_of::<libc::proc_bsdinfo>() as libc::c_int;
        // SAFETY: proc_pidinfo writes up to `size` bytes into `info`; we pass
        // the matching size and a zeroed, correctly-typed buffer.
        let n = unsafe {
            libc::proc_pidinfo(
                pid as libc::c_int,
                libc::PROC_PIDTBSDINFO,
                0,
                &mut info as *mut _ as *mut libc::c_void,
                size,
            )
        };
        (n == size).then_some(info)
    }

    pub fn pid_info(pid: u32) -> Option<GuestProcInfo> {
        let info = bsdinfo(pid)?;
        Some(GuestProcInfo {
            state: state_char(info.pbi_status),
            ppid: info.pbi_ppid,
            pgid: info.pbi_pgid,
            uid: info.pbi_uid,
            gid: info.pbi_gid,
            comm: comm_from(&info.pbi_comm),
        })
    }

    /// True iff `pid` is a (transitive) child of THIS process — walk the ppid
    /// chain up. Bounded so a cycle / unexpected tree can't loop forever.
    pub fn is_descendant_of_self(pid: u32) -> bool {
        let me = std::process::id();
        if pid == me || pid == 0 {
            return false;
        }
        let mut cur = pid;
        for _ in 0..64 {
            let Some(info) = bsdinfo(cur) else {
                return false;
            };
            if info.pbi_ppid == me {
                return true;
            }
            if info.pbi_ppid == 0 || info.pbi_ppid == cur {
                return false;
            }
            cur = info.pbi_ppid;
        }
        false
    }
}

#[cfg(not(target_os = "macos"))]
mod imp {
    use super::GuestProcInfo;
    pub fn pid_info(_pid: u32) -> Option<GuestProcInfo> {
        None
    }
    pub fn is_descendant_of_self(_pid: u32) -> bool {
        false
    }
}

pub use imp::{is_descendant_of_self, pid_info};
