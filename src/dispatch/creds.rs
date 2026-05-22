//! creds syscall handlers. Methods on `SyscallDispatcher`; see
//! `super` for the dispatcher struct and the normalized dispatch table.
use super::*;

/// Owned credentials-subsystem state. Split out of `SyscallDispatcher`.
///
/// Tracked (real, effective, saved) uid and gid plus the umask. Carrick
/// runs the guest as a single host identity, but tools like apt's `_apt`
/// privsep drop to a non-root user via setresuid/setresgid and then
/// VERIFY the new identity via getuid/geteuid/getresuid (and likewise for
/// gid). Returning the host's identity unconditionally breaks the
/// verification with "Could not switch group". We accept any setres*()
/// the guest requests, record the values here, and echo them back to the
/// corresponding get*() calls.
#[derive(Clone, Copy)]
pub(super) struct CredState {
    pub ruid: u32,
    pub euid: u32,
    pub suid: u32,
    pub rgid: u32,
    pub egid: u32,
    pub sgid: u32,
    pub umask: u32,
}

impl CredState {
    pub(super) fn new() -> Self {
        // Default identity is root (uid 0, gid 0) — what `id` shows in a
        // typical container.
        Self {
            ruid: 0,
            euid: 0,
            suid: 0,
            rgid: 0,
            egid: 0,
            sgid: 0,
            umask: LINUX_DEFAULT_UMASK,
        }
    }
}

impl SyscallDispatcher {
    pub(super) fn cred_snapshot(&self) -> CredState {
        *self.creds.lock()
    }

    pub(super) fn capget<M: GuestMemory>(
        &self,
        ctx: &mut SyscallCtx<M>,
    ) -> Result<DispatchOutcome, DispatchError> {
        let header_address = ctx.arg(0);
        let data_address = ctx.arg(1);
        let memory = &mut *ctx.memory;
        let header = match read_capability_header(memory, header_address) {
            Ok(header) => header,
            Err(errno) => return Ok(DispatchOutcome::Errno { errno }),
        };
        if !linux_capability_version_is_supported(header.version) {
            return Ok(DispatchOutcome::Errno {
                errno: LINUX_EINVAL,
            });
        }
        if header.pid < 0 {
            return Ok(DispatchOutcome::Errno { errno: LINUX_ESRCH });
        }
        if data_address == 0 {
            return Ok(DispatchOutcome::Returned { value: 0 });
        }
        let words = linux_capability_data_words(header.version);
        let empty = vec![LinuxCapabilityData::empty(); words];
        if memory
            .write_bytes(data_address, capability_data_bytes(&empty).as_slice())
            .is_err()
        {
            return Ok(DispatchOutcome::Errno {
                errno: LINUX_EFAULT,
            });
        }
        Ok(DispatchOutcome::Returned { value: 0 })
    }

    pub(super) fn capset<M: GuestMemory>(
        &self,
        ctx: &mut SyscallCtx<M>,
    ) -> Result<DispatchOutcome, DispatchError> {
        let header_address = ctx.arg(0);
        let data_address = ctx.arg(1);
        let memory = &*ctx.memory;
        let header = match read_capability_header(memory, header_address) {
            Ok(header) => header,
            Err(errno) => return Ok(DispatchOutcome::Errno { errno }),
        };
        if !linux_capability_version_is_supported(header.version) {
            return Ok(DispatchOutcome::Errno {
                errno: LINUX_EINVAL,
            });
        }
        if header.pid < 0 {
            return Ok(DispatchOutcome::Errno { errno: LINUX_ESRCH });
        }
        let words = linux_capability_data_words(header.version);
        let data = match read_capability_data(memory, data_address, words) {
            Ok(data) => data,
            Err(errno) => return Ok(DispatchOutcome::Errno { errno }),
        };
        if data.iter().any(|word| !word.is_empty()) {
            return Ok(DispatchOutcome::Errno { errno: LINUX_EPERM });
        }
        Ok(DispatchOutcome::Returned { value: 0 })
    }

    pub(super) fn getpid(&self) -> DispatchOutcome {
        DispatchOutcome::Returned {
            value: std::process::id() as i64,
        }
    }

    pub(super) fn umask<M: GuestMemory>(
        &self,
        ctx: &mut SyscallCtx<M>,
    ) -> Result<DispatchOutcome, DispatchError> {
        let new = ctx.arg(0) as u32 & 0o777;
        let mut creds = self.creds.lock();
        let previous = creds.umask;
        creds.umask = new;
        Ok(DispatchOutcome::Returned {
            value: previous as i64,
        })
    }

    pub(super) fn setpriority<M: GuestMemory>(
        &self,
        ctx: &mut SyscallCtx<M>,
    ) -> Result<DispatchOutcome, DispatchError> {
        let which = ctx.arg(0);
        let who = ctx.arg(1) as i32;
        let prio = ctx.arg(2) as i32;
        if which > LINUX_PRIO_USER || !(-20..=19).contains(&prio) {
            return Ok(DispatchOutcome::Errno {
                errno: LINUX_EINVAL,
            });
        }
        if which == LINUX_PRIO_PROCESS && who != 0 && who != LINUX_BOOTSTRAP_PID as i32 {
            return Ok(DispatchOutcome::Errno { errno: LINUX_ESRCH });
        }
        Ok(DispatchOutcome::Returned { value: 0 })
    }

    pub(super) fn getpriority<M: GuestMemory>(
        &self,
        ctx: &mut SyscallCtx<M>,
    ) -> Result<DispatchOutcome, DispatchError> {
        let which = ctx.arg(0);
        let who = ctx.arg(1) as i32;
        if which > LINUX_PRIO_USER {
            return Ok(DispatchOutcome::Errno {
                errno: LINUX_EINVAL,
            });
        }
        if which == LINUX_PRIO_PROCESS && who != 0 && who != LINUX_BOOTSTRAP_PID as i32 {
            return Ok(DispatchOutcome::Errno { errno: LINUX_ESRCH });
        }
        // Linux returns 20 - nice. Default nice is 0 → return 20. This is a
        // bootstrap value; we don't model per-process priority.
        Ok(DispatchOutcome::Returned { value: 20 })
    }

    /// `setresuid(ruid, euid, suid)`. -1 means "don't change". We record
    /// the new values; the guest gets to see them via getuid/geteuid/
    /// getresuid. Always succeeds — we're single-identity and tools
    /// can pretend to drop privileges as they like.
    pub(super) fn setresuid<M: GuestMemory>(
        &self,
        ctx: &mut SyscallCtx<M>,
    ) -> Result<DispatchOutcome, DispatchError> {
        let r = ctx.arg(0);
        let e = ctx.arg(1);
        let s = ctx.arg(2);
        let mut creds = self.creds.lock();
        if r as i64 != -1 {
            creds.ruid = r as u32;
        }
        if e as i64 != -1 {
            creds.euid = e as u32;
        }
        if s as i64 != -1 {
            creds.suid = s as u32;
        }
        Ok(DispatchOutcome::Returned { value: 0 })
    }

    pub(super) fn setresgid<M: GuestMemory>(
        &self,
        ctx: &mut SyscallCtx<M>,
    ) -> Result<DispatchOutcome, DispatchError> {
        let r = ctx.arg(0);
        let e = ctx.arg(1);
        let s = ctx.arg(2);
        let mut creds = self.creds.lock();
        if r as i64 != -1 {
            creds.rgid = r as u32;
        }
        if e as i64 != -1 {
            creds.egid = e as u32;
        }
        if s as i64 != -1 {
            creds.sgid = s as u32;
        }
        Ok(DispatchOutcome::Returned { value: 0 })
    }

    /// `setreuid(ruid, euid)`: same as setresuid with suid=-1.
    pub(super) fn setreuid<M: GuestMemory>(
        &self,
        ctx: &mut SyscallCtx<M>,
    ) -> Result<DispatchOutcome, DispatchError> {
        let r = ctx.arg(0);
        let e = ctx.arg(1);
        let mut creds = self.creds.lock();
        if r as i64 != -1 {
            creds.ruid = r as u32;
        }
        if e as i64 != -1 {
            creds.euid = e as u32;
        }
        Ok(DispatchOutcome::Returned { value: 0 })
    }

    pub(super) fn setregid<M: GuestMemory>(
        &self,
        ctx: &mut SyscallCtx<M>,
    ) -> Result<DispatchOutcome, DispatchError> {
        let r = ctx.arg(0);
        let e = ctx.arg(1);
        let mut creds = self.creds.lock();
        if r as i64 != -1 {
            creds.rgid = r as u32;
        }
        if e as i64 != -1 {
            creds.egid = e as u32;
        }
        Ok(DispatchOutcome::Returned { value: 0 })
    }

    /// `setuid(uid)`: set effective uid and (if currently privileged)
    /// real + saved too. We always treat the caller as privileged so
    /// all three move together — matches what apt expects.
    pub(super) fn setuid<M: GuestMemory>(
        &self,
        ctx: &mut SyscallCtx<M>,
    ) -> Result<DispatchOutcome, DispatchError> {
        let u = ctx.arg(0) as u32;
        let mut creds = self.creds.lock();
        creds.ruid = u;
        creds.euid = u;
        creds.suid = u;
        Ok(DispatchOutcome::Returned { value: 0 })
    }

    pub(super) fn setgid<M: GuestMemory>(
        &self,
        ctx: &mut SyscallCtx<M>,
    ) -> Result<DispatchOutcome, DispatchError> {
        let g = ctx.arg(0) as u32;
        let mut creds = self.creds.lock();
        creds.rgid = g;
        creds.egid = g;
        creds.sgid = g;
        Ok(DispatchOutcome::Returned { value: 0 })
    }

    /// `getresuid(*ruid, *euid, *suid)` — write our tracked tuple.
    pub(super) fn getresuid<M: GuestMemory>(
        &self,
        ctx: &mut SyscallCtx<M>,
    ) -> Result<DispatchOutcome, DispatchError> {
        let creds = self.cred_snapshot();
        for (i, value) in [creds.ruid, creds.euid, creds.suid].iter().enumerate() {
            let ptr = ctx.arg(i);
            if ptr == 0 {
                continue;
            }
            if ctx.memory.write_bytes(ptr, &value.to_le_bytes()).is_err() {
                return Ok(DispatchOutcome::Errno {
                    errno: LINUX_EFAULT,
                });
            }
        }
        Ok(DispatchOutcome::Returned { value: 0 })
    }

    pub(super) fn getresgid<M: GuestMemory>(
        &self,
        ctx: &mut SyscallCtx<M>,
    ) -> Result<DispatchOutcome, DispatchError> {
        let creds = self.cred_snapshot();
        for (i, value) in [creds.rgid, creds.egid, creds.sgid].iter().enumerate() {
            let ptr = ctx.arg(i);
            if ptr == 0 {
                continue;
            }
            if ctx.memory.write_bytes(ptr, &value.to_le_bytes()).is_err() {
                return Ok(DispatchOutcome::Errno {
                    errno: LINUX_EFAULT,
                });
            }
        }
        Ok(DispatchOutcome::Returned { value: 0 })
    }

    /// `getgroups(size, *list)`. Linux returns the number of
    /// supplementary groups; the carrick guest runs as root (uid/gid 0)
    /// and belongs to the single supplementary group gid 0, matching a
    /// fresh root shell in the container. With `size == 0` we report the
    /// count (1) without touching `list`; otherwise we write the one
    /// gid_t to the guest buffer and return the number written.
    pub(super) fn getgroups<M: GuestMemory>(
        &self,
        ctx: &mut SyscallCtx<M>,
    ) -> Result<DispatchOutcome, DispatchError> {
        // `size` is a Linux `int`; a negative value is invalid.
        let size = ctx.arg(0) as i32;
        if size < 0 {
            return Ok(DispatchOutcome::Errno {
                errno: LINUX_EINVAL,
            });
        }
        // Query mode: report the count without writing.
        if size == 0 {
            return Ok(DispatchOutcome::Returned { value: 1 });
        }
        // The buffer is too small to hold the supplementary group list.
        if size < 1 {
            return Ok(DispatchOutcome::Errno {
                errno: LINUX_EINVAL,
            });
        }
        // Write the single supplementary group (gid 0) as a little-endian
        // gid_t (u32, 4 bytes).
        let list = ctx.arg(1);
        let gid: u32 = 0;
        if ctx.memory.write_bytes(list, &gid.to_le_bytes()).is_err() {
            return Ok(DispatchOutcome::Errno {
                errno: LINUX_EFAULT,
            });
        }
        Ok(DispatchOutcome::Returned { value: 1 })
    }

    pub(super) fn sys_setfsuid<M: GuestMemory>(
        &self,
        _ctx: &mut SyscallCtx<M>,
    ) -> Result<DispatchOutcome, DispatchError> {
        let creds = self.cred_snapshot();
        Ok(DispatchOutcome::Returned {
            value: i64::from(creds.euid),
        })
    }

    pub(super) fn sys_setfsgid<M: GuestMemory>(
        &self,
        _ctx: &mut SyscallCtx<M>,
    ) -> Result<DispatchOutcome, DispatchError> {
        let creds = self.cred_snapshot();
        Ok(DispatchOutcome::Returned {
            value: i64::from(creds.egid),
        })
    }

    pub(super) fn sys_setgroups<M: GuestMemory>(
        &self,
        _ctx: &mut SyscallCtx<M>,
    ) -> Result<DispatchOutcome, DispatchError> {
        Ok(DispatchOutcome::Returned { value: 0 })
    }

    pub(super) fn sys_getpid<M: GuestMemory>(
        &self,
        _ctx: &mut SyscallCtx<M>,
    ) -> Result<DispatchOutcome, DispatchError> {
        Ok(self.getpid())
    }

    pub(super) fn sys_getppid<M: GuestMemory>(
        &self,
        _ctx: &mut SyscallCtx<M>,
    ) -> Result<DispatchOutcome, DispatchError> {
        // getpid() reports the real host pid, and carrick forks each guest
        // process as a real host child, so the host process tree mirrors the
        // guest tree. The root guest process reports the stable bootstrap
        // parent (init) rather than leaking carrick's non-deterministic host
        // launcher pid; a forked child reports its real host parent, which IS
        // its parent guest process. Returning a hardcoded 1 here made every
        // forked child look reparented-to-init — tripping LTP's tst_test
        // heartbeat ("Main test process might have exit!").
        let bootstrap_host_pid = self.proc.lock().bootstrap_host_pid;
        let value = if std::process::id() == bootstrap_host_pid {
            LINUX_BOOTSTRAP_PID as i64
        } else {
            // SAFETY: getppid(2) is always successful and has no side effects.
            unsafe { libc::getppid() as i64 }
        };
        Ok(DispatchOutcome::Returned { value })
    }

    pub(super) fn sys_getuid<M: GuestMemory>(
        &self,
        _ctx: &mut SyscallCtx<M>,
    ) -> Result<DispatchOutcome, DispatchError> {
        let creds = self.cred_snapshot();
        Ok(DispatchOutcome::Returned {
            value: i64::from(creds.ruid),
        })
    }

    pub(super) fn sys_geteuid<M: GuestMemory>(
        &self,
        _ctx: &mut SyscallCtx<M>,
    ) -> Result<DispatchOutcome, DispatchError> {
        let creds = self.cred_snapshot();
        Ok(DispatchOutcome::Returned {
            value: i64::from(creds.euid),
        })
    }

    pub(super) fn sys_getgid<M: GuestMemory>(
        &self,
        _ctx: &mut SyscallCtx<M>,
    ) -> Result<DispatchOutcome, DispatchError> {
        let creds = self.cred_snapshot();
        Ok(DispatchOutcome::Returned {
            value: i64::from(creds.rgid),
        })
    }

    pub(super) fn sys_getegid<M: GuestMemory>(
        &self,
        _ctx: &mut SyscallCtx<M>,
    ) -> Result<DispatchOutcome, DispatchError> {
        let creds = self.cred_snapshot();
        Ok(DispatchOutcome::Returned {
            value: i64::from(creds.egid),
        })
    }
}

fn read_capability_header(
    memory: &impl GuestMemory,
    address: u64,
) -> Result<LinuxCapabilityHeader, i32> {
    let bytes = memory
        .read_bytes(address, core::mem::size_of::<LinuxCapabilityHeader>())
        .map_err(|_| LINUX_EFAULT)?;
    LinuxCapabilityHeader::read_from_bytes(&bytes).map_err(|_| LINUX_EFAULT)
}

fn read_capability_data(
    memory: &impl GuestMemory,
    address: u64,
    count: usize,
) -> Result<Vec<LinuxCapabilityData>, i32> {
    let size = core::mem::size_of::<LinuxCapabilityData>();
    let length = count.checked_mul(size).ok_or(LINUX_EINVAL)?;
    let bytes = memory
        .read_bytes(address, length)
        .map_err(|_| LINUX_EFAULT)?;
    bytes
        .chunks_exact(size)
        .map(|chunk| LinuxCapabilityData::read_from_bytes(chunk).map_err(|_| LINUX_EFAULT))
        .collect()
}

fn capability_data_bytes(data: &[LinuxCapabilityData]) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(std::mem::size_of_val(data));
    for word in data {
        bytes.extend_from_slice(word.as_bytes());
    }
    bytes
}

fn linux_capability_version_is_supported(version: u32) -> bool {
    matches!(
        version,
        LINUX_CAPABILITY_VERSION_1 | LINUX_CAPABILITY_VERSION_2 | LINUX_CAPABILITY_VERSION_3
    )
}

fn linux_capability_data_words(version: u32) -> usize {
    if version == LINUX_CAPABILITY_VERSION_1 {
        1
    } else {
        2
    }
}
