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

    pub(super) fn getpid(&self) -> DispatchOutcome {
        DispatchOutcome::Returned {
            value: std::process::id() as i64,
        }
    }
}

impl SyscallDispatcher {
    define_syscall! {
        fn capget(this, cx, header_address: GuestPtr, data_address: GuestPtr) {
            let memory = &mut *cx.memory;
            let header = match read_capability_header(memory, header_address.0) {
                Ok(header) => header,
                Err(errno) => return Ok(errno.into()),
            };
            if !linux_capability_version_is_supported(header.version) {
                return Ok(LINUX_EINVAL.into());
            }
            if header.pid < 0 {
                return Ok(LINUX_ESRCH.into());
            }
            if data_address.0 == 0 {
                return Ok(DispatchOutcome::Returned { value: 0 });
            }
            let words = linux_capability_data_words(header.version);
            let empty = vec![LinuxCapabilityData::empty(); words];
            if memory
                .write_bytes(data_address.0, capability_data_bytes(&empty).as_slice())
                .is_err()
            {
                return Ok(LINUX_EFAULT.into());
            }
            Ok(DispatchOutcome::Returned { value: 0 })
        }

        fn capset(this, cx, header_address: GuestPtr, data_address: GuestPtr) {
            let memory = &*cx.memory;
            let header = match read_capability_header(memory, header_address.0) {
                Ok(header) => header,
                Err(errno) => return Ok(errno.into()),
            };
            if !linux_capability_version_is_supported(header.version) {
                return Ok(LINUX_EINVAL.into());
            }
            if header.pid < 0 {
                return Ok(LINUX_ESRCH.into());
            }
            let words = linux_capability_data_words(header.version);
            let data = match read_capability_data(memory, data_address.0, words) {
                Ok(data) => data,
                Err(errno) => return Ok(errno.into()),
            };
            if data.iter().any(|word| !word.is_empty()) {
                return Ok(LINUX_EPERM.into());
            }
            Ok(DispatchOutcome::Returned { value: 0 })
        }

        fn umask(this, cx, new: u64) {
            let new = new as u32 & 0o777;
            let mut creds = this.creds.lock();
            let previous = creds.umask;
            creds.umask = new;
            Ok(DispatchOutcome::Returned {
                value: previous as i64,
            })
        }

        fn setpriority(this, cx, which: u64, who: Pid, prio: u64) {
            let prio = prio as i32;
            if which > LINUX_PRIO_USER || !(-20..=19).contains(&prio) {
                return Ok(LINUX_EINVAL.into());
            }
            if which == LINUX_PRIO_PROCESS && who.0 != 0 && who.0 != LINUX_BOOTSTRAP_PID as i32 {
                return Ok(LINUX_ESRCH.into());
            }
            Ok(DispatchOutcome::Returned { value: 0 })
        }

        fn getpriority(this, cx, which: u64, who: Pid) {
            if which > LINUX_PRIO_USER {
                return Ok(LINUX_EINVAL.into());
            }
            if which == LINUX_PRIO_PROCESS && who.0 != 0 && who.0 != LINUX_BOOTSTRAP_PID as i32 {
                return Ok(LINUX_ESRCH.into());
            }
            Ok(DispatchOutcome::Returned { value: 20 })
        }

        fn setresuid(this, cx, r: u64, e: u64, s: u64) {
            let mut creds = this.creds.lock();
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

        fn setresgid(this, cx, r: u64, e: u64, s: u64) {
            let mut creds = this.creds.lock();
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

        fn setreuid(this, cx, r: u64, e: u64) {
            let mut creds = this.creds.lock();
            if r as i64 != -1 {
                creds.ruid = r as u32;
            }
            if e as i64 != -1 {
                creds.euid = e as u32;
            }
            Ok(DispatchOutcome::Returned { value: 0 })
        }

        fn setregid(this, cx, r: u64, e: u64) {
            let mut creds = this.creds.lock();
            if r as i64 != -1 {
                creds.rgid = r as u32;
            }
            if e as i64 != -1 {
                creds.egid = e as u32;
            }
            Ok(DispatchOutcome::Returned { value: 0 })
        }

        fn setuid(this, cx, u: u64) {
            let u = u as u32;
            let mut creds = this.creds.lock();
            creds.ruid = u;
            creds.euid = u;
            creds.suid = u;
            Ok(DispatchOutcome::Returned { value: 0 })
        }

        fn setgid(this, cx, g: u64) {
            let g = g as u32;
            let mut creds = this.creds.lock();
            creds.rgid = g;
            creds.egid = g;
            creds.sgid = g;
            Ok(DispatchOutcome::Returned { value: 0 })
        }

        fn getresuid(this, cx, ruid_ptr: GuestPtr, euid_ptr: GuestPtr, suid_ptr: GuestPtr) {
            let creds = this.cred_snapshot();
            for (ptr, value) in [
                (ruid_ptr, creds.ruid),
                (euid_ptr, creds.euid),
                (suid_ptr, creds.suid),
            ] {
                if ptr.0 == 0 {
                    continue;
                }
                if cx.memory.write_bytes(ptr.0, &value.to_le_bytes()).is_err() {
                    return Ok(LINUX_EFAULT.into());
                }
            }
            Ok(DispatchOutcome::Returned { value: 0 })
        }

        fn getresgid(this, cx, rgid_ptr: GuestPtr, egid_ptr: GuestPtr, sgid_ptr: GuestPtr) {
            let creds = this.cred_snapshot();
            for (ptr, value) in [
                (rgid_ptr, creds.rgid),
                (egid_ptr, creds.egid),
                (sgid_ptr, creds.sgid),
            ] {
                if ptr.0 == 0 {
                    continue;
                }
                if cx.memory.write_bytes(ptr.0, &value.to_le_bytes()).is_err() {
                    return Ok(LINUX_EFAULT.into());
                }
            }
            Ok(DispatchOutcome::Returned { value: 0 })
        }

        fn getgroups(this, cx, size: u64, list: GuestPtr) {
            let size = size as i32;
            if size < 0 {
                return Ok(LINUX_EINVAL.into());
            }
            if size == 0 {
                return Ok(DispatchOutcome::Returned { value: 1 });
            }
            if size < 1 {
                return Ok(LINUX_EINVAL.into());
            }
            if cx.memory.write_bytes(list.0, &0u32.to_le_bytes()).is_err() {
                return Ok(LINUX_EFAULT.into());
            }
            Ok(DispatchOutcome::Returned { value: 1 })
        }

        fn sys_setfsuid(this, cx, _uid: u64) {
            let creds = this.cred_snapshot();
            Ok(DispatchOutcome::Returned {
                value: i64::from(creds.euid),
            })
        }

        fn sys_setfsgid(this, cx, _gid: u64) {
            let creds = this.cred_snapshot();
            Ok(DispatchOutcome::Returned {
                value: i64::from(creds.egid),
            })
        }

        fn sys_setgroups(this, cx, _size: u64, _list: GuestPtr) {
            Ok(DispatchOutcome::Returned { value: 0 })
        }

        fn sys_getpid(this, cx) {
            Ok(this.getpid())
        }

        fn sys_getppid(this, cx) {
            let bootstrap_host_pid = this.proc.lock().bootstrap_host_pid;
            let value = if std::process::id() == bootstrap_host_pid {
                LINUX_BOOTSTRAP_PID as i64
            } else {
                unsafe { libc::getppid() as i64 }
            };
            Ok(DispatchOutcome::Returned { value })
        }

        fn sys_getuid(this, cx) {
            let creds = this.cred_snapshot();
            Ok(DispatchOutcome::Returned {
                value: i64::from(creds.ruid),
            })
        }

        fn sys_geteuid(this, cx) {
            let creds = this.cred_snapshot();
            Ok(DispatchOutcome::Returned {
                value: i64::from(creds.euid),
            })
        }

        fn sys_getgid(this, cx) {
            let creds = this.cred_snapshot();
            Ok(DispatchOutcome::Returned {
                value: i64::from(creds.rgid),
            })
        }

        fn sys_getegid(this, cx) {
            let creds = this.cred_snapshot();
            Ok(DispatchOutcome::Returned {
                value: i64::from(creds.egid),
            })
        }
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
