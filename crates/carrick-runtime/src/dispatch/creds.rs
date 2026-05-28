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

    /// We model the CAP_SETUID/CAP_SETGID capability as "running as root"
    /// (euid 0) — carrick has no finer capability model, and LTP's set*id
    /// tests gate their privileged/unprivileged expectations on euid==0.
    fn is_privileged(&self) -> bool {
        self.euid == 0
    }
}

/// The Linux `(uid_t)-1` "leave unchanged" sentinel. uid_t is unsigned, so the
/// guest passes 0xFFFFFFFF zero-extended into a 64-bit register; decode that as
/// "keep", any other value as a concrete id. (The old `arg as i64 != -1` check
/// was wrong: 0xFFFFFFFF as i64 is 4294967295, never -1, so a `-1` arg was
/// treated as a real uid 4294967295.)
fn keep_or(arg: u64) -> Option<u32> {
    let v = arg as u32;
    if v == u32::MAX { None } else { Some(v) }
}

/// Linux set*id transition rules (kernel/sys.c). Each returns `Err(())` ⇒ the
/// caller maps to EPERM. Pure functions on the (r,e,s) triple so they're
/// unit-testable independent of which uid/gid family they serve.
mod setid {
    /// setresuid/setresgid: when unprivileged, every non-(-1) target id must
    /// already be one of {real, effective, saved}; privileged sets anything.
    pub(super) fn setres(
        privileged: bool,
        cur: (u32, u32, u32),
        r: Option<u32>,
        e: Option<u32>,
        s: Option<u32>,
    ) -> Result<(u32, u32, u32), ()> {
        let (mut real, mut eff, mut saved) = cur;
        if !privileged {
            let allowed = |id: u32| id == real || id == eff || id == saved;
            for id in [r, e, s].into_iter().flatten() {
                if !allowed(id) {
                    return Err(());
                }
            }
        }
        if let Some(v) = r {
            real = v;
        }
        if let Some(v) = e {
            eff = v;
        }
        if let Some(v) = s {
            saved = v;
        }
        Ok((real, eff, saved))
    }

    /// setreuid/setregid + the saved-id rule. Unprivileged: new real ∈
    /// {real, eff}; new eff ∈ {real, eff, saved}. If real is changed, OR eff is
    /// set to a value != the PREVIOUS real, the saved id becomes the new eff.
    pub(super) fn setre(
        privileged: bool,
        cur: (u32, u32, u32),
        r: Option<u32>,
        e: Option<u32>,
    ) -> Result<(u32, u32, u32), ()> {
        let (old_real, old_eff, old_saved) = cur;
        if !privileged {
            if let Some(nr) = r {
                if nr != old_real && nr != old_eff {
                    return Err(());
                }
            }
            if let Some(ne) = e {
                if ne != old_real && ne != old_eff && ne != old_saved {
                    return Err(());
                }
            }
        }
        let real = r.unwrap_or(old_real);
        let eff = e.unwrap_or(old_eff);
        let saved = if r.is_some() || e.is_some_and(|ne| ne != old_real) {
            eff
        } else {
            old_saved
        };
        Ok((real, eff, saved))
    }

    /// setuid/setgid. Privileged sets real=eff=saved=u. Unprivileged: u must be
    /// the real or saved id, and only the EFFECTIVE id changes.
    pub(super) fn set(
        privileged: bool,
        cur: (u32, u32, u32),
        u: u32,
    ) -> Result<(u32, u32, u32), ()> {
        let (real, _eff, saved) = cur;
        if privileged {
            return Ok((u, u, u));
        }
        if u != real && u != saved {
            return Err(());
        }
        Ok((real, u, saved))
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
                // Linux writes the kernel's PREFERRED version back into the
                // header and returns EINVAL, so a probing caller can retry with
                // the right version (LTP capget02). version is the first u32.
                let pref = crate::linux_abi::LINUX_CAPABILITY_VERSION_3;
                let _ = memory.write_bytes(header_address.0, &pref.to_le_bytes());
                return Ok(LINUX_EINVAL.into());
            }
            // pid < 0 is EINVAL (not ESRCH); a positive pid that isn't this
            // process is ESRCH. carrick is a single guest process, so only
            // 0 / our pid / the bootstrap alias exist (LTP capget02).
            if header.pid < 0 {
                return Ok(LINUX_EINVAL.into());
            }
            if header.pid > 0
                && header.pid != std::process::id() as i32
                && header.pid != LINUX_BOOTSTRAP_PID as i32
            {
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
            let priv_ = creds.is_privileged();
            match setid::setres(priv_, (creds.ruid, creds.euid, creds.suid),
                                 keep_or(r), keep_or(e), keep_or(s)) {
                Ok((ru, eu, su)) => { creds.ruid = ru; creds.euid = eu; creds.suid = su; }
                Err(()) => return Ok(LINUX_EPERM.into()),
            }
            let new_euid = creds.euid;
            drop(creds);
            crate::cred_ipc::publish_self(new_euid);
            Ok(DispatchOutcome::Returned { value: 0 })
        }

        fn setresgid(this, cx, r: u64, e: u64, s: u64) {
            let mut creds = this.creds.lock();
            let priv_ = creds.is_privileged();
            match setid::setres(priv_, (creds.rgid, creds.egid, creds.sgid),
                                 keep_or(r), keep_or(e), keep_or(s)) {
                Ok((rg, eg, sg)) => { creds.rgid = rg; creds.egid = eg; creds.sgid = sg; }
                Err(()) => return Ok(LINUX_EPERM.into()),
            }
            Ok(DispatchOutcome::Returned { value: 0 })
        }

        fn setreuid(this, cx, r: u64, e: u64) {
            let mut creds = this.creds.lock();
            let priv_ = creds.is_privileged();
            match setid::setre(priv_, (creds.ruid, creds.euid, creds.suid),
                               keep_or(r), keep_or(e)) {
                Ok((ru, eu, su)) => { creds.ruid = ru; creds.euid = eu; creds.suid = su; }
                Err(()) => return Ok(LINUX_EPERM.into()),
            }
            let new_euid = creds.euid;
            drop(creds);
            crate::cred_ipc::publish_self(new_euid);
            Ok(DispatchOutcome::Returned { value: 0 })
        }

        fn setregid(this, cx, r: u64, e: u64) {
            let mut creds = this.creds.lock();
            let priv_ = creds.is_privileged();
            match setid::setre(priv_, (creds.rgid, creds.egid, creds.sgid),
                               keep_or(r), keep_or(e)) {
                Ok((rg, eg, sg)) => { creds.rgid = rg; creds.egid = eg; creds.sgid = sg; }
                Err(()) => return Ok(LINUX_EPERM.into()),
            }
            Ok(DispatchOutcome::Returned { value: 0 })
        }

        fn setuid(this, cx, u: u64) {
            let mut creds = this.creds.lock();
            let priv_ = creds.is_privileged();
            match setid::set(priv_, (creds.ruid, creds.euid, creds.suid), u as u32) {
                Ok((ru, eu, su)) => { creds.ruid = ru; creds.euid = eu; creds.suid = su; }
                Err(()) => return Ok(LINUX_EPERM.into()),
            }
            let new_euid = creds.euid;
            drop(creds);
            crate::cred_ipc::publish_self(new_euid);
            Ok(DispatchOutcome::Returned { value: 0 })
        }

        fn setgid(this, cx, g: u64) {
            let mut creds = this.creds.lock();
            let priv_ = creds.is_privileged();
            match setid::set(priv_, (creds.rgid, creds.egid, creds.sgid), g as u32) {
                Ok((rg, eg, sg)) => { creds.rgid = rg; creds.egid = eg; creds.sgid = sg; }
                Err(()) => return Ok(LINUX_EPERM.into()),
            }
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

#[cfg(test)]
mod setid_tests {
    use super::setid;

    // setres: unprivileged may only set ids already in {r,e,s}; privileged any.
    #[test]
    fn setres_unprivileged_restricts_to_current_ids() {
        // cur = (100, 100, 100). Unprivileged set to 200 → EPERM.
        assert_eq!(setid::setres(false, (100, 100, 100), Some(200), None, None), Err(()));
        // To an id already held (100) → ok, no change.
        assert_eq!(setid::setres(false, (100, 100, 100), Some(100), None, None), Ok((100, 100, 100)));
    }

    #[test]
    fn setres_privileged_sets_anything_and_keeps_minus_one() {
        // -1 (None) leaves a field unchanged; others set.
        assert_eq!(setid::setres(true, (0, 0, 0), Some(5), None, Some(7)), Ok((5, 0, 7)));
    }

    // setreuid saved-id rule (the subtle part LTP setreuid02 pins down).
    #[test]
    fn setre_saved_id_follows_when_real_changes() {
        // Privileged, cur (0,0,0). setreuid(ruid=5, euid=6): real changes →
        // saved becomes the new euid (6).
        assert_eq!(setid::setre(true, (0, 0, 0), Some(5), Some(6)), Ok((5, 6, 6)));
    }

    #[test]
    fn setre_saved_id_follows_when_euid_differs_from_old_real() {
        // cur (10, 10, 10). setreuid(-1, euid=20): real unchanged but new euid
        // (20) != old real (10) → saved follows → (10, 20, 20).
        assert_eq!(setid::setre(true, (10, 10, 10), None, Some(20)), Ok((10, 20, 20)));
    }

    #[test]
    fn setre_saved_id_unchanged_when_euid_equals_old_real() {
        // cur (10, 99, 88). setreuid(-1, euid=10): euid set to OLD REAL (10),
        // real not given → saved stays 88.
        assert_eq!(setid::setre(true, (10, 99, 88), None, Some(10)), Ok((10, 10, 88)));
    }

    #[test]
    fn setre_unprivileged_rejects_foreign_real() {
        // cur (100, 100, 100). new real 200 ∉ {100,100} → EPERM.
        assert_eq!(setid::setre(false, (100, 100, 100), Some(200), None), Err(()));
        // new euid may be the saved id even if unprivileged.
        assert_eq!(setid::setre(false, (100, 100, 50), None, Some(50)), Ok((100, 50, 50)));
    }

    // setuid: privileged sets all three; unprivileged only the effective id,
    // and only to the real or saved id.
    #[test]
    fn set_privileged_sets_all_three() {
        assert_eq!(setid::set(true, (0, 0, 0), 9), Ok((9, 9, 9)));
    }

    #[test]
    fn set_unprivileged_changes_only_effective_and_gates_value() {
        // cur (100, 100, 50). setuid(50): 50 is the saved id → ok, only euid
        // changes → (100, 50, 50→unchanged=50). real+saved unchanged.
        assert_eq!(setid::set(false, (100, 100, 50), 50), Ok((100, 50, 50)));
        // setuid(999): not real/saved → EPERM.
        assert_eq!(setid::set(false, (100, 100, 50), 999), Err(()));
    }
}
