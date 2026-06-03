//! Credentials: uid/gid identity, capabilities, umask, and process priority.
//!
//! # Theory of operation
//!
//! carrick runs the entire guest as ONE host identity (whatever the macOS user
//! launched it as), so it cannot truly become another uid. But it must still
//! pass the identity DANCE that real software performs, and that dance is
//! verify-after-set: apt's `_apt` privsep does `setresuid`/`setresgid` to drop
//! privilege, then immediately `getuid`/`geteuid`/`getresuid` to CONFIRM the
//! new identity ("Could not switch group" if it doesn't match). Returning the
//! host's real identity unconditionally would break that.
//!
//! So the model is a faithful in-memory credential register file
//! ([`CredState`]): accept every `set*uid`/`set*gid`/`setres*`/`setre*` the
//! guest requests, store the new (real, effective, saved) ids, and echo them
//! back from the corresponding `get*` calls. The default identity is root
//! (uid 0 / gid 0) — what `id` shows in a typical container. The host kernel is
//! NOT consulted for these (it would answer for the real macOS user); the one
//! exception is anything that genuinely affects host behavior, which is folded
//! into VFS access checks via the tracked `fsuid`/`fsgid`.
//!
//! Subtleties worth knowing before touching this:
//!
//!   - `fsuid`/`fsgid` (the VFS-access identity) track `euid`/`egid` — every
//!     `set*uid`/`set*gid` resets them — but `setfsuid`/`setfsgid` can point
//!     them elsewhere independently, and (per the Linux quirk) those two return
//!     the PREVIOUS value, not the new one.
//!   - Capabilities (`capget`/`capset`) are recorded/echoed; carrick runs as
//!     root-equivalent so the cap sets are permissive, but the calls must
//!     succeed and round-trip for libcap-based feature checks.
//!   - `nice` is a per-process attribute, so `setpriority`/`getpriority`
//!     store it in a process-global static (correct: fork gives a fresh
//!     address space) and translate between the user value `[-20,19]` and the
//!     kernel-ABI `20 - nice` that glibc converts back. `is_self_priority_target`
//!     accepts the caller's pid, `LINUX_BOOTSTRAP_PID`, and (under a PID
//!     namespace) the ns-pid that maps back to us.
//!
//! Methods are `impl` blocks on [`SyscallDispatcher`]; see [`super`] for the
//! dispatcher struct and the normalized dispatch table.
use super::*;

/// Per-process nice value (the calling process's PRIO_PROCESS priority).
/// Default 0. setpriority(PRIO_PROCESS, self) stores it (clamped to [-20,19])
/// and getpriority(PRIO_PROCESS, self) reports it as the kernel-ABI `20 - nice`
/// (glibc converts back). A process-global static is correct: nice is a
/// per-process attribute and carrick's fork creates a fresh address space.
static NICE_VALUE: std::sync::atomic::AtomicI32 = std::sync::atomic::AtomicI32::new(0);

fn is_self_priority_target(who: i32) -> bool {
    if who == 0 || who == LINUX_BOOTSTRAP_PID as i32 || who == std::process::id() as i32 {
        return true;
    }
    // Under a PID namespace the guest names itself (PRIO_PROCESS with its own
    // pid/tid) by its NS-pid, not the host pid. Accept the caller's ns-pid and
    // any ns-pid that maps back to our host pid.
    if crate::namespace::pid::enabled() && who > 0 {
        let w = who as u32;
        if w == crate::namespace::pid::self_ns_pid()
            || crate::namespace::pid::ns_to_host_or_self(w) == Some(std::process::id())
        {
            return true;
        }
    }
    false
}

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
    /// Filesystem uid/gid (the id used for VFS access checks). Tracks euid/egid
    /// by default — every set*uid/set*gid resets it to the new euid/egid — but
    /// setfsuid/setfsgid can point it elsewhere independently. setfs*id returns
    /// the PREVIOUS value (LTP setfsuid01/03, setfsgid01/02).
    pub fsuid: u32,
    pub fsgid: u32,
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
            fsuid: 0,
            fsgid: 0,
            umask: LINUX_DEFAULT_UMASK,
        }
    }

    /// Seed every uid/gid view (real/effective/saved/fs) to `(uid, gid)` — the
    /// container's initial identity from `docker run --user` / image `USER`,
    /// applied once before the guest starts (so a later set*id still follows the
    /// Linux transition rules from this baseline).
    pub(super) fn seed_identity(&mut self, uid: u32, gid: u32) {
        self.ruid = uid;
        self.euid = uid;
        self.suid = uid;
        self.fsuid = uid;
        self.rgid = gid;
        self.egid = gid;
        self.sgid = gid;
        self.fsgid = gid;
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
            if let Some(nr) = r
                && nr != old_real
                && nr != old_eff
            {
                return Err(());
            }
            if let Some(ne) = e
                && ne != old_real
                && ne != old_eff
                && ne != old_saved
            {
                return Err(());
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
        // In a PID namespace the container init is pid 1 and every member sees
        // its ns-local pid; identity (the host pid) otherwise (§5.3).
        DispatchOutcome::Returned {
            value: i64::from(crate::namespace::pid::self_ns_pid()),
        }
    }

    /// The supplementary group list `getgroups(2)` reports: the primary egid
    /// plus every group in the guest's `/etc/group` that lists the current user
    /// (resolved from `/etc/passwd` by euid) as a member — the same set runc
    /// derives, so `id` matches Docker. Falls back to just the egid when the
    /// files are absent/unreadable.
    pub(super) fn supplementary_groups(&self) -> Vec<u32> {
        let (euid, egid) = {
            let c = self.creds.lock();
            (c.euid, c.egid)
        };
        let mut gids: Vec<u32> = vec![egid];
        // uid -> username via /etc/passwd (name:passwd:uid:gid:...).
        let username = self.read_exec_file("/etc/passwd").and_then(|b| {
            String::from_utf8_lossy(&b).lines().find_map(|line| {
                let f: Vec<&str> = line.split(':').collect();
                if f.len() >= 3 && f[2].parse::<u32>().ok() == Some(euid) {
                    Some(f[0].to_string())
                } else {
                    None
                }
            })
        });
        // Groups that name the user as a member (name:passwd:gid:m1,m2,...).
        if let (Some(user), Some(group)) = (username, self.read_exec_file("/etc/group")) {
            for line in String::from_utf8_lossy(&group).lines() {
                let f: Vec<&str> = line.split(':').collect();
                if f.len() < 4 {
                    continue;
                }
                let Ok(gid) = f[2].parse::<u32>() else {
                    continue;
                };
                if !gids.contains(&gid) && f[3].split(',').any(|m| !m.is_empty() && m == user) {
                    gids.push(gid);
                }
            }
        }
        gids
    }
}

impl SyscallDispatcher {
    define_syscall! {
        fn capget(this, cx, header_address: GuestPtr, data_address: GuestPtr) {
            let memory = &mut *cx.memory;
            let header = read_capability_header(memory, header_address.0)?;
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
            // Report the modeled capability set (Docker default, or a full set
            // inside a fresh user namespace) rather than an empty set, so
            // libcap-based tools see a coherent story (docs/namespaces-design.md
            // §4.4). capget data words are 32-bit halves of each 64-bit set:
            // word 0 = low 32 bits, word 1 = high 32 bits (capability_words).
            let caps = crate::namespace::process::caps();
            let words = linux_capability_data_words(header.version);
            let data = capability_words(&caps, words);
            if memory
                .write_bytes(data_address.0, capability_data_bytes(&data).as_slice())
                .is_err()
            {
                return Ok(LINUX_EFAULT.into());
            }
            Ok(DispatchOutcome::Returned { value: 0 })
        }

        fn capset(this, cx, header_address: GuestPtr, data_address: GuestPtr) {
            let memory = &*cx.memory;
            let header = read_capability_header(memory, header_address.0)?;
            if !linux_capability_version_is_supported(header.version) {
                return Ok(LINUX_EINVAL.into());
            }
            if header.pid < 0 {
                return Ok(LINUX_ESRCH.into());
            }
            let words = linux_capability_data_words(header.version);
            let data = read_capability_data(memory, data_address.0, words)?;
            // Accept-and-record so libcap tools (dpkg, setpriv) that capset() to
            // DROP caps don't abort — carrick is the kernel and does not modulate
            // DAC by capabilities (docs/namespaces-design.md §4.4). The bounding/
            // ambient sets are preserved (capset cannot raise them). But the
            // STRUCTURAL well-formedness invariants Linux enforces for EVERY
            // caller (root included) are not privilege checks, and libcap relies
            // on the errno, so they ARE enforced here:
            //   * a capability may be effective only if it is also permitted, and
            //   * capset can never RAISE permitted (only drop/keep it).
            // Violations are EPERM even for a fully-privileged caller (oracle:
            // debian:stable root, capset{eff=1,prm=0} -> EPERM). Valid drops
            // satisfy both rules, so dpkg/setpriv still succeed.
            let mut caps = crate::namespace::process::caps();
            let (eff, prm, inh) = capability_set_from_words(&data);
            if (eff & !prm) != 0 || (prm & !caps.permitted) != 0 {
                return Ok(LINUX_EPERM.into());
            }
            caps.effective = eff;
            caps.permitted = prm;
            caps.inheritable = inh;
            crate::namespace::process::set_caps(caps);
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
            use std::sync::atomic::Ordering;
            let prio = prio as i32;
            if which > LINUX_PRIO_USER {
                return Ok(LINUX_EINVAL.into());
            }
            // A negative id (pid/pgid/uid) names no target → ESRCH for every
            // PRIO_* class (setpriority02).
            if who.0 < 0 {
                return Ok(LINUX_ESRCH.into());
            }
            // PRIO_PROCESS names a process OR a thread (Linux nice is per-thread);
            // a live sibling guest thread tid is a valid self-process target.
            let sibling = cx
                .thread
                .as_ref()
                .is_some_and(|t| t.registry.is_live(who.0 as crate::thread::ThreadId));
            if which == LINUX_PRIO_PROCESS && !is_self_priority_target(who.0) && !sibling {
                return Ok(LINUX_ESRCH.into());
            }
            // Linux CLAMPS the nice value to [-20,19] (it does NOT reject an
            // out-of-range value with EINVAL): glibc's nice() passes
            // current+increment straight through and relies on this clamp
            // (LTP nice02 does nice(50) → clamps to 19).
            let clamped = prio.clamp(-20, 19);
            // For the calling process, enforce the unprivileged nice-lowering
            // rule (raising priority needs CAP_SYS_NICE): a non-root euid can't
            // set a nice BELOW the current one. setpriority(2) reports EACCES
            // for that case; EPERM is for a target-ownership mismatch.
            if which == LINUX_PRIO_PROCESS {
                let current = NICE_VALUE.load(Ordering::Relaxed);
                if clamped < current && this.cred_snapshot().euid != 0 {
                    return Ok(LINUX_EACCES.into());
                }
                NICE_VALUE.store(clamped, Ordering::Relaxed);
            }
            Ok(DispatchOutcome::Returned { value: 0 })
        }

        fn getpriority(this, cx, which: u64, who: Pid) {
            use std::sync::atomic::Ordering;
            if which > LINUX_PRIO_USER {
                return Ok(LINUX_EINVAL.into());
            }
            // A negative id names no target → ESRCH, for every PRIO_* class
            // (getpriority02); PRIO_PROCESS additionally resolves only self/init.
            if who.0 < 0 {
                return Ok(LINUX_ESRCH.into());
            }
            let sibling = cx
                .thread
                .as_ref()
                .is_some_and(|t| t.registry.is_live(who.0 as crate::thread::ThreadId));
            if which == LINUX_PRIO_PROCESS && !is_self_priority_target(who.0) && !sibling {
                return Ok(LINUX_ESRCH.into());
            }
            // Kernel ABI: getpriority returns `20 - nice` (so the value is never
            // negative); glibc converts it back. Report the calling process's
            // stored nice for PRIO_PROCESS, else the default (nice 0 → 20).
            let nice = if which == LINUX_PRIO_PROCESS {
                NICE_VALUE.load(Ordering::Relaxed)
            } else {
                0
            };
            Ok(DispatchOutcome::Returned {
                value: (20 - nice) as i64,
            })
        }

        fn setresuid(this, cx, r: u64, e: u64, s: u64) {
            let mut creds = this.creds.lock();
            let priv_ = creds.is_privileged();
            match setid::setres(priv_, (creds.ruid, creds.euid, creds.suid),
                                 keep_or(r), keep_or(e), keep_or(s)) {
                Ok((ru, eu, su)) => { creds.ruid = ru; creds.euid = eu; creds.suid = su; creds.fsuid = creds.euid; }
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
                Ok((rg, eg, sg)) => { creds.rgid = rg; creds.egid = eg; creds.sgid = sg; creds.fsgid = creds.egid; }
                Err(()) => return Ok(LINUX_EPERM.into()),
            }
            Ok(DispatchOutcome::Returned { value: 0 })
        }

        fn setreuid(this, cx, r: u64, e: u64) {
            let mut creds = this.creds.lock();
            let priv_ = creds.is_privileged();
            match setid::setre(priv_, (creds.ruid, creds.euid, creds.suid),
                               keep_or(r), keep_or(e)) {
                Ok((ru, eu, su)) => { creds.ruid = ru; creds.euid = eu; creds.suid = su; creds.fsuid = creds.euid; }
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
                Ok((rg, eg, sg)) => { creds.rgid = rg; creds.egid = eg; creds.sgid = sg; creds.fsgid = creds.egid; }
                Err(()) => return Ok(LINUX_EPERM.into()),
            }
            Ok(DispatchOutcome::Returned { value: 0 })
        }

        fn setuid(this, cx, u: u64) {
            let mut creds = this.creds.lock();
            let priv_ = creds.is_privileged();
            match setid::set(priv_, (creds.ruid, creds.euid, creds.suid), u as u32) {
                Ok((ru, eu, su)) => { creds.ruid = ru; creds.euid = eu; creds.suid = su; creds.fsuid = creds.euid; }
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
                Ok((rg, eg, sg)) => { creds.rgid = rg; creds.egid = eg; creds.sgid = sg; creds.fsgid = creds.egid; }
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
            // A prior setgroups(2) replaced the set verbatim; otherwise fall
            // back to the /etc/group-derived membership (id(1) compatibility).
            let groups = match this.setgroups_override.lock().clone() {
                Some(g) => g,
                None => this.supplementary_groups(),
            };
            // size == 0 is a pure query: return the count without writing.
            if size == 0 {
                return Ok(DispatchOutcome::Returned {
                    value: groups.len() as i64,
                });
            }
            if (size as usize) < groups.len() {
                // Buffer too small to hold the whole set (Linux EINVAL).
                return Ok(LINUX_EINVAL.into());
            }
            let mut bytes = Vec::with_capacity(groups.len() * 4);
            for g in &groups {
                bytes.extend_from_slice(&g.to_le_bytes());
            }
            if cx.memory.write_bytes(list.0, &bytes).is_err() {
                return Ok(LINUX_EFAULT.into());
            }
            Ok(DispatchOutcome::Returned {
                value: groups.len() as i64,
            })
        }

        fn sys_setfsuid(this, cx, uid: u64) {
            // Always returns the PREVIOUS fsuid (setfsuid never fails). The new
            // fsuid takes effect only if privileged or `uid` already matches one
            // of {ruid, euid, suid, fsuid}; `(uid_t)-1` is a pure query.
            let mut creds = this.creds.lock();
            let prev = creds.fsuid;
            let uid = uid as u32;
            if uid != u32::MAX
                && (creds.is_privileged()
                    || uid == creds.ruid
                    || uid == creds.euid
                    || uid == creds.suid
                    || uid == creds.fsuid)
            {
                creds.fsuid = uid;
            }
            Ok(DispatchOutcome::Returned {
                value: i64::from(prev),
            })
        }

        fn sys_setfsgid(this, cx, gid: u64) {
            let mut creds = this.creds.lock();
            let prev = creds.fsgid;
            let gid = gid as u32;
            if gid != u32::MAX
                && (creds.is_privileged()
                    || gid == creds.rgid
                    || gid == creds.egid
                    || gid == creds.sgid
                    || gid == creds.fsgid)
            {
                creds.fsgid = gid;
            }
            Ok(DispatchOutcome::Returned {
                value: i64::from(prev),
            })
        }

        fn sys_setgroups(this, cx, size: u64, list: GuestPtr) {
            // Linux caps the supplementary set at NGROUPS_MAX (65536).
            const NGROUPS_MAX: u64 = 65536;
            if size > NGROUPS_MAX {
                return Ok(LINUX_EINVAL.into());
            }
            let n = size as usize;
            let mut groups = Vec::with_capacity(n);
            if n > 0 {
                let bytes = match cx.memory.read_bytes(list.0, n * 4) {
                    Ok(b) => b,
                    Err(_) => return Ok(LINUX_EFAULT.into()),
                };
                for chunk in bytes.chunks_exact(4) {
                    groups.push(u32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]));
                }
            }
            // Replace the whole supplementary set (Linux semantics): getgroups
            // now returns exactly this. CPython subprocess `extra_groups=` sets
            // it in the pre-exec child and reads it back via os.getgroups().
            *this.setgroups_override.lock() = Some(groups);
            Ok(DispatchOutcome::Returned { value: 0 })
        }

        fn sys_getpid(this, cx) {
            Ok(this.getpid())
        }

        fn sys_getppid(this, cx) {
            // PID-namespace translation (§5.3, §5.4): the ns-init (ns-pid 1) has
            // no parent inside the namespace, so getppid()==0; other members map
            // their host ppid to its ns-pid (0 if the parent is outside the ns);
            // a reparented orphan reports ns-pid 1.
            if crate::namespace::pid::enabled() {
                return Ok(DispatchOutcome::Returned {
                    value: i64::from(crate::namespace::pid::self_ns_ppid()),
                });
            }
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

/// Split a modeled [`crate::namespace::process::CapabilitySet`] into the
/// `count` 32-bit `LinuxCapabilityData` words the capget(2) ABI expects: word 0
/// carries the low 32 bits of each set, word 1 (v2/v3) the high 32 bits.
fn capability_words(
    caps: &crate::namespace::process::CapabilitySet,
    count: usize,
) -> Vec<LinuxCapabilityData> {
    (0..count)
        .map(|i| {
            let shift = (i as u32) * 32;
            let half = |v: u64| -> u32 { (v >> shift) as u32 };
            LinuxCapabilityData {
                effective: half(caps.effective),
                permitted: half(caps.permitted),
                inheritable: half(caps.inheritable),
            }
        })
        .collect()
}

/// Reassemble the (effective, permitted, inheritable) u64 sets from the capset(2)
/// data words (inverse of [`capability_words`]).
fn capability_set_from_words(data: &[LinuxCapabilityData]) -> (u64, u64, u64) {
    let mut eff = 0u64;
    let mut prm = 0u64;
    let mut inh = 0u64;
    for (i, word) in data.iter().enumerate() {
        let shift = (i as u32) * 32;
        eff |= u64::from(word.effective) << shift;
        prm |= u64::from(word.permitted) << shift;
        inh |= u64::from(word.inheritable) << shift;
    }
    (eff, prm, inh)
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
        assert_eq!(
            setid::setres(false, (100, 100, 100), Some(200), None, None),
            Err(())
        );
        // To an id already held (100) → ok, no change.
        assert_eq!(
            setid::setres(false, (100, 100, 100), Some(100), None, None),
            Ok((100, 100, 100))
        );
    }

    #[test]
    fn setres_privileged_sets_anything_and_keeps_minus_one() {
        // -1 (None) leaves a field unchanged; others set.
        assert_eq!(
            setid::setres(true, (0, 0, 0), Some(5), None, Some(7)),
            Ok((5, 0, 7))
        );
    }

    // setreuid saved-id rule (the subtle part LTP setreuid02 pins down).
    #[test]
    fn setre_saved_id_follows_when_real_changes() {
        // Privileged, cur (0,0,0). setreuid(ruid=5, euid=6): real changes →
        // saved becomes the new euid (6).
        assert_eq!(
            setid::setre(true, (0, 0, 0), Some(5), Some(6)),
            Ok((5, 6, 6))
        );
    }

    #[test]
    fn setre_saved_id_follows_when_euid_differs_from_old_real() {
        // cur (10, 10, 10). setreuid(-1, euid=20): real unchanged but new euid
        // (20) != old real (10) → saved follows → (10, 20, 20).
        assert_eq!(
            setid::setre(true, (10, 10, 10), None, Some(20)),
            Ok((10, 20, 20))
        );
    }

    #[test]
    fn setre_saved_id_unchanged_when_euid_equals_old_real() {
        // cur (10, 99, 88). setreuid(-1, euid=10): euid set to OLD REAL (10),
        // real not given → saved stays 88.
        assert_eq!(
            setid::setre(true, (10, 99, 88), None, Some(10)),
            Ok((10, 10, 88))
        );
    }

    #[test]
    fn setre_unprivileged_rejects_foreign_real() {
        // cur (100, 100, 100). new real 200 ∉ {100,100} → EPERM.
        assert_eq!(
            setid::setre(false, (100, 100, 100), Some(200), None),
            Err(())
        );
        // new euid may be the saved id even if unprivileged.
        assert_eq!(
            setid::setre(false, (100, 100, 50), None, Some(50)),
            Ok((100, 50, 50))
        );
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
