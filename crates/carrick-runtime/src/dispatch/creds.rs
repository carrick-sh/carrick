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
//! So the model is a faithful immutable credential register file
//! ([`crate::kernel::Credentials`]): accept every
//! `set*uid`/`set*gid`/`setres*`/`setre*` the
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
use crate::linux_abi::LinuxErrno;
use carrick_abi::{NsGid, NsUid};

syscall_table! {
    /// Per-module syscall routing for the `creds` subsystem (Task A1).
    ///
    /// Owns the `number → handler` arms for every syscall this module
    /// implements. `resolve_handler` in `dispatch/mod.rs` chains this with
    /// the other modules' tables. Add a `creds` syscall by adding an arm
    /// HERE — no shared routing table to edit.
    pub(crate) fn dispatch_creds;
    90 => capget,
    91 => capset,
    140 => setpriority,
    141 => getpriority,
    143 => setregid,
    144 => setgid,
    145 => setreuid,
    146 => setuid,
    147 => setresuid,
    148 => getresuid,
    149 => setresgid,
    150 => getresgid,
    158 => getgroups,
    166 => umask,
    151 => sys_setfsuid,
    152 => sys_setfsgid,
    159 => sys_setgroups,
    172 => sys_getpid,
    173 => sys_getppid,
    174 => sys_getuid,
    175 => sys_geteuid,
    176 => sys_getgid,
    177 => sys_getegid,
}

/// Per-process nice value (the calling process's PRIO_PROCESS priority).
/// Default 0. setpriority(PRIO_PROCESS, self) stores it (clamped to [-20,19])
/// and getpriority(PRIO_PROCESS, self) reports it as the kernel-ABI `20 - nice`
/// (glibc converts back). A process-global static is correct: nice is a
/// per-process attribute and carrick's fork creates a fresh address space.
static NICE_VALUE: std::sync::atomic::AtomicI32 = std::sync::atomic::AtomicI32::new(0);

fn is_self_priority_target(who: i32) -> bool {
    // PRIO_PROCESS names the caller by 0 (self for setpriority, unlike signals)
    // or by its (ns-)pid — the process-level cases are the canonical
    // NsPid::names_self (host pid, bootstrap pid, or the caller's ns-pid).
    who == 0 || NsPid(who).names_self()
}

/// A `setpriority(PRIO_PROCESS, who)` target relative to the caller.
enum PrioTarget {
    /// The calling process itself (who 0, the caller's own ns-pid/host pid, or a
    /// live sibling thread).
    Caller,
    /// Another live carrick guest process, carrying its published effective uid
    /// (root/0 when the peer hasn't published — the conservative reading for the
    /// container init, which is root and never drops privilege).
    Other { euid: NsUid },
    /// No such process — ESRCH.
    NotFound,
}

/// Resolve a concrete `setpriority(PRIO_PROCESS, who)` pid against carrick's
/// guest process model. Deliberately does NOT treat the bootstrap pid (1) as
/// self (unlike [`is_self_priority_target`]): a non-init caller naming init
/// (pid 1) must resolve to that OTHER, root-owned process so the ownership check
/// can reject it with EPERM (LTP setpriority02). The peer's effective uid is
/// read from the fork-coherent cred publication that `kill(2)` already uses.
fn resolve_prio_process_target<M: GuestMemory>(cx: &SyscallCtx<'_, M>, who: i32) -> PrioTarget {
    let host = std::process::id();
    let is_self = who == 0
        || who as u32 == host
        || (crate::namespace::pid::enabled()
            && (who as u32 == crate::namespace::pid::self_ns_pid()
                || crate::namespace::pid::ns_to_host_or_self(who as u32) == Some(host)))
        || cx.thread.as_ref().is_some_and(|t| {
            t.registry
                .is_live(crate::thread::ThreadId::from_guest_supplied_tid(who))
        });
    if is_self {
        return PrioTarget::Caller;
    }
    match crate::namespace::pid::ns_to_host_or_self(who as u32) {
        Some(h) if crate::host_proc::is_guest_process(h) => PrioTarget::Other {
            euid: crate::cred_ipc::read_target(h as i32).unwrap_or(NsUid::ROOT),
        },
        _ => PrioTarget::NotFound,
    }
}

/// The Linux `(uid_t)-1` "leave unchanged" sentinel. uid_t is unsigned, so the
/// guest passes 0xFFFFFFFF zero-extended into a 64-bit register; decode that as
/// "keep", any other value as a concrete id. (The old `arg as i64 != -1` check
/// was wrong: 0xFFFFFFFF as i64 is 4294967295, never -1, so a `-1` arg was
/// treated as a real uid 4294967295.)
fn keep_or_uid(arg: u64) -> Option<NsUid> {
    let v = arg as u32;
    if v == u32::MAX { None } else { Some(NsUid(v)) }
}

fn keep_or_gid(arg: u64) -> Option<NsGid> {
    let v = arg as u32;
    if v == u32::MAX { None } else { Some(NsGid(v)) }
}

/// Linux set*id transition rules (kernel/sys.c). Each returns `Err(())` ⇒ the
/// caller maps to EPERM. Pure functions on the (r,e,s) triple so they're
/// unit-testable independent of which uid/gid family they serve.
mod setid {
    /// setresuid/setresgid: when unprivileged, every non-(-1) target id must
    /// already be one of {real, effective, saved}; privileged sets anything.
    pub(super) fn setres<T: Copy + Eq>(
        privileged: bool,
        cur: (T, T, T),
        r: Option<T>,
        e: Option<T>,
        s: Option<T>,
    ) -> Result<(T, T, T), ()> {
        let (mut real, mut eff, mut saved) = cur;
        if !privileged {
            let allowed = |id: T| id == real || id == eff || id == saved;
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
    pub(super) fn setre<T: Copy + Eq>(
        privileged: bool,
        cur: (T, T, T),
        r: Option<T>,
        e: Option<T>,
    ) -> Result<(T, T, T), ()> {
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
    pub(super) fn set<T: Copy + Eq>(
        privileged: bool,
        cur: (T, T, T),
        u: T,
    ) -> Result<(T, T, T), ()> {
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

/// Per-process identity served by the EL1 syscall shim. Credentials are not
/// present because Linux permits them to diverge per thread; credential reads
/// always trap through the captured KernelContext path.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct IdentitySnapshot {
    pub pid: u32,
}

impl SyscallDispatcher {
    pub(super) fn cred_snapshot(&self) -> Arc<crate::kernel::Credentials> {
        if let Some(credentials) = super::resources::credentials() {
            return credentials;
        }
        #[cfg(test)]
        {
            self.capture_one_task_context()
                .expect("test credential context")
                .resources()
                .credentials()
        }
        #[cfg(not(test))]
        {
            tracing::error!("credential read escaped its captured KernelContext scope");
            std::process::abort();
        }
    }

    #[cfg(test)]
    pub(super) fn credentials_from_context(
        &self,
        kernel: &crate::kernel::KernelContext,
    ) -> Arc<crate::kernel::Credentials> {
        kernel.resources().credentials()
    }

    pub(super) fn update_credentials(
        &self,
        kernel: &crate::kernel::KernelContext,
        update: impl FnOnce(&mut crate::kernel::Credentials),
    ) -> Result<Arc<crate::kernel::Credentials>, LinuxErrno> {
        match kernel.kernel().update_credentials(kernel, update) {
            Ok(updated) => Ok(updated.resources().credentials()),
            Err(
                crate::kernel::KernelOperationError::StaleContext
                | crate::kernel::KernelOperationError::ParentExited
                | crate::kernel::KernelOperationError::UnknownThread(_),
            ) => Err(crate::linux_abi::LINUX_EINTR),
            Err(crate::kernel::KernelOperationError::TaskBusy(_)) => {
                Err(crate::linux_abi::LINUX_EAGAIN)
            }
            Err(error) => {
                tracing::error!(%error, "credential COW publication invariant failed");
                std::process::abort();
            }
        }
    }

    fn update_fs_umask(&self, kernel: &crate::kernel::KernelContext, umask: u32) -> u32 {
        match kernel.kernel().update_fs_umask(kernel, umask) {
            Ok((_, previous)) => previous,
            Err(error) => {
                // umask(2) has no error return. Reservation contention is
                // retried inside Kernel; any remaining failure means the exact
                // dispatch context violated its authority boundary.
                tracing::error!(%error, "CLONE_FS umask publication invariant failed");
                std::process::abort();
            }
        }
    }

    /// Capture the per-process identity fast-path value at an explicit Kernel
    /// boundary. The context parameter prevents lifecycle callers from silently
    /// reintroducing registry recapture even though PID itself is process-wide.
    pub(crate) fn identity_snapshot(
        &self,
        _kernel: &crate::kernel::KernelContext,
    ) -> IdentitySnapshot {
        IdentitySnapshot {
            pid: self.identity_pid(),
        }
    }

    /// The CALLING Linux process's own pid — exactly what `getpid(2)` reports.
    ///
    /// This is the only correct source for a guest-visible "my pid" field
    /// (`si_pid`, SysV `msg_lspid`/`msg_lrpid`/`shm_cpid`/`shm_lpid`, …).
    /// NEVER reach for `crate::namespace::pid::self_ns_pid()` there: it starts
    /// from `std::process::id()`, and under HVPatch every logical Linux process
    /// is a thread of ONE VM carrier, so that value is identical for all of
    /// them. `virtual_pid` is the carrier's kernel-graph task id for this exact
    /// process, published by `bind_hvpatch_process`; the `self_ns_pid()`
    /// fallback only runs where no kernel-graph process is bound.
    pub(crate) fn identity_pid(&self) -> u32 {
        if let Some(pid) = self.proc.lock().virtual_pid {
            return pid;
        }
        crate::namespace::pid::self_ns_pid()
    }

    pub(super) fn getpid(&self) -> DispatchOutcome {
        // In a PID namespace the container init is pid 1 and every member sees
        // its ns-local pid; identity (the host pid) otherwise (§5.3).
        DispatchOutcome::Returned {
            value: i64::from(self.identity_pid()),
        }
    }

    /// The supplementary group list `getgroups(2)` reports: the primary egid
    /// plus every group in the guest's `/etc/group` that lists the current user
    /// (resolved from `/etc/passwd` by euid) as a member — the same set runc
    /// derives, so `id` matches Docker. Falls back to just the egid when the
    /// files are absent/unreadable.
    fn supplementary_groups_from_files(
        &self,
        credentials: &crate::kernel::Credentials,
    ) -> Vec<NsGid> {
        let c = credentials;
        let (euid, egid) = (c.euid, c.egid);
        let mut gids: Vec<NsGid> = vec![egid];
        // uid -> username via /etc/passwd (name:passwd:uid:gid:...).
        let username = self.read_exec_file("/etc/passwd").and_then(|b| {
            String::from_utf8_lossy(&b).lines().find_map(|line| {
                let f: Vec<&str> = line.split(':').collect();
                if f.len() >= 3 && f[2].parse::<u32>().ok() == Some(euid.raw()) {
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
                let gid = NsGid::new(gid);
                if !gids.contains(&gid) && f[3].split(',').any(|m| !m.is_empty() && m == user) {
                    gids.push(gid);
                }
            }
        }
        gids
    }

    pub(super) fn current_groups(&self) -> Vec<NsGid> {
        let credentials = self.cred_snapshot();
        match credentials.supplementary_groups_override() {
            Some(groups) => groups.to_vec(),
            None => self.supplementary_groups_from_files(&credentials),
        }
    }

    /// Publish the mature one-task adapter's leader credential for peer host
    /// processes. This file is transport, not in-process authority: nonleaders
    /// and multiplexed HVPatch tasks never overwrite one host-PID projection.
    pub(super) fn publish_external_credential_projection(
        &self,
        context: &crate::kernel::KernelContext,
        credentials: &crate::kernel::Credentials,
    ) {
        let leader = crate::kernel::LinuxTid::for_task_leader(context.task().key().id);
        if context.thread().key().tid == leader && self.hvpatch_process().is_none() {
            crate::cred_ipc::publish_self(credentials.euid());
        }
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
                return Ok(DispatchOutcome::errno(LINUX_EINVAL));
            }
            // pid < 0 is EINVAL (not ESRCH). A positive pid that isn't the caller
            // is ESRCH. The guest sees NS-pids — getpid() returns self_ns_pid()
            // (e.g. 1), NOT carrick's host pid — so a process querying its OWN caps
            // via capget(getpid()) (exactly what the LTP tst_capget framework
            // helper does) must be matched against the ns-pid, not
            // std::process::id(). pid 0 means "the calling process".
            if header.pid < 0 {
                return Ok(DispatchOutcome::errno(LINUX_EINVAL));
            }
            // Consolidated onto the canonical self-check rather than a fourth
            // hand-rolled copy — its own doc records that exactly this drift
            // caused the tkill01/sched ns-pid bugs. It also carries the NARROWED
            // bootstrap-pid arm: on the kernel lane pid 1 is the container init,
            // a DIFFERENT process from the caller, and this copy would have let
            // any child read the init's capabilities as if they were its own.
            if header.pid > 0 && !NsPid(header.pid).names_self() {
                return Ok(DispatchOutcome::errno(LINUX_ESRCH));
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
                return Ok(DispatchOutcome::errno(LINUX_EFAULT));
            }
            Ok(DispatchOutcome::Returned { value: 0 })
        }

        fn capset(this, cx, header_address: GuestPtr, data_address: GuestPtr) {
            let memory = &mut *cx.memory;
            let header = read_capability_header(memory, header_address.0)?;
            if !linux_capability_version_is_supported(header.version) {
                // Mirror capget: write the kernel's PREFERRED version back into
                // the header so a probing caller can retry with the right one,
                // then EINVAL (capset02).
                let pref = crate::linux_abi::LINUX_CAPABILITY_VERSION_3;
                let _ = memory.write_bytes(header_address.0, &pref.to_le_bytes());
                return Ok(DispatchOutcome::errno(LINUX_EINVAL));
            }
            if header.pid < 0 {
                return Ok(DispatchOutcome::errno(LINUX_ESRCH));
            }
            // capset (unlike capget) can only modify the CALLING process: a
            // nonzero pid that isn't the caller is EPERM, even for root
            // (capset03). The guest sees NS-pids, so match against self_ns_pid().
            // Same consolidation as capget above. capset is the sharper case:
            // it MODIFIES the named process, so treating the init's pid as self
            // let a child's capset silently act as though it were the init.
            if header.pid > 0 && !NsPid(header.pid).names_self() {
                return Ok(DispatchOutcome::errno(LINUX_EPERM));
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
                return Ok(DispatchOutcome::errno(LINUX_EPERM));
            }
            // Validate the new INHERITABLE (pI) set, the third invariant Linux
            // enforces for every caller (capset02/capset03). A caller may only
            // raise pI bits it is entitled to:
            //   * WITH CAP_SETPCAP: any bit in (bounding | old_inheritable).
            //   * WITHOUT it: only bits in (old_permitted | old_inheritable).
            // A new pI bit outside that set is EPERM. (`caps` is still the OLD
            // set here — it is mutated below.)
            let setpcap_bit = 1u64 << crate::namespace::process::CAP_SETPCAP;
            let allowed_inh = if caps.effective & setpcap_bit != 0 {
                caps.bounding | caps.inheritable
            } else {
                caps.permitted | caps.inheritable
            };
            if (inh & !allowed_inh) != 0 {
                return Ok(DispatchOutcome::errno(LINUX_EPERM));
            }
            caps.effective = eff;
            caps.permitted = prm;
            caps.inheritable = inh;
            crate::namespace::process::set_caps(caps);
            Ok(DispatchOutcome::Returned { value: 0 })
        }

        fn umask(this, cx, new: u64) {
            let new = new as u32 & 0o777;
            let previous = this.update_fs_umask(cx.kernel, new);
            Ok(DispatchOutcome::Returned { value: previous as i64 })
        }

        fn setpriority(this, cx, which: u64, who: Pid, prio: u64) {
            use std::sync::atomic::Ordering;
            let prio = prio as i32;
            // An unknown `which` class is EINVAL (setpriority02 case 0).
            if which > LINUX_PRIO_USER {
                return Ok(DispatchOutcome::errno(LINUX_EINVAL));
            }
            // A negative id (pid/pgid/uid) names no target → ESRCH for every
            // PRIO_* class (setpriority02).
            if who.0 < 0 {
                return Ok(DispatchOutcome::errno(LINUX_ESRCH));
            }
            let euid = this.cred_snapshot().euid;
            // Linux CLAMPS the nice value to [-20,19] (it does NOT reject an
            // out-of-range value with EINVAL): glibc's nice() passes
            // current+increment straight through and relies on this clamp
            // (LTP nice02 does nice(50) → clamps to 19).
            let clamped = prio.clamp(-20, 19);

            // PRIO_PROCESS names a concrete process (or thread — Linux nice is
            // per-thread). Resolve its identity/ownership against the guest
            // process model.
            if which == LINUX_PRIO_PROCESS {
                match resolve_prio_process_target(cx, who.0) {
                    // The caller itself → fall through to the self nice rule.
                    PrioTarget::Caller => {}
                    // Ownership (setpriority(2) EPERM): a non-root caller may only
                    // affect a process whose euid matches its own (setpriority02
                    // case 6 — `nobody` targeting init/root).
                    PrioTarget::Other { euid: target_euid }
                        if !euid.is_root() && euid != target_euid =>
                    {
                        return Ok(DispatchOutcome::errno(LINUX_EPERM));
                    }
                    // Another guest process the caller MAY affect (privileged or
                    // same owner), or no such process. carrick tracks nice only
                    // for the CALLING process, so it cannot service a cross-
                    // process set: report ESRCH rather than a bogus success that
                    // the paired getpriority() readback (which also cannot see a
                    // peer's nice) would contradict — LTP setpriority01 then fails
                    // every sub-case uniformly, matching the container oracle.
                    PrioTarget::Other { .. } | PrioTarget::NotFound => {
                        return Ok(DispatchOutcome::errno(LINUX_ESRCH));
                    }
                }
            }

            // Nice-lowering rule for the CALLER — PRIO_PROCESS on self, or
            // PRIO_PGRP/PRIO_USER with who==0 (the caller's own group/user):
            // raising priority (a nice BELOW the current value) needs
            // CAP_SYS_NICE, so an unprivileged caller gets EACCES (setpriority02
            // cases 4 and 5). EPERM (above) is target-ownership; EACCES is the
            // privilege to raise one's own priority.
            if clamped < NICE_VALUE.load(Ordering::Relaxed) && !euid.is_root() {
                return Ok(DispatchOutcome::errno(LINUX_EACCES));
            }
            if which == LINUX_PRIO_PROCESS {
                NICE_VALUE.store(clamped, Ordering::Relaxed);
            }
            Ok(DispatchOutcome::Returned { value: 0 })
        }

        fn getpriority(this, cx, which: u64, who: Pid) {
            use std::sync::atomic::Ordering;
            if which > LINUX_PRIO_USER {
                return Ok(DispatchOutcome::errno(LINUX_EINVAL));
            }
            // A negative id names no target → ESRCH, for every PRIO_* class
            // (getpriority02); PRIO_PROCESS additionally resolves only self/init.
            if who.0 < 0 {
                return Ok(DispatchOutcome::errno(LINUX_ESRCH));
            }
            let sibling = cx
                .thread
                .as_ref()
                .is_some_and(|t| {
                    t.registry
                        .is_live(crate::thread::ThreadId::from_guest_supplied_tid(who.0))
                });
            if which == LINUX_PRIO_PROCESS && !is_self_priority_target(who.0) && !sibling {
                return Ok(DispatchOutcome::errno(LINUX_ESRCH));
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
            let current = this.cred_snapshot();
            let (ruid, euid, suid) = match setid::setres(
                current.is_privileged(),
                (current.ruid, current.euid, current.suid),
                keep_or_uid(r),
                keep_or_uid(e),
                keep_or_uid(s),
            ) {
                Ok(values) => values,
                Err(()) => return Ok(DispatchOutcome::errno(LINUX_EPERM)),
            };
            let updated = this.update_credentials(cx.kernel, |credentials| {
                credentials.set_uid_triple(ruid, euid, suid);
            })?;
            this.publish_external_credential_projection(cx.kernel, &updated);
            Ok(DispatchOutcome::Returned { value: 0 })
        }

        fn setresgid(this, cx, r: u64, e: u64, s: u64) {
            let current = this.cred_snapshot();
            let (rgid, egid, sgid) = match setid::setres(
                current.is_privileged(),
                (current.rgid, current.egid, current.sgid),
                keep_or_gid(r),
                keep_or_gid(e),
                keep_or_gid(s),
            ) {
                Ok(values) => values,
                Err(()) => return Ok(DispatchOutcome::errno(LINUX_EPERM)),
            };
            this.update_credentials(cx.kernel, |credentials| {
                credentials.set_gid_triple(rgid, egid, sgid);
            })?;
            Ok(DispatchOutcome::Returned { value: 0 })
        }

        fn setreuid(this, cx, r: u64, e: u64) {
            let current = this.cred_snapshot();
            let (ruid, euid, suid) = match setid::setre(
                current.is_privileged(),
                (current.ruid, current.euid, current.suid),
                keep_or_uid(r),
                keep_or_uid(e),
            ) {
                Ok(values) => values,
                Err(()) => return Ok(DispatchOutcome::errno(LINUX_EPERM)),
            };
            let updated = this.update_credentials(cx.kernel, |credentials| {
                credentials.set_uid_triple(ruid, euid, suid);
            })?;
            this.publish_external_credential_projection(cx.kernel, &updated);
            Ok(DispatchOutcome::Returned { value: 0 })
        }

        fn setregid(this, cx, r: u64, e: u64) {
            let current = this.cred_snapshot();
            let (rgid, egid, sgid) = match setid::setre(
                current.is_privileged(),
                (current.rgid, current.egid, current.sgid),
                keep_or_gid(r),
                keep_or_gid(e),
            ) {
                Ok(values) => values,
                Err(()) => return Ok(DispatchOutcome::errno(LINUX_EPERM)),
            };
            this.update_credentials(cx.kernel, |credentials| {
                credentials.set_gid_triple(rgid, egid, sgid);
            })?;
            Ok(DispatchOutcome::Returned { value: 0 })
        }

        fn setuid(this, cx, u: u64) {
            let current = this.cred_snapshot();
            let (ruid, euid, suid) = match setid::set(
                current.is_privileged(),
                (current.ruid, current.euid, current.suid),
                NsUid::new(u as u32),
            ) {
                Ok(values) => values,
                Err(()) => return Ok(DispatchOutcome::errno(LINUX_EPERM)),
            };
            let updated = this.update_credentials(cx.kernel, |credentials| {
                credentials.set_uid_triple(ruid, euid, suid);
            })?;
            this.publish_external_credential_projection(cx.kernel, &updated);
            Ok(DispatchOutcome::Returned { value: 0 })
        }

        fn setgid(this, cx, g: u64) {
            let current = this.cred_snapshot();
            let (rgid, egid, sgid) = match setid::set(
                current.is_privileged(),
                (current.rgid, current.egid, current.sgid),
                NsGid::new(g as u32),
            ) {
                Ok(values) => values,
                Err(()) => return Ok(DispatchOutcome::errno(LINUX_EPERM)),
            };
            this.update_credentials(cx.kernel, |credentials| {
                credentials.set_gid_triple(rgid, egid, sgid);
            })?;
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
                cx.memory.write_bytes(ptr.0, &value.raw().to_le_bytes())?;
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
                cx.memory.write_bytes(ptr.0, &value.raw().to_le_bytes())?;
            }
            Ok(DispatchOutcome::Returned { value: 0 })
        }

        fn getgroups(this, cx, size: u64, list: GuestPtr) {
            let size = size as i32;
            if size < 0 {
                return Ok(DispatchOutcome::errno(LINUX_EINVAL));
            }
            // A prior setgroups(2) replaced the set verbatim; otherwise fall
            // back to the /etc/group-derived membership (id(1) compatibility).
            let groups = this.current_groups();
            // size == 0 is a pure query: return the count without writing.
            if size == 0 {
                return Ok(DispatchOutcome::Returned {
                    value: groups.len() as i64,
                });
            }
            if (size as usize) < groups.len() {
                // Buffer too small to hold the whole set (Linux EINVAL).
                return Ok(DispatchOutcome::errno(LINUX_EINVAL));
            }
            let mut bytes = Vec::with_capacity(groups.len() * 4);
            for g in &groups {
                bytes.extend_from_slice(&g.raw().to_le_bytes());
            }
            cx.memory.write_bytes(list.0, &bytes)?;
            Ok(DispatchOutcome::Returned {
                value: groups.len() as i64,
            })
        }

        fn sys_setfsuid(this, cx, uid: u64) {
            let current = this.cred_snapshot();
            let previous = current.fsuid;
            let raw_uid = uid as u32;
            if raw_uid != u32::MAX {
                let uid = NsUid::new(raw_uid);
                if (current.is_privileged()
                    || uid == current.ruid
                    || uid == current.euid
                    || uid == current.suid)
                    && uid != current.fsuid
                {
                    this.update_credentials(cx.kernel, |credentials| credentials.set_fsuid(uid))?;
                }
            }
            Ok(DispatchOutcome::Returned {
                value: i64::from(previous.raw()),
            })
        }

        fn sys_setfsgid(this, cx, gid: u64) {
            let current = this.cred_snapshot();
            let previous = current.fsgid;
            let raw_gid = gid as u32;
            if raw_gid != u32::MAX {
                let gid = NsGid::new(raw_gid);
                if (current.is_privileged()
                    || gid == current.rgid
                    || gid == current.egid
                    || gid == current.sgid)
                    && gid != current.fsgid
                {
                    this.update_credentials(cx.kernel, |credentials| credentials.set_fsgid(gid))?;
                }
            }
            Ok(DispatchOutcome::Returned {
                value: i64::from(previous.raw()),
            })
        }

        fn sys_setgroups(this, cx, size: u64, list: GuestPtr) {
            // setgroups requires CAP_SETGID (Linux checks may_setgroups() first).
            // We model that capability as "running as root": a non-root euid is
            // EPERM (setgroups03). This precedes the size/EFAULT checks, matching
            // the kernel's ordering (the EPERM case runs as `nobody`, the EINVAL
            // and EFAULT cases as root).
            if !this.cred_snapshot().euid.is_root() {
                return Ok(DispatchOutcome::errno(LINUX_EPERM));
            }
            // Linux caps the supplementary set at NGROUPS_MAX (65536).
            const NGROUPS_MAX: u64 = 65536;
            if size > NGROUPS_MAX {
                return Ok(DispatchOutcome::errno(LINUX_EINVAL));
            }
            let n = size as usize;
            let mut groups = Vec::with_capacity(n);
            if n > 0 {
                let bytes = cx.memory.read_bytes(list.0, n * 4)?;
                for chunk in bytes.chunks_exact(4) {
                    groups.push(NsGid::new(u32::from_le_bytes([
                        chunk[0], chunk[1], chunk[2], chunk[3],
                    ])));
                }
            }
            // Replace the whole supplementary set (Linux semantics): getgroups
            // now returns exactly this. CPython subprocess `extra_groups=` sets
            // it in the pre-exec child and reads it back via os.getgroups().
            this.update_credentials(cx.kernel, |credentials| {
                credentials.set_supplementary_groups(groups);
            })?;
            Ok(DispatchOutcome::Returned { value: 0 })
        }

        fn sys_getpid(this, cx) {
            Ok(this.getpid())
        }

        fn sys_getppid(this, cx) {
            if let Some(ppid) = this
                .hvpatch_process()
                .and_then(|process| process.parent_pid())
            {
                return Ok(DispatchOutcome::Returned {
                    value: i64::from(ppid),
                });
            }
            if let Some(ppid) = this.proc.lock().virtual_ppid {
                return Ok(DispatchOutcome::Returned {
                    value: i64::from(ppid),
                });
            }
            // PID-namespace translation (§5.3, §5.4): the ns-init (ns-pid 1) has
            // no parent inside the namespace, so getppid()==0; other members map
            // their host ppid to its ns-pid (0 if the parent is outside the ns);
            // a reparented orphan reports ns-pid 1.
            if crate::namespace::pid::enabled() {
                return Ok(DispatchOutcome::Returned {
                    value: i64::from(crate::namespace::pid::self_ns_ppid()),
                });
            }
            let (bootstrap_host_pid, subreaper_ancestor) = {
                let proc = this.proc.lock();
                (proc.bootstrap_host_pid, proc.subreaper_ancestor)
            };
            let value = identity_guest_ppid(
                std::process::id(),
                bootstrap_host_pid,
                unsafe { libc::getppid() as u32 },
                crate::guest_cpu::adopted_parent_for_self(),
                subreaper_ancestor,
            );
            Ok(DispatchOutcome::Returned { value })
        }

        fn sys_getuid(this, cx) {
            let creds = this.cred_snapshot();
            Ok(DispatchOutcome::Returned {
                value: i64::from(creds.ruid.raw()),
            })
        }

        fn sys_geteuid(this, cx) {
            let creds = this.cred_snapshot();
            Ok(DispatchOutcome::Returned {
                value: i64::from(creds.euid.raw()),
            })
        }

        fn sys_getgid(this, cx) {
            let creds = this.cred_snapshot();
            Ok(DispatchOutcome::Returned {
                value: i64::from(creds.rgid.raw()),
            })
        }

        fn sys_getegid(this, cx) {
            let creds = this.cred_snapshot();
            Ok(DispatchOutcome::Returned {
                value: i64::from(creds.egid.raw()),
            })
        }
    }
}

fn read_capability_header(
    memory: &impl GuestMemory,
    address: u64,
) -> Result<LinuxCapabilityHeader, LinuxErrno> {
    let bytes = memory
        .read_bytes(address, core::mem::size_of::<LinuxCapabilityHeader>())
        .map_err(|_| LINUX_EFAULT)?;
    LinuxCapabilityHeader::read_from_bytes(&bytes).map_err(|_| LINUX_EFAULT)
}

fn read_capability_data(
    memory: &impl GuestMemory,
    address: u64,
    count: usize,
) -> Result<Vec<LinuxCapabilityData>, LinuxErrno> {
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

/// Translate the identity-namespace parent relationship exposed to the guest.
///
/// The FreeBSD native lane acquires host reaper status so the top-level runtime
/// process can reap guest orphans. That makes the host report the runtime's pid
/// as an orphan's parent. Unless the guest explicitly selected that process as
/// a child subreaper, the observable Linux parent is still init (PID 1); the
/// host pid is an implementation detail. Direct children keep their real parent,
/// and an explicit subreaper remains observable by its guest process id.
fn identity_guest_ppid(
    current: u32,
    bootstrap: u32,
    host_ppid: u32,
    adopted_parent: Option<u32>,
    subreaper_ancestor: u32,
) -> i64 {
    if current == bootstrap {
        return LINUX_BOOTSTRAP_PID as i64;
    }
    match adopted_parent {
        Some(parent)
            if parent == bootstrap && host_ppid == bootstrap && subreaper_ancestor == 0 =>
        {
            LINUX_BOOTSTRAP_PID as i64
        }
        Some(parent) => i64::from(parent),
        None => i64::from(host_ppid),
    }
}

#[cfg(test)]
mod ppid_tests {
    use super::identity_guest_ppid;
    use crate::linux_abi::LINUX_BOOTSTRAP_PID;

    #[test]
    fn direct_child_observes_its_real_guest_parent() {
        assert_eq!(identity_guest_ppid(200, 100, 100, None, 0), 100);
    }

    #[test]
    fn init_reaper_adoption_is_exposed_as_pid_one() {
        assert_eq!(
            identity_guest_ppid(300, 100, 100, Some(100), 0),
            LINUX_BOOTSTRAP_PID as i64
        );
    }

    #[test]
    fn explicit_subreaper_adoption_keeps_the_subreaper_pid() {
        assert_eq!(identity_guest_ppid(300, 100, 100, Some(100), 100), 100);
    }

    #[test]
    fn clone_parent_keeps_recorded_parent_when_host_parent_differs() {
        assert_eq!(identity_guest_ppid(300, 100, 200, Some(100), 0), 100);
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

#[cfg(test)]
mod identity_snapshot_tests {
    use super::*;

    /// `identity_snapshot()` must read the SAME sources as the getpid/get*id
    /// handlers, so the EL1 fast path and the trap path can never disagree.
    #[test]
    fn snapshot_mirrors_getpid_and_cred_snapshot() {
        let d = SyscallDispatcher::new();
        let context = d.capture_one_task_context().expect("kernel context");
        let id = d.identity_snapshot(&context);
        let c = d.credentials_from_context(&context);
        assert_eq!(id.pid, crate::namespace::pid::self_ns_pid());
        // Credentials remain Kernel authority and are deliberately absent from
        // the shared process identity page.
        assert_eq!(
            (c.ruid, c.euid, c.rgid, c.egid),
            (NsUid::ROOT, NsUid::ROOT, NsGid::ROOT, NsGid::ROOT)
        );
    }

    #[test]
    fn setgroups_publishes_exact_kernel_authority_including_empty_set() {
        let mut dispatcher = SyscallDispatcher::new();
        let reporter = CompatReporter::default();
        let base = 0x4000;
        let mut memory = LinearMemory::new(base, vec![0; 0x1000]);
        memory
            .write_bytes(base, &[9_u32.to_le_bytes(), 10_u32.to_le_bytes()].concat())
            .unwrap();

        let context = dispatcher.capture_one_task_context().unwrap();
        let outcome = dispatcher
            .dispatch(
                &context,
                SyscallRequest::new(159, SyscallArgs::from([2, base, 0, 0, 0, 0])),
                &mut memory,
                &reporter,
            )
            .unwrap();
        assert!(matches!(outcome, DispatchOutcome::Returned { value: 0 }));

        let current = dispatcher.capture_one_task_context().unwrap();
        assert_eq!(
            current
                .resources()
                .credentials()
                .supplementary_groups_override(),
            Some([NsGid::new(9), NsGid::new(10)].as_slice())
        );
        let outcome = dispatcher
            .dispatch(
                &current,
                SyscallRequest::new(159, SyscallArgs::from([0; 6])),
                &mut memory,
                &reporter,
            )
            .unwrap();
        assert!(matches!(outcome, DispatchOutcome::Returned { value: 0 }));
        let empty = dispatcher.capture_one_task_context().unwrap();
        assert_eq!(
            empty
                .resources()
                .credentials()
                .supplementary_groups_override(),
            Some([].as_slice())
        );
        let outcome = dispatcher
            .dispatch(
                &empty,
                SyscallRequest::new(158, SyscallArgs::from([0; 6])),
                &mut memory,
                &reporter,
            )
            .unwrap();
        assert!(matches!(outcome, DispatchOutcome::Returned { value: 0 }));
    }
}
