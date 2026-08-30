//! Structural paired-lock authority for the SysV subsystem.
//!
//! SysV operations that mutate or inspect both the per-process attachment table
//! and the shared SysV IPC namespace must acquire the locks in strict structural order:
//!
//! 1. Per-process attachment lock (`SysvProcessGuard`) FIRST.
//! 2. Mint an exclusive borrow-bound [`SysvNamespacePermit`] capturing the exact namespace.
//! 3. Linearly consume the permit to acquire the shared namespace lock (`SysvPairedNamespaceGuard`).
//!
//! This module structurally enforces that:
//! - A `SysvProcessGuard` captures the exact `&'a SysvIpcNamespace` at construction.
//! - A `SysvNamespacePermit` can only be minted by exclusively borrowing `&mut SysvProcessGuard`.
//! - A `SysvNamespacePermit` is consumed linearly by `permit.lock_paired()` and cannot reacquire.
//! - Paired operations operate strictly through the captured namespace and accept no external receiver.
//!
//! Host-backed `nattch` accounting remains synchronous under this exact paired
//! authority. Extracting that I/O requires a separate generation-authenticated
//! transaction and is not claimed by this structural-order milestone.

use super::{
    HostAliasShmatCommit, LinuxErrno, PendingShmat, SysvIpcNamespace, SysvProcessAttachments,
    SysvShmState, adjust_shm_nattch, align_up_u64, decrement_shm_attachment, unix_now_secs,
};
use parking_lot::MutexGuard;
use std::marker::PhantomData;

/// Borrow-bound guard over a process's SysV attachments and captured namespace reference.
///
/// This guard must be acquired first before any paired SysV namespace access.
/// It is the only mechanism that can mint a [`SysvNamespacePermit`].
pub struct SysvProcessGuard<'a> {
    pub(super) guard: MutexGuard<'a, SysvProcessAttachments>,
    pub(super) namespace: &'a SysvIpcNamespace,
}

impl<'a> SysvProcessGuard<'a> {
    pub(super) fn new(
        guard: MutexGuard<'a, SysvProcessAttachments>,
        namespace: &'a SysvIpcNamespace,
    ) -> Self {
        Self { guard, namespace }
    }

    /// Mint an exclusive, borrow-bound permit required for paired namespace acquisition.
    ///
    /// The permit exclusively borrows `&mut self` and captures the exact namespace reference.
    pub fn namespace_permit<'b>(&'b mut self) -> SysvNamespacePermit<'b> {
        SysvNamespacePermit {
            _borrow: PhantomData,
            namespace: self.namespace,
        }
    }

    pub fn first_remapped_attachment(&self) -> Option<u64> {
        self.guard.remapped_attachments.iter().next().copied()
    }

    pub fn is_inheritance_committed(&self) -> bool {
        self.guard.inheritance_committed
    }

    /// Paired site 1: Record remapped file pages covering an attachment segment.
    pub(crate) fn note_remap_file_pages(
        &mut self,
        addr: u64,
        end: u64,
    ) -> Result<bool, LinuxErrno> {
        let attachments = self.guard.attachments.clone();
        let permit = self.namespace_permit();
        let paired = permit.lock_paired();
        let mut found = None;
        for (attached, shmid) in attachments {
            let Some(segment) = paired.state.segments.get(&shmid) else {
                return Err(crate::linux_abi::LINUX_EIDRM);
            };
            let Some(attached_end) = attached.checked_add(segment.size as u64) else {
                continue;
            };
            if addr >= attached && end <= attached_end {
                found = Some(attached);
                break;
            }
        }
        drop(paired);
        if let Some(attached) = found {
            self.guard.remapped_attachments.insert(attached);
            Ok(true)
        } else {
            Ok(false)
        }
    }

    /// Paired site 2: Authoritatively commit inherited fork attachments.
    pub(crate) fn commit_fork_inheritance(&mut self) {
        if self.guard.inheritance_committed {
            return;
        }
        self.guard.inheritance_committed = true;
        let attachments: Vec<i32> = self.guard.attachments.values().copied().collect();
        let permit = self.namespace_permit();
        let mut paired = permit.lock_paired();
        for shmid in attachments {
            if let Some(segment) = paired.state.segments.get_mut(&shmid) {
                segment.nattch = adjust_shm_nattch(segment, 1);
            }
        }
    }

    /// Paired site 3: Commit a remapped shmat attachment.
    pub(crate) fn commit_remapped_shmat(
        &mut self,
        shmid: i32,
        lpid: i32,
        reservation: PendingShmat,
    ) -> u64 {
        let Some(va) = self.guard.remapped_attachments.iter().next().copied() else {
            std::process::abort();
        };
        let old_shmid = self.guard.attachments.insert(va, shmid);
        if old_shmid == Some(shmid) {
            // Same-shmid remap: attachment is already recorded for this exact segment.
            // Roll back the unused pending reservation before acquiring any paired lock
            // to avoid recursive locking during PendingShmat::drop.
            drop(reservation);
            return va;
        }
        let namespace = self.namespace;
        let permit = self.namespace_permit();
        let mut paired = permit.lock_paired();
        if let Some(old_shmid) = old_shmid {
            let _ = decrement_shm_attachment(&mut paired.state, old_shmid, lpid, None);
        }
        let _ = reservation
            .commit_under_paired_guard(namespace, &mut paired.state, unix_now_secs(), lpid)
            .unwrap_or_else(|()| std::process::abort());
        va
    }

    /// Paired site 4: Validate an shmdt address and determine segment length.
    pub(crate) fn validate_shmdt(&mut self, addr: u64) -> Result<(i32, usize), LinuxErrno> {
        if self.guard.remapped_attachments.contains(&addr) {
            return Err(crate::linux_abi::LINUX_EINVAL);
        }
        let Some(shmid) = self.guard.attachments.get(&addr).copied() else {
            return Err(crate::linux_abi::LINUX_EINVAL);
        };
        let permit = self.namespace_permit();
        let paired = permit.lock_paired();
        let Some(segment) = paired.state.segments.get(&shmid) else {
            return Err(crate::linux_abi::LINUX_EINVAL);
        };
        let Some(aligned_len) = align_up_u64(segment.size as u64, crate::trap::HVF_PAGE_SIZE)
        else {
            return Err(crate::linux_abi::LINUX_ENOMEM);
        };
        let Ok(len) = usize::try_from(aligned_len) else {
            return Err(crate::linux_abi::LINUX_ENOMEM);
        };
        Ok((shmid, len))
    }

    /// Paired site 5: Commit an shmdt detachment after memory unmap succeeds.
    pub(crate) fn commit_shmdt(&mut self, addr: u64, shmid: i32, lpid: i32, dtime: u64) {
        if self.guard.remapped_attachments.contains(&addr)
            || self.guard.attachments.get(&addr).copied() != Some(shmid)
        {
            std::process::abort();
        }
        let permit = self.namespace_permit();
        let mut paired = permit.lock_paired();
        if !paired.state.segments.contains_key(&shmid) {
            std::process::abort();
        }
        let ok = decrement_shm_attachment(&mut paired.state, shmid, lpid, Some(dtime));
        if !ok {
            std::process::abort();
        }
        drop(paired);
        self.guard.attachments.remove(&addr);
    }

    /// Paired host-alias commit: Record the newly installed attachment and commit the reservation.
    pub(crate) fn commit_host_alias_shmat(&mut self, commit: HostAliasShmatCommit) {
        if self.guard.attachments.contains_key(&commit.va) {
            std::process::abort();
        }
        let namespace = self.namespace;
        let permit = self.namespace_permit();
        let mut paired = permit.lock_paired();
        let shmid = commit
            .reservation
            .commit_under_paired_guard(namespace, &mut paired.state, commit.atime, commit.lpid)
            .unwrap_or_else(|()| std::process::abort());
        drop(paired);
        self.guard.attachments.insert(commit.va, shmid);
    }
}

/// Borrow-bound token minted exclusively from a live [`SysvProcessGuard`].
///
/// A permit cannot be freely constructed, cloned, copied, leaked, or used with an
/// unrelated process or namespace.
///
/// The compiler rejects two permits borrowed from one live process guard:
///
/// ```compile_fail,E0499
/// use carrick_runtime::dispatch::sysv::lock_authority::SysvProcessGuard;
///
/// fn mint_two(guard: &mut SysvProcessGuard<'_>) {
///     let first = guard.namespace_permit();
///     let second = guard.namespace_permit();
///     let _ = (first, second);
/// }
/// ```
///
/// The actual permit type is linear:
///
/// ```compile_fail,E0599
/// use carrick_runtime::dispatch::sysv::lock_authority::SysvProcessGuard;
///
/// fn clone_owned(guard: &mut SysvProcessGuard<'_>) {
///     let permit = guard.namespace_permit();
///     let _copy = permit.clone();
/// }
/// ```
///
/// Its borrow cannot escape the process guard:
///
/// ```compile_fail
/// use carrick_runtime::dispatch::sysv::lock_authority::{
///     SysvNamespacePermit, SysvProcessGuard,
/// };
///
/// fn leak(guard: &mut SysvProcessGuard<'_>) -> SysvNamespacePermit<'static> {
///     guard.namespace_permit()
/// }
/// ```
///
/// Paired locking accepts no separately chosen namespace:
///
/// ```compile_fail,E0061
/// use carrick_runtime::dispatch::sysv::lock_authority::SysvProcessGuard;
///
/// fn choose_namespace(guard: &mut SysvProcessGuard<'_>, other: &()) {
///     guard.namespace_permit().lock_paired(other);
/// }
/// ```
pub struct SysvNamespacePermit<'borrow> {
    _borrow: PhantomData<&'borrow mut ()>,
    namespace: &'borrow SysvIpcNamespace,
}

impl<'borrow> SysvNamespacePermit<'borrow> {
    /// Linearly consume the permit to acquire the shared namespace lock.
    pub fn lock_paired(self) -> SysvPairedNamespaceGuard<'borrow> {
        let state = self.namespace.state.lock();
        SysvPairedNamespaceGuard {
            _permit: self,
            state,
        }
    }
}

/// Mutex guard over [`SysvShmState`] holding an active paired permit.
pub struct SysvPairedNamespaceGuard<'borrow> {
    _permit: SysvNamespacePermit<'borrow>,
    pub(super) state: MutexGuard<'borrow, SysvShmState>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn permit_lifetimes_and_types_are_strictly_bound() {
        static_assertions::assert_not_impl_any!(SysvProcessGuard<'_>: Clone, Copy);
        static_assertions::assert_not_impl_any!(SysvNamespacePermit<'_>: Clone, Copy);
        static_assertions::assert_not_impl_any!(SysvPairedNamespaceGuard<'_>: Clone, Copy);
    }

    fn assert_rustc_fails_with(source: &str, expected_needle: &str) {
        let mut child = std::process::Command::new("rustc")
            .arg("--crate-type=lib")
            .arg("--edition=2021")
            .arg("--emit=metadata")
            .arg("-o")
            .arg("/dev/null")
            .arg("-")
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .expect("spawn rustc");

        use std::io::Write;
        child
            .stdin
            .as_mut()
            .expect("stdin")
            .write_all(source.as_bytes())
            .expect("write source to rustc stdin");

        let output = child.wait_with_output().expect("wait for rustc");
        assert!(
            !output.status.success(),
            "expected compilation to fail, but it succeeded for snippet:\n{source}"
        );
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            stderr.contains(expected_needle),
            "expected stderr to contain '{expected_needle}', but got:\n{stderr}"
        );
    }

    #[test]
    fn compiler_rejects_direct_permit_construction() {
        let source = r#"
            mod inner {
                pub struct SysvNamespacePermit<'borrow> {
                    _borrow: std::marker::PhantomData<&'borrow mut ()>,
                    namespace: &'borrow (),
                }
            }
            fn try_construct(ns: &()) {
                let _ = inner::SysvNamespacePermit {
                    _borrow: std::marker::PhantomData,
                    namespace: ns,
                };
            }
        "#;
        assert_rustc_fails_with(source, "private");
    }

    #[test]
    fn compiler_rejects_simultaneous_permit_minting() {
        let source = r#"
            pub struct Guard<'a>(&'a mut ());
            pub struct Permit<'b>(&'b mut ());
            impl<'a> Guard<'a> {
                pub fn permit<'b>(&'b mut self) -> Permit<'b> {
                    Permit(self.0)
                }
            }
            fn try_two_permits(mut g: Guard<'_>) {
                let p1 = g.permit();
                let p2 = g.permit();
                let _ = (p1, p2);
            }
        "#;
        assert_rustc_fails_with(source, "cannot borrow `g` as mutable more than once");
    }

    #[test]
    fn compiler_rejects_permit_escaping_guard_lifetime() {
        let source = r#"
            pub struct Guard<'a>(&'a ());
            pub struct Permit<'b>(&'b ());
            impl<'a> Guard<'a> {
                pub fn permit<'b>(&'b mut self) -> Permit<'b> {
                    Permit(self.0)
                }
            }
            fn try_escape<'a>() -> Permit<'static> {
                let unit = ();
                let mut guard = Guard(&unit);
                guard.permit()
            }
        "#;
        assert_rustc_fails_with(source, "cannot return value referencing local variable");
    }

    #[test]
    fn compiler_rejects_cloning_owned_permit() {
        let source = r#"
            pub struct Permit<'b>(std::marker::PhantomData<&'b mut ()>);
            fn try_clone(p: Permit<'_>) {
                let _ = p.clone();
            }
        "#;
        assert_rustc_fails_with(source, "no method named `clone`");
    }

    #[test]
    fn compiler_rejects_arbitrary_namespace_supplied_to_guard_methods() {
        let source = r#"
            pub struct Guard<'a>(&'a ());
            pub struct Namespace;
            impl<'a> Guard<'a> {
                pub fn commit(&mut self) {}
            }
            fn try_foreign_namespace(mut g: Guard<'_>, ns: Namespace) {
                g.commit(&ns);
            }
        "#;
        assert_rustc_fails_with(source, "takes 0 arguments but 1 argument was supplied");
    }

    #[test]
    fn compiler_rejects_external_access_to_with_state() {
        let source = r#"
            mod outer {
                pub mod sysv {
                    pub struct SysvIpcNamespace;
                    impl SysvIpcNamespace {
                        pub(in crate::outer::sysv) fn with_state<F, R>(&self, f: F) -> R
                        where
                            F: FnOnce(&()) -> R,
                        {
                            f(&())
                        }
                    }
                }
                pub mod fs {
                    use super::sysv::SysvIpcNamespace;
                    pub fn try_access_namespace_state(ns: &SysvIpcNamespace) {
                        ns.with_state(|_| ());
                    }
                }
            }
        "#;
        assert_rustc_fails_with(source, "is private");
    }

    #[test]
    fn compiler_rejects_external_access_to_lock_sysv_process() {
        let source = r#"
            mod outer {
                pub mod sysv {
                    pub struct SyscallDispatcher;
                    impl SyscallDispatcher {
                        pub(in crate::outer::sysv) fn lock_sysv_process(&self) {}
                    }
                }
                pub mod fs {
                    use super::sysv::SyscallDispatcher;
                    pub fn try_lock_sysv_process(d: &SyscallDispatcher) {
                        d.lock_sysv_process();
                    }
                }
            }
        "#;
        assert_rustc_fails_with(source, "is private");
    }

    #[test]
    fn compiler_rejects_reverse_locking_order_attempt() {
        let source = r#"
            pub struct SysvProcessGuard<'a>(std::marker::PhantomData<&'a mut ()>);
            pub struct SysvNamespacePermit<'b>(std::marker::PhantomData<&'b mut ()>);
            pub struct SysvPairedNamespaceGuard<'b>(std::marker::PhantomData<&'b mut ()>);

            impl<'a> SysvProcessGuard<'a> {
                pub fn namespace_permit<'b>(&'b mut self) -> SysvNamespacePermit<'b> {
                    SysvNamespacePermit(std::marker::PhantomData)
                }
            }
            impl<'b> SysvNamespacePermit<'b> {
                pub fn lock_paired(self) -> SysvPairedNamespaceGuard<'b> {
                    SysvPairedNamespaceGuard(std::marker::PhantomData)
                }
            }
            fn try_reverse_order(mut p: SysvProcessGuard<'_>) {
                let permit = p.namespace_permit();
                let paired = permit.lock_paired();
                let _p2 = p.namespace_permit();
                let _ = paired;
            }
        "#;
        assert_rustc_fails_with(source, "cannot borrow `p` as mutable more than once");
    }
}
