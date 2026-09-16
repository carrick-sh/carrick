//! Admission for live rootfs namespace transactions. The state mutex only
//! reserves parent sets; filesystem work runs outside it. Archive admission is
//! acquired by the caller before topology admission.
use std::collections::HashSet;

use parking_lot::{Condvar, Mutex, RwLock};

use super::InodeIdentity;

#[derive(Debug, Default)]
pub struct NamespaceMutationCoordinator {
    topology: RwLock<()>,
    state: Mutex<ParentAdmissionState>,
    changed: Condvar,
    #[cfg(test)]
    observed: Condvar,
}

#[derive(Debug, Default)]
struct ParentAdmissionState {
    held: HashSet<NamespaceParentIdentity>,
    #[cfg(test)]
    waiting: usize,
}

/// Host inode identity and an in-memory namespace path are distinct domains.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum NamespaceParentIdentity {
    Host(InodeIdentity),
    Logical(crate::fs_backend::NormalizedRelPath),
}

pub struct AnchoredParent {
    pub path: String,
    pub identity: NamespaceParentIdentity,
    pub resolved: super::rootfs::ResolvedParent,
}

pub struct NamespaceMutationPermit<'a> {
    anchors: Vec<AnchoredParent>,
    topology_exclusive: bool,
    _authority: std::marker::PhantomData<&'a NamespaceMutationCoordinator>,
}

impl NamespaceMutationPermit<'_> {
    pub fn parent(&self, path: &str) -> Option<&super::rootfs::ResolvedParent> {
        self.anchors
            .iter()
            .find(|anchor| anchor.path == path)
            .map(|anchor| &anchor.resolved)
    }

    pub fn topology_exclusive(&self) -> bool {
        self.topology_exclusive
    }
}

/// Releases reservations on resolver errors, callback errors, unwinding and
/// revalidation, not merely on the successful publication path.
struct ParentReservation<'a> {
    coordinator: &'a NamespaceMutationCoordinator,
    parents: Vec<NamespaceParentIdentity>,
}

impl Drop for ParentReservation<'_> {
    fn drop(&mut self) {
        let mut state = self.coordinator.state.lock();
        for parent in &self.parents {
            state.held.remove(parent);
        }
        self.coordinator.changed.notify_all();
    }
}

impl NamespaceMutationCoordinator {
    /// Test synchronization: observe an actual conflicting reservation waiter.
    #[cfg(test)]
    pub fn wait_until_contended(&self) -> bool {
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        let mut state = self.state.lock();
        while state.waiting == 0 {
            if self.observed.wait_until(&mut state, deadline).timed_out() {
                return state.waiting != 0;
            }
        }
        true
    }

    fn reserve(&self, mut parents: Vec<NamespaceParentIdentity>) -> ParentReservation<'_> {
        let mut unique = HashSet::with_capacity(parents.len());
        parents.retain(|identity| unique.insert(identity.clone()));
        let mut state = self.state.lock();
        while parents.iter().any(|parent| state.held.contains(parent)) {
            #[cfg(test)]
            {
                state.waiting += 1;
                self.observed.notify_all();
            }
            self.changed.wait(&mut state);
            #[cfg(test)]
            {
                state.waiting -= 1;
            }
        }
        state.held.extend(parents.iter().cloned());
        ParentReservation {
            coordinator: self,
            parents,
        }
    }

    pub fn with_parents<R, ResolveError, OperationError>(
        &self,
        topology_change: bool,
        resolve_parents: impl Fn() -> Result<Vec<AnchoredParent>, ResolveError>,
        operation: impl FnOnce(&NamespaceMutationPermit<'_>) -> Result<R, OperationError>,
    ) -> Result<Result<R, OperationError>, ResolveError> {
        // Keep both lexical guards alive through callback publication. Exactly
        // one is present; no guard is acquired by the other branch.
        let _topology_read = (!topology_change).then(|| self.topology.read());
        let _topology_write = topology_change.then(|| self.topology.write());
        loop {
            let first = resolve_parents()?;
            let reservation =
                self.reserve(first.iter().map(|parent| parent.identity.clone()).collect());
            let revalidated = resolve_parents()?;
            // Compare path-to-parent mappings, not a sorted identity set: two
            // paths can exchange parents while retaining the same lock set.
            if !same_anchors(&first, &revalidated) {
                drop(reservation);
                continue;
            }
            let result = operation(&NamespaceMutationPermit {
                anchors: revalidated,
                topology_exclusive: topology_change,
                _authority: std::marker::PhantomData,
            });
            drop(reservation);
            return Ok(result);
        }
    }

    pub fn with_archive<R>(&self, operation: impl FnOnce(&NamespaceMutationPermit<'_>) -> R) -> R {
        let _topology = self.topology.write();
        operation(&NamespaceMutationPermit {
            anchors: Vec::new(),
            topology_exclusive: true,
            _authority: std::marker::PhantomData,
        })
    }
}

fn same_anchors(first: &[AnchoredParent], second: &[AnchoredParent]) -> bool {
    first.len() == second.len()
        && first.iter().zip(second).all(|(first, second)| {
            first.path == second.path
                && first.identity == second.identity
                && first.resolved.leaf == second.resolved.leaf
                && first.resolved.rel == second.resolved.rel
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;
    use std::sync::{Arc, mpsc};
    use std::time::Duration;

    fn anchors(ids: &[u64]) -> Vec<AnchoredParent> {
        ids.iter()
            .enumerate()
            .map(|(index, ino)| {
                let path = format!("/parent{index}/file");
                AnchoredParent {
                    identity: NamespaceParentIdentity::Host(InodeIdentity::new(1, *ino)),
                    resolved: super::super::rootfs::ResolvedParent {
                        parent_fd: None,
                        leaf: std::ffi::CString::new("file").unwrap(),
                        rel: crate::fs_backend::NormalizedRelPath::from_normalized_str(&path),
                    },
                    path,
                }
            })
            .collect()
    }

    fn wait_for_waiter(coordinator: &NamespaceMutationCoordinator) -> bool {
        coordinator.wait_until_contended()
    }

    fn contention_case(first: Vec<u64>, second: Vec<u64>) {
        let coordinator = Arc::new(NamespaceMutationCoordinator::default());
        let (tx, rx) = mpsc::channel();
        let mut contender = None;
        let (observed_waiter, early_publication) = coordinator
            .with_parents(
                false,
                || Ok::<_, ()>(anchors(&first)),
                |_| {
                    let coordinator_for_thread = Arc::clone(&coordinator);
                    contender = Some(std::thread::spawn(move || {
                        coordinator_for_thread.with_parents(
                            false,
                            || Ok::<_, ()>(anchors(&second)),
                            |_| {
                                tx.send(()).unwrap();
                                Ok::<_, ()>(())
                            },
                        )
                    }));
                    let waiting = wait_for_waiter(&coordinator);
                    // Observation occurs under the admission-state mutex, after
                    // the contender has found a conflicting reservation.
                    let early = rx.try_recv().is_ok();
                    Ok::<_, ()>((waiting, early))
                },
            )
            .unwrap()
            .unwrap();
        // Release holder admission before assertions, including failure paths.
        let completed = rx.recv_timeout(Duration::from_secs(5));
        if completed.is_ok() {
            contender.unwrap().join().unwrap().unwrap().unwrap();
        }
        assert!(observed_waiter);
        assert!(!early_publication);
        assert!(completed.is_ok());
        assert!(coordinator.state.lock().held.is_empty());
    }

    #[test]
    fn same_parent_is_excluded_through_publication() {
        contention_case(vec![7], vec![7]);
    }

    #[test]
    fn inverse_parent_pairs_are_reserved_without_deadlock() {
        contention_case(vec![8, 7], vec![7, 8]);
    }

    #[test]
    fn logical_parent_reservation_excludes_competing_memory_mutation() {
        let coordinator = Arc::new(NamespaceMutationCoordinator::default());
        let identity = NamespaceParentIdentity::Logical(
            crate::fs_backend::NormalizedRelPath::from_normalized_str("/memory/parent"),
        );
        let reservation = coordinator.reserve(vec![identity.clone()]);
        let (tx, rx) = mpsc::channel();
        let other = Arc::clone(&coordinator);
        let contender = std::thread::spawn(move || {
            other.with_parents(
                false,
                || {
                    let mut resolved = anchors(&[7]);
                    resolved[0].identity = identity.clone();
                    Ok::<_, ()>(resolved)
                },
                |_| {
                    tx.send(()).unwrap();
                    Ok::<_, ()>(())
                },
            )
        });
        let waiting = wait_for_waiter(&coordinator);
        let early = rx.try_recv().is_ok();
        drop(reservation);
        let completed = rx.recv_timeout(Duration::from_secs(5));
        if completed.is_ok() {
            contender.join().unwrap().unwrap().unwrap();
        }
        assert!(waiting);
        assert!(!early);
        assert!(completed.is_ok());
        assert!(coordinator.state.lock().held.is_empty());
    }

    #[test]
    fn unrelated_parent_progresses_during_publication() {
        let coordinator = Arc::new(NamespaceMutationCoordinator::default());
        let (tx, rx) = mpsc::channel();
        let mut contender = None;
        let progressed = coordinator
            .with_parents(
                false,
                || Ok::<_, ()>(anchors(&[7])),
                |_| {
                    let other = Arc::clone(&coordinator);
                    contender = Some(std::thread::spawn(move || {
                        other.with_parents(
                            false,
                            || Ok::<_, ()>(anchors(&[8])),
                            |_| {
                                tx.send(()).unwrap();
                                Ok::<_, ()>(())
                            },
                        )
                    }));
                    Ok::<_, ()>(rx.recv_timeout(Duration::from_secs(5)).is_ok())
                },
            )
            .unwrap()
            .unwrap();
        // If an implementation wrongly serialized unrelated parents, releasing
        // the holder still allows the worker to finish before reporting red.
        contender.unwrap().join().unwrap().unwrap().unwrap();
        assert!(progressed);
    }

    #[test]
    fn changed_parent_mapping_revalidates_even_when_identity_set_matches() {
        let coordinator = NamespaceMutationCoordinator::default();
        let resolves = Cell::new(0);
        coordinator
            .with_parents(
                false,
                || {
                    let n = resolves.get();
                    resolves.set(n + 1);
                    Ok::<_, ()>(anchors(if n == 0 { &[1, 2] } else { &[2, 1] }))
                },
                |permit| {
                    assert_eq!(
                        permit.anchors[0].identity,
                        NamespaceParentIdentity::Host(InodeIdentity::new(1, 2))
                    );
                    Ok::<_, ()>(())
                },
            )
            .unwrap()
            .unwrap();
        assert_eq!(resolves.get(), 4);
        assert!(coordinator.state.lock().held.is_empty());
    }

    #[test]
    fn resolver_error_and_callback_error_release_reservations() {
        let coordinator = NamespaceMutationCoordinator::default();
        let calls = Cell::new(0);
        let result = coordinator.with_parents(
            false,
            || {
                calls.set(calls.get() + 1);
                if calls.get() == 2 {
                    Err(())
                } else {
                    Ok(anchors(&[1]))
                }
            },
            |_| Ok::<_, ()>(()),
        );
        assert!(result.is_err());
        assert!(coordinator.state.lock().held.is_empty());
        assert_eq!(
            coordinator.with_parents(false, || Ok::<_, ()>(anchors(&[1])), |_| Err::<(), _>(7)),
            Ok(Err(7))
        );
        assert!(coordinator.state.lock().held.is_empty());
    }

    #[test]
    fn historical_parent_identities_do_not_accumulate() {
        let coordinator = NamespaceMutationCoordinator::default();
        for ino in 0..1000 {
            coordinator
                .with_parents(false, || Ok::<_, ()>(anchors(&[ino])), |_| Ok::<_, ()>(()))
                .unwrap()
                .unwrap();
            assert!(coordinator.state.lock().held.is_empty());
        }
        assert!(coordinator.state.lock().held.capacity() < 32);
    }

    #[test]
    fn second_resolution_capability_lives_through_publication() {
        let coordinator = NamespaceMutationCoordinator::default();
        let latest = std::cell::RefCell::new(std::sync::Weak::new());
        coordinator
            .with_parents(
                false,
                || {
                    let fd: std::os::fd::OwnedFd = std::fs::File::open("/dev/null").unwrap().into();
                    let fd = Arc::new(fd);
                    *latest.borrow_mut() = Arc::downgrade(&fd);
                    let mut resolved = anchors(&[7]);
                    resolved[0].resolved.parent_fd = Some(fd);
                    Ok::<_, ()>(resolved)
                },
                |permit| {
                    let retained = permit
                        .parent("/parent0/file")
                        .unwrap()
                        .parent_fd
                        .as_ref()
                        .unwrap();
                    assert!(Arc::ptr_eq(retained, &latest.borrow().upgrade().unwrap()));
                    assert!(!permit.topology_exclusive());
                    Ok::<_, ()>(())
                },
            )
            .unwrap()
            .unwrap();
        assert!(latest.borrow().upgrade().is_none());
        coordinator.with_archive(|permit| assert!(permit.topology_exclusive()));
    }
}
