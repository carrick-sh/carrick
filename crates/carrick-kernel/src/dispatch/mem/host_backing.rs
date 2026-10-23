//! Physical byte-source custody. No guest VA, protection or fork policy is
//! stored here: those belong to the production reservation owner.
use super::backing::PrivateFileBacking;
use carrick_el1_abi::HostBackingIdentity;
use core::num::NonZeroU64;
use parking_lot::Mutex;
use std::collections::BTreeMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Weak};

// Physical custody identity, not task/MM identity. Distinct custodians must
// reject each other's tokens even when both have just retained their first file.
static NEXT_HANDLE: AtomicU64 = AtomicU64::new(1);

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum SourceKey {
    Description(usize),
    Image(usize, u64),
}
impl SourceKey {
    fn of(source: &PrivateFileBacking) -> Self {
        match source {
            PrivateFileBacking::Description(reference) => {
                Self::Description(std::ptr::from_ref(reference.description()) as usize)
            }
            PrivateFileBacking::LoadedImage {
                initialized_offset,
                bytes,
            } => Self::Image(Arc::as_ptr(bytes) as usize, *initialized_offset),
        }
    }
}
struct Record {
    key: SourceKey,
    label: String,
    source: PrivateFileBacking,
    custody: Arc<HostBackingCustody>,
    handle: NonZeroU64,
}
#[derive(Default)]
struct State {
    records: BTreeMap<u64, Weak<Record>>,
    sources: BTreeMap<SourceKey, Weak<Record>>,
}
#[derive(Default)]
pub(super) struct HostBackingCustody {
    state: Mutex<State>,
}

/// A source reference, independent of descriptor slots and MM lifetime.
/// Handles are monotonic within this custody; retired tokens are never reused.
#[derive(Clone)]
pub(super) struct HostBackingLease(Arc<Record>);
impl HostBackingCustody {
    #[cfg(test)]
    pub(super) fn retain_source(
        self: &Arc<Self>,
        source: PrivateFileBacking,
    ) -> Option<HostBackingLease> {
        self.retain_labeled_source(source, String::new())
    }

    pub(super) fn retain_labeled_source(
        self: &Arc<Self>,
        source: PrivateFileBacking,
        label: String,
    ) -> Option<HostBackingLease> {
        let mut state = self.state.lock();
        let key = SourceKey::of(&source);
        if let Some(record) = state.sources.get(&key).and_then(Weak::upgrade) {
            return Some(HostBackingLease(record));
        }
        let handle = NonZeroU64::new(
            NEXT_HANDLE
                .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |value| {
                    value.checked_add(1)
                })
                .ok()?,
        )?;
        let record = Arc::new(Record {
            key,
            label,
            source,
            custody: Arc::clone(self),
            handle,
        });
        state.records.insert(handle.get(), Arc::downgrade(&record));
        state.sources.insert(key, Arc::downgrade(&record));
        Some(HostBackingLease(record))
    }

    pub(super) fn label(&self, identity: HostBackingIdentity) -> Option<String> {
        if identity.generation() != NonZeroU64::MIN {
            return None;
        }
        let weak = self
            .state
            .lock()
            .records
            .get(&identity.handle().get())?
            .clone();
        let record = weak.upgrade()?;
        Some(record.label.clone())
    }

    pub(super) fn source(&self, identity: HostBackingIdentity) -> Option<PrivateFileBacking> {
        if identity.generation() != NonZeroU64::MIN {
            return None;
        }
        let record = self
            .state
            .lock()
            .records
            .get(&identity.handle().get())?
            .upgrade()?;
        Some(record.source.clone())
    }
}
impl HostBackingLease {
    pub(super) fn identity(&self, offset: u64) -> HostBackingIdentity {
        HostBackingIdentity::new(self.0.handle, NonZeroU64::MIN, offset)
    }
}
impl carrick_hal::fork_stock::HostBackingRetention for HostBackingLease {
    fn identity(&self) -> HostBackingIdentity {
        self.identity(0)
    }
    fn read(
        &self,
        request: carrick_hal::fork_stock::HostBackingRead,
    ) -> Result<Vec<u8>, carrick_hal::fork_stock::HostBackingReadError> {
        use carrick_hal::fork_stock::HostBackingReadError;
        let identity = request.identity();
        if identity.handle() != self.0.handle || identity.generation() != NonZeroU64::MIN {
            return Err(HostBackingReadError::Stale);
        }
        super::backing::read_retained_source(
            self.0.source.clone(),
            identity,
            request.length(),
            carrick_el1_abi::GRANT_PAGE_SIZE,
        )
        .map_err(|_| HostBackingReadError::Unavailable)
    }
}
impl Drop for Record {
    fn drop(&mut self) {
        let mut state = self.custody.state.lock();
        state.records.remove(&self.handle.get());
        if state
            .sources
            .get(&self.key)
            .is_some_and(|record| std::ptr::eq(record.as_ptr(), self))
        {
            state.sources.remove(&self.key);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn fork_source_custody_bounds_identity_work_for_many_sources() {
        use carrick_hal::fork_stock::{ForkHostBackingCustody, HostBackingRetention};
        use std::sync::atomic::AtomicUsize;

        struct CountedLease {
            lease: HostBackingLease,
            calls: Arc<AtomicUsize>,
        }
        impl HostBackingRetention for CountedLease {
            fn identity(&self) -> HostBackingIdentity {
                self.calls.fetch_add(1, Ordering::Relaxed);
                self.lease.identity(0)
            }
            fn read(
                &self,
                request: carrick_hal::fork_stock::HostBackingRead,
            ) -> Result<Vec<u8>, carrick_hal::fork_stock::HostBackingReadError> {
                self.lease.read(request)
            }
        }

        for count in [1, 512] {
            let owner = Arc::new(HostBackingCustody::default());
            let calls = Arc::new(AtomicUsize::new(0));
            let mut inherited = ForkHostBackingCustody::default();
            let mut identities = Vec::new();
            for _ in 0..count {
                let lease = owner
                    .retain_source(PrivateFileBacking::LoadedImage {
                        initialized_offset: 0,
                        bytes: Arc::new(vec![0x5a]),
                    })
                    .unwrap();
                identities.push(lease.identity(0));
                inherited.inherit(Arc::new(CountedLease {
                    lease,
                    calls: Arc::clone(&calls),
                }));
            }
            assert_eq!(calls.load(Ordering::Relaxed), count);
            for identity in identities.into_iter().rev() {
                assert!(
                    inherited
                        .retain(identity, || panic!("inherited source needs no parent MM"))
                        .is_some()
                );
            }
            assert_eq!(
                calls.load(Ordering::Relaxed),
                count,
                "one identity authentication per inherited source; no repeated source scans"
            );
        }
    }

    #[test]
    fn inherited_source_reads_bounded_bytes_after_parent_custody_is_gone() {
        use carrick_hal::fork_stock::{
            HostBackingRead, HostBackingReadError, HostBackingRetention,
        };
        let parent = Arc::new(HostBackingCustody::default());
        let lease = parent
            .retain_source(PrivateFileBacking::LoadedImage {
                initialized_offset: 4,
                bytes: Arc::new(b"parent bytes".to_vec()),
            })
            .unwrap();
        let identity = lease.identity(0);
        let child: Arc<dyn HostBackingRetention> = Arc::new(lease.clone());
        drop(lease);
        drop(parent);
        let request = HostBackingRead::new(identity, 8).unwrap();
        assert_eq!(child.read(request).unwrap(), b"\0\0\0\0pare");
        assert_eq!(
            child
                .read(HostBackingRead::new(identity.advance(8).unwrap(), 7).unwrap())
                .unwrap(),
            b"nt bytes"[..7]
        );
        let wrong = HostBackingIdentity::new(identity.handle(), NonZeroU64::new(2).unwrap(), 0);
        assert_eq!(
            child.read(HostBackingRead::new(wrong, 1).unwrap()),
            Err(HostBackingReadError::Stale)
        );
        assert!(HostBackingRead::new(identity, 0).is_none());
        assert!(
            HostBackingRead::new(
                identity,
                carrick_el1_abi::EL1_FRAME_GRANT_TARGET_SIZE as usize + 1
            )
            .is_none()
        );
        assert!(
            HostBackingRead::new(
                HostBackingIdentity::new(identity.handle(), identity.generation(), u64::MAX),
                1
            )
            .is_none()
        );
    }

    #[test]
    fn repeated_source_retention_uses_one_physical_record() {
        let custody = Arc::new(HostBackingCustody::default());
        let source = PrivateFileBacking::LoadedImage {
            initialized_offset: 0,
            bytes: Arc::new(b"file".to_vec()),
        };
        let first = custody.retain_source(source.clone()).unwrap();
        for _ in 0..1000 {
            let next = custody.retain_source(source.clone()).unwrap();
            assert_eq!(first.identity(0), next.identity(0));
            assert_eq!(custody.state.lock().records.len(), 1);
        }
        drop(first);
        assert!(custody.state.lock().sources.is_empty());
    }

    #[test]
    fn two_live_custodians_reject_each_others_source_tokens() {
        let a = Arc::new(HostBackingCustody::default());
        let b = Arc::new(HostBackingCustody::default());
        let retain = |custody: &Arc<HostBackingCustody>, bytes: &[u8]| {
            custody
                .retain_source(PrivateFileBacking::LoadedImage {
                    initialized_offset: 0,
                    bytes: Arc::new(bytes.to_vec()),
                })
                .unwrap()
        };
        let a_source = retain(&a, b"parent-a");
        let b_source = retain(&b, b"parent-b");
        assert_ne!(a_source.identity(0), b_source.identity(0));
        assert!(a.source(b_source.identity(0)).is_none());
        assert!(b.source(a_source.identity(0)).is_none());
        assert!(a.source(a_source.identity(0)).is_some());
        assert!(b.source(b_source.identity(0)).is_some());
    }
    #[test]
    fn retained_source_outlives_original_lease_and_rejects_retirement() {
        let custody = Arc::new(HostBackingCustody::default());
        let lease = custody
            .retain_source(PrivateFileBacking::LoadedImage {
                initialized_offset: 0,
                bytes: Arc::new(b"file".to_vec()),
            })
            .unwrap();
        let identity = lease.identity(0);
        let child = lease.clone();
        drop(lease);
        assert!(custody.source(identity).is_some());
        drop(child);
        assert!(custody.source(identity).is_none());
        assert!(custody.state.lock().records.is_empty());
        let next = custody
            .retain_source(PrivateFileBacking::LoadedImage {
                initialized_offset: 0,
                bytes: Arc::new(b"next".to_vec()),
            })
            .unwrap();
        assert_ne!(next.identity(0).handle(), identity.handle());
        assert!(custody.source(identity).is_none());
    }
}
