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

struct Record {
    source: PrivateFileBacking,
    custody: Arc<HostBackingCustody>,
    handle: NonZeroU64,
}
#[derive(Default)]
struct State {
    records: BTreeMap<u64, Weak<Record>>,
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
    pub(super) fn retain_source(
        self: &Arc<Self>,
        source: PrivateFileBacking,
    ) -> Option<HostBackingLease> {
        let mut state = self.state.lock();
        let handle = NonZeroU64::new(
            NEXT_HANDLE
                .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |value| {
                    value.checked_add(1)
                })
                .ok()?,
        )?;
        let record = Arc::new(Record {
            source,
            custody: Arc::clone(self),
            handle,
        });
        state.records.insert(handle.get(), Arc::downgrade(&record));
        Some(HostBackingLease(record))
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
impl Drop for Record {
    fn drop(&mut self) {
        self.custody.state.lock().records.remove(&self.handle.get());
    }
}

#[cfg(test)]
mod tests {
    use super::*;
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
