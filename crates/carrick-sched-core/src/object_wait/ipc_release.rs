//! IPC data locks use the existing notification queues, not readiness epochs.
//! One source names a directory slot for the carrier lifetime: freeing an
//! object or table does not retire the slot's lock or its release authority.
use super::{
    BorrowedObjectNotificationSource, ObjectWaitError, ObjectWaitKey, OwnedObjectWakeEffects,
};
use crate::{LockWait, Waker, ZoneTables};
use core::num::NonZeroU64;
use core::sync::atomic::Ordering;

/// The IPC descriptor authority owns this ceiling (CLONE_FILES groups).
pub const IPC_DESCRIPTOR_TABLE_CAPACITY: usize = 256;
/// Every IPC directory object slot and descriptor table owns one source.
/// No readiness lane, member control, or MM cause shares this domain.
pub const IPC_LOCK_RELEASE_QUEUES: usize =
    super::IPC_OBJECT_CAPACITY + IPC_DESCRIPTOR_TABLE_CAPACITY;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct IpcLockIndex(usize);
impl IpcLockIndex {
    pub const fn object(index: usize) -> Option<Self> {
        if index < super::IPC_OBJECT_CAPACITY {
            Some(Self(index))
        } else {
            None
        }
    }
    pub const fn table(index: usize) -> Option<Self> {
        if index < IPC_DESCRIPTOR_TABLE_CAPACITY {
            Some(Self(super::IPC_OBJECT_CAPACITY + index))
        } else {
            None
        }
    }
    pub const fn key(self, carrier: NonZeroU64) -> ObjectWaitKey {
        ObjectWaitKey {
            index: (super::IPC_LOCK_RELEASE_WAIT_BASE + self.0) as u32,
            generation: carrier.get(),
        }
    }
}

/// Venue capability borrowed by shared IPC guards. Implementations publish on
/// an already admitted source after exclusion has been released. They must not
/// acquire the data lock, bind a source, allocate, or wait for execution.
pub trait IpcLockRelease: Send + Sync {
    fn carrier(&self) -> NonZeroU64;
    fn released(&self, index: IpcLockIndex);
}

/// An ISA-neutral release venue. Base source admission belongs to the carrier;
/// guard releases only borrow it. The completion function is the existing
/// host/guest scheduler venue, never an independent wake callback registry.
pub struct IpcLockReleaseVenue<'z, C: Copy + Send + Sync + zerocopy::FromZeros> {
    pub zone: &'z ZoneTables<C>,
    pub carrier: NonZeroU64,
    pub waker: Waker,
    pub deliver: for<'a> fn(&'a ZoneTables<C>, OwnedObjectWakeEffects<'a, C>),
}
impl<C: Copy + Send + Sync + zerocopy::FromZeros> IpcLockRelease for IpcLockReleaseVenue<'_, C> {
    fn carrier(&self) -> NonZeroU64 {
        self.carrier
    }
    fn released(&self, index: IpcLockIndex) {
        let Ok(source) = self.zone.ipc_lock_release_source(index, self.carrier) else {
            unreachable!("IPC lock published without its admitted release source");
        };
        source
            .reserve()
            .publish(self.waker, &|effects| (self.deliver)(self.zone, effects));
    }
}

impl<C: Copy + Send + Sync + zerocopy::FromZeros> ZoneTables<C> {
    /// Admit before exposing the corresponding IPC directory slot. The
    /// carrier owns one permanent base publisher until its zone is destroyed.
    /// Identical concurrent admission is idempotent under queue exclusion;
    /// another carrier identity is stale, never permission to rebind.
    pub fn bind_ipc_lock_release(
        &self,
        index: IpcLockIndex,
        carrier: NonZeroU64,
        wait: &impl LockWait<C>,
        completion: &dyn Fn(OwnedObjectWakeEffects<'_, C>),
    ) -> Result<(), ObjectWaitError> {
        let key = index.key(carrier);
        if self.notification_generation(key) == key.generation {
            return Ok(());
        }
        self.initialize_object_handbacks(key, wait)?;
        let guard = self.lock_completion_index(key, wait, completion)?;
        let queue = guard.queue();
        let actual = queue.generation.load(Ordering::Acquire);
        if actual == key.generation {
            return Ok(());
        }
        if actual != 0 {
            return Err(ObjectWaitError::Stale);
        }
        queue.completion_mode.store(1, Ordering::Release);
        queue.epoch.store(1, Ordering::SeqCst);
        queue.publishers.store(1, Ordering::Release);
        queue.generation.store(key.generation, Ordering::Release);
        #[cfg(all(test, not(feature = "loom")))]
        tests::after_publication();
        Ok(())
    }
}

#[cfg(all(test, not(feature = "loom")))]
mod tests {
    #![allow(clippy::unwrap_used, clippy::panic)]
    use super::*;
    use crate::object_wait::OperationToken;
    use crate::{Aarch64ParkedContext, BoundedSpin, Claim, ParkedContextWords, ThreadIdentity};
    use std::{
        boxed::Box,
        cell::RefCell,
        sync::{Mutex, mpsc},
        time::Duration,
        vec::Vec,
    };

    struct PublicationHook {
        published: mpsc::Sender<()>,
        enrolled: mpsc::Receiver<()>,
    }
    std::thread_local! {
        static PUBLICATION: RefCell<Option<PublicationHook>> = const { RefCell::new(None) };
    }
    pub(super) fn after_publication() {
        PUBLICATION.with(|hook| {
            if let Some(hook) = hook.borrow_mut().take() {
                hook.published.send(()).unwrap();
                hook.enrolled.recv_timeout(Duration::from_secs(5)).unwrap();
            }
        });
    }

    fn concurrent_admission<C: Copy + Send + Sync + zerocopy::FromZeros>() {
        // SAFETY: the scheduler ABI starts at zero, with its native alignment.
        let zone = unsafe {
            let ptr = std::alloc::alloc_zeroed(std::alloc::Layout::new::<ZoneTables<C>>());
            assert!(!ptr.is_null());
            Box::from_raw(ptr.cast::<ZoneTables<C>>())
        };
        for index in [
            IpcLockIndex::object(0).unwrap(),
            IpcLockIndex::table(0).unwrap(),
        ] {
            let carrier = NonZeroU64::new(777).unwrap();
            let handed = Mutex::new(Vec::new());
            let completion = |effects: OwnedObjectWakeEffects<'_, C>| {
                let _ = effects.deliver_handbacks(&mut |r| handed.lock().unwrap().push(r));
            };
            let records = [101, 102].map(|tid| {
                zone.alloc_record(ThreadIdentity {
                    tid,
                    serial: tid,
                    mm: 7,
                    file_table: 99,
                    generation: 1,
                    affinity_source: crate::AffinitySource::UNBOUND,
                    affinity: 1,
                    lifecycle_page: 0,
                    control_slot: 0,
                })
                .unwrap()
            });
            let (published_tx, published_rx) = mpsc::channel();
            let (enrolled_tx, enrolled_rx) = mpsc::channel();
            std::thread::scope(|scope| {
                let binder = scope.spawn(|| {
                    PUBLICATION.with(|hook| {
                        *hook.borrow_mut() = Some(PublicationHook {
                            published: published_tx,
                            enrolled: enrolled_rx,
                        });
                    });
                    zone.bind_ipc_lock_release(index, carrier, &BoundedSpin(0), &completion)
                        .unwrap();
                });
                published_rx.recv_timeout(Duration::from_secs(5)).unwrap();
                zone.bind_ipc_lock_release(index, carrier, &BoundedSpin(0), &completion)
                    .unwrap();
                let source = zone.ipc_lock_release_source(index, carrier).unwrap();
                for (i, record) in records.into_iter().enumerate() {
                    source
                        .reserve()
                        .park_host_rechecked(
                            source.observe(),
                            record,
                            OperationToken::new(i as u64 + 1, 11).unwrap(),
                            &completion,
                            || true,
                        )
                        .unwrap();
                    assert!(matches!(
                        zone.record(record).claim(),
                        Claim::Transferring { .. }
                    ));
                }
                enrolled_tx.send(()).unwrap();
                binder.join().unwrap();
            });
            assert_eq!(handed.lock().unwrap().len(), records.len());
            assert_eq!(
                zone.object_queue(index.key(carrier).index() as usize)
                    .publishers
                    .load(Ordering::Acquire),
                1,
                "both counted admissions must return to the permanent base publisher"
            );
            for record in records {
                assert!(unsafe { zone.record(record).take_object_operation() }.is_some());
                zone.free_record(record);
            }
        }
    }

    #[test]
    fn concurrent_ipc_admission_aarch64_keeps_guard_generation() {
        concurrent_admission::<Aarch64ParkedContext>();
    }

    #[test]
    fn concurrent_ipc_admission_cpl0_keeps_guard_generation() {
        concurrent_admission::<ParkedContextWords>();
    }
}

impl<C: Copy + Send + Sync + zerocopy::FromZeros> ZoneTables<C> {
    /// Borrow only a source admitted by this carrier's IPC directory owner.
    pub fn ipc_lock_release_source(
        &self,
        index: IpcLockIndex,
        carrier: NonZeroU64,
    ) -> Result<BorrowedObjectNotificationSource<'_, '_, C>, ObjectWaitError> {
        let key = index.key(carrier);
        if self.notification_generation(key) != key.generation {
            return Err(ObjectWaitError::Stale);
        }
        Ok(BorrowedObjectNotificationSource {
            zone: self,
            key,
            _source: core::marker::PhantomData,
        })
    }
}
