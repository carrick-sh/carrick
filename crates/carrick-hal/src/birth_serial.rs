//! Retained host access to the carrier zone's task/thread birth source.
use core::num::NonZeroU64;

/// Exact backend-issued carrier and VM incarnation, never a generation alone.
#[derive(Clone)]
pub struct BirthSourceIdentity {
    owner: std::sync::Arc<dyn core::any::Any + Send + Sync>,
    carrier: NonZeroU64,
    generation: NonZeroU64,
}
impl BirthSourceIdentity {
    pub fn from_backend_identity(
        owner: std::sync::Arc<dyn core::any::Any + Send + Sync>,
        carrier: NonZeroU64,
        generation: NonZeroU64,
    ) -> Self {
        Self {
            owner,
            carrier,
            generation,
        }
    }
}
impl PartialEq for BirthSourceIdentity {
    fn eq(&self, other: &Self) -> bool {
        std::sync::Arc::ptr_eq(&self.owner, &other.owner)
            && self.carrier == other.carrier
            && self.generation == other.generation
    }
}
impl Eq for BirthSourceIdentity {}
impl core::fmt::Debug for BirthSourceIdentity {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("BirthSourceIdentity")
            .field("carrier", &self.carrier)
            .field("generation", &self.generation)
            .finish_non_exhaustive()
    }
}
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum BirthSourceError {
    #[error("birth issuer belongs to a different or retired carrier VM")]
    StaleOwner,
    #[error("carrier birth serial space exhausted")]
    Exhausted,
}
/// Implementations own backing through every operation, authenticate the exact
/// incarnation and use its actual ZoneTables word. No borrowed/raw host pointer
/// escapes this boundary. Guest issuance accesses that same word directly.
pub trait BirthSerialSource: Send + Sync + core::fmt::Debug {
    fn identity(&self) -> &BirthSourceIdentity;
    fn allocate(&self, expected: &BirthSourceIdentity) -> Result<NonZeroU64, BirthSourceError>;
    fn adopt_initial(
        &self,
        expected: &BirthSourceIdentity,
        high_water: NonZeroU64,
    ) -> Result<(), BirthSourceError>;
    /// Only for exclusive pre-native handoff or observing already-issued births.
    /// This cannot repair identities escaped from independent live issuers.
    fn advance_past(
        &self,
        expected: &BirthSourceIdentity,
        issued: NonZeroU64,
    ) -> Result<(), BirthSourceError>;
}

/// VM-free fixture backing; never part of a product capability implementation.
#[cfg(any(test, feature = "test-support"))]
pub mod test_support {
    use super::*;
    use carrick_sched_core::ZoneTables;
    use std::sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    };
    pub struct OwnedBirthZone<C: Copy + Send + Sync + zerocopy::FromZeros + 'static> {
        pub zone: Arc<ZoneTables<C>>,
        identity: BirthSourceIdentity,
        live: AtomicBool,
    }
    impl<C: Copy + Send + Sync + zerocopy::FromZeros + 'static> core::fmt::Debug for OwnedBirthZone<C> {
        fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
            self.identity.fmt(f)
        }
    }
    impl<C: Copy + Send + Sync + zerocopy::FromZeros + 'static> OwnedBirthZone<C> {
        pub fn new(zone: Arc<ZoneTables<C>>) -> Self {
            Self {
                identity: BirthSourceIdentity::from_backend_identity(
                    zone.clone(),
                    NonZeroU64::MIN,
                    NonZeroU64::MIN,
                ),
                zone,
                live: AtomicBool::new(true),
            }
        }
        pub fn retire(&self) {
            self.live.store(false, Ordering::Release);
        }
        fn check(&self, expected: &BirthSourceIdentity) -> Result<(), BirthSourceError> {
            if expected == &self.identity && self.live.load(Ordering::Acquire) {
                Ok(())
            } else {
                Err(BirthSourceError::StaleOwner)
            }
        }
    }
    impl<C: Copy + Send + Sync + zerocopy::FromZeros + 'static> BirthSerialSource
        for OwnedBirthZone<C>
    {
        fn identity(&self) -> &BirthSourceIdentity {
            &self.identity
        }
        fn allocate(&self, expected: &BirthSourceIdentity) -> Result<NonZeroU64, BirthSourceError> {
            self.check(expected)?;
            self.zone
                .serial_issuer()
                .allocate()
                .ok_or(BirthSourceError::Exhausted)
        }
        fn adopt_initial(
            &self,
            expected: &BirthSourceIdentity,
            high_water: NonZeroU64,
        ) -> Result<(), BirthSourceError> {
            self.check(expected)?;
            if self.zone.serial_issuer().adopt_initial(high_water) {
                Ok(())
            } else {
                Err(BirthSourceError::StaleOwner)
            }
        }
        fn advance_past(
            &self,
            expected: &BirthSourceIdentity,
            issued: NonZeroU64,
        ) -> Result<(), BirthSourceError> {
            self.check(expected)?;
            self.zone.serial_issuer().advance_past(issued);
            Ok(())
        }
    }
}
