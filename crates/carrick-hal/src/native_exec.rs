//! Carrier-retained native exec service contract and capability directory.

use std::sync::Arc;

use carrick_core_abi::service::{ExecCapabilityId, ServiceFailureCode, ServiceRequest};

use crate::fork_stock::{HostBackingRetention, NativeHostFileRefused};

/// Counted ENOSYS for an exec request whose capability names no live service.
pub const UNROUTED_EXEC: ServiceFailureCode = match ServiceFailureCode::new(38) {
    Some(code) => code,
    None => ServiceFailureCode::MINIMUM,
};

/// Carrier-retained file/loader service. It owns no task lookup; the service
/// cell has already authenticated `request` against the stopped ring member.
pub trait NativeExecHostService<Plan: Send + 'static>:
    core::fmt::Debug + Send + Sync + 'static
{
    /// Prepare the image of `successor`, whose published reservation root is
    /// still unadmitted: the service imports the image's rows into it.
    fn prepare(
        &self,
        request: ServiceRequest,
        payload: &[u8],
        successor: carrick_el1_abi::ReservationMm,
    ) -> Result<Box<dyn NativeExecPreparation<Plan>>, ServiceFailureCode>;

    /// Serve one ring-staged host-file record
    /// ([`carrick_core_abi::host_file`]) under the caller's own access
    /// context, which a path record carries by value, writing its reply in
    /// place. `Err` refuses the exact request
    /// (the ring answers counted ENOSYS); no reply may have been written. A
    /// private-mapping record returns the retained byte source, which the
    /// carrier registers for the caller's MM before acknowledging.
    fn serve_host_file(
        &self,
        request: ServiceRequest,
        record: &mut [u8],
    ) -> Result<Option<Arc<dyn HostBackingRetention>>, NativeHostFileRefused>;

    /// Answer one ring-staged clock record against this capability's
    /// container `ClockDomain`, in place ([`carrick_core_abi::clock`]).
    /// `Err` leaves the record unanswered; the carrier then replies ENOSYS.
    fn serve_clock(
        &self,
        record: &mut [u8; carrick_core_abi::clock::CLOCK_RECORD_BYTES],
    ) -> Result<(), carrick_core_abi::clock::ClockRecordError>;

    /// Serve the root fork seed crossing: write the host-served root's live
    /// cwd and root into `record` once ([`carrick_core_abi::service::RootForkSeed::serve`]).
    /// `false` refuses it; the fork then fails without a child.
    fn root_fork_seed(&self, record: &mut carrick_core_abi::service::RootForkSeed) -> bool;
}

/// Opaque fallibly prepared image. Exact carrier custody retains this result
/// until the ring consumes successor adoption or terminal cleanup drops it.
pub trait NativeExecPreparation<Plan: Send + 'static>: core::fmt::Debug + Send + 'static {
    fn into_parts(self: Box<Self>) -> NativeExecParts<Plan>;
}

/// A prepared successor image: the carrier maps `plan` except its lazy
/// regions, which the successor's ring owner supplies from `sources`.
pub struct NativeExecParts<Plan> {
    pub plan: Plan,
    pub lazy_regions: Vec<(u64, u64)>,
    pub sources: Vec<Arc<dyn HostBackingRetention>>,
}

type RegisteredExecService<Plan> = (ExecCapabilityId, Arc<dyn NativeExecHostService<Plan>>);

/// Exact carrier registration for a retained exec service.
///
/// The directory, rather than the run that installed it, owns the service
/// while guest work can name its capability.  The returned registration is
/// the run's unique removal authority and must settle after its process tree
/// has joined but before container resources are retired.
pub struct NativeExecServiceDirectory<Plan: Send + 'static> {
    services: parking_lot::Mutex<Vec<RegisteredExecService<Plan>>>,
}

impl<Plan: Send + 'static> Default for NativeExecServiceDirectory<Plan> {
    fn default() -> Self {
        Self {
            services: parking_lot::Mutex::new(Vec::new()),
        }
    }
}

impl<Plan: Send + 'static> core::fmt::Debug for NativeExecServiceDirectory<Plan> {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("NativeExecServiceDirectory")
            .field("services", &self.services)
            .finish()
    }
}

#[derive(
    ::core::clone::Clone,
    ::core::marker::Copy,
    ::core::fmt::Debug,
    ::core::cmp::Eq,
    ::core::cmp::PartialEq,
)]
pub enum NativeExecRegistrationError {
    Duplicate,
    Absent,
}

impl<Plan: Send + 'static> NativeExecServiceDirectory<Plan> {
    pub fn install(
        self: &Arc<Self>,
        capability: ExecCapabilityId,
        service: Arc<dyn NativeExecHostService<Plan>>,
    ) -> Result<NativeExecServiceRegistration<Plan>, NativeExecRegistrationError> {
        let mut services = self.services.lock();
        if services.iter().any(|(id, _)| *id == capability) {
            return Err(NativeExecRegistrationError::Duplicate);
        }
        services.push((capability, service));
        Ok(NativeExecServiceRegistration {
            directory: Arc::clone(self),
            capability,
            armed: true,
        })
    }

    pub fn service(
        &self,
        capability: ExecCapabilityId,
    ) -> Option<Arc<dyn NativeExecHostService<Plan>>> {
        self.services
            .lock()
            .iter()
            .find(|(id, _)| *id == capability)
            .map(|(_, service)| Arc::clone(service))
    }

    /// The service a guest exec request names, or the counted ENOSYS a
    /// request receives when no live service holds that capability (for
    /// example a fork child of a root whose image the host replaced). A
    /// guest-selected capability is never carrier custody to fail on.
    pub fn resolve(
        &self,
        capability: ExecCapabilityId,
    ) -> Result<Arc<dyn NativeExecHostService<Plan>>, ServiceFailureCode> {
        self.service(capability).ok_or(UNROUTED_EXEC)
    }

    fn remove(&self, capability: ExecCapabilityId) -> Result<(), NativeExecRegistrationError> {
        let mut services = self.services.lock();
        let index = services
            .iter()
            .position(|(id, _)| *id == capability)
            .ok_or(NativeExecRegistrationError::Absent)?;
        services.swap_remove(index);
        Ok(())
    }
}

/// Consuming authority to release one carrier-retained exec service.
#[must_use]
pub struct NativeExecServiceRegistration<Plan: Send + 'static> {
    directory: Arc<NativeExecServiceDirectory<Plan>>,
    capability: ExecCapabilityId,
    armed: bool,
}

impl<Plan: Send + 'static> NativeExecServiceRegistration<Plan> {
    pub fn retire(mut self) -> Result<(), NativeExecRegistrationError> {
        self.directory.remove(self.capability)?;
        self.armed = false;
        Ok(())
    }
}

impl<Plan: Send + 'static> Drop for NativeExecServiceRegistration<Plan> {
    fn drop(&mut self) {
        if self.armed {
            let _ = self.directory.remove(self.capability);
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod native_exec_service_registration_tests {
    use super::*;

    #[derive(Debug)]
    struct RetainedService {
        _retained: Arc<()>,
    }

    impl NativeExecHostService<()> for RetainedService {
        fn prepare(
            &self,
            _request: ServiceRequest,
            _payload: &[u8],
            _successor: carrick_el1_abi::ReservationMm,
        ) -> Result<Box<dyn NativeExecPreparation<()>>, ServiceFailureCode> {
            Err(ServiceFailureCode::MINIMUM)
        }

        fn serve_host_file(
            &self,
            _request: ServiceRequest,
            _record: &mut [u8],
        ) -> Result<Option<Arc<dyn HostBackingRetention>>, NativeHostFileRefused> {
            Err(NativeHostFileRefused)
        }

        fn serve_clock(
            &self,
            _record: &mut [u8; carrick_core_abi::clock::CLOCK_RECORD_BYTES],
        ) -> Result<(), carrick_core_abi::clock::ClockRecordError> {
            Err(carrick_core_abi::clock::ClockRecordError::Invalid)
        }

        fn root_fork_seed(&self, _record: &mut carrick_core_abi::service::RootForkSeed) -> bool {
            false
        }
    }

    /// #936: a native child of a post-exec root names the root's original
    /// exec capability, which the host exec retired. The request must be a
    /// counted ENOSYS (as on main), never a carrier custody fatal.
    #[test]
    fn retired_or_unknown_exec_capability_is_a_counted_enosys() {
        let directory = Arc::new(NativeExecServiceDirectory::<()>::default());
        let capability = carrick_core_abi::service::ExecCapabilityId::new(
            core::num::NonZeroU64::new(7).unwrap(),
        );
        assert_eq!(
            directory
                .resolve(capability)
                .err()
                .map(ServiceFailureCode::raw),
            Some(38)
        );
        let service: Arc<dyn NativeExecHostService<()>> = Arc::new(RetainedService {
            _retained: Arc::new(()),
        });
        let registration = directory.install(capability, service).unwrap();
        assert!(directory.resolve(capability).is_ok());
        registration.retire().unwrap();
        assert_eq!(
            directory
                .resolve(capability)
                .err()
                .map(ServiceFailureCode::raw),
            Some(38)
        );
    }

    #[test]
    fn native_exec_registration_retirement_releases_installed_service() {
        let directory = Arc::new(NativeExecServiceDirectory::<()>::default());
        let retained = Arc::new(());
        let witness = Arc::downgrade(&retained);
        let capability = carrick_core_abi::service::ExecCapabilityId::new(
            core::num::NonZeroU64::new(1).unwrap(),
        );
        let service: Arc<dyn NativeExecHostService<()>> = Arc::new(RetainedService {
            _retained: Arc::clone(&retained),
        });
        drop(retained);

        let registration = directory.install(capability, service).unwrap();
        assert!(
            witness.upgrade().is_some(),
            "installed service was not retained"
        );
        assert!(
            directory.service(capability).is_some(),
            "plain root exec capability must resolve before retirement"
        );
        registration.retire().unwrap();
        assert!(
            witness.upgrade().is_none(),
            "settled registration retained the service owner"
        );
    }
}
