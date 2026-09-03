//! Explicit ownership of one Carrick kernel carrier.

use std::sync::Arc;

use carrick_runtime::{CarrierLease, CarrierRuntime};

use crate::{ContainerBuilder, EmbedError};

pub(crate) enum CarrierBinding {
    Explicit(CarrierRuntime),
    ImplicitSingleUse,
}

impl CarrierBinding {
    pub(crate) fn reserve(&self) -> Result<(CarrierRuntime, CarrierLease, bool), EmbedError> {
        let (runtime, implicit) = match self {
            Self::Explicit(runtime) => (runtime.clone(), false),
            Self::ImplicitSingleUse => (
                CarrierRuntime::new_implicit_single_use().map_err(|error| {
                    EmbedError::from_runtime(error, crate::error::Phase::Prepare)
                })?,
                true,
            ),
        };
        let lease = runtime
            .reserve(crate::prepared::embedded_launch_context())
            .map_err(|error| EmbedError::from_runtime(error, crate::error::Phase::Prepare))?;
        Ok((runtime, lease, implicit))
    }
}

#[derive(Debug)]
struct FinalizerState {
    close_requested: bool,
    terminal: Option<Result<(), String>>,
}

#[derive(Debug)]
struct Finalizer {
    state: parking_lot::Mutex<FinalizerState>,
    changed: parking_lot::Condvar,
    join: parking_lot::Mutex<Option<std::thread::JoinHandle<()>>>,
}

impl Finalizer {
    fn request_close(&self) {
        let mut state = self.state.lock();
        state.close_requested = true;
        self.changed.notify_all();
    }

    fn wait(&self) -> Result<(), EmbedError> {
        if let Some(join) = self.join.lock().take()
            && join.join().is_err()
        {
            return Err(EmbedError::CarrierFailed {
                reason: "carrier finalizer thread panicked".to_owned(),
            });
        }
        let mut state = self.state.lock();
        while state.terminal.is_none() {
            self.changed.wait(&mut state);
        }
        match state.terminal.as_ref() {
            None => Err(EmbedError::CarrierFailed {
                reason: "carrier finalizer completed without a terminal result".to_owned(),
            }),
            Some(Ok(())) => Ok(()),
            Some(Err(reason)) => Err(EmbedError::CarrierFailed {
                reason: reason.clone(),
            }),
        }
    }
}

#[derive(Debug)]
struct CarrierInner {
    runtime: CarrierRuntime,
    finalizer: Arc<Finalizer>,
}

impl Drop for CarrierInner {
    fn drop(&mut self) {
        // The finalizer already exists and owns its own runtime clone. Drop
        // merely closes admission asynchronously; it never destroys hardware
        // or joins a worker on the caller's thread.
        self.finalizer.request_close();
    }
}

/// A cloneable handle to the one Carrick kernel carrier in this host process.
///
/// Builders created through [`Self::container`] share its VM and kernel graph
/// while retaining independent container identity and policy. Call
/// [`Self::shutdown`] after all runs complete for deterministic teardown.
#[derive(Clone, Debug)]
pub struct Carrier {
    inner: Arc<CarrierInner>,
}

impl Carrier {
    /// Start an explicit carrier. A process may own only one at a time.
    pub fn new() -> Result<Self, EmbedError> {
        let runtime = CarrierRuntime::new_explicit()
            .map_err(|error| EmbedError::from_runtime(error, crate::error::Phase::Prepare))?;
        let finalizer = Arc::new(Finalizer {
            state: parking_lot::Mutex::new(FinalizerState {
                close_requested: false,
                terminal: None,
            }),
            changed: parking_lot::Condvar::new(),
            join: parking_lot::Mutex::new(None),
        });
        let worker_finalizer = Arc::clone(&finalizer);
        let worker_runtime = runtime.clone();
        let join = std::thread::Builder::new()
            .name("carrick-carrier-finalizer".to_owned())
            .spawn(move || {
                {
                    let mut state = worker_finalizer.state.lock();
                    while !state.close_requested {
                        worker_finalizer.changed.wait(&mut state);
                    }
                }
                let terminal = worker_runtime
                    .shutdown_wait()
                    .map(|_| ())
                    .map_err(|error| error.to_string());
                let mut state = worker_finalizer.state.lock();
                state.terminal = Some(terminal);
                worker_finalizer.changed.notify_all();
            })
            .map_err(|error| EmbedError::CarrierFailed {
                reason: format!("failed to start carrier finalizer: {error}"),
            })?;
        *finalizer.join.lock() = Some(join);
        Ok(Self {
            inner: Arc::new(CarrierInner { runtime, finalizer }),
        })
    }

    /// Build a container explicitly bound to this carrier generation.
    pub fn container(&self, image: impl Into<String>) -> ContainerBuilder {
        ContainerBuilder::from_carrier(image, self.inner.runtime.clone())
    }

    /// Close admission and wait for exact container retirement, service drain,
    /// persistent-VM destruction, and lifecycle publication.
    pub async fn shutdown(self) -> Result<(), EmbedError> {
        self.inner.finalizer.request_close();
        let finalizer = Arc::clone(&self.inner.finalizer);
        tokio::task::spawn_blocking(move || finalizer.wait())
            .await
            .map_err(|error| EmbedError::CarrierFailed {
                reason: format!("carrier finalizer join task panicked: {error}"),
            })?
    }

    #[cfg(feature = "test-support")]
    pub(crate) fn snapshot(&self) -> Result<carrick_runtime::CarrierSnapshot, EmbedError> {
        self.inner
            .runtime
            .snapshot()
            .map_err(|error| EmbedError::from_runtime(error, crate::error::Phase::Execute))
    }
}

#[cfg(test)]
mod tests {
    use super::Carrier;
    use carrick_runtime::kernel::{LaunchContext, RunId};

    fn assert_send_sync_clone<T: Send + Sync + Clone>() {}

    #[test]
    fn public_carrier_is_send_sync_and_clone() {
        assert_send_sync_clone::<Carrier>();
    }

    #[tokio::test]
    async fn one_explicit_carrier_owns_the_process_generation() {
        let _serial = crate::CARRIER_TEST_LOCK.lock().await;
        let carrier = Carrier::new().expect("first explicit carrier");
        assert!(matches!(
            Carrier::new(),
            Err(crate::EmbedError::CarrierAlreadyActive)
        ));
        carrier.shutdown().await.expect("shutdown first carrier");

        let replacement = Carrier::new().expect("replacement carrier");
        replacement.shutdown().await.expect("shutdown replacement");
    }

    #[tokio::test]
    async fn shutdown_closes_admission_before_waiting_for_prepared_lease() {
        let _serial = crate::CARRIER_TEST_LOCK.lock().await;
        let carrier = Carrier::new().expect("carrier");
        let observer = carrier.clone();
        let lease = observer
            .inner
            .runtime
            .reserve(LaunchContext::unmanaged(RunId::new("held-prepared")))
            .expect("prepared lease");

        let shutdown = tokio::spawn(carrier.shutdown());
        loop {
            if observer.inner.runtime.snapshot().expect("snapshot").state
                == carrick_runtime::CarrierAdmissionState::Closing
            {
                break;
            }
            tokio::task::yield_now().await;
        }
        assert!(matches!(
            observer
                .inner
                .runtime
                .reserve(LaunchContext::unmanaged(RunId::new("rejected-after-close"))),
            Err(carrick_runtime::runtime::RuntimeError::CarrierClosing)
        ));
        drop(lease);
        shutdown
            .await
            .expect("shutdown task")
            .expect("shutdown result");
        assert_eq!(
            observer
                .inner
                .runtime
                .snapshot()
                .expect("closed snapshot")
                .state,
            carrick_runtime::CarrierAdmissionState::Closed
        );
    }

    #[tokio::test]
    async fn failed_image_resolution_leaves_no_carrier_reservation() {
        let _serial = crate::CARRIER_TEST_LOCK.lock().await;
        let carrier = Carrier::new().expect("carrier");
        let store = crate::ImageStore::new(tempfile::tempdir().expect("temp store").path());
        let result = carrier
            .container("missing-for-carrier-test:latest")
            .image_store(store)
            .pull_policy(crate::PullPolicy::Never)
            .prepare()
            .await;
        assert!(matches!(result, Err(crate::EmbedError::Image(_))));
        assert_eq!(
            carrier
                .inner
                .runtime
                .snapshot()
                .expect("snapshot")
                .registered_containers,
            0
        );
        carrier.shutdown().await.expect("shutdown");
    }
}
