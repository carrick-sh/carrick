//! Test and embedding builder for kernel and scheduler configurations.

use std::sync::Arc;

use carrick_hal::{
    GuestCpuPolicy, HostSignalBridge, NullHostSignalBridge, SchedulingPolicy, ThreadId,
};

use crate::kernel::core::{Kernel, KernelContext, KernelError, RootBootstrap};
use crate::kernel::scheduler::Scheduler;
use crate::kernel::scheduler::preemption::{HostMonotonicClock, MonotonicClock};

/// Fluent builder to configure a [`Kernel`] and [`Scheduler`] with injected policy and clock.
pub struct KernelBuilder {
    observed_pid: i32,
    diagnostic_name: String,
    policy: Option<Arc<dyn SchedulingPolicy>>,
    clock: Option<Box<dyn MonotonicClock>>,
    host_signal: Option<Arc<dyn HostSignalBridge>>,
}

impl Default for KernelBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl KernelBuilder {
    pub fn new() -> Self {
        Self {
            observed_pid: 1,
            diagnostic_name: "kernel-builder".to_owned(),
            policy: None,
            clock: None,
            host_signal: None,
        }
    }

    pub fn with_pid(mut self, pid: i32) -> Self {
        self.observed_pid = pid;
        self
    }

    pub fn with_diagnostic_name(mut self, name: impl Into<String>) -> Self {
        self.diagnostic_name = name.into();
        self
    }

    pub fn with_policy(mut self, policy: Arc<dyn SchedulingPolicy>) -> Self {
        self.policy = Some(policy);
        self
    }

    pub fn with_clock(mut self, clock: Box<dyn MonotonicClock>) -> Self {
        self.clock = Some(clock);
        self
    }

    pub fn with_host_signal(mut self, host_signal: Arc<dyn HostSignalBridge>) -> Self {
        self.host_signal = Some(host_signal);
        self
    }

    pub fn build(self) -> Result<(Arc<Kernel>, KernelContext, Arc<Scheduler>), KernelError> {
        let host_signal = self
            .host_signal
            .unwrap_or_else(|| Arc::new(NullHostSignalBridge::default()));
        let bootstrap = RootBootstrap::for_one_task_adapter(
            self.observed_pid,
            ThreadId::synthetic_for_tests(self.observed_pid),
            self.diagnostic_name,
            host_signal,
        )?;
        let (kernel, context) = Kernel::bootstrap_root(bootstrap)?;
        let policy = self
            .policy
            .unwrap_or_else(|| Arc::new(GuestCpuPolicy::new(carrick_hal::MAX_GUEST_CPUS)));
        let clock = self.clock.unwrap_or_else(|| Box::new(HostMonotonicClock));
        let scheduler = Arc::new(Scheduler::new_with_policy_and_clock(
            Arc::clone(&kernel),
            policy,
            clock,
        ));
        Ok((kernel, context, scheduler))
    }
}
