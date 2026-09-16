use std::panic::{AssertUnwindSafe, catch_unwind};
use std::sync::Arc;

use carrick_abi::{CanonicalNr, LinuxErrno, LinuxGuestAbi};
use carrick_observability::compat::SyscallArgs;

use super::{ProcessInfo, SyscallOutcome};
use crate::dispatch::{DispatchError, SyscallRequest};

/// Immutable syscall identity and its interceptor-visible effective arguments.
#[derive(Debug, Clone, Copy)]
pub struct InterceptedSyscall<'a> {
    original: &'a SyscallRequest,
    effective_args: SyscallArgs,
}

impl<'a> InterceptedSyscall<'a> {
    pub(crate) const fn new(original: &'a SyscallRequest, effective_args: SyscallArgs) -> Self {
        Self {
            original,
            effective_args,
        }
    }

    pub const fn canonical_number(&self) -> CanonicalNr {
        self.original.number
    }

    pub fn native_number(&self) -> u64 {
        self.original.native_number.raw()
    }

    pub fn name(&self) -> &'static str {
        carrick_abi::syscall::lookup_aarch64(self.original.number.raw())
            .map_or("unknown", |entry| entry.name)
    }

    pub const fn original_args(&self) -> SyscallArgs {
        self.original.args
    }

    pub const fn effective_args(&self) -> SyscallArgs {
        self.effective_args
    }

    pub const fn guest_abi(&self) -> LinuxGuestAbi {
        self.original.guest_abi
    }

    pub const fn current_guest_sp(&self) -> Option<u64> {
        self.original.current_guest_sp
    }
}

/// Result requested by a syscall interceptor.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InterceptAction {
    Continue,
    RewriteArgs(SyscallArgs),
    Return(i64),
    Errno(LinuxErrno),
}

/// Receives a read-only syscall snapshot before dispatch.
pub trait SyscallInterceptor: Send + Sync {
    fn intercept(
        &self,
        process: &ProcessInfo<'_>,
        call: &InterceptedSyscall<'_>,
    ) -> InterceptAction;
}

/// The effective scalar arguments and any terminal result proposed by a chain.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Interception {
    pub effective_args: SyscallArgs,
    pub proposed: Option<SyscallOutcome>,
}

/// A sealed, deterministically ordered set of trusted syscall interceptors.
#[derive(Clone, Default)]
pub(crate) struct InterceptorChain {
    interceptors: Vec<Arc<dyn SyscallInterceptor>>,
}

impl InterceptorChain {
    pub(crate) fn new(interceptors: Vec<Arc<dyn SyscallInterceptor>>) -> Self {
        Self { interceptors }
    }

    pub(crate) fn with_appended(&self, interceptor: Arc<dyn SyscallInterceptor>) -> Self {
        let mut interceptors = self.interceptors.clone();
        interceptors.push(interceptor);
        Self::new(interceptors)
    }

    pub(crate) fn apply(
        &self,
        process: &ProcessInfo<'_>,
        request: &SyscallRequest,
    ) -> Result<Interception, DispatchError> {
        let mut effective_args = request.args;
        let mut proposed = None;

        for interceptor in &self.interceptors {
            let call = InterceptedSyscall::new(request, effective_args);
            let action = catch_unwind(AssertUnwindSafe(|| interceptor.intercept(process, &call)))
                .map_err(|_| DispatchError::InterceptorPanicked {
                container_id: process.context().container().id(),
            })?;

            match action {
                InterceptAction::Continue => {}
                InterceptAction::RewriteArgs(args) => effective_args = args,
                InterceptAction::Return(value) => {
                    proposed = Some(SyscallOutcome::returned(value));
                    break;
                }
                InterceptAction::Errno(errno) => {
                    proposed = Some(SyscallOutcome::errno(errno));
                    break;
                }
            }
        }

        Ok(Interception {
            effective_args,
            proposed,
        })
    }
}
