use std::sync::Arc;

use parking_lot::Mutex;

use super::FileAuthorityCore;
use super::{
    AuthorityCall, AuthorityFatal, AuthorityReply, CanonicalAuthorityTarget, Command, Request,
    Response,
};

pub(crate) trait FileAuthorityTransport: Send + Sync {
    fn transact(&self, call: AuthorityCall) -> Result<AuthorityReply, AuthorityFatal>;

    fn execute(&self, request: Request) -> Result<Response, AuthorityFatal> {
        if matches!(request.command, Command::AcquireCapabilityLease { .. }) {
            return Err(AuthorityFatal::CapabilityMismatch);
        }
        let reply = self.transact(AuthorityCall::without_capabilities(request))?;
        if !reply.capabilities.is_empty() {
            return Err(AuthorityFatal::CapabilityMismatch);
        }
        Ok(reply.response)
    }
}

/// Direct client for the no-host-fork authority lane.
///
/// The mutex is the transport serialization point only. The same request and
/// response values are later encoded by the datagram client; callers never get
/// access to the core, its leases, or its backing objects.
#[derive(Debug, Clone)]
pub(crate) struct DirectFileAuthority {
    core: Arc<Mutex<FileAuthorityCore>>,
}

impl DirectFileAuthority {
    pub(crate) fn for_run(core: FileAuthorityCore) -> Self {
        Self {
            core: Arc::new(Mutex::new(core)),
        }
    }

    #[allow(
        dead_code,
        reason = "consumed by canonical dispatch in the in-carrier cutover"
    )]
    pub(crate) fn transact_canonical(
        &self,
        call: AuthorityCall,
        target: CanonicalAuthorityTarget,
    ) -> Result<AuthorityReply, AuthorityFatal> {
        self.core.lock().execute_canonical_call(call, target)
    }

    #[cfg(test)]
    pub(crate) fn model_table_count(&self) -> usize {
        self.core.lock().model_table_count()
    }

    #[cfg(test)]
    pub(crate) fn model_description_count(&self) -> usize {
        self.core.lock().model_description_count()
    }
}

impl FileAuthorityTransport for DirectFileAuthority {
    fn transact(&self, call: AuthorityCall) -> Result<AuthorityReply, AuthorityFatal> {
        self.core.lock().execute_call(call)
    }
}
