#[cfg(test)]
use std::sync::Arc;

#[cfg(test)]
use parking_lot::Mutex;

#[cfg(test)]
use super::FileAuthorityCore;
use super::{AuthorityCall, AuthorityFatal, AuthorityReply, Command, Request, Response};

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
#[cfg(test)]
#[derive(Debug, Clone)]
pub(crate) struct DirectFileAuthority {
    core: Arc<Mutex<FileAuthorityCore>>,
}

#[cfg(test)]
impl DirectFileAuthority {
    pub(crate) fn for_run(core: FileAuthorityCore) -> Self {
        Self {
            core: Arc::new(Mutex::new(core)),
        }
    }
}

#[cfg(test)]
impl FileAuthorityTransport for DirectFileAuthority {
    fn transact(&self, call: AuthorityCall) -> Result<AuthorityReply, AuthorityFatal> {
        self.core.lock().execute_call(call)
    }
}
