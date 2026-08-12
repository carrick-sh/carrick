use std::sync::Arc;

use parking_lot::Mutex;

use super::{AuthorityFatal, FileAuthorityCore, Request, Response};

pub(crate) trait FileAuthorityTransport: Send + Sync {
    fn execute(&self, request: Request) -> Result<Response, AuthorityFatal>;
}

/// Direct client for the no-host-fork authority lane.
///
/// The mutex is the transport serialization point only. The same request and
/// response values are later encoded by the datagram client; callers never get
/// access to the core or its backing objects.
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

    #[cfg(test)]
    pub(super) fn revision(&self) -> super::Revision {
        self.core.lock().revision()
    }
}

impl FileAuthorityTransport for DirectFileAuthority {
    fn execute(&self, request: Request) -> Result<Response, AuthorityFatal> {
        self.core.lock().execute(request)
    }
}
