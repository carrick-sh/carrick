//! Connection tracking and per-connection worker management for CarrierControlServer.

use std::collections::HashMap;
use std::net::Shutdown;
use std::os::unix::net::{UnixListener, UnixStream};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread::JoinHandle;

use parking_lot::Mutex;

use super::{ControlEndpoint, ControlNonce};

const MAX_CONCURRENT_CONNECTIONS: usize = 16;

pub(super) struct ConnectionTracker {
    next_id: u64,
    streams: Arc<Mutex<HashMap<u64, UnixStream>>>,
    handlers: Vec<JoinHandle<()>>,
}

struct RemoveOnDrop {
    id: u64,
    streams: Arc<Mutex<HashMap<u64, UnixStream>>>,
}

impl Drop for RemoveOnDrop {
    fn drop(&mut self) {
        self.streams.lock().remove(&self.id);
    }
}

impl ConnectionTracker {
    pub(super) fn new() -> Self {
        Self {
            next_id: 0,
            streams: Arc::new(Mutex::new(HashMap::new())),
            handlers: Vec::new(),
        }
    }

    pub(super) fn spawn_handler(
        &mut self,
        mut stream: UnixStream,
        kernel: Arc<super::super::Kernel>,
        init: super::super::TaskKey,
        nonce: ControlNonce,
        exec: Arc<dyn super::CarrierExecAdmission>,
        archive: Arc<dyn super::CarrierArchiveControl>,
    ) {
        self.handlers.retain(|h| !h.is_finished());
        if self.streams.lock().len() >= MAX_CONCURRENT_CONNECTIONS {
            let _ = stream.shutdown(Shutdown::Both);
            return;
        }

        let Ok(clone) = stream.try_clone() else {
            return;
        };
        let id = self.next_id;
        self.next_id += 1;
        self.streams.lock().insert(id, clone);

        let streams = Arc::clone(&self.streams);
        let builder = std::thread::Builder::new();
        if let Ok(handle) = builder
            .name(format!("carrick-carrier-control-conn-{}", id))
            .spawn(move || {
                let _guard = RemoveOnDrop { id, streams };
                if let Err(_error) = super::handle(
                    &mut stream,
                    &kernel,
                    init,
                    nonce,
                    exec.as_ref(),
                    archive.as_ref(),
                ) {
                    #[cfg(test)]
                    eprintln!("carrier control test connection failed: {_error}");
                }
            })
        {
            self.handlers.push(handle);
        } else {
            self.streams.lock().remove(&id);
        }
    }

    pub(super) fn cancel_and_join(&mut self) {
        let streams: Vec<UnixStream> = self.streams.lock().drain().map(|(_, s)| s).collect();
        for s in streams {
            let _ = s.shutdown(Shutdown::Both);
        }
        for h in self.handlers.drain(..) {
            let _ = h.join();
        }
    }
}

pub(super) struct ControlServerContext {
    pub(super) kernel: Arc<super::super::Kernel>,
    pub(super) init: super::super::TaskKey,
    pub(super) nonce: ControlNonce,
    pub(super) exec: Arc<dyn super::CarrierExecAdmission>,
    pub(super) archive: Arc<dyn super::CarrierArchiveControl>,
}

pub(super) fn run_accept_loop(
    listener: UnixListener,
    thread_shutdown: Arc<AtomicBool>,
    context: ControlServerContext,
    thread_endpoint: ControlEndpoint,
) {
    let mut tracker = ConnectionTracker::new();
    while !thread_shutdown.load(Ordering::Acquire) {
        let Ok((stream, _)) = listener.accept() else {
            continue;
        };
        if thread_shutdown.load(Ordering::Acquire) {
            break;
        }
        tracker.spawn_handler(
            stream,
            Arc::clone(&context.kernel),
            context.init,
            context.nonce,
            Arc::clone(&context.exec),
            Arc::clone(&context.archive),
        );
    }
    tracker.cancel_and_join();
    drop(thread_endpoint);
}
