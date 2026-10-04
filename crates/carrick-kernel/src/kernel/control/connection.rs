//! Connection tracking and per-connection worker management for CarrierControlServer.

use std::io;
use std::net::Shutdown;
use std::os::fd::AsFd;
use std::os::unix::net::{UnixListener, UnixStream};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread::JoinHandle;

use parking_lot::Mutex;

pub(super) use super::super::socket_rpc::{Cancellation, Connection, ConnectionSlots};

use super::{ControlEndpoint, ControlNonce};

pub(super) struct ConnectionTracker {
    next_id: u64,
    slots: Arc<ConnectionSlots>,
    cancellation: Arc<Cancellation>,
    handlers: Vec<JoinHandle<()>>,
}

impl std::fmt::Debug for ConnectionTracker {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ConnectionTracker")
            .field("next_id", &self.next_id)
            .field("live_handlers", &self.slots.live_count())
            .field("handlers", &self.handlers.len())
            .finish()
    }
}

impl ConnectionTracker {
    pub(super) fn new(cancellation: Arc<Cancellation>) -> Self {
        Self {
            next_id: 0,
            slots: Arc::default(),
            cancellation,
            handlers: Vec::new(),
        }
    }

    fn reap_finished(&mut self) {
        let mut finished = Vec::new();
        let mut active = Vec::new();
        for handle in self.handlers.drain(..) {
            if handle.is_finished() {
                finished.push(handle);
            } else {
                active.push(handle);
            }
        }
        self.handlers = active;
        for handle in finished {
            let _ = handle.join();
        }
    }

    pub(super) fn spawn_handler(
        &mut self,
        stream: UnixStream,
        kernel: Arc<super::super::Kernel>,
        init: super::super::TaskKey,
        nonce: ControlNonce,
        exec: Arc<dyn super::CarrierExecAdmission>,
        archive: Arc<dyn super::CarrierArchiveControl>,
    ) {
        self.reap_finished();
        let Some(permit) = self.slots.try_acquire() else {
            let _ = stream.shutdown(Shutdown::Both);
            drop(stream);
            return;
        };

        let Ok(connection) = Connection::new(stream, Arc::clone(&self.cancellation)) else {
            return;
        };
        let id = self.next_id;
        self.next_id += 1;
        let builder = std::thread::Builder::new();
        if let Ok(handle) = builder
            .name(format!("carrick-control-conn-{id}"))
            .spawn(move || {
                // Declare the permit first so it drops last, after the
                // socket and request context, on return or unwinding. A
                // failed spawn also drops the captured permit and rolls
                // back admission without needing a handler to start.
                let _permit = permit;
                let mut connection = connection;
                let context = ControlServerContext {
                    kernel,
                    init,
                    nonce,
                    exec,
                    archive,
                };
                if let Err(_error) = super::handle(
                    &mut connection,
                    &context.kernel,
                    context.init,
                    context.nonce,
                    context.exec.as_ref(),
                    context.archive.as_ref(),
                ) {
                    #[cfg(test)]
                    eprintln!("carrier control test connection failed: {_error}");
                }
            })
        {
            self.handlers.push(handle);
        }
    }

    pub(super) fn cancel_and_join(&mut self) {
        // The pipe stays readable after cancellation, waking every current
        // and future wait. Joins hold no slot-state lock needed by release.
        self.cancellation.cancel();
        for h in self.handlers.drain(..) {
            let _ = h.join();
        }
    }

    #[cfg(test)]
    pub(super) fn live_handlers_count(&self) -> usize {
        self.slots.live_count()
    }

    #[cfg(test)]
    pub(super) fn retained_handlers_count(&self) -> usize {
        self.handlers.len()
    }

    #[cfg(test)]
    pub(super) fn slot_observer(&self) -> Arc<ConnectionSlots> {
        Arc::clone(&self.slots)
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
    tracker: Arc<Mutex<ConnectionTracker>>,
    cancellation: Arc<Cancellation>,
) {
    while !thread_shutdown.load(Ordering::Acquire) {
        let (stream, _) = match listener.accept() {
            Ok(accepted) => accepted,
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                if cancellation.wait(listener.as_fd(), libc::POLLIN).is_err() {
                    break;
                }
                continue;
            }
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(_) => break,
        };
        if thread_shutdown.load(Ordering::Acquire) {
            break;
        }
        tracker.lock().spawn_handler(
            stream,
            Arc::clone(&context.kernel),
            context.init,
            context.nonce,
            Arc::clone(&context.exec),
            Arc::clone(&context.archive),
        );
    }
    tracker.lock().cancel_and_join();
    // Ownership of the record is the server's, not the accept
    // loop's: `shutdown` releases it, and a teardown quiesce keeps
    // it (marked `TearingDown`) until the terminal receipt is
    // durable.
    drop(thread_endpoint);
}
