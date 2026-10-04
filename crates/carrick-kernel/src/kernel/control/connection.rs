//! Connection tracking and per-connection worker management for CarrierControlServer.

use std::collections::HashMap;
use std::net::Shutdown;
use std::os::unix::net::{UnixListener, UnixStream};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread::JoinHandle;

use parking_lot::Mutex;

use super::{ControlEndpoint, ControlNonce};

pub(super) const CONTROL_MAX_CONNECTIONS: usize = 16;

pub(super) struct ConnectionTracker {
    next_id: u64,
    slots: Arc<ConnectionSlots>,
    handlers: Vec<JoinHandle<()>>,
}

#[derive(Default)]
struct ConnectionState {
    live: usize,
    streams: HashMap<u64, UnixStream>,
}

#[derive(Default)]
pub(super) struct ConnectionSlots {
    state: Mutex<ConnectionState>,
    #[cfg(test)]
    changed: parking_lot::Condvar,
}

struct ConnectionPermit {
    id: u64,
    slots: Arc<ConnectionSlots>,
}

impl Drop for ConnectionPermit {
    fn drop(&mut self) {
        let mut state = self.slots.state.lock();
        state.streams.remove(&self.id);
        state.live -= 1;
        #[cfg(test)]
        self.slots.changed.notify_all();
    }
}

#[cfg(test)]
impl ConnectionSlots {
    pub(super) fn wait_for_count(&self, expected: usize, bound: std::time::Duration) -> bool {
        let deadline = std::time::Instant::now() + bound;
        let mut state = self.state.lock();
        while state.live != expected {
            if self.changed.wait_until(&mut state, deadline).timed_out() {
                return state.live == expected;
            }
        }
        true
    }
}

impl std::fmt::Debug for ConnectionTracker {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let state = self.slots.state.lock();
        f.debug_struct("ConnectionTracker")
            .field("next_id", &self.next_id)
            .field("active_streams", &state.streams.len())
            .field("live_handlers", &state.live)
            .field("handlers", &self.handlers.len())
            .finish()
    }
}

impl ConnectionTracker {
    pub(super) fn new() -> Self {
        Self {
            next_id: 0,
            slots: Arc::default(),
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
        let mut state = self.slots.state.lock();
        if state.live >= CONTROL_MAX_CONNECTIONS {
            let _ = stream.shutdown(Shutdown::Both);
            drop(stream);
            return;
        }

        let Ok(clone) = stream.try_clone() else {
            return;
        };
        let id = self.next_id;
        self.next_id += 1;
        state.streams.insert(id, clone);
        state.live += 1;
        #[cfg(test)]
        self.slots.changed.notify_all();
        let permit = ConnectionPermit {
            id,
            slots: Arc::clone(&self.slots),
        };
        drop(state);

        let builder = std::thread::Builder::new();
        if let Ok(handle) = builder
            .name(format!("carrick-control-conn-{id}"))
            .spawn(move || {
                // Declare the permit first so it drops last, after the
                // socket and request context, on return or unwinding. A
                // failed spawn also drops the captured permit and rolls
                // back admission without needing a handler to start.
                let _permit = permit;
                let mut connection = stream;
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
        // Draining cancellation sockets does not release admission. Each
        // handler retains its counted permit until it returns; joins hold
        // no slot-state lock needed by the handler's final release.
        let streams: Vec<UnixStream> = self
            .slots
            .state
            .lock()
            .streams
            .drain()
            .map(|(_, s)| s)
            .collect();
        for s in streams {
            let _ = s.shutdown(Shutdown::Both);
        }
        for h in self.handlers.drain(..) {
            let _ = h.join();
        }
    }

    #[cfg(test)]
    pub(super) fn live_handlers_count(&self) -> usize {
        self.slots.state.lock().live
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
) {
    while !thread_shutdown.load(Ordering::Acquire) {
        let Ok((stream, _)) = listener.accept() else {
            continue;
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
