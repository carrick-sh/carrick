//! Abstract model of connect's notification scope and FIN publication order.
//!
//! The mutex-owned listener queue and per-description epoll owner lists model
//! `InZoneAdmission::enqueue` and `FileDescription::epoll_owners`. A notification
//! models either the owner's wait-queue callback or its poll-fd wake; neither
//! may add a dispatch to an accepted socket on connection establishment. The
//! held-listener test binds this model to the real dispatch/multiplexer path.
//! This model does not cover fd reuse, wake coalescing, or the host reactor.

use loom::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use loom::sync::{Arc, Mutex};
use loom::{model::Builder, thread};

fn model(f: impl Fn() + Send + Sync + 'static) {
    let mut builder = Builder::new();
    builder.max_threads = 3;
    builder.max_branches = 1_000;
    builder.preemption_bound = Some(2);
    builder.check(f);
}

#[derive(Default)]
struct Socket {
    write_closed: AtomicBool,
    owners: Mutex<Vec<Arc<AtomicUsize>>>,
}

fn notify(owners: &Mutex<Vec<Arc<AtomicUsize>>>) {
    // Take the owner snapshot and release its guard before invoking callbacks,
    // just as notify_connect_epolls does through FileDescription::epoll_owners.
    let owners = owners.lock().unwrap().clone();
    for owner in owners {
        owner.fetch_add(1, Ordering::Release);
    }
}

fn connect_accept(cohort_broadcast: bool) {
    model(move || {
        let client = Arc::new(Socket::default());
        let server = Arc::new(Socket::default());
        let listener = Arc::new(Mutex::new(None));
        let client_wakes = Arc::new(AtomicUsize::new(0));
        let accepted_wakes = Arc::new(AtomicUsize::new(0));
        let cohort = Arc::new(Mutex::new(vec![client_wakes.clone()]));
        client.owners.lock().unwrap().push(client_wakes.clone());

        let connecting = {
            let client = client.clone();
            let server = server.clone();
            let listener = listener.clone();
            let cohort = cohort.clone();
            thread::spawn(move || {
                // State/queue publication precedes the listener wake. Accept
                // may now register an epoll before connect finishes notifying.
                *listener.lock().unwrap() = Some(server);
                if cohort_broadcast {
                    notify(&cohort);
                } else {
                    notify(&client.owners);
                }
            })
        };
        let accepting = {
            let accepted_wakes = accepted_wakes.clone();
            thread::spawn(move || {
                if let Some(server) = listener.lock().unwrap().take() {
                    assert!(!server.write_closed.load(Ordering::Acquire));
                    server.owners.lock().unwrap().push(accepted_wakes.clone());
                    cohort.lock().unwrap().push(accepted_wakes);
                    true
                } else {
                    false // accept has not yet received the listener publication
                }
            })
        };
        connecting.join().unwrap();
        let accepted = accepting.join().unwrap();
        assert_eq!(client_wakes.load(Ordering::Acquire), 1);
        assert_eq!(
            accepted_wakes.load(Ordering::Acquire),
            0,
            "connect must not dispatch an accepted RDHUP waiter"
        );
        if accepted {
            // With no intervening peer teardown, SHUT_WR publishes FIN and
            // only then notifies the exact server's owners. One real wake.
            server.write_closed.store(true, Ordering::Release);
            notify(&server.owners);
            assert_eq!(accepted_wakes.load(Ordering::Acquire), 1);
        }
    });
}

#[test]
fn connect_notification_racing_accept_stays_on_the_client_description() {
    connect_accept(false);
}

#[test]
#[should_panic(expected = "connect must not dispatch an accepted RDHUP waiter")]
fn cohort_broadcast_negative_control_reproduces_the_extra_dispatch() {
    connect_accept(true);
}

#[test]
fn fin_state_is_visible_before_the_waiter_receives_its_notification() {
    model(|| {
        let server = Arc::new(Socket::default());
        let wake = Arc::new(AtomicUsize::new(0));
        server.owners.lock().unwrap().push(wake.clone());
        let publisher = {
            let server = server.clone();
            thread::spawn(move || {
                server.write_closed.store(true, Ordering::Release);
                notify(&server.owners);
            })
        };
        let waiter = thread::spawn(move || {
            if wake.load(Ordering::Acquire) != 0 {
                assert!(server.write_closed.load(Ordering::Acquire));
            }
        });
        publisher.join().unwrap();
        waiter.join().unwrap();
    });
}
