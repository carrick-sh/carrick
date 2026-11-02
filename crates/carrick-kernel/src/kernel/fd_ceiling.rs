use std::sync::Arc;

use carrick_hal::FdCeilingPublisher;
use parking_lot::Mutex;

#[derive(Debug)]
struct State {
    maximum: u32,
    disabled: bool,
    publishers: Vec<Arc<dyn FdCeilingPublisher>>,
}

/// Kernel-owned authority for the carrier-wide monotonic descriptor ceiling.
#[derive(Debug)]
pub struct FdCeilingAuthority {
    state: Mutex<State>,
}

impl Default for FdCeilingAuthority {
    fn default() -> Self {
        Self::new()
    }
}

impl FdCeilingAuthority {
    pub fn new() -> Self {
        Self {
            state: Mutex::new(State {
                maximum: 2,
                disabled: false,
                publishers: Vec::new(),
            }),
        }
    }

    pub fn publish(&self, fd: i32) {
        let Ok(fd) = u32::try_from(fd) else {
            return;
        };
        let mut state = self.state.lock();
        if fd <= state.maximum {
            return;
        }
        state.maximum = fd;
        for publisher in &state.publishers {
            publisher.raise(fd);
        }
    }

    /// Whether every registered publisher's word now covers `fd`: the
    /// authority's running maximum is at least `fd` (it publishes before it
    /// records), or the fast reject is permanently disabled.
    pub fn covers(&self, fd: u32) -> bool {
        let state = self.state.lock();
        state.disabled || state.maximum >= fd
    }

    pub fn register(&self, publisher: Arc<dyn FdCeilingPublisher>) {
        let mut state = self.state.lock();
        if state
            .publishers
            .iter()
            .any(|current| Arc::ptr_eq(current, &publisher))
        {
            return;
        }
        if state.disabled {
            publisher.disable();
        }
        publisher.raise(state.maximum);
        state.publishers.push(publisher);
    }

    pub fn disable(&self) {
        let mut state = self.state.lock();
        if state.disabled {
            return;
        }
        state.disabled = true;
        for publisher in &state.publishers {
            publisher.disable();
        }
    }
}

/// The host venue's ceiling sink: a descriptor the shared authority installs
/// from the carrier (a native child's venue `openat`, a host-created pipe in a
/// ring-owned table) raises the same carrier word as a host FileTable install
/// (#1398).
impl carrick_el1_abi::DescriptorCeiling for FdCeilingAuthority {
    fn cover(&self, fd: u32) -> bool {
        let Ok(number) = i32::try_from(fd) else {
            return false;
        };
        self.publish(number);
        self.covers(fd)
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};

    use carrick_hal::FdCeilingPublisher;

    use super::FdCeilingAuthority;

    #[derive(Debug, Default)]
    struct RecordingPublisher {
        maximum: AtomicU32,
        disabled: AtomicBool,
        events: parking_lot::Mutex<Vec<&'static str>>,
    }

    impl FdCeilingPublisher for RecordingPublisher {
        fn raise(&self, maximum: u32) {
            self.events.lock().push("raise");
            self.maximum.fetch_max(maximum, Ordering::Release);
        }

        fn disable(&self) {
            self.events.lock().push("disable");
            self.disabled.store(true, Ordering::Release);
        }
    }

    #[test]
    fn repeated_registration_retains_one_publisher() {
        let authority = FdCeilingAuthority::new();
        let publisher = Arc::new(RecordingPublisher::default());
        for _ in 0..64 {
            authority.register(publisher.clone());
        }
        assert_eq!(Arc::strong_count(&publisher), 2);
        assert_eq!(&*publisher.events.lock(), &["raise"]);
        authority.publish(75);
        assert_eq!(&*publisher.events.lock(), &["raise", "raise"]);
    }

    #[test]
    fn registration_receives_existing_maximum() {
        let authority = FdCeilingAuthority::new();
        authority.publish(41);
        let publisher = Arc::new(RecordingPublisher::default());
        authority.register(publisher.clone());
        assert_eq!(publisher.maximum.load(Ordering::Acquire), 41);
    }

    #[test]
    fn disable_before_registration_is_permanent() {
        let authority = FdCeilingAuthority::new();
        authority.disable();
        let publisher = Arc::new(RecordingPublisher::default());
        authority.register(publisher.clone());
        assert!(publisher.disabled.load(Ordering::Acquire));
        assert_eq!(&*publisher.events.lock(), &["disable", "raise"]);
        authority.publish(91);
        assert!(publisher.disabled.load(Ordering::Acquire));
    }

    #[test]
    fn publication_is_monotonic_under_concurrency() {
        let authority = Arc::new(FdCeilingAuthority::new());
        let publisher = Arc::new(RecordingPublisher::default());
        authority.register(publisher.clone());
        let threads = (0..64)
            .map(|fd| {
                let authority = authority.clone();
                std::thread::spawn(move || authority.publish(fd))
            })
            .collect::<Vec<_>>();
        for thread in threads {
            thread.join().expect("publisher thread");
        }
        assert_eq!(publisher.maximum.load(Ordering::Acquire), 63);
    }

    #[test]
    fn concurrent_registration_and_publication_are_serialized() {
        for _ in 0..64 {
            let authority = Arc::new(FdCeilingAuthority::new());
            let publisher = Arc::new(RecordingPublisher::default());
            let start = Arc::new(std::sync::Barrier::new(3));
            let register = {
                let authority = authority.clone();
                let publisher = publisher.clone();
                let start = start.clone();
                std::thread::spawn(move || {
                    start.wait();
                    authority.register(publisher);
                })
            };
            let publish = {
                let authority = authority.clone();
                let start = start.clone();
                std::thread::spawn(move || {
                    start.wait();
                    authority.publish(73);
                })
            };
            start.wait();
            register.join().expect("register thread");
            publish.join().expect("publish thread");

            assert_eq!(publisher.maximum.load(Ordering::Acquire), 73);
            assert!(
                publisher
                    .events
                    .lock()
                    .iter()
                    .all(|event| *event == "raise")
            );
        }
    }
}
