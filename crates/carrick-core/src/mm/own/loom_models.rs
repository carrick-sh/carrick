//! loom model of the memory-ownership core's shell protocol (#3061): one lock
//! around every transition, backend calls run with the lock released, and
//! the results reported back through their tickets. Run with
//! `cargo test -p carrick-core --features loom --lib loom_models`.
//!
//! Every transition runs inside `Shell::with`, which checks the core's
//! invariants before it releases the lock, and a backend call can only run
//! between two `with` scopes, so the shell can't hold the lock across the
//! backend (the deadlock class of #3061's pre-review P0-4).
use super::explore::ExplorerVenue;
use super::*;
use loom::sync::{Arc, Mutex};
use loom::thread;

type Core = CarrierCore<ExplorerVenue, u8, u8>;

fn carrier() -> CarrierId {
    // SAFETY: each model run builds one core.
    unsafe { CarrierId::assume_unique(NonZeroU64::MIN) }
}

fn spec(ipa: u64, len: u64) -> MappingSpec<u8> {
    MappingSpec {
        extent: extent(ipa, len),
        host_addr: 0x1000,
        host: 1,
    }
}

struct Shell {
    core: Mutex<Core>,
}

impl Shell {
    fn with<T>(&self, transition: impl FnOnce(&mut Core) -> T) -> T {
        let mut core = self.core.lock().unwrap();
        let out = transition(&mut core);
        core.check_invariants().unwrap();
        out
    }

    /// The backend; it takes `&self`, not a lock guard, so it runs unlocked.
    fn backend(&self, _action: BackendAction) -> BackendResult {
        BackendResult::Done
    }
}

fn extent(ipa: u64, len: u64) -> GpaExtent {
    GpaExtent::new(ipa, len).unwrap()
}

/// A mapper and a destroyer race. The destroy is "not now" while the map is
/// in flight; whichever order wins, the map's result lands in its own
/// generation and no mapping survives the destroy.
#[test]
fn a_map_in_flight_and_a_destroy_settle_in_either_order() {
    loom::model(|| {
        let shell = Arc::new(Shell {
            core: Mutex::new({
                let mut core = Core::new(carrier());
                core.create().unwrap();
                core.commit_create().unwrap();
                core
            }),
        });
        let mapper = {
            let shell = Arc::clone(&shell);
            thread::spawn(move || {
                let Ok((ticket, action)) = shell.with(|core| core.begin_map(spec(0, 2))) else {
                    return false;
                };
                let result = shell.backend(action);
                shell.with(|core| core.finish_map(ticket, result).is_ok())
            })
        };
        let destroyer = {
            let shell = Arc::clone(&shell);
            thread::spawn(move || {
                loop {
                    match shell.with(|core| core.begin_destroy()) {
                        Ok((ticket, action)) => {
                            let result = shell.backend(action);
                            shell.with(|core| core.finish_destroy(ticket, result).unwrap());
                            break;
                        }
                        // "Not now": the map reports first. A real shell enrols on
                        // the ticket's release; the model yields to it.
                        Err(Refusal::InFlight) => thread::yield_now(),
                        Err(other) => panic!("destroy refused: {other:?}"),
                    }
                }
            })
        };
        let mapped = mapper.join().unwrap();
        destroyer.join().unwrap();
        let core = Arc::try_unwrap(shell)
            .ok()
            .unwrap()
            .core
            .into_inner()
            .unwrap();
        assert_eq!(core.generation().1, GenerationState::Gone);
        assert_eq!(core.mapping_count(), 0, "mapped first: {mapped}");
        assert!(core.teardown().is_ok());
    });
}

/// A pinner and a retirer race on one extent. The extent is released exactly
/// once, and never while the pin is out.
#[test]
fn a_pin_and_a_retire_release_the_extent_exactly_once() {
    loom::model(|| {
        let mut core = Core::new(carrier());
        core.create().unwrap();
        let (ticket, _) = core.begin_map(spec(0, 4)).unwrap();
        core.finish_map(ticket, BackendResult::Done).unwrap();
        core.commit_create().unwrap();
        let id = core.carve(extent(0, 1), 9).unwrap();
        let shell = Arc::new(Shell {
            core: Mutex::new(core),
        });
        let pinner = {
            let shell = Arc::clone(&shell);
            thread::spawn(move || {
                let Ok(pin) = shell.with(|core| core.pin(0, 1)) else {
                    return 0;
                };
                shell.with(|core| usize::from(core.unpin(pin).unwrap().is_some()))
            })
        };
        let retirer = {
            let shell = Arc::clone(&shell);
            thread::spawn(move || {
                shell.with(|core| match core.retire_extent(id).unwrap() {
                    Retire::Released(_) => 1,
                    Retire::Deferred => 0,
                })
            })
        };
        let releases = pinner.join().unwrap() + retirer.join().unwrap();
        assert_eq!(releases, 1, "the extent is released exactly once");
        let mut core = Arc::try_unwrap(shell)
            .ok()
            .unwrap()
            .core
            .into_inner()
            .unwrap();
        assert_eq!(core.extent_count(), 0);
        let (ticket, _) = core.begin_destroy().unwrap();
        core.finish_destroy(ticket, BackendResult::Done).unwrap();
        assert!(core.teardown().is_ok());
    });
}
