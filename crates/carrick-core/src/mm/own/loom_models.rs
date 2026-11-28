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

type GrantCore = CarrierCore<ExplorerVenue, u8, u8, u8>;

struct GrantShell {
    core: Mutex<GrantCore>,
}

impl GrantShell {
    fn with<T>(&self, transition: impl FnOnce(&mut GrantCore) -> T) -> T {
        let mut core = self.core.lock().unwrap();
        let out = transition(&mut core);
        core.check_invariants().unwrap();
        out
    }
}

/// PR 1a: a guest member holds the MM's editor while the shell supplies a
/// copy-on-write grant. The supply is "not now", changes nothing, and reruns
/// after the guest's release; it is supplied exactly once, and the editor
/// ends free.
#[test]
fn a_cow_supply_is_busy_once_then_supplied_after_the_guest_editor_releases() {
    loom::model(|| {
        let mm = MmKey::new(NonZeroU64::MIN);
        let mut core = GrantCore::new(carrier());
        assert!(core.guest_editor(mm, true));
        let shell = Arc::new(GrantShell {
            core: Mutex::new(core),
        });
        let guest = {
            let shell = Arc::clone(&shell);
            thread::spawn(move || shell.with(|core| assert!(core.guest_editor(mm, false))))
        };
        let supplier = {
            let shell = Arc::clone(&shell);
            thread::spawn(move || {
                let excluded = ExcludedMm::claimed(mm);
                let mut busy = 0;
                loop {
                    match shell.with(|core| core.supply_cow(&excluded, 0x1000)) {
                        Ok(CowSupply::Carved(_)) => panic!("the MM has no chunk yet"),
                        Ok(CowSupply::NeedsChunk(demand)) => {
                            // The chunk's backend map runs unlocked.
                            let chunk = extent(0x200_000, demand.chunk_len());
                            let ticket =
                                shell.with(|core| core.admit_chunk(demand, chunk).unwrap());
                            shell.with(|core| {
                                core.finish_supply_cow(ticket, Supplied::Published(7))
                                    .unwrap()
                            });
                            return busy;
                        }
                        // A real shell enrols on the editor's release and
                        // probes once; the model yields to the guest.
                        Err(MmRefusal::NotNow(NotNow::EditorRelease(key))) => {
                            assert_eq!(key, mm);
                            busy += 1;
                            thread::yield_now();
                        }
                        Err(other) => panic!("supply refused: {other:?}"),
                    }
                }
            })
        };
        guest.join().unwrap();
        let _busy = supplier.join().unwrap();
        let mut core = Arc::try_unwrap(shell)
            .ok()
            .unwrap()
            .core
            .into_inner()
            .unwrap();
        assert_eq!(core.editor(mm), Some(MmEditor::Free));
        assert_eq!(core.grant_count(), 1);
        assert_eq!(core.retire_all_mms().unwrap(), [7]);
        assert!(core.teardown().is_ok());
    });
}

/// PR 1b: the MM's last guest edit races its exit and two-phase release.
/// The exit is "not now" while the guest holds the editor and reruns after
/// its release; the release runs its I/O unlocked, a "not now" outcome
/// leaves the MM releasable, and the grant comes back exactly once.
#[test]
fn an_exit_waits_for_the_guest_editor_and_a_not_now_release_reruns() {
    loom::model(|| {
        let mm = MmKey::new(NonZeroU64::MIN);
        let mut core = GrantCore::new(carrier());
        let excluded = ExcludedMm::claimed(mm);
        let Ok(CowSupply::NeedsChunk(demand)) = core.supply_cow(&excluded, 0x1000) else {
            panic!("the MM has no chunk yet");
        };
        let chunk = extent(0x200_000, demand.chunk_len());
        let ticket = core.admit_chunk(demand, chunk).unwrap();
        core.finish_supply_cow(ticket, Supplied::Published(7))
            .unwrap();
        assert!(core.guest_editor(mm, true));
        let shell = Arc::new(GrantShell {
            core: Mutex::new(core),
        });
        let guest = {
            let shell = Arc::clone(&shell);
            thread::spawn(move || shell.with(|core| assert!(core.guest_editor(mm, false))))
        };
        let releaser = {
            let shell = Arc::clone(&shell);
            thread::spawn(move || {
                loop {
                    match shell.with(|core| core.exit_mm(mm)) {
                        Ok(()) => break,
                        // A real shell enrols on the editor's release and
                        // probes once; the model yields to the guest.
                        Err(MmRefusal::NotNow(NotNow::EditorRelease(key))) => {
                            assert_eq!(key, mm);
                            thread::yield_now();
                        }
                        Err(other) => panic!("exit refused: {other:?}"),
                    }
                }
                let mut returned = Vec::new();
                for outcome in [
                    ReleaseOutcome::NotNow(ReleaseWait::OwedReturns),
                    ReleaseOutcome::Done,
                ] {
                    let (ticket, grants) = shell.with(|core| core.begin_release(mm).unwrap());
                    returned.extend(grants);
                    // The shell's release I/O runs unlocked.
                    let verdict = shell.with(|core| core.finish_release(ticket, outcome).unwrap());
                    assert_eq!(verdict, outcome);
                }
                returned
            })
        };
        guest.join().unwrap();
        assert_eq!(releaser.join().unwrap(), [7], "the grant comes back once");
        let core = Arc::try_unwrap(shell)
            .ok()
            .unwrap()
            .core
            .into_inner()
            .unwrap();
        assert_eq!(core.mm_life(mm), None);
        assert_eq!(core.chunk_count(), 0);
        assert!(core.teardown().is_ok());
    });
}

/// #3105: two guest members hold prepared-commit shares of one MM while the
/// shell supplies a copy-on-write grant. The supply is "not now" for the
/// shares' drain, changes nothing, and is admitted only after the last share
/// is released (G5); the shares leave in either order and the editor ends
/// free with the grant supplied exactly once.
#[test]
fn a_cow_supply_waits_for_the_last_commit_share() {
    loom::model(|| {
        let mm = MmKey::new(NonZeroU64::MIN);
        let mut core = GrantCore::new(carrier());
        assert!(core.guest_commit(mm, true));
        assert!(core.guest_commit(mm, true));
        let shell = Arc::new(GrantShell {
            core: Mutex::new(core),
        });
        let members: Vec<_> = (0..2)
            .map(|_| {
                let shell = Arc::clone(&shell);
                thread::spawn(move || shell.with(|core| assert!(core.guest_commit(mm, false))))
            })
            .collect();
        let supplier = {
            let shell = Arc::clone(&shell);
            thread::spawn(move || {
                let excluded = ExcludedMm::claimed(mm);
                loop {
                    let supplied = shell.with(|core| {
                        let shares = core.editor(mm);
                        let answer = core.supply_cow(&excluded, 0x1000);
                        if answer.is_ok() {
                            // G5: admitted only once no share holds the MM.
                            assert_eq!(shares, Some(MmEditor::Free));
                        }
                        answer
                    });
                    match supplied {
                        Ok(CowSupply::Carved(_)) => panic!("the MM has no chunk yet"),
                        Ok(CowSupply::NeedsChunk(demand)) => {
                            let chunk = extent(0x200_000, demand.chunk_len());
                            let ticket =
                                shell.with(|core| core.admit_chunk(demand, chunk).unwrap());
                            shell.with(|core| {
                                core.finish_supply_cow(ticket, Supplied::Published(7))
                                    .unwrap()
                            });
                            return;
                        }
                        // A real shell enrols on the last share's release
                        // and probes once; the model yields to the members.
                        Err(MmRefusal::NotNow(NotNow::CommitsDrain(key))) => {
                            assert_eq!(key, mm);
                            thread::yield_now();
                        }
                        Err(other) => panic!("supply refused: {other:?}"),
                    }
                }
            })
        };
        for member in members {
            member.join().unwrap();
        }
        supplier.join().unwrap();
        let mut core = Arc::try_unwrap(shell)
            .ok()
            .unwrap()
            .core
            .into_inner()
            .unwrap();
        assert_eq!(core.editor(mm), Some(MmEditor::Free));
        assert_eq!(core.grant_count(), 1);
        assert_eq!(core.retire_all_mms().unwrap(), [7]);
        assert!(core.teardown().is_ok());
    });
}
