use super::*;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc;

#[derive(Clone, Debug, Eq, PartialEq)]
enum Event {
    Map(u64),
    Unmap(u64),
    Destroy,
}

/// A recording backend (test double): every call lands in `events`, and
/// `fail_unmaps` / `fail_destroys` refuse the next calls.
#[derive(Default)]
struct Recorder {
    events: Mutex<Vec<Event>>,
    fail_unmaps: Mutex<usize>,
    fail_destroys: Mutex<usize>,
}

struct Backend(Arc<Recorder>);

impl Stage2Backend for Backend {
    unsafe fn map(
        &self,
        _host: *mut core::ffi::c_void,
        ipa: u64,
        _size: usize,
        _perms: MemPerms,
    ) -> Stage2Status {
        self.0.events.lock().push(Event::Map(ipa));
        Stage2Status::SUCCESS
    }

    unsafe fn unmap(&self, ipa: u64, _size: usize) -> Stage2Status {
        let mut fail = self.0.fail_unmaps.lock();
        if *fail > 0 {
            *fail -= 1;
            return Stage2Status::from_raw(0xfae9_4001);
        }
        self.0.events.lock().push(Event::Unmap(ipa));
        Stage2Status::SUCCESS
    }

    unsafe fn destroy(&self) -> Stage2Status {
        let mut fail = self.0.fail_destroys.lock();
        if *fail > 0 {
            *fail -= 1;
            return Stage2Status::from_raw(0xfae9_4001);
        }
        self.0.events.lock().push(Event::Destroy);
        Stage2Status::SUCCESS
    }
}

const PAGE: usize = 0x4000;

fn custody() -> (Arc<Stage2Custody<()>>, Arc<Recorder>) {
    let recorder = Arc::new(Recorder::default());
    (
        Arc::new(Stage2Custody::new(Box::new(Backend(recorder.clone())), ())),
        recorder,
    )
}

fn live(custody: &Stage2Custody<()>) -> CarrierVmGeneration {
    let generation = custody.begin_create().expect("begin_create");
    custody
        .commit_create_with(generation, |_| {})
        .expect("commit_create");
    generation
}

fn map(custody: &Stage2Custody<()>, generation: CarrierVmGeneration, ipa: u64) -> Stage2Mapping {
    let mut guard = custody.stage2_in(generation).expect("live stage 2");
    // SAFETY: the recorder touches no host memory.
    unsafe { guard.map(core::ptr::null_mut(), ipa, PAGE, MemPerms::ReadWrite) }.expect("map")
}

fn destroy(custody: &Stage2Custody<()>, generation: CarrierVmGeneration) -> Stage2Destroyed {
    custody.begin_destroy(generation).expect("begin_destroy");
    // SAFETY: no guest CPU in a unit test.
    let destroyed = unsafe { custody.destroy_stage2(generation, |_, _| {}) }.expect("destroy");
    custody.finish_destroy(generation).expect("finish_destroy");
    destroyed
}

/// Parks `custody`'s raw destroy at its named point with the lock held, and
/// returns (parked, release): `parked` fires once the destroy holds the lock.
fn park_raw_destroy(custody: &Stage2Custody<()>) -> (mpsc::Receiver<()>, mpsc::Sender<()>) {
    let (parked_tx, parked_rx) = mpsc::channel();
    let (release_tx, release_rx) = mpsc::channel::<()>();
    let release_rx = Arc::new(Mutex::new(release_rx));
    custody.set_hook(Some(Arc::new(move |point| {
        if let Stage2HookPoint::RawDestroyHoldingLock(_) = point {
            parked_tx.send(()).expect("test alive");
            release_rx.lock().recv().expect("released");
        }
    })));
    (parked_rx, release_tx)
}

struct DropFlag(Arc<AtomicBool>);

impl Drop for DropFlag {
    fn drop(&mut self) {
        self.0.store(true, Ordering::SeqCst);
    }
}

fn backing() -> (Stage2Backing, Arc<AtomicBool>) {
    let dropped = Arc::new(AtomicBool::new(false));
    (Box::new(DropFlag(dropped.clone())), dropped)
}

#[test]
fn a_mapping_carries_the_generation_of_the_guard_that_installed_it() {
    let (custody, _) = custody();
    let first = live(&custody);
    let mapping = map(&custody, first, 0x1000_0000);
    assert_eq!(mapping.generation(), first);
    // SAFETY: as above.
    unsafe { custody.unmap(mapping) }.expect("unmap");
    let _ = destroy(&custody, first);
    let second = live(&custody);
    assert!(second.0 > first.0, "generations only grow");
    assert_eq!(map(&custody, second, 0x1000_0000).generation(), second);
}

#[test]
fn an_unmap_after_its_generation_is_destroyed_never_reaches_the_successor() {
    let (custody, recorder) = custody();
    let first = live(&custody);
    let stale = map(&custody, first, 0x2000_0000);
    let also_stale = map(&custody, first, 0x2000_4000);
    let _ = destroy(&custody, first);
    let second = live(&custody);
    let _successor = map(&custody, second, 0x2000_0000);

    // SAFETY: as above.
    unsafe { custody.unmap(stale) }.expect("a gone mapping is consumed");
    let mut guard = custody.stage2_in(second).expect("successor live");
    // SAFETY: as above.
    unsafe { guard.unmap(also_stale) }.expect("a gone mapping is consumed");
    drop(guard);

    assert_eq!(
        *recorder.events.lock(),
        vec![
            Event::Map(0x2000_0000),
            Event::Map(0x2000_4000),
            Event::Destroy,
            Event::Map(0x2000_0000),
        ],
        "no unmap of the predecessor's extents may reach the successor VM"
    );
    assert_eq!(custody.stage2_in(first).err(), Some(Stage2Gone));
}

#[test]
fn an_unmap_racing_the_raw_destroy_learns_its_mapping_is_gone() {
    let (custody, recorder) = custody();
    let generation = live(&custody);
    let mapping = map(&custody, generation, 0x3000_0000);
    let (parked, release) = park_raw_destroy(&custody);

    let destroyer = {
        let custody = custody.clone();
        std::thread::spawn(move || destroy(&custody, generation))
    };
    parked.recv().expect("destroy parked holding the lock");
    // The destroy holds the custody lock now, so this unmapper can only see
    // the lifecycle after the raw destroy: its mapping is gone.
    let unmapper = {
        let custody = custody.clone();
        // SAFETY: as above.
        std::thread::spawn(move || unsafe { custody.unmap(mapping) })
    };
    release.send(()).expect("destroy alive");
    let _ = destroyer.join().expect("destroyer");
    unmapper
        .join()
        .expect("unmapper")
        .expect("gone mapping consumed");

    assert_eq!(
        *recorder.events.lock(),
        vec![Event::Map(0x3000_0000), Event::Destroy],
        "the unmap reached the backend beside or after the raw destroy"
    );
}

#[test]
fn a_creating_vm_destroyed_raw_admits_no_mapping_in_the_window() {
    let (custody, recorder) = custody();
    let generation = custody.begin_create().expect("begin_create");
    let (parked, release) = park_raw_destroy(&custody);
    let destroyer = {
        let custody = custody.clone();
        // SAFETY: as above.
        std::thread::spawn(move || unsafe { custody.destroy_stage2(generation, |_, _| {}) })
    };
    parked.recv().expect("destroy parked holding the lock");
    let mapper = {
        let custody = custody.clone();
        std::thread::spawn(move || match custody.stage2_in(generation) {
            Err(Stage2Gone) => None,
            Ok(mut guard) => {
                // SAFETY: as above.
                Some(unsafe {
                    guard.map(
                        core::ptr::null_mut(),
                        0x4000_0000,
                        PAGE,
                        MemPerms::ReadWrite,
                    )
                })
            }
        })
    };
    release.send(()).expect("destroy alive");
    let _ = destroyer.join().expect("destroyer").expect("raw destroy");
    assert!(
        mapper.join().expect("mapper").is_none(),
        "a mapping was admitted for a Creating VM after its raw destroy"
    );
    assert_eq!(custody.lifecycle(), Stage2Lifecycle::Gone(generation));
    custody.finish_destroy(generation).expect("finish");
    assert_eq!(custody.lifecycle(), Stage2Lifecycle::Vacant);
    assert_eq!(*recorder.events.lock(), vec![Event::Destroy]);
}

#[test]
fn destroying_refuses_new_mappings_but_unmaps_still_reach_its_stage2() {
    let (custody, recorder) = custody();
    let generation = live(&custody);
    let mapping = map(&custody, generation, 0x5000_0000);
    custody.begin_destroy(generation).expect("begin_destroy");
    let mut guard = custody.stage2_in(generation).expect("stage 2 still exists");
    assert!(!guard.admits_mappings());
    // SAFETY: as above.
    let refused = unsafe {
        guard.map(
            core::ptr::null_mut(),
            0x5000_4000,
            PAGE,
            MemPerms::ReadWrite,
        )
    };
    assert_eq!(refused, Err(Stage2Status::NO_LIVE_VM));
    // SAFETY: as above.
    unsafe { guard.unmap(mapping) }.expect("unmap in Destroying");
    drop(guard);
    assert_eq!(
        *recorder.events.lock(),
        vec![Event::Map(0x5000_0000), Event::Unmap(0x5000_0000)]
    );
}

#[test]
fn an_unretired_mapping_keeps_its_backing_until_a_retry_unmaps_it() {
    let (custody, recorder) = custody();
    let generation = live(&custody);
    let mapping = map(&custody, generation, 0x6000_0000);
    *recorder.fail_unmaps.lock() = 1;
    let (keeper, dropped) = backing();
    {
        let mut guard = custody.stage2_in(generation).expect("live");
        // SAFETY: as above.
        let (mapping, _) = unsafe { guard.unmap(mapping) }.expect_err("first unmap refused");
        assert!(guard.keep_unretired(mapping, keeper).is_none());
        assert_eq!(guard.unretired_count(), 1);
    }
    assert!(
        !dropped.load(Ordering::SeqCst),
        "backing freed while still mapped"
    );
    let released = custody
        .stage2_in(generation)
        .expect("live")
        .retry_unretired();
    assert_eq!(released.len(), 1);
    assert!(!dropped.load(Ordering::SeqCst));
    drop(released);
    assert!(dropped.load(Ordering::SeqCst));
    assert_eq!(custody.lock().unretired_count(), 0);
    assert_eq!(
        *recorder.events.lock(),
        vec![Event::Map(0x6000_0000), Event::Unmap(0x6000_0000)]
    );
}

#[test]
fn the_raw_destroy_drains_its_generations_unretired_backings() {
    let (custody, recorder) = custody();
    let generation = live(&custody);
    let mapping = map(&custody, generation, 0x7000_0000);
    *recorder.fail_unmaps.lock() = 1;
    let (keeper, dropped) = backing();
    {
        let mut guard = custody.stage2_in(generation).expect("live");
        // SAFETY: as above.
        let (mapping, _) = unsafe { guard.unmap(mapping) }.expect_err("unmap refused");
        assert!(guard.keep_unretired(mapping, keeper).is_none());
    }
    let destroyed = destroy(&custody, generation);
    assert_eq!(destroyed.generation, generation);
    assert_eq!(destroyed.released_backings.len(), 1);
    assert!(!dropped.load(Ordering::SeqCst));
    drop(destroyed);
    assert!(dropped.load(Ordering::SeqCst));
    assert_eq!(custody.lock().unretired_count(), 0);
}

#[test]
fn a_late_unretired_handoff_after_its_destroy_returns_the_backing() {
    let (custody, _) = custody();
    let first = live(&custody);
    let mapping = map(&custody, first, 0x7800_0000);
    let _ = destroy(&custody, first);
    let second = live(&custody);
    let (keeper, dropped) = backing();
    let mut guard = custody.stage2_in(second).expect("successor live");
    let returned = guard.keep_unretired(mapping, keeper);
    assert_eq!(
        guard.unretired_count(),
        0,
        "a gone mapping joined the successor's list"
    );
    drop(guard);
    drop(returned.expect("backing handed back"));
    assert!(dropped.load(Ordering::SeqCst));
}

#[test]
fn a_refused_raw_destroy_keeps_the_exact_lifecycle() {
    let (custody, recorder) = custody();
    let generation = live(&custody);
    let mapping = map(&custody, generation, 0x8000_0000);
    custody.begin_destroy(generation).expect("begin_destroy");
    *recorder.fail_destroys.lock() = 1;
    // SAFETY: as above.
    let refused = unsafe { custody.destroy_stage2(generation, |_, _| panic!("settled")) };
    assert!(matches!(refused, Err(Stage2CustodyError::Backend(_))));
    assert_eq!(custody.lifecycle(), Stage2Lifecycle::Destroying(generation));
    // SAFETY: as above.
    unsafe { custody.unmap(mapping) }.expect("its stage 2 still exists");
    assert_eq!(
        *recorder.events.lock(),
        vec![Event::Map(0x8000_0000), Event::Unmap(0x8000_0000)]
    );
}

#[test]
fn no_successor_is_created_before_the_destroy_finishes() {
    let (custody, _) = custody();
    let generation = live(&custody);
    custody.begin_destroy(generation).expect("begin_destroy");
    // SAFETY: as above.
    let _ = unsafe { custody.destroy_stage2(generation, |_, _| {}) }.expect("destroy");
    assert_eq!(
        custody.begin_create(),
        Err(Stage2CustodyError::LifecycleConflict)
    );
    custody.finish_destroy(generation).expect("finish");
    assert!(custody.begin_create().is_ok());
}

/// The confirmed deadlock of #2968's fix round 4: a pool constructor held its
/// own mutex and then took the custody lock, while `commit_destroy` held the
/// custody lock and then took the pool mutex. With the pool mutex a
/// `Stage2Inner`, the inverted acquisition panics at once.
#[test]
fn taking_the_custody_lock_under_a_stage2_inner_lock_panics() {
    let (custody, _) = custody();
    let pool = Stage2Inner::new(0u32);
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _pool = pool.lock();
        let _ = custody.lifecycle();
    }));
    let message = result.expect_err("inverted lock order accepted");
    let message = message
        .downcast_ref::<String>()
        .map(String::as_str)
        .unwrap_or_default();
    assert!(message.contains("stage-2 lock order"), "{message}");
    // The right order is fine, and the held count unwound with the panic.
    let generation = live(&custody);
    let guard = custody.stage2_in(generation).expect("live");
    let pool_guard = pool.lock();
    drop(pool_guard);
    drop(guard);
    let _ = custody.lifecycle();
}

/// A callback run under a generation guard that takes the same custody's
/// lock again would wait on its own thread forever (the shape the Mac found
/// in a record retirement's unmap callback). The custody turns that
/// re-entry into a panic at the acquisition, so it fails the test that
/// reaches it instead of hanging it.
#[test]
fn reentering_a_custody_from_under_its_own_guard_panics_instead_of_hanging() {
    let (custody, _) = custody();
    let generation = live(&custody);
    let reentry = std::thread::spawn({
        let custody = custody.clone();
        move || {
            let _guard = custody.stage2_in(generation).expect("live stage 2");
            let _ = custody.lifecycle();
        }
    })
    .join();
    let message = reentry
        .expect_err("a re-entry must panic")
        .downcast::<String>()
        .map(|message| *message)
        .unwrap_or_default();
    assert!(
        message.contains("stage-2 custody re-entry"),
        "unexpected panic: {message}"
    );
    // The panicking thread's guard dropped while unwinding: another thread,
    // and a fresh lock on this one, both take the lock normally.
    assert_eq!(custody.lifecycle(), Stage2Lifecycle::Live(generation));
    // A second custody's lock is not a re-entry of the first.
    let (other, _) = self::custody();
    let _guard = custody.lock();
    assert_eq!(other.lifecycle(), Stage2Lifecycle::Vacant);
}
