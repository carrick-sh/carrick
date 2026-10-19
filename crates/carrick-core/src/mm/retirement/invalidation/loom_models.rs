//! loom models of the two Dekker pairs (#681 slice 1a). Run with
//! `cargo test -p carrick-core --features loom --lib loom_models`.
use super::*;
use carrick_guest_arch::{ContextGeneration, MmGeneration};
use core::num::NonZeroU64;
use loom::sync::Arc;

#[derive(Debug, Default)]
struct LoomWord(loom::sync::atomic::AtomicU64);

impl ServedWord for LoomWord {
    fn load(&self, order: Ordering) -> u64 {
        self.0.load(order)
    }
    fn store(&self, value: u64, order: Ordering) {
        self.0.store(value, order);
    }
    fn fetch_max(&self, value: u64, order: Ordering) -> u64 {
        self.0.fetch_max(value, order)
    }
    fn compare_exchange(
        &self,
        current: u64,
        new: u64,
        success: Ordering,
        failure: Ordering,
    ) -> Result<u64, u64> {
        self.0.compare_exchange(current, new, success, failure)
    }
    fn fetch_update<F: FnMut(u64) -> Option<u64>>(
        &self,
        set_order: Ordering,
        fetch_order: Ordering,
        f: F,
    ) -> Result<u64, u64> {
        self.0.fetch_update(set_order, fetch_order, f)
    }
    fn fence(order: Ordering) {
        loom::sync::atomic::fence(order);
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct Tag(u64);

impl ResidencyTag for Tag {
    fn residency_word(self) -> u64 {
        self.0
    }
}

fn context(root: u64, mm: u64) -> AddressContext<Tag> {
    let nz = |raw| NonZeroU64::new(raw).expect("nonzero test identity");
    AddressContext {
        root: Tag(root),
        mm: MmGeneration::new(nz(mm)),
        generation: ContextGeneration::new(nz(1)),
    }
}

#[derive(Default)]
struct LoomVenue {
    kicked: core::cell::Cell<bool>,
}

// SAFETY: loom threads cache no translations; served words are the model.
unsafe impl InvalidationVenue for LoomVenue {
    type Tag = Tag;
    type Error = ();
    const SCOPE: InvalidationScope = InvalidationScope::PerCpu;
    fn kick(&self, _cpu: CpuId) {
        self.kicked.set(true);
    }
    fn invalidate_local(
        &mut self,
        _kind: InvalidationKind,
        _scope: InvalidationScope,
    ) -> Result<(), ()> {
        Ok(())
    }
    fn relax(&mut self) -> Result<(), ()> {
        loom::thread::yield_now();
        Ok(())
    }
}

type Table = ServedTable<2, LoomWord>;

fn model(body: impl Fn() + Sync + Send + 'static) {
    let mut builder = loom::model::Builder::new();
    builder.preemption_bound = Some(3);
    builder.check(body);
}

/// A member installing A concurrently with a request for A: the request
/// counts the member, or the member's install serves the generation.
#[test]
fn loom_models_install_races_request_serves_or_counts() {
    model(|| {
        let table = Arc::new(Table::default());
        {
            let mut seat = MemberSeat::claim(&*table, CpuId::new(1)).expect("free seat");
            seat.install(context(0x2000, 2), &mut LoomVenue::default())
                .expect("install B");
        }
        let member_table = table.clone();
        let member = loom::thread::spawn(move || {
            let mut seat = MemberSeat::claim(&*member_table, CpuId::new(1)).expect("free seat");
            seat.install(context(0x1000, 1), &mut LoomVenue::default())
                .expect("install A");
        });
        let pending = stage(&*table, context(0x1000, 1), InvalidationKind::Unmap)
            .commit(None, &mut LoomVenue::default())
            .map_err(|_| ())
            .expect("commit");
        let counted = pending.counts(CpuId::new(1));
        let generation = pending.generation();
        member.join().expect("member");
        let served =
            table.members[1].served[InvalidationKind::Unmap.index()].load(Ordering::Acquire);
        assert!(
            counted || generation.served_by(served),
            "member neither counted nor served"
        );
        if counted {
            assert!(
                table.members[1].owed[InvalidationKind::Unmap.index()].load(Ordering::Acquire)
                    >= generation.get().get()
            );
        }
        let _ = pending.try_complete();
    });
}

/// A stopped member entering concurrently with a request for its context:
/// the request kicks it (it was running), or it serves before executing.
#[test]
fn loom_models_entry_races_request_kicks_or_serves() {
    model(|| {
        let table = Arc::new(Table::default());
        {
            let mut seat = MemberSeat::claim(&*table, CpuId::new(1)).expect("free seat");
            seat.install(context(0x1000, 1), &mut LoomVenue::default())
                .expect("install A");
        }
        let member_table = table.clone();
        let member = loom::thread::spawn(move || {
            let mut seat = MemberSeat::claim(&*member_table, CpuId::new(1)).expect("free seat");
            seat.enter(&mut LoomVenue::default()).expect("enter");
            // The first instruction after entry: record served at that point.
            member_table.members[1].served[InvalidationKind::Unmap.index()].load(Ordering::Relaxed)
        });
        let mut venue = LoomVenue::default();
        let pending = stage(&*table, context(0x1000, 1), InvalidationKind::Unmap)
            .commit(None, &mut venue)
            .map_err(|_| ())
            .expect("commit");
        let generation = pending.generation();
        let saw_running = venue.kicked.get();
        let served_at_entry = member.join().expect("member");
        assert!(pending.counts(CpuId::new(1)));
        assert!(
            saw_running || generation.served_by(served_at_entry),
            "member entered stale without a kick"
        );
        let _ = pending.try_complete();
    });
}
