//! loom models of the two Dekker pairs (#681 slice 1a). Run with
//! `cargo test -p carrick-core --features loom --lib loom_models`.
use super::*;
use alloc::boxed::Box;
use carrick_guest_arch::{ContextGeneration, MmGeneration};
use core::num::NonZeroU64;

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
    flushes: core::cell::Cell<usize>,
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
        self.flushes.set(self.flushes.get() + 1);
        Ok(())
    }
    fn relax(&mut self) -> Result<(), ()> {
        loom::thread::yield_now();
        Ok(())
    }
}

type Table = ServedTable<2, LoomWord>;

/// Bound 3: each Dekker pair is broken by one preemption between a store
/// and its fence-separated load; the stop/enter ABA needs a second between
/// the stop and the enter, and a third lets the completer's reads land inside
/// either window. Removing any one protocol fence fails a model at this
/// bound (recorded in the commit); bound 4 adds no new interleaving class.
fn model(body: impl Fn() + Sync + Send + 'static) {
    let mut builder = loom::model::Builder::new();
    builder.preemption_bound = Some(3);
    builder.check(body);
}

/// A table that outlives every model thread, so seats can move into them.
fn leaked_table() -> &'static Table {
    Box::leak(Box::new(Table::with_domain(
        issue_domain_nonce().expect("fresh domain nonce"),
    )))
}

fn seat(table: &'static Table, member: u32) -> MemberSeat<&'static Table, 2, LoomWord> {
    MemberSeat::claim(table, CpuId::new(member), &mut LoomVenue::default())
        .map_err(|_| ())
        .expect("free seat")
}

fn commit(
    table: &'static Table,
    venue: &mut LoomVenue,
) -> PendingInvalidation<&'static Table, 2, LoomWord> {
    stage(table, context(0x1000, 1), InvalidationKind::Unmap)
        .commit(None, venue)
        .map_err(|_| ())
        .expect("commit")
}

/// The completion verdict is safe: if it completes, member 1 has served the
/// generation or is stopped with the debt recorded.
fn assert_verdict_safe(
    table: &'static Table,
    pending: PendingInvalidation<&'static Table, 2, LoomWord>,
) {
    let generation = pending.generation();
    let member = &table.members()[1];
    if pending.try_complete().is_ok() {
        let served = generation.served_by(member.served(InvalidationKind::Unmap));
        let durable = !member.is_running()
            && member
                .owed(InvalidationKind::Unmap)
                .is_some_and(|o| o.value() >= generation.value());
        assert!(served || durable, "completed while member 1 is stale");
    }
}

/// A member installing A concurrently with a request for A: the request
/// counts the member, or the member's install serves the generation.
#[test]
fn loom_models_install_races_request_serves_or_counts() {
    model(|| {
        let table = leaked_table();
        let mut member_seat = seat(table, 1);
        member_seat
            .install(context(0x2000, 2), &mut LoomVenue::default())
            .expect("install B");
        let member = loom::thread::spawn(move || {
            member_seat
                .install(context(0x1000, 1), &mut LoomVenue::default())
                .expect("install A");
            member_seat
        });
        let pending = commit(table, &mut LoomVenue::default());
        let counted = pending.counts(CpuId::new(1));
        let generation = pending.generation();
        let member_seat = member.join().expect("member");
        let served = table.members()[1].served(InvalidationKind::Unmap);
        assert!(
            counted || generation.served_by(served),
            "member neither counted nor served"
        );
        if counted {
            assert!(
                table.members()[1]
                    .owed(InvalidationKind::Unmap)
                    .is_some_and(|o| o.value() >= generation.value())
            );
        }
        assert_verdict_safe(table, pending);
        drop(member_seat);
    });
}

/// A stopped member entering concurrently with a request for its context:
/// the request kicks it (it was running), or it serves before executing.
#[test]
fn loom_models_entry_races_request_kicks_or_serves() {
    model(|| {
        let table = leaked_table();
        let mut member_seat = seat(table, 1);
        member_seat
            .install(context(0x1000, 1), &mut LoomVenue::default())
            .expect("install A");
        let member = loom::thread::spawn(move || {
            member_seat.enter(&mut LoomVenue::default()).expect("enter");
            // The first instruction after entry: served at that point.
            let served = table.members()[1].served(InvalidationKind::Unmap);
            (member_seat, served)
        });
        let mut venue = LoomVenue::default();
        let pending = commit(table, &mut venue);
        let generation = pending.generation();
        let kicked = venue.kicked.get();
        let (member_seat, served_at_entry) = member.join().expect("member");
        assert!(pending.counts(CpuId::new(1)));
        assert!(
            kicked || generation.served_by(served_at_entry),
            "member entered stale without a kick"
        );
        let completed = pending.try_complete().is_ok();
        assert!(
            !completed || generation.served_by(served_at_entry),
            "completed while the running member is stale"
        );
        drop(member_seat);
    });
}

/// Requester, member and completer on three threads. The member was running
/// in A and goes through a stop/enter ABA while the request is published;
/// the completer receives the request from the requester and decides with
/// no fence of its own. A completion is never granted while the member can
/// execute (after its enter) without having served the generation.
#[test]
fn loom_models_requester_member_completer_with_stop_enter_aba() {
    model(|| {
        let table = leaked_table();
        let mut member_seat = seat(table, 1);
        member_seat
            .install(context(0x1000, 1), &mut LoomVenue::default())
            .expect("install A");
        member_seat.enter(&mut LoomVenue::default()).expect("enter");
        let member = loom::thread::spawn(move || {
            member_seat.stop();
            member_seat.enter(&mut LoomVenue::default()).expect("enter");
            let served = table.members()[1].served(InvalidationKind::Unmap);
            (member_seat, served)
        });
        let requester = loom::thread::spawn(move || commit(table, &mut LoomVenue::default()));
        let pending = requester.join().expect("requester");
        let generation = pending.generation();
        let completed = pending.try_complete().is_ok();
        let (member_seat, served_after_enter) = member.join().expect("member");
        assert!(
            !completed || generation.served_by(served_after_enter),
            "completed, then the member executed stale after its enter"
        );
        drop(member_seat);
    });
}

/// Two concurrent requesters for the same context: both generations are
/// issued, both count the running member, and the member's owed debt
/// reflects both generations without either overwriting the other.
#[test]
fn loom_models_two_concurrent_requesters() {
    model(|| {
        let table = leaked_table();
        let mut member_seat = seat(table, 1);
        member_seat
            .install(context(0x1000, 1), &mut LoomVenue::default())
            .expect("install A");
        member_seat.enter(&mut LoomVenue::default()).expect("enter");

        let req1 = loom::thread::spawn(move || commit(table, &mut LoomVenue::default()));
        let req2 = loom::thread::spawn(move || commit(table, &mut LoomVenue::default()));

        let pending1 = req1.join().expect("req1");
        let pending2 = req2.join().expect("req2");

        let gen1 = pending1.generation();
        let gen2 = pending2.generation();

        assert_ne!(gen1, gen2, "distinct requests have distinct generations");
        assert!(pending1.counts(CpuId::new(1)));
        assert!(pending2.counts(CpuId::new(1)));

        let owed = table.members()[1].owed(InvalidationKind::Unmap);
        assert!(owed.is_some_and(|o| o.value() >= gen1.value() && o.value() >= gen2.value()));

        member_seat.serve(&mut LoomVenue::default()).expect("serve");
        let served = table.members()[1].served(InvalidationKind::Unmap);
        assert!(gen1.served_by(served));
        assert!(gen2.served_by(served));

        assert!(pending1.try_complete().is_ok());
        assert!(pending2.try_complete().is_ok());

        drop(member_seat);
    });
}

/// A member seat claim racing with a request: either the claim observes the
/// request and serves it via admission flush, or the request sees the member's
/// initial unclaimed/uninstalled state and the member's later install serves it.
#[test]
fn loom_models_claim_races_request() {
    model(|| {
        let table = leaked_table();
        let claim_thread = loom::thread::spawn(move || {
            let mut venue = LoomVenue::default();
            let seat = MemberSeat::claim(table, CpuId::new(1), &mut venue).expect("claim");
            (seat, venue)
        });
        let mut venue = LoomVenue::default();
        let pending = commit(table, &mut venue);
        let generation = pending.generation();
        let (mut seat, claim_venue) = claim_thread.join().expect("claim thread");
        let served = table.members()[1].served(InvalidationKind::Unmap);
        let served_by_claim = generation.served_by(served);

        if served_by_claim {
            assert!(claim_venue.flushes.get() >= INVALIDATION_KINDS);
        } else {
            // Claim completed its latest read before the request issued;
            // a subsequent install must owe and serve this generation.
            seat.install(context(0x1000, 1), &mut LoomVenue::default())
                .expect("install A");
            let served_after_install = table.members()[1].served(InvalidationKind::Unmap);
            assert!(generation.served_by(served_after_install));
        }

        assert_verdict_safe(table, pending);
        drop(seat);
    });
}

/// A member claiming its seat concurrently with a domain-wide request (the
/// seat Dekker pair): the request counts the member, or the claim's
/// admission flush covers the generation before the member can translate.
#[test]
fn loom_models_claim_races_domain_request_counts_or_flushes() {
    model(|| {
        let table = leaked_table();
        let member = loom::thread::spawn(move || seat(table, 1));
        let pending = stage_domain::<_, 2, LoomWord, Tag>(table, InvalidationKind::Unmap)
            .commit(None, &mut LoomVenue::default())
            .map_err(|_| ())
            .expect("commit");
        let counted = pending.counts(CpuId::new(1));
        let generation = pending.generation();
        let member_seat = member.join().expect("member");
        let served = table.members()[1].served(InvalidationKind::Unmap);
        assert!(
            counted || generation.served_by(served),
            "a claimed member was neither counted nor flushed"
        );
        assert_verdict_safe(table, pending);
        drop(member_seat);
    });
}
