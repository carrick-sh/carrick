//! VM-free witnesses for the invalidation domain (#681 slice 1a).
use super::*;
use alloc::vec::Vec;
use carrick_guest_arch::{ContextGeneration, MmGeneration};
use core::cell::Cell;
use core::num::NonZeroU64;
use core::sync::atomic::AtomicBool;
use std::time::{Duration, Instant};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct Tag(u64);

impl ResidencyTag for Tag {
    fn residency_word(self) -> u64 {
        self.0
    }
}

fn nz(raw: u64) -> NonZeroU64 {
    NonZeroU64::new(raw).expect("test identities are nonzero")
}

fn context(root: u64, mm: u64) -> AddressContext<Tag> {
    AddressContext {
        root: Tag(root),
        mm: MmGeneration::new(nz(mm)),
        generation: ContextGeneration::new(nz(1)),
    }
}

const A: (u64, u64) = (0x1000, 1);
const B: (u64, u64) = (0x2000, 2);

fn ctx(key: (u64, u64)) -> AddressContext<Tag> {
    context(key.0, key.1)
}

#[derive(Debug, Eq, PartialEq)]
enum VenueError {
    TimedOut,
}

/// A host-thread venue: counts local invalidations, records kicks, and
/// bounds every wait at five seconds.
struct RecordingVenue {
    invalidations: usize,
    kicked: Cell<u64>,
    deadline: Instant,
}

impl RecordingVenue {
    fn new() -> Self {
        Self {
            invalidations: 0,
            kicked: Cell::new(0),
            deadline: Instant::now() + Duration::from_secs(5),
        }
    }
    fn kicked(&self, cpu: u32) -> bool {
        self.kicked.get() & (1 << cpu) != 0
    }
}

// SAFETY: host threads cache no translations; `invalidate_local` records the
// obligation and is complete on return for this model.
unsafe impl InvalidationVenue for RecordingVenue {
    type Tag = Tag;
    type Error = VenueError;
    const SCOPE: InvalidationScope = InvalidationScope::PerCpu;
    fn kick(&self, cpu: CpuId) {
        self.kicked.set(self.kicked.get() | (1 << cpu.raw()));
    }
    fn invalidate_local(
        &mut self,
        _kind: InvalidationKind,
        _scope: InvalidationScope,
    ) -> Result<(), VenueError> {
        self.invalidations += 1;
        Ok(())
    }
    fn relax(&mut self) -> Result<(), VenueError> {
        if Instant::now() > self.deadline {
            return Err(VenueError::TimedOut);
        }
        std::thread::yield_now();
        Ok(())
    }
}

fn cpu(raw: u32) -> CpuId {
    CpuId::new(raw)
}

fn served(table: &ServedTable<3>, member: usize, kind: InvalidationKind) -> u64 {
    table.members[member].served[kind.index()].load(Ordering::Acquire)
}

fn owed(table: &ServedTable<3>, member: usize, kind: InvalidationKind) -> u64 {
    table.members[member].owed[kind.index()].load(Ordering::Acquire)
}

// ---------------------------------------------------------------------------
// Witness 1: the stopped-member overwrite (#692), red against a model of the
// current x86 per-sender request cell, green on the domain.
// ---------------------------------------------------------------------------

/// The steps every protocol is driven through. Member 1 is the stopped
/// member; member 0 is the requester (no context of its own).
trait StoppedMemberProtocol {
    type Request: Copy;
    fn install_and_stop(&mut self, context: AddressContext<Tag>);
    fn request(&mut self, context: AddressContext<Tag>) -> Self::Request;
    fn reenter(&mut self);
    fn member_served(&self, request: Self::Request) -> bool;
}

/// Member stopped in A; the requester publishes for A, then for B from the
/// same sender; the member re-enters A. Returns whether it re-entered stale.
fn stopped_member_reenters_stale<P: StoppedMemberProtocol>(protocol: &mut P) -> bool {
    protocol.install_and_stop(ctx(A));
    let for_a = protocol.request(ctx(A));
    let _for_b = protocol.request(ctx(B));
    protocol.reenter();
    !protocol.member_served(for_a)
}

/// Faithful model of `carrick_x86::cpl0_entry::ShootdownRequest` (one cell
/// per sender: root, mm_key, owner_generation, generation) and
/// `carrick_el1::isa::x86::interrupt::service_shootdowns`, which reloads CR3
/// only when the sender's cell names the member's live context and carries a
/// generation newer than `last_seen_generation`.
#[derive(Default)]
struct PerSenderCellModel {
    next_generation: u64,
    cell_key: (u64, u64, u64),
    cell_generation: u64,
    live: (u64, u64, u64),
    last_seen_generation: u64,
}

fn cell_key(context: AddressContext<Tag>) -> (u64, u64, u64) {
    (
        context.root.0,
        context.mm.raw().get(),
        context.generation.raw().get(),
    )
}

impl StoppedMemberProtocol for PerSenderCellModel {
    type Request = u64;
    fn install_and_stop(&mut self, context: AddressContext<Tag>) {
        self.live = cell_key(context);
    }
    fn request(&mut self, context: AddressContext<Tag>) -> u64 {
        // The member is stopped: the sender publishes into its own cell and
        // cannot wait for a guest-confirmed drain.
        self.next_generation += 1;
        self.cell_key = cell_key(context);
        self.cell_generation = self.next_generation;
        self.next_generation
    }
    fn reenter(&mut self) {
        if self.cell_generation > self.last_seen_generation && self.cell_key == self.live {
            self.last_seen_generation = self.cell_generation;
        }
    }
    fn member_served(&self, request: u64) -> bool {
        self.last_seen_generation >= request
    }
}

struct DomainModel {
    table: ServedTable<3>,
    member: RecordingVenue,
    requester: RecordingVenue,
}

impl StoppedMemberProtocol for DomainModel {
    type Request = InvalidationGeneration;
    fn install_and_stop(&mut self, context: AddressContext<Tag>) {
        let mut seat = MemberSeat::claim(&self.table, cpu(1)).expect("free seat");
        seat.install(context, &mut self.member).expect("install");
        seat.stop();
    }
    fn request(&mut self, context: AddressContext<Tag>) -> InvalidationGeneration {
        let mut seat = MemberSeat::claim(&self.table, cpu(0)).expect("free seat");
        let pending = stage(&self.table, context, InvalidationKind::Unmap)
            .commit(Some(&mut seat), &mut self.requester)
            .expect("commit");
        let generation = pending.generation();
        // A stopped member does not block completion: its debt is durable.
        let _proof = pending.try_complete().expect("stopped debt completes");
        generation
    }
    fn reenter(&mut self) {
        let mut seat = MemberSeat::claim(&self.table, cpu(1)).expect("free seat");
        seat.enter(&mut self.member).expect("enter");
    }
    fn member_served(&self, request: InvalidationGeneration) -> bool {
        request.served_by(served(&self.table, 1, InvalidationKind::Unmap))
    }
}

#[test]
fn per_sender_cell_model_loses_stopped_member_debt_692() {
    // Red: today's cell protocol lets the B request overwrite the A debt.
    assert!(stopped_member_reenters_stale(
        &mut PerSenderCellModel::default()
    ));
}

#[test]
fn domain_keeps_stopped_member_debt_across_later_requests() {
    let mut domain = DomainModel {
        table: ServedTable::new(),
        member: RecordingVenue::new(),
        requester: RecordingVenue::new(),
    };
    assert!(!stopped_member_reenters_stale(&mut domain));
    assert_eq!(domain.member.invalidations, 1);
    assert!(
        !domain.requester.kicked(1),
        "a stopped member is never kicked"
    );
}

// ---------------------------------------------------------------------------
// Witness 2: exhaustion pins at MAX and keeps refusing, through the protocol.
// ---------------------------------------------------------------------------

/// Every word of this table starts one below MAX.
#[derive(Debug)]
struct NearMax(AtomicU64);

impl Default for NearMax {
    fn default() -> Self {
        Self(AtomicU64::new(u64::MAX - 1))
    }
}

impl ServedWord for NearMax {
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
        core::sync::atomic::fence(order);
    }
}

#[test]
fn exhausted_counter_pins_at_max_and_commit_refuses_without_publishing() {
    let counter = GenerationCounter::<NearMax>::default();
    assert_eq!(counter.issue().map(|g| g.get().get()), Ok(u64::MAX));
    assert_eq!(counter.issue(), Err(GenerationExhausted));
    assert_eq!(counter.latest(Ordering::Relaxed), u64::MAX);

    let table = ServedTable::<1, NearMax>::default();
    let mut venue = RecordingVenue::new();
    let last = stage(&table, ctx(A), InvalidationKind::Unmap)
        .commit(None, &mut venue)
        .map_err(|_| ())
        .expect("the last generation is issuable");
    assert_eq!(last.generation().get().get(), u64::MAX);
    let _ = last.try_complete();
    let owed_before = table.members[0].owed[0].load(Ordering::Relaxed);
    for _ in 0..3 {
        assert!(matches!(
            stage(&table, ctx(A), InvalidationKind::Unmap).commit(None, &mut venue),
            Err(CommitError::Exhausted)
        ));
        assert_eq!(table.issue.counter.latest(Ordering::Relaxed), u64::MAX);
        assert_eq!(
            table.members[0].owed[0].load(Ordering::Relaxed),
            owed_before
        );
    }
}

// ---------------------------------------------------------------------------
// Witness 4: two live threads. A running member must serve before the
// request completes; a stopped member's debt persists until re-entry.
// ---------------------------------------------------------------------------

#[test]
fn running_member_serves_before_completion_and_stopped_debt_survives() {
    let table = ServedTable::<3>::new();
    let ready = AtomicBool::new(false);
    let go = AtomicBool::new(false);
    let done = AtomicBool::new(false);
    std::thread::scope(|scope| {
        let member = scope.spawn(|| {
            let mut venue = RecordingVenue::new();
            let mut seat = MemberSeat::claim(&table, cpu(1)).expect("free seat");
            seat.install(ctx(A), &mut venue).expect("install");
            seat.enter(&mut venue).expect("enter");
            ready.store(true, Ordering::Release);
            // Running, but not at a safe point until released.
            while !go.load(Ordering::Acquire) {
                assert!(Instant::now() < venue.deadline, "go never arrived");
                std::thread::yield_now();
            }
            while !done.load(Ordering::Acquire) {
                seat.serve(&mut venue).expect("serve");
                assert!(Instant::now() < venue.deadline, "done never arrived");
                std::thread::yield_now();
            }
            seat.stop();
            venue.invalidations
        });
        while !ready.load(Ordering::Acquire) {
            std::thread::yield_now();
        }

        let mut stopped_venue = RecordingVenue::new();
        let mut stopped = MemberSeat::claim(&table, cpu(2)).expect("free seat");
        stopped
            .install(ctx(A), &mut stopped_venue)
            .expect("install");
        stopped.stop();

        let mut venue = RecordingVenue::new();
        let mut requester = MemberSeat::claim(&table, cpu(0)).expect("free seat");
        let pending = stage(&table, ctx(A), InvalidationKind::Unmap)
            .commit(Some(&mut requester), &mut venue)
            .map_err(|_| ())
            .expect("commit");
        let generation = pending.generation();
        assert!(pending.counts(cpu(1)) && pending.counts(cpu(2)));
        assert!(!pending.counts(cpu(0)), "the requester has no context");
        assert!(venue.kicked(1), "the running member is kicked");
        assert!(!venue.kicked(2), "the stopped member is not kicked");

        let pending = pending
            .try_complete()
            .expect_err("the running member has not served");
        assert!(!generation.served_by(served(&table, 1, InvalidationKind::Unmap)));

        go.store(true, Ordering::Release);
        let completion = pending
            .wait(Some(&mut requester), &mut venue)
            .map_err(|(_, error)| error)
            .expect("the running member serves");
        assert_eq!(completion.generation(), generation);
        assert!(generation.served_by(served(&table, 1, InvalidationKind::Unmap)));

        // The stopped member still owes the generation and serves on entry.
        assert!(owed(&table, 2, InvalidationKind::Unmap) >= generation.get().get());
        assert!(!generation.served_by(served(&table, 2, InvalidationKind::Unmap)));
        assert!(stopped.has_debt());
        assert_eq!(stopped_venue.invalidations, 0);
        stopped.enter(&mut stopped_venue).expect("enter");
        assert!(generation.served_by(served(&table, 2, InvalidationKind::Unmap)));
        assert!(!stopped.has_debt());
        assert_eq!(stopped_venue.invalidations, 1);

        done.store(true, Ordering::Release);
        assert_eq!(member.join().expect("member thread"), 1);
    });
}

// ---------------------------------------------------------------------------
// Witness 5: the steady-state check is own-line loads with zero RMWs.
// ---------------------------------------------------------------------------

#[derive(Debug, Default)]
struct CountingWord {
    value: AtomicU64,
    loads: AtomicU64,
    stores: AtomicU64,
    rmws: AtomicU64,
}

impl ServedWord for CountingWord {
    fn load(&self, order: Ordering) -> u64 {
        self.loads.fetch_add(1, Ordering::Relaxed);
        self.value.load(order)
    }
    fn store(&self, value: u64, order: Ordering) {
        self.stores.fetch_add(1, Ordering::Relaxed);
        self.value.store(value, order);
    }
    fn fetch_max(&self, value: u64, order: Ordering) -> u64 {
        self.rmws.fetch_add(1, Ordering::Relaxed);
        self.value.fetch_max(value, order)
    }
    fn compare_exchange(
        &self,
        current: u64,
        new: u64,
        success: Ordering,
        failure: Ordering,
    ) -> Result<u64, u64> {
        self.rmws.fetch_add(1, Ordering::Relaxed);
        self.value.compare_exchange(current, new, success, failure)
    }
    fn fetch_update<F: FnMut(u64) -> Option<u64>>(
        &self,
        set_order: Ordering,
        fetch_order: Ordering,
        f: F,
    ) -> Result<u64, u64> {
        self.rmws.fetch_add(1, Ordering::Relaxed);
        self.value.fetch_update(set_order, fetch_order, f)
    }
    fn fence(order: Ordering) {
        core::sync::atomic::fence(order);
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
struct Work {
    loads: u64,
    stores: u64,
    rmws: u64,
}

fn add(work: &mut Work, word: &CountingWord) {
    work.loads += word.loads.load(Ordering::Relaxed);
    work.stores += word.stores.load(Ordering::Relaxed);
    work.rmws += word.rmws.load(Ordering::Relaxed);
}

fn steady_line(member: &ResidencyMember<CountingWord>) -> Work {
    let mut work = Work::default();
    member
        .owed
        .iter()
        .chain(member.served.iter())
        .for_each(|word| add(&mut work, word));
    work
}

/// Every member word. The issue counter's word is private to the ABI crate;
/// an RMW on it always advances it, so the test checks its value instead.
fn all_members(table: &ServedTable<2, CountingWord>) -> Work {
    let mut work = Work::default();
    for member in &table.members {
        for word in member.owed.iter().chain(member.served.iter()).chain([
            &member.running,
            &member.revision,
            &member.tag,
            &member.mm,
            &member.context,
            &member.seat,
        ]) {
            add(&mut work, word);
        }
    }
    work
}

#[test]
fn steady_state_check_is_own_line_loads_with_zero_rmws() {
    let table = ServedTable::<2, CountingWord>::default();
    let mut venue = RecordingVenue::new();
    let mut seat = MemberSeat::claim(&table, cpu(0)).expect("free seat");
    seat.install(ctx(A), &mut venue).expect("install");
    seat.enter(&mut venue).expect("enter");
    let pending = stage(&table, ctx(A), InvalidationKind::RevokeWrite)
        .commit(None, &mut venue)
        .map_err(|_| ())
        .expect("commit");
    seat.serve(&mut venue).expect("serve the debt");
    let _proof = pending.try_complete().expect("served");
    assert!(!seat.has_debt());

    let counter_before = table.issue.counter.latest(Ordering::Relaxed);
    let own_before = steady_line(&table.members[0]);
    let table_before = all_members(&table);
    const ROUNDS: u64 = 1000;
    for _ in 0..ROUNDS {
        assert!(!seat.has_debt());
        seat.serve(&mut venue).expect("no debt");
    }
    let own = steady_line(&table.members[0]);
    let all = all_members(&table);
    assert_eq!(
        table.issue.counter.latest(Ordering::Relaxed),
        counter_before
    );
    // Exactly owed[2] + served[2] per check, twice per round, nothing else.
    assert_eq!(own.loads - own_before.loads, ROUNDS * 2 * 4);
    assert_eq!(all.loads - table_before.loads, ROUNDS * 2 * 4);
    assert_eq!(all.stores, table_before.stores);
    assert_eq!(all.rmws, table_before.rmws);
    assert_eq!(venue.invalidations, 1);
}

// ---------------------------------------------------------------------------
// Protocol edges.
// ---------------------------------------------------------------------------

#[test]
fn requester_serves_itself_inline() {
    let table = ServedTable::<3>::new();
    let mut venue = RecordingVenue::new();
    let mut seat = MemberSeat::claim(&table, cpu(0)).expect("free seat");
    seat.install(ctx(A), &mut venue).expect("install");
    seat.enter(&mut venue).expect("enter");
    let pending = stage(&table, ctx(A), InvalidationKind::Unmap)
        .commit(Some(&mut seat), &mut venue)
        .map_err(|_| ())
        .expect("commit");
    assert!(pending.counts(cpu(0)));
    assert!(!venue.kicked(0), "the requester never kicks itself");
    assert_eq!(venue.invalidations, 1);
    let completion = pending.try_complete().expect("served inline");
    assert_eq!(completion.kind(), InvalidationKind::Unmap);
}

#[test]
fn staging_has_no_effect_until_commit() {
    let table = ServedTable::<3>::new();
    let mut venue = RecordingVenue::new();
    let mut seat = MemberSeat::claim(&table, cpu(1)).expect("free seat");
    seat.install(ctx(A), &mut venue).expect("install");
    stage(&table, ctx(A), InvalidationKind::Unmap).rollback();
    drop(stage(&table, ctx(A), InvalidationKind::RevokeWrite));
    assert_eq!(table.issue.counter.latest(Ordering::Relaxed), 0);
    assert!(table.members.iter().all(|member| {
        member
            .owed
            .iter()
            .all(|word| word.load(Ordering::Relaxed) == 0)
    }));
    assert!(!seat.has_debt());
}

#[test]
fn install_serves_generations_issued_before_its_publication() {
    // A member skipped because it was in B when the request for A was
    // issued must not reach A with translations older than that request.
    let table = ServedTable::<3>::new();
    let mut venue = RecordingVenue::new();
    let mut seat = MemberSeat::claim(&table, cpu(1)).expect("free seat");
    seat.install(ctx(B), &mut venue).expect("install");
    let pending = stage(&table, ctx(A), InvalidationKind::Unmap)
        .commit(None, &mut venue)
        .map_err(|_| ())
        .expect("commit");
    assert!(!pending.counts(cpu(1)));
    let generation = pending.generation();
    let _proof = pending.try_complete().expect("no member counted");
    seat.install(ctx(A), &mut venue).expect("install");
    assert!(generation.served_by(served(&table, 1, InvalidationKind::Unmap)));
    assert!(generation.served_by(served(&table, 1, InvalidationKind::RevokeWrite)));
}

#[test]
fn seats_are_exclusive_and_bounded() {
    let table = ServedTable::<3>::new();
    let seat = MemberSeat::claim(&table, cpu(1)).expect("free seat");
    assert!(matches!(
        MemberSeat::claim(&table, cpu(1)),
        Err(SeatError::Claimed)
    ));
    assert!(matches!(
        MemberSeat::claim(&table, cpu(3)),
        Err(SeatError::OutOfRange)
    ));
    drop(seat);
    assert!(MemberSeat::claim(&table, cpu(1)).is_ok());

    let other = ServedTable::<3>::new();
    let mut foreign = MemberSeat::claim(&other, cpu(0)).expect("free seat");
    let mut venue = RecordingVenue::new();
    assert!(matches!(
        stage(&table, ctx(A), InvalidationKind::Unmap).commit(Some(&mut foreign), &mut venue),
        Err(CommitError::ForeignSeat)
    ));
    assert_eq!(table.issue.counter.latest(Ordering::Relaxed), 0);
}

#[test]
fn reclaim_releases_only_the_exact_completion() {
    let table = ServedTable::<3>::new();
    let other = ServedTable::<3>::new();
    let mut venue = RecordingVenue::new();
    let mut queue = ReclaimQueue::new();

    let first = stage(&table, ctx(A), InvalidationKind::Unmap)
        .commit(None, &mut venue)
        .map_err(|_| ())
        .expect("commit");
    queue.push(first.reclaim_tag(), "frame-a");
    let second = stage(&table, ctx(B), InvalidationKind::Unmap)
        .commit(None, &mut venue)
        .map_err(|_| ())
        .expect("commit");
    queue.push(second.reclaim_tag(), "frame-b");
    let foreign = stage(&other, ctx(A), InvalidationKind::Unmap)
        .commit(None, &mut venue)
        .map_err(|_| ())
        .expect("commit");
    assert_eq!(foreign.generation(), first.generation());

    let foreign = foreign.try_complete().expect("no member counted");
    assert!(queue.drain_ready(&foreign).is_empty(), "other domain");
    let second = second.try_complete().expect("no member counted");
    assert_eq!(queue.drain_ready(&second), Vec::from(["frame-b"]));
    assert_eq!(queue.len(), 1);
    let first = first.try_complete().expect("no member counted");
    assert_eq!(queue.drain_ready(&first), Vec::from(["frame-a"]));
    assert!(queue.is_empty());
}
