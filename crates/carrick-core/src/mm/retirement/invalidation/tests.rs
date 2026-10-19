//! VM-free witnesses for the invalidation domain (#681 slice 1a).
use super::*;
use crate::mm::retirement::{AddressResidency, ResidencyError, ResidencyState, ResidencyVenue};
use alloc::boxed::Box;
use alloc::rc::Rc;
use alloc::vec::Vec;
use carrick_conformance_contract::{
    Completeness, ContractId, ContractObservation, ContractRegistry, ExecutionLayer,
    SemanticAssertion, WorkMetric, WorkSnapshot, evaluate,
};
use carrick_guest_arch::{ContextGeneration, MmGeneration};
use core::cell::{Cell, RefCell, RefMut};
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

fn domain() -> DomainNonce {
    issue_domain_nonce().expect("fresh domain nonce")
}

fn table3() -> ServedTable<3> {
    ServedTable::new(domain())
}

#[derive(Debug, Eq, PartialEq)]
enum VenueError {
    TimedOut,
    Injected,
}

/// A host-thread venue: counts local invalidations, records kicks, can fail
/// the next invalidation on demand, and bounds every wait at five seconds.
struct RecordingVenue {
    invalidations: usize,
    kicked: Cell<u64>,
    fail_next: bool,
    deadline: Instant,
}

impl RecordingVenue {
    fn new() -> Self {
        Self {
            invalidations: 0,
            kicked: Cell::new(0),
            fail_next: false,
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
        if core::mem::take(&mut self.fail_next) {
            return Err(VenueError::Injected);
        }
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

/// Invalidations performed by one seat admission (one per kind).
const CLAIM_FLUSHES: usize = INVALIDATION_KINDS;

fn cpu(raw: u32) -> CpuId {
    CpuId::new(raw)
}

fn seat<'t, const N: usize>(
    table: &'t ServedTable<N>,
    raw: u32,
    venue: &mut RecordingVenue,
) -> MemberSeat<'t, N> {
    MemberSeat::claim(table, cpu(raw), venue).expect("free seat")
}

fn served<const N: usize>(
    table: &ServedTable<N>,
    member: usize,
    kind: InvalidationKind,
) -> Option<InvalidationGeneration> {
    table.members()[member].served(kind)
}

fn owed<const N: usize>(
    table: &ServedTable<N>,
    member: usize,
    kind: InvalidationKind,
) -> Option<InvalidationGeneration> {
    table.members()[member].owed(kind)
}

fn commit<'t, const N: usize>(
    table: &'t ServedTable<N>,
    key: (u64, u64),
    kind: InvalidationKind,
    requester: Option<&mut MemberSeat<'t, N>>,
    venue: &mut RecordingVenue,
) -> PendingInvalidation<'t, N> {
    stage(table, ctx(key), kind)
        .commit(requester, venue)
        .map_err(|_| ())
        .expect("commit")
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

/// The domain with persistent seats: the member and requester keep their
/// caches (and seats) for the whole scenario, as real vCPUs do.
struct DomainModel {
    table: &'static ServedTable<3>,
    member: MemberSeat<'static, 3>,
    requester: MemberSeat<'static, 3>,
    member_venue: RecordingVenue,
    requester_venue: RecordingVenue,
}

impl DomainModel {
    fn new() -> Self {
        let table: &'static ServedTable<3> = Box::leak(Box::new(table3()));
        let mut member_venue = RecordingVenue::new();
        let mut requester_venue = RecordingVenue::new();
        let member = seat(table, 1, &mut member_venue);
        let requester = seat(table, 0, &mut requester_venue);
        Self {
            table,
            member,
            requester,
            member_venue,
            requester_venue,
        }
    }
}

impl StoppedMemberProtocol for DomainModel {
    type Request = InvalidationGeneration;
    fn install_and_stop(&mut self, context: AddressContext<Tag>) {
        self.member
            .install(context, &mut self.member_venue)
            .expect("install");
        self.member.stop();
    }
    fn request(&mut self, context: AddressContext<Tag>) -> InvalidationGeneration {
        let pending = stage(self.table, context, InvalidationKind::Unmap)
            .commit(Some(&mut self.requester), &mut self.requester_venue)
            .map_err(|_| ())
            .expect("commit");
        let generation = pending.generation();
        // A stopped member does not block completion: its debt is durable.
        let _proof = pending.try_complete().expect("stopped debt completes");
        generation
    }
    fn reenter(&mut self) {
        self.member.enter(&mut self.member_venue).expect("enter");
    }
    fn member_served(&self, request: InvalidationGeneration) -> bool {
        request.served_by(served(self.table, 1, InvalidationKind::Unmap))
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
    let mut domain = DomainModel::new();
    assert!(!stopped_member_reenters_stale(&mut domain));
    // Admission flush, then exactly one serve on re-entry.
    assert_eq!(domain.member_venue.invalidations, CLAIM_FLUSHES + 1);
    assert!(
        !domain.requester_venue.kicked(1),
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
    let counter = GenerationCounter::<NearMax>::with_domain(domain());
    assert_eq!(counter.issue().map(|g| g.value().get()), Ok(u64::MAX));
    assert_eq!(counter.issue(), Err(GenerationExhausted));
    assert_eq!(
        counter.latest(Ordering::Relaxed).map(|g| g.value().get()),
        Some(u64::MAX)
    );

    let table = ServedTable::<1, NearMax>::with_domain(domain());
    let mut venue = RecordingVenue::new();
    let last = stage(&table, ctx(A), InvalidationKind::Unmap)
        .commit(None, &mut venue)
        .map_err(|_| ())
        .expect("the last generation is issuable");
    assert_eq!(last.generation().value().get(), u64::MAX);
    let _ = last.try_complete();
    let owed_before = table.members()[0].owed(InvalidationKind::Unmap);
    for _ in 0..3 {
        assert!(matches!(
            stage(&table, ctx(A), InvalidationKind::Unmap).commit(None, &mut venue),
            Err(CommitError::Exhausted)
        ));
        assert_eq!(
            table
                .counter()
                .latest(Ordering::Relaxed)
                .map(|g| g.value().get()),
            Some(u64::MAX)
        );
        assert_eq!(
            table.members()[0].owed(InvalidationKind::Unmap),
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
    let table = table3();
    let ready = AtomicBool::new(false);
    let go = AtomicBool::new(false);
    let done = AtomicBool::new(false);
    std::thread::scope(|scope| {
        let member = scope.spawn(|| {
            let mut venue = RecordingVenue::new();
            let mut seat = seat(&table, 1, &mut venue);
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
        let mut stopped = seat(&table, 2, &mut stopped_venue);
        stopped
            .install(ctx(A), &mut stopped_venue)
            .expect("install");
        stopped.stop();

        let mut venue = RecordingVenue::new();
        let mut requester = seat(&table, 0, &mut venue);
        let pending = commit(
            &table,
            A,
            InvalidationKind::Unmap,
            Some(&mut requester),
            &mut venue,
        );
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
        assert!(
            owed(&table, 2, InvalidationKind::Unmap)
                .is_some_and(|o| o.value() >= generation.value())
        );
        assert!(!generation.served_by(served(&table, 2, InvalidationKind::Unmap)));
        assert!(stopped.has_debt());
        assert_eq!(stopped_venue.invalidations, CLAIM_FLUSHES);
        stopped.enter(&mut stopped_venue).expect("enter");
        assert!(generation.served_by(served(&table, 2, InvalidationKind::Unmap)));
        assert!(!stopped.has_debt());
        assert_eq!(stopped_venue.invalidations, CLAIM_FLUSHES + 1);

        done.store(true, Ordering::Release);
        assert_eq!(member.join().expect("member thread"), CLAIM_FLUSHES + 1);
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

fn inspect(member: &ResidencyMember<CountingWord>) -> &MemberWords<CountingWord> {
    // SAFETY: read-only inspection of the instrumentation counters.
    unsafe { member.words() }
}

fn steady_line(member: &ResidencyMember<CountingWord>) -> Work {
    let words = inspect(member);
    let mut work = Work::default();
    words
        .owed
        .iter()
        .chain(words.served.iter())
        .for_each(|word| add(&mut work, word));
    work
}

/// Every member word. The issue counter's word is private to the ABI crate;
/// an RMW on it always advances it, so the test checks its value instead.
fn all_members<const N: usize>(table: &ServedTable<N, CountingWord>) -> Work {
    let mut work = Work::default();
    for member in table.members() {
        let words = inspect(member);
        for word in words.owed.iter().chain(words.served.iter()).chain([
            &words.running,
            &words.revision,
            &words.tag,
            &words.mm,
            &words.context,
            &words.seat,
        ]) {
            add(&mut work, word);
        }
    }
    work
}

/// The contract descriptor's fixture identity for these VM-free witnesses.
const FIXTURE: &str = "carrick-core::mm::retirement::invalidation::tests";

/// One steady-state measurement on a table of `N` members, every member
/// seated in the same context with its debt served.
fn steady_state_work<const N: usize>() -> ContractObservation {
    let table = ServedTable::<N, CountingWord>::with_domain(domain());
    let mut venues: Vec<RecordingVenue> = (0..N).map(|_| RecordingVenue::new()).collect();
    let mut seats: Vec<MemberSeat<'_, N, CountingWord>> = venues
        .iter_mut()
        .enumerate()
        .map(|(index, venue)| {
            let mut seat = MemberSeat::claim(&table, cpu(index as u32), venue).expect("free seat");
            seat.install(ctx(A), venue).expect("install");
            seat.enter(venue).expect("enter");
            seat
        })
        .collect();
    let pending = stage(&table, ctx(A), InvalidationKind::RevokeWrite)
        .commit(None, &mut venues[0])
        .map_err(|_| ())
        .expect("commit");
    for (seat, venue) in seats.iter_mut().zip(venues.iter_mut()) {
        seat.serve(venue).expect("serve the debt");
    }
    let _proof = pending.try_complete().expect("served");
    assert!(seats.iter().all(|seat| !seat.has_debt()));

    let counter_before = table.counter().latest(Ordering::Relaxed);
    let own_before = steady_line(&table.members()[0]);
    let table_before = all_members(&table);
    let flushes_before = venues[0].invalidations;
    const ROUNDS: u64 = 1000;
    for _ in 0..ROUNDS {
        assert!(!seats[0].has_debt());
        seats[0].serve(&mut venues[0]).expect("no debt");
    }
    let own = steady_line(&table.members()[0]);
    let all = all_members(&table);
    assert_eq!(table.counter().latest(Ordering::Relaxed), counter_before);
    // Exactly owed[2] + served[2] per check, twice per round, nothing else:
    // no other member's line and no store anywhere.
    assert_eq!(own.loads - own_before.loads, ROUNDS * 2 * 4);
    assert_eq!(all.loads - table_before.loads, ROUNDS * 2 * 4);
    assert_eq!(all.stores, table_before.stores);
    assert_eq!(venues[0].invalidations, flushes_before);

    let mut work = WorkSnapshot::new();
    work.insert(
        WorkMetric::InvalidationSteadyStateRmws,
        all.rmws - table_before.rmws,
    )
    .expect("metric recorded once");
    ContractObservation {
        contract_id: ContractId::new("kernel.mm.invalidation-domain").expect("contract id"),
        layer: ExecutionLayer::VmFree,
        implementation_revision: "invalidation-domain-1a".into(),
        fixture_identity: FIXTURE.into(),
        scale: N as u64,
        semantic_assertions: alloc::vec![SemanticAssertion::pass(
            "steady_state_check_reads_only_own_owed_and_served",
        )],
        work: Some(work),
        timing: None,
        completeness: Completeness::Complete,
    }
}

#[test]
fn steady_state_check_is_own_line_loads_with_zero_rmws() {
    let observations = [
        steady_state_work::<1>(),
        steady_state_work::<2>(),
        steady_state_work::<3>(),
    ];
    let repo_root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(std::path::Path::parent)
        .expect("workspace root");
    let registry = ContractRegistry::load(repo_root).expect("contract registry");
    evaluate(
        registry
            .require("kernel.mm.invalidation-domain")
            .expect("contract"),
        &observations,
    )
    .expect("structural budget holds");
}

// ---------------------------------------------------------------------------
// Review P1s: install failure keeps debt; seat reuse flushes the new cache;
// a completion never crosses domains.
// ---------------------------------------------------------------------------

#[test]
fn install_failure_leaves_debt_visible_and_served_on_entry() {
    let table = table3();
    let mut venue = RecordingVenue::new();
    let mut member = seat(&table, 1, &mut venue);
    member.install(ctx(B), &mut venue).expect("install B");
    // A request for A while the member is in B does not count it.
    let pending = commit(&table, A, InvalidationKind::Unmap, None, &mut venue);
    assert!(!pending.counts(cpu(1)));
    let generation = pending.generation();
    let _proof = pending.try_complete().expect("no member counted");

    // Installing A must serve that generation; the local flush fails.
    venue.fail_next = true;
    assert_eq!(
        member.install(ctx(A), &mut venue),
        Err(VenueError::Injected)
    );
    assert!(member.has_debt(), "the failed install's debt stays visible");
    assert!(
        owed(&table, 1, InvalidationKind::Unmap).is_some_and(|o| o.value() >= generation.value())
    );
    member.enter(&mut venue).expect("enter");
    assert!(!member.has_debt());
    assert!(generation.served_by(served(&table, 1, InvalidationKind::Unmap)));
    assert!(generation.served_by(served(&table, 1, InvalidationKind::RevokeWrite)));
}

#[test]
fn seat_reuse_flushes_the_new_cache_before_adopting_the_watermark() {
    let table = table3();
    // Member 2's previous holder served everything up to some generation.
    let mut old_venue = RecordingVenue::new();
    let mut old = seat(&table, 2, &mut old_venue);
    old.install(ctx(A), &mut old_venue).expect("install");
    let pending = commit(&table, A, InvalidationKind::Unmap, None, &mut old_venue);
    old.serve(&mut old_venue).expect("serve");
    let generation = pending.generation();
    let _proof = pending.try_complete().expect("served");
    drop(old);

    // A vCPU whose own cache still holds stale A entries moves from member 1
    // to member 2. Its cache never served `generation`; admission must flush.
    let mut moving = RecordingVenue::new();
    let first = seat(&table, 1, &mut moving);
    assert_eq!(moving.invalidations, CLAIM_FLUSHES);
    drop(first);
    let before = moving.invalidations;
    let second = seat(&table, 2, &mut moving);
    assert_eq!(moving.invalidations - before, CLAIM_FLUSHES);
    assert!(generation.served_by(served(&table, 2, InvalidationKind::Unmap)));
    assert!(!second.has_debt());

    // A failed admission flush releases the seat.
    drop(second);
    moving.fail_next = true;
    assert!(matches!(
        MemberSeat::claim(&table, cpu(2), &mut moving),
        Err(SeatError::Venue(VenueError::Injected))
    ));
    assert!(!table.members()[2].is_seated());
    assert!(!table.members()[2].is_running());
}

#[derive(Clone, Debug, Default)]
struct CellResidency(Rc<RefCell<ResidencyState>>);

// SAFETY: single-threaded test venue; every clone shares one RefCell and no
// waiter ever blocks (loads are never in flight).
unsafe impl ResidencyVenue for CellResidency {
    type Guard<'a> = RefMut<'a, ResidencyState>;
    fn lock(&self) -> Self::Guard<'_> {
        self.0.borrow_mut()
    }
    fn wait(&self, _guard: &mut Self::Guard<'_>) {}
    fn notify_all(&self) {}
}

#[test]
fn completion_from_another_domain_never_acknowledges_or_reclaims() {
    let table = table3();
    let other = table3();
    let mut venue = RecordingVenue::new();
    let mine = commit(&table, A, InvalidationKind::Unmap, None, &mut venue);
    let theirs = commit(&other, A, InvalidationKind::Unmap, None, &mut venue);
    assert_eq!(mine.generation().value(), theirs.generation().value());
    assert_ne!(mine.generation(), theirs.generation());

    let mut queue = ReclaimQueue::new();
    queue.push(mine.reclaim_tag(), "frame");
    let residency =
        AddressResidency::<CellResidency, InvalidationGeneration>::new(mine.generation());
    let retirement = residency.begin_retirement().expect("live");

    let theirs = theirs.try_complete().expect("no member counted");
    assert!(queue.drain_ready(&theirs).is_empty());
    assert_eq!(
        retirement.acknowledge(theirs),
        Err(ResidencyError::StaleGeneration)
    );

    let mine = mine.try_complete().expect("no member counted");
    assert_eq!(queue.drain_ready(&mine), Vec::from(["frame"]));
    assert_eq!(retirement.acknowledge(mine), Ok(()));
}

// ---------------------------------------------------------------------------
// Protocol edges.
// ---------------------------------------------------------------------------

#[test]
fn requester_serves_itself_inline() {
    let table = table3();
    let mut venue = RecordingVenue::new();
    let mut seat = seat(&table, 0, &mut venue);
    seat.install(ctx(A), &mut venue).expect("install");
    seat.enter(&mut venue).expect("enter");
    let before = venue.invalidations;
    let pending = commit(
        &table,
        A,
        InvalidationKind::Unmap,
        Some(&mut seat),
        &mut venue,
    );
    assert!(pending.counts(cpu(0)));
    assert!(!venue.kicked(0), "the requester never kicks itself");
    assert_eq!(venue.invalidations - before, 1);
    let completion = pending.try_complete().expect("served inline");
    assert_eq!(completion.kind(), InvalidationKind::Unmap);
}

#[test]
fn staging_has_no_effect_until_commit() {
    let table = table3();
    let mut venue = RecordingVenue::new();
    let mut seat = seat(&table, 1, &mut venue);
    seat.install(ctx(A), &mut venue).expect("install");
    stage(&table, ctx(A), InvalidationKind::Unmap).rollback();
    drop(stage(&table, ctx(A), InvalidationKind::RevokeWrite));
    assert!(table.counter().latest(Ordering::Relaxed).is_none());
    assert!(table.members().iter().all(|member| {
        InvalidationKind::ALL
            .iter()
            .all(|&kind| member.owed(kind).is_none())
    }));
    assert!(!seat.has_debt());
}

#[test]
fn install_serves_generations_issued_before_its_publication() {
    // A member skipped because it was in B when the request for A was
    // issued must not reach A with translations older than that request.
    let table = table3();
    let mut venue = RecordingVenue::new();
    let mut seat = seat(&table, 1, &mut venue);
    seat.install(ctx(B), &mut venue).expect("install");
    let pending = commit(&table, A, InvalidationKind::Unmap, None, &mut venue);
    assert!(!pending.counts(cpu(1)));
    let generation = pending.generation();
    let _proof = pending.try_complete().expect("no member counted");
    seat.install(ctx(A), &mut venue).expect("install");
    assert!(generation.served_by(served(&table, 1, InvalidationKind::Unmap)));
    assert!(generation.served_by(served(&table, 1, InvalidationKind::RevokeWrite)));
}

#[test]
fn seats_are_exclusive_and_bounded() {
    let table = table3();
    let mut venue = RecordingVenue::new();
    let held = seat(&table, 1, &mut venue);
    assert!(matches!(
        MemberSeat::claim(&table, cpu(1), &mut venue),
        Err(SeatError::Claimed)
    ));
    assert!(matches!(
        MemberSeat::claim(&table, cpu(3), &mut venue),
        Err(SeatError::OutOfRange)
    ));
    drop(held);
    assert!(MemberSeat::claim(&table, cpu(1), &mut venue).is_ok());

    let other = table3();
    let mut foreign = seat(&other, 0, &mut venue);
    assert!(matches!(
        stage(&table, ctx(A), InvalidationKind::Unmap).commit(Some(&mut foreign), &mut venue),
        Err(CommitError::ForeignSeat)
    ));
    assert!(table.counter().latest(Ordering::Relaxed).is_none());
}

#[test]
fn reclaim_releases_only_the_exact_completion() {
    let table = table3();
    let mut venue = RecordingVenue::new();
    let mut queue = ReclaimQueue::new();

    let first = commit(&table, A, InvalidationKind::Unmap, None, &mut venue);
    queue.push(first.reclaim_tag(), "frame-a");
    let second = commit(&table, B, InvalidationKind::Unmap, None, &mut venue);
    queue.push(second.reclaim_tag(), "frame-b");

    let second = second.try_complete().expect("no member counted");
    assert_eq!(queue.drain_ready(&second), Vec::from(["frame-b"]));
    assert_eq!(queue.len(), 1);
    let first = first.try_complete().expect("no member counted");
    assert_eq!(queue.drain_ready(&first), Vec::from(["frame-a"]));
    assert!(queue.is_empty());
}

#[test]
fn domain_nonces_are_unique_and_the_counter_refuses_at_max() {
    assert_ne!(domain(), domain());
    let counter = AtomicU64::new(u64::MAX - 1);
    let last = super::issue_domain_nonce_with(&counter).expect("last nonce");
    assert_eq!(last.get().get(), u64::MAX - 1);
    for _ in 0..2 {
        assert_eq!(
            super::issue_domain_nonce_with(&counter),
            Err(GenerationExhausted)
        );
        assert_eq!(counter.load(Ordering::Relaxed), u64::MAX);
    }
}
