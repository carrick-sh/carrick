//! MMU publication v2: one guest-to-host record shared by ARM and x86.
//!
//! The guest plans and executes every descriptor edit (an `EditIntent`) under
//! its exact-MM editor, then publishes one fixed 128-byte record describing
//! the settled outcome. The host never plans or walks descriptors; it only
//! authenticates the record against its own physical ledger. Four address
//! domains stay distinct in the typed view: the informational user span
//! ([`UserRange`], never resolved by the host), the translation root
//! ([`RootGpa`]), the output frames ([`FrameGpa`]) and owner/inventory
//! generations ([`EditBacking`]).
//!
//! An indeterminate outcome (stores neither settled nor undone) is
//! deliberately not representable: it remains guest-fatal and never crosses
//! this boundary as data.

use carrick_guest_arch::{EditBacking, FrameGpa, GuestIsa, GuestLen, RootGpa, UserRange, UserVa};
use core::cell::UnsafeCell;
use core::num::NonZeroU64;
use core::sync::atomic::{AtomicU64, Ordering};

/// Exact MM key named by the edit owner; not a host pid or a root address.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct PublicationMm(NonZeroU64);
impl PublicationMm {
    pub const fn new(raw: NonZeroU64) -> Self {
        Self(raw)
    }
    pub const fn raw(self) -> NonZeroU64 {
        self.0
    }
}

/// Incarnation of one MM slot. A recycled slot keeps its key and receives a
/// new incarnation, so a stale record cannot authenticate against the
/// successor.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct MmIncarnation(NonZeroU64);
impl MmIncarnation {
    pub const fn new(raw: NonZeroU64) -> Self {
        Self(raw)
    }
    pub const fn raw(self) -> NonZeroU64 {
        self.0
    }
}

/// The `EditOwner` generation of the publishing edit; strictly increasing per
/// MM incarnation.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct EditSequence(NonZeroU64);
impl EditSequence {
    pub const fn new(raw: NonZeroU64) -> Self {
        Self(raw)
    }
    pub const fn raw(self) -> NonZeroU64 {
        self.0
    }
}

/// The descriptor operation class, mirroring `EditOperation` without ISA bits.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum PublicationKind {
    Prepare = 1,
    Map = 2,
    Publish = 3,
    Protect = 4,
    ArmCow = 5,
    CowRepoint = 6,
    Unmap = 7,
    Coalesce = 8,
}
impl PublicationKind {
    const fn from_wire(raw: u8) -> Option<Self> {
        Some(match raw {
            1 => Self::Prepare,
            2 => Self::Map,
            3 => Self::Publish,
            4 => Self::Protect,
            5 => Self::ArmCow,
            6 => Self::CowRepoint,
            7 => Self::Unmap,
            8 => Self::Coalesce,
            _ => return None,
        })
    }
    /// Kinds that name a new output frame and its prepared backing.
    pub const fn names_output(self) -> bool {
        matches!(self, Self::Prepare | Self::Map | Self::CowRepoint)
    }
}

/// Settled guest outcome. There is intentionally no indeterminate variant.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum PublicationOutcome {
    /// Every store landed and the requested drain completed.
    Applied = 1,
    /// Validation refused the edit before any live store.
    Refused = 2,
    /// Stores landed, then the guest restored every prior word.
    RolledBack = 3,
}
impl PublicationOutcome {
    const fn from_wire(raw: u8) -> Option<Self> {
        Some(match raw {
            1 => Self::Applied,
            2 => Self::Refused,
            3 => Self::RolledBack,
            _ => return None,
        })
    }
}

/// Scope of the translation drain the guest completed before publishing.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum PublicationDrain {
    /// Broadcast invalidation over every CPU that may cache this MM.
    Global = 1,
    /// Only the publishing CPU was drained; remote CPUs may still cache it.
    LocalOnly = 2,
}
impl PublicationDrain {
    const fn from_wire(raw: u8) -> Option<Self> {
        Some(match raw {
            1 => Self::Global,
            2 => Self::LocalOnly,
            _ => return None,
        })
    }
}

const fn isa_to_wire(isa: GuestIsa) -> u8 {
    match isa {
        GuestIsa::Aarch64 => 1,
        GuestIsa::X86_64 => 2,
    }
}
const fn isa_from_wire(raw: u8) -> Option<GuestIsa> {
    match raw {
        1 => Some(GuestIsa::Aarch64),
        2 => Some(GuestIsa::X86_64),
        _ => None,
    }
}

/// Fixed 128-byte wire record. Fields are private: producers encode from a
/// typed [`PublicationView`] and consumers decode back to one, so no bare
/// `u64` crosses the boundary in either direction.
#[repr(C, align(8))]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MmPublication {
    revision: u32,
    kind: u8,
    outcome: u8,
    drain: u8,
    isa: u8,
    mm: u64,
    incarnation: u64,
    edit_sequence: u64,
    root: u64,
    span_va: u64,
    span_len: u64,
    output: u64,
    prior_output: u64,
    backing_frame: u64,
    backing_mapping: u64,
    owner_generation: u64,
    inventory_revision: u64,
    reserved: [u64; 2],
    digest: u64,
}

const _: () = {
    use core::mem::{align_of, offset_of, size_of};
    assert!(size_of::<MmPublication>() == 128);
    assert!(align_of::<MmPublication>() == 8);
    assert!(offset_of!(MmPublication, revision) == 0);
    assert!(offset_of!(MmPublication, kind) == 4);
    assert!(offset_of!(MmPublication, outcome) == 5);
    assert!(offset_of!(MmPublication, drain) == 6);
    assert!(offset_of!(MmPublication, isa) == 7);
    assert!(offset_of!(MmPublication, mm) == 8);
    assert!(offset_of!(MmPublication, incarnation) == 16);
    assert!(offset_of!(MmPublication, edit_sequence) == 24);
    assert!(offset_of!(MmPublication, root) == 32);
    assert!(offset_of!(MmPublication, span_va) == 40);
    assert!(offset_of!(MmPublication, span_len) == 48);
    assert!(offset_of!(MmPublication, output) == 56);
    assert!(offset_of!(MmPublication, prior_output) == 64);
    assert!(offset_of!(MmPublication, backing_frame) == 72);
    assert!(offset_of!(MmPublication, backing_mapping) == 80);
    assert!(offset_of!(MmPublication, owner_generation) == 88);
    assert!(offset_of!(MmPublication, inventory_revision) == 96);
    assert!(offset_of!(MmPublication, reserved) == 104);
    assert!(offset_of!(MmPublication, digest) == 120);
};

/// Typed content of one publication. Construct with [`PublicationView::checked`]
/// so span, root and output invariants hold before encoding.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PublicationView {
    kind: PublicationKind,
    outcome: PublicationOutcome,
    drain: PublicationDrain,
    isa: GuestIsa,
    mm: PublicationMm,
    incarnation: MmIncarnation,
    edit_sequence: EditSequence,
    root: RootGpa,
    span: UserRange,
    output: Option<FrameGpa>,
    prior_output: Option<FrameGpa>,
    backing: Option<EditBacking>,
}

/// Identity of the publishing edit, grouped so constructors stay readable.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PublicationIdentity {
    pub mm: PublicationMm,
    pub incarnation: MmIncarnation,
    pub edit_sequence: EditSequence,
    pub root: RootGpa,
}

/// Physical frames named by the edit; the host authenticates these, never
/// the span.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PublicationFrames {
    pub output: Option<FrameGpa>,
    pub prior_output: Option<FrameGpa>,
    pub backing: Option<EditBacking>,
}

/// Why a record or view was rejected. Every variant is a quarantine cause at
/// the consumer; none is a retry signal.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PublicationDecodeError {
    Revision,
    Kind,
    Outcome,
    Drain,
    Isa,
    Identity,
    Root,
    Span,
    Output,
    Backing,
    Reserved,
    Digest,
}

const PAGE_MASK: u64 = 0xfff;

impl PublicationView {
    /// Validate shape: page-aligned non-empty span, page-aligned output
    /// frames, output and backing present exactly for kinds that name one.
    pub fn checked(
        kind: PublicationKind,
        outcome: PublicationOutcome,
        drain: PublicationDrain,
        isa: GuestIsa,
        identity: PublicationIdentity,
        span: UserRange,
        frames: PublicationFrames,
    ) -> Result<Self, PublicationDecodeError> {
        if span.is_empty()
            || span.start().raw() & PAGE_MASK != 0
            || span.len().raw() & PAGE_MASK != 0
        {
            return Err(PublicationDecodeError::Span);
        }
        let aligned = |frame: Option<FrameGpa>| frame.is_none_or(|f| f.raw() & PAGE_MASK == 0);
        if !aligned(frames.output) || !aligned(frames.prior_output) {
            return Err(PublicationDecodeError::Output);
        }
        if frames
            .output
            .is_some_and(|f| f.raw().checked_add(span.len().raw()).is_none())
        {
            return Err(PublicationDecodeError::Output);
        }
        if kind.names_output() != frames.output.is_some() {
            return Err(PublicationDecodeError::Output);
        }
        if kind.names_output() != frames.backing.is_some() {
            return Err(PublicationDecodeError::Backing);
        }
        if kind == PublicationKind::CowRepoint && frames.prior_output.is_none() {
            return Err(PublicationDecodeError::Output);
        }
        Ok(Self {
            kind,
            outcome,
            drain,
            isa,
            mm: identity.mm,
            incarnation: identity.incarnation,
            edit_sequence: identity.edit_sequence,
            root: identity.root,
            span,
            output: frames.output,
            prior_output: frames.prior_output,
            backing: frames.backing,
        })
    }

    pub const fn kind(&self) -> PublicationKind {
        self.kind
    }
    pub const fn outcome(&self) -> PublicationOutcome {
        self.outcome
    }
    pub const fn drain(&self) -> PublicationDrain {
        self.drain
    }
    pub const fn isa(&self) -> GuestIsa {
        self.isa
    }
    pub const fn mm(&self) -> PublicationMm {
        self.mm
    }
    pub const fn incarnation(&self) -> MmIncarnation {
        self.incarnation
    }
    pub const fn edit_sequence(&self) -> EditSequence {
        self.edit_sequence
    }
    pub const fn root(&self) -> RootGpa {
        self.root
    }
    /// Informational only: the host must never resolve this user span.
    pub const fn span(&self) -> UserRange {
        self.span
    }
    /// Bytes of output named by the edit, equal to the span length.
    pub const fn output_len(&self) -> GuestLen {
        self.span.len()
    }
    pub const fn output(&self) -> Option<FrameGpa> {
        self.output
    }
    pub const fn prior_output(&self) -> Option<FrameGpa> {
        self.prior_output
    }
    pub const fn backing(&self) -> Option<EditBacking> {
        self.backing
    }
}

/// Integrity digest over the first 120 bytes (FNV-1a, 64-bit). It detects a
/// torn or mis-sized record; it is not a cryptographic authenticator, so the
/// consumer still authenticates every field against its own ledger.
fn digest_words(words: &[u64; 15]) -> u64 {
    let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
    for word in words {
        for byte in word.to_le_bytes() {
            hash ^= u64::from(byte);
            hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
        }
    }
    hash
}

const fn opt_frame(frame: Option<FrameGpa>) -> u64 {
    match frame {
        Some(frame) => frame.raw(),
        None => 0,
    }
}

impl MmPublication {
    pub const REVISION: u32 = 2;
    pub const SIZE: usize = 128;

    fn header_word(&self) -> u64 {
        u64::from(self.revision)
            | u64::from(self.kind) << 32
            | u64::from(self.outcome) << 40
            | u64::from(self.drain) << 48
            | u64::from(self.isa) << 56
    }

    fn words(&self) -> [u64; 15] {
        [
            self.header_word(),
            self.mm,
            self.incarnation,
            self.edit_sequence,
            self.root,
            self.span_va,
            self.span_len,
            self.output,
            self.prior_output,
            self.backing_frame,
            self.backing_mapping,
            self.owner_generation,
            self.inventory_revision,
            self.reserved[0],
            self.reserved[1],
        ]
    }

    /// Encode a validated view and seal it with its digest.
    pub fn encode(view: &PublicationView) -> Self {
        let backing = view.backing;
        let mut record = Self {
            revision: Self::REVISION,
            kind: view.kind as u8,
            outcome: view.outcome as u8,
            drain: view.drain as u8,
            isa: isa_to_wire(view.isa),
            mm: view.mm.raw().get(),
            incarnation: view.incarnation.raw().get(),
            edit_sequence: view.edit_sequence.raw().get(),
            root: view.root.address().raw(),
            span_va: view.span.start().raw(),
            span_len: view.span.len().raw(),
            output: opt_frame(view.output),
            prior_output: opt_frame(view.prior_output),
            backing_frame: backing.map_or(0, |b| b.frame_id.get()),
            backing_mapping: backing.map_or(0, |b| b.mapping_id.get()),
            owner_generation: backing.map_or(0, |b| b.owner_generation.get()),
            inventory_revision: backing.map_or(0, |b| b.inventory_revision.get()),
            reserved: [0; 2],
            digest: 0,
        };
        record.digest = digest_words(&record.words());
        record
    }

    /// Decode and validate every field. Any failure is a quarantine cause.
    pub fn decode(&self) -> Result<PublicationView, PublicationDecodeError> {
        use PublicationDecodeError as E;
        if self.revision != Self::REVISION {
            return Err(E::Revision);
        }
        if self.digest != digest_words(&self.words()) {
            return Err(E::Digest);
        }
        if self.reserved != [0; 2] {
            return Err(E::Reserved);
        }
        let kind = PublicationKind::from_wire(self.kind).ok_or(E::Kind)?;
        let outcome = PublicationOutcome::from_wire(self.outcome).ok_or(E::Outcome)?;
        let drain = PublicationDrain::from_wire(self.drain).ok_or(E::Drain)?;
        let isa = isa_from_wire(self.isa).ok_or(E::Isa)?;
        let nz = |raw: u64| NonZeroU64::new(raw).ok_or(E::Identity);
        let identity = PublicationIdentity {
            mm: PublicationMm::new(nz(self.mm)?),
            incarnation: MmIncarnation::new(nz(self.incarnation)?),
            edit_sequence: EditSequence::new(nz(self.edit_sequence)?),
            root: RootGpa::page_aligned(FrameGpa::new(self.root)).ok_or(E::Root)?,
        };
        let span = UserRange::checked(UserVa::new(self.span_va), GuestLen::new(self.span_len))
            .ok_or(E::Span)?;
        let frame = |raw: u64| (raw != 0).then_some(FrameGpa::new(raw));
        let backing_words = [
            self.backing_frame,
            self.backing_mapping,
            self.owner_generation,
            self.inventory_revision,
        ];
        let backing = if backing_words == [0; 4] {
            None
        } else {
            let nz = |raw: u64| NonZeroU64::new(raw).ok_or(E::Backing);
            Some(EditBacking {
                frame_id: nz(self.backing_frame)?,
                mapping_id: nz(self.backing_mapping)?,
                owner_generation: nz(self.owner_generation)?,
                inventory_revision: nz(self.inventory_revision)?,
            })
        };
        PublicationView::checked(
            kind,
            outcome,
            drain,
            isa,
            identity,
            span,
            PublicationFrames {
                output: frame(self.output),
                prior_output: frame(self.prior_output),
                backing,
            },
        )
    }
}

/// Bounded single-producer/single-consumer record ring for later per-vCPU
/// use. The producer is the publishing CPU; the consumer is the host drain.
/// `head` and `tail` are free-running counters; slot = counter % N.
#[repr(C, align(8))]
pub struct PublicationRing<const N: usize> {
    head: AtomicU64,
    tail: AtomicU64,
    watermark: u64,
    slots: [UnsafeCell<MmPublication>; N],
}

// SAFETY: slot access is partitioned by the head/tail protocol. The single
// producer writes only slots in [head, tail + N) before releasing `head`; the
// single consumer reads only slots in [tail, head) after acquiring `head` and
// releases them by storing `tail`. `split` takes `&mut self`, so at most one
// producer and one consumer handle exist at a time.
unsafe impl<const N: usize> Sync for PublicationRing<N> {}

/// The ring could not accept a record; the producer must request a drain
/// before continuing. The caller still holds the record; nothing was dropped.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RingFull;

/// Occupancy after a successful push.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RingPressure {
    Below,
    /// Occupancy reached the watermark: request a host drain now.
    AtWatermark,
}

const EMPTY_RECORD: MmPublication = MmPublication {
    revision: 0,
    kind: 0,
    outcome: 0,
    drain: 0,
    isa: 0,
    mm: 0,
    incarnation: 0,
    edit_sequence: 0,
    root: 0,
    span_va: 0,
    span_len: 0,
    output: 0,
    prior_output: 0,
    backing_frame: 0,
    backing_mapping: 0,
    owner_generation: 0,
    inventory_revision: 0,
    reserved: [0; 2],
    digest: 0,
};

impl<const N: usize> PublicationRing<N> {
    /// `None` when `N` is zero or the watermark is outside `1..=N`.
    pub fn new(watermark: usize) -> Option<Self> {
        if N == 0 || watermark == 0 || watermark > N {
            return None;
        }
        Some(Self {
            head: AtomicU64::new(0),
            tail: AtomicU64::new(0),
            watermark: u64::try_from(watermark).ok()?,
            slots: core::array::from_fn(|_| UnsafeCell::new(EMPTY_RECORD)),
        })
    }

    /// Records published and not yet consumed.
    pub fn occupancy(&self) -> u64 {
        let head = self.head.load(Ordering::Acquire);
        head.wrapping_sub(self.tail.load(Ordering::Acquire))
    }

    pub fn split(&mut self) -> (RingProducer<'_, N>, RingConsumer<'_, N>) {
        let ring: &Self = self;
        (RingProducer { ring }, RingConsumer { ring })
    }

    fn slot(&self, counter: u64) -> Option<&UnsafeCell<MmPublication>> {
        let n = u64::try_from(N).ok()?;
        self.slots.get(usize::try_from(counter % n).ok()?)
    }
}

pub struct RingProducer<'a, const N: usize> {
    ring: &'a PublicationRing<N>,
}

impl<const N: usize> RingProducer<'_, N> {
    pub fn push(&mut self, record: &MmPublication) -> Result<RingPressure, RingFull> {
        let ring = self.ring;
        let head = ring.head.load(Ordering::Relaxed);
        let tail = ring.tail.load(Ordering::Acquire);
        let used = head.wrapping_sub(tail);
        if used >= u64::try_from(N).map_err(|_| RingFull)? {
            return Err(RingFull);
        }
        let slot = ring.slot(head).ok_or(RingFull)?;
        // SAFETY: `head - tail < N`, so this slot is outside [tail, head) and
        // the consumer does not read it until `head` is released below.
        unsafe { *slot.get() = *record };
        ring.head.store(head.wrapping_add(1), Ordering::Release);
        if used + 1 >= ring.watermark {
            Ok(RingPressure::AtWatermark)
        } else {
            Ok(RingPressure::Below)
        }
    }
}

pub struct RingConsumer<'a, const N: usize> {
    ring: &'a PublicationRing<N>,
}

impl<const N: usize> RingConsumer<'_, N> {
    pub fn pop(&mut self) -> Option<MmPublication> {
        let ring = self.ring;
        let tail = ring.tail.load(Ordering::Relaxed);
        let head = ring.head.load(Ordering::Acquire);
        if tail == head {
            return None;
        }
        let slot = ring.slot(tail)?;
        // SAFETY: `tail < head`, and the acquire load of `head` orders the
        // producer's write of this slot before this read. The producer does
        // not overwrite it until `tail` is released below.
        let record = unsafe { *slot.get() };
        ring.tail.store(tail.wrapping_add(1), Ordering::Release);
        Some(record)
    }
}

impl<const N: usize> Iterator for RingConsumer<'_, N> {
    type Item = MmPublication;
    fn next(&mut self) -> Option<MmPublication> {
        self.pop()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn nz(raw: u64) -> NonZeroU64 {
        NonZeroU64::new(raw).unwrap()
    }

    fn map_view(sequence: u64) -> PublicationView {
        PublicationView::checked(
            PublicationKind::Map,
            PublicationOutcome::Applied,
            PublicationDrain::Global,
            GuestIsa::Aarch64,
            PublicationIdentity {
                mm: PublicationMm::new(nz(7)),
                incarnation: MmIncarnation::new(nz(3)),
                edit_sequence: EditSequence::new(nz(sequence)),
                root: RootGpa::page_aligned(FrameGpa::new(0x4000_0000)).unwrap(),
            },
            UserRange::checked(UserVa::new(0x40_0000), GuestLen::new(0x2000)).unwrap(),
            PublicationFrames {
                output: Some(FrameGpa::new(0x8000_0000)),
                prior_output: None,
                backing: Some(EditBacking {
                    frame_id: nz(11),
                    mapping_id: nz(12),
                    owner_generation: nz(13),
                    inventory_revision: nz(14),
                }),
            },
        )
        .unwrap()
    }

    #[test]
    fn layout_is_literal() {
        assert_eq!(core::mem::size_of::<MmPublication>(), MmPublication::SIZE);
        // Exhaustive pattern: a new field must update the offset guards.
        let _ = |MmPublication {
                     revision: _,
                     kind: _,
                     outcome: _,
                     drain: _,
                     isa: _,
                     mm: _,
                     incarnation: _,
                     edit_sequence: _,
                     root: _,
                     span_va: _,
                     span_len: _,
                     output: _,
                     prior_output: _,
                     backing_frame: _,
                     backing_mapping: _,
                     owner_generation: _,
                     inventory_revision: _,
                     reserved: _,
                     digest: _,
                 }: MmPublication| {};
    }

    #[test]
    fn round_trip_preserves_every_domain() {
        let view = map_view(5);
        let record = MmPublication::encode(&view);
        assert_eq!(record.decode(), Ok(view));
    }

    #[test]
    fn indeterminate_outcome_is_not_decodable() {
        let mut record = MmPublication::encode(&map_view(5));
        record.outcome = 4;
        record.digest = digest_words(&record.words());
        assert_eq!(record.decode(), Err(PublicationDecodeError::Outcome));
        record.outcome = 0;
        record.digest = digest_words(&record.words());
        assert_eq!(record.decode(), Err(PublicationDecodeError::Outcome));
    }

    #[test]
    fn torn_record_fails_digest() {
        let mut record = MmPublication::encode(&map_view(5));
        record.owner_generation ^= 1;
        assert_eq!(record.decode(), Err(PublicationDecodeError::Digest));
    }

    #[test]
    fn output_kinds_require_output_and_backing() {
        let view = map_view(5);
        let identity = PublicationIdentity {
            mm: view.mm(),
            incarnation: view.incarnation(),
            edit_sequence: view.edit_sequence(),
            root: view.root(),
        };
        let none = PublicationFrames {
            output: None,
            prior_output: None,
            backing: None,
        };
        assert_eq!(
            PublicationView::checked(
                PublicationKind::Map,
                PublicationOutcome::Applied,
                PublicationDrain::Global,
                GuestIsa::X86_64,
                identity,
                view.span(),
                none,
            ),
            Err(PublicationDecodeError::Output)
        );
        assert!(
            PublicationView::checked(
                PublicationKind::Unmap,
                PublicationOutcome::Applied,
                PublicationDrain::LocalOnly,
                GuestIsa::X86_64,
                identity,
                view.span(),
                none,
            )
            .is_ok()
        );
    }

    #[test]
    fn ring_is_bounded_and_signals_watermark() {
        let mut ring = PublicationRing::<4>::new(3).unwrap();
        let (mut producer, mut consumer) = ring.split();
        let records: [MmPublication; 5] =
            core::array::from_fn(|i| MmPublication::encode(&map_view(i as u64 + 1)));
        assert_eq!(producer.push(&records[0]), Ok(RingPressure::Below));
        assert_eq!(producer.push(&records[1]), Ok(RingPressure::Below));
        assert_eq!(producer.push(&records[2]), Ok(RingPressure::AtWatermark));
        assert_eq!(producer.push(&records[3]), Ok(RingPressure::AtWatermark));
        assert_eq!(producer.push(&records[4]), Err(RingFull));
        assert_eq!(consumer.pop(), Some(records[0]));
        assert_eq!(producer.push(&records[4]), Ok(RingPressure::AtWatermark));
        let drained: alloc::vec::Vec<_> = consumer.by_ref().collect();
        assert_eq!(drained, records[1..].to_vec());
        assert_eq!(consumer.pop(), None);
    }

    #[test]
    fn ring_rejects_invalid_watermark() {
        assert!(PublicationRing::<4>::new(0).is_none());
        assert!(PublicationRing::<4>::new(5).is_none());
        assert!(PublicationRing::<0>::new(1).is_none());
    }
}
