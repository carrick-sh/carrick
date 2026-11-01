//! Shared-memory sequence words and an atomic word-backed byte buffer for
//! lock-free seqlock readers.
//!
//! Two writer protocols exist, and each has its own type so one word can
//! never be driven by both:
//!
//! - [`SeqWord`]: writers already hold an external lock (the fd-core table
//!   lock) and only publish odd/even transitions.
//! - [`ExclusiveSeq`]: the sequence word *is* the writer lock. The only way
//!   to write is [`ExclusiveSeq::try_write`], which claims even `s` -> odd
//!   `s + 1` with a compare-exchange and returns a [`SeqWriteGuard`] that
//!   publishes `s + 2` on drop. Readers take a [`SeqReadTicket`] (only from
//!   an even word) and accept their copy only if [`ExclusiveSeq::validate`]
//!   finds the word unchanged.
//!
//! Every guarded datum is an atomic word, so a reader racing a writer reads
//! stale or mixed *values*, never a data race; the sequence check rejects
//! the mix. Because each completed write advances the word by two, an
//! invalidate-then-refill between a reader's ticket and its validation
//! always changes the word (no ABA short of 2^63 writes inside one read).
//!
//! Memory-ordering argument (fence-based seqlock):
//!
//! - Writer: `compare_exchange(s, s + 1, Acquire, Relaxed)`, then a release
//!   fence, then relaxed data stores, then `store(s + 2, Release)`.
//! - Reader: `load(Acquire) == s` (even), relaxed data loads, an acquire
//!   fence, then `load(Relaxed)`.
//! - If any reader data load observes a store of a write that began after
//!   the reader's ticket, the writer's release fence synchronizes with the
//!   reader's acquire fence, so the writer's odd store happens-before the
//!   reader's validation load, which therefore cannot return `s`.
//! - The ticket's acquire load synchronizes with the release store that
//!   produced `s`, so every data store of the write that produced `s` is
//!   visible to the data loads.
//! - The writer's acquire compare-exchange synchronizes with the previous
//!   writer's release publication, so writers are totally ordered.

use core::sync::atomic::{AtomicU64, Ordering, fence};

/// Atomic 64-bit word backing [`SeqWord`] and [`SeqByteBuf`].
///
/// Implemented for [`core::sync::atomic::AtomicU64`] in production and for
/// Loom's `AtomicU64` wrappers under `#[cfg(all(test, feature = "loom"))]` in
/// test crates so Loom models exercise the production seqlock types without
/// changing `--all-features` ABI layouts.
pub trait SeqAtomic: Default {
    fn load(&self, order: Ordering) -> u64;
    fn store(&self, val: u64, order: Ordering);
    fn release_fence();
    fn acquire_fence();
    /// Back off while another writer holds the word (Loom yields here).
    #[inline]
    fn spin_loop() {
        core::hint::spin_loop();
    }
}

/// [`SeqAtomic`] words that can also serve as their own writer lock.
pub trait SeqLockAtomic: SeqAtomic {
    fn compare_exchange(
        &self,
        current: u64,
        new: u64,
        success: Ordering,
        failure: Ordering,
    ) -> Result<u64, u64>;
}

impl SeqAtomic for AtomicU64 {
    #[inline]
    fn load(&self, order: Ordering) -> u64 {
        AtomicU64::load(self, order)
    }

    #[inline]
    fn store(&self, val: u64, order: Ordering) {
        AtomicU64::store(self, val, order);
    }

    #[inline]
    fn release_fence() {
        fence(Ordering::Release);
    }

    #[inline]
    fn acquire_fence() {
        fence(Ordering::Acquire);
    }
}

impl SeqLockAtomic for AtomicU64 {
    #[inline]
    fn compare_exchange(
        &self,
        current: u64,
        new: u64,
        success: Ordering,
        failure: Ordering,
    ) -> Result<u64, u64> {
        AtomicU64::compare_exchange(self, current, new, success, failure)
    }
}

/// One shared-memory sequence word whose writers serialize externally.
///
/// Writers hold their own lock, call [`SeqWord::begin_write`] (storing an odd
/// sequence and issuing a release fence so subsequent relaxed stores cannot
/// be reordered before the odd transition), mutate the guarded atomic words
/// with relaxed stores, and finish with [`SeqWord::end_write`] (storing the
/// next even sequence with release ordering).
///
/// Readers call `load(Ordering::Acquire)`, reject odd values, perform only
/// relaxed atomic loads of the guarded words, and validate afterward with
/// [`SeqWord::unchanged_since`] (which issues an acquire fence before
/// re-reading the sequence word).
#[repr(transparent)]
#[derive(Debug, Default)]
pub struct SeqWord<A = AtomicU64>(A);

impl SeqWord<AtomicU64> {
    #[inline]
    pub const fn new() -> Self {
        Self(AtomicU64::new(0))
    }
}

impl<A: SeqAtomic> SeqWord<A> {
    #[inline]
    pub const fn from_atomic(atomic: A) -> Self {
        Self(atomic)
    }

    #[inline]
    pub fn load(&self, order: Ordering) -> u64 {
        self.0.load(order)
    }

    #[inline]
    pub fn begin_write(&self) {
        let seq = self.0.load(Ordering::Relaxed);
        self.0.store(seq | 1, Ordering::Relaxed);
        A::release_fence();
    }

    #[inline]
    pub fn end_write(&self) {
        let seq = self.0.load(Ordering::Relaxed);
        self.0.store((seq | 1).wrapping_add(1), Ordering::Release);
    }

    #[inline]
    pub fn unchanged_since(&self, seq: u64) -> bool {
        A::acquire_fence();
        self.0.load(Ordering::Relaxed) == seq
    }
}

/// An even sequence value a reader observed before copying guarded words.
///
/// Only [`ExclusiveSeq::read_begin`] constructs one, and only from an even
/// (no writer active) word.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SeqReadTicket(u64);

/// A sequence word that is also its own writer lock (see the module docs).
#[repr(transparent)]
#[derive(Debug, Default)]
pub struct ExclusiveSeq<A = AtomicU64>(A);

impl ExclusiveSeq<AtomicU64> {
    #[inline]
    pub const fn new() -> Self {
        Self(AtomicU64::new(0))
    }
}

impl<A: SeqLockAtomic> ExclusiveSeq<A> {
    #[inline]
    pub const fn from_atomic(atomic: A) -> Self {
        Self(atomic)
    }

    /// Start a read: `None` while a writer holds the word.
    #[inline]
    pub fn read_begin(&self) -> Option<SeqReadTicket> {
        let seq = self.0.load(Ordering::Acquire);
        (seq & 1 == 0).then_some(SeqReadTicket(seq))
    }

    /// Finish a read: `true` iff no write began since `ticket`, so every
    /// guarded word loaded between the two calls belongs to one publication.
    #[inline]
    pub fn validate(&self, ticket: SeqReadTicket) -> bool {
        A::acquire_fence();
        self.0.load(Ordering::Relaxed) == ticket.0
    }

    /// Claim the writer side, or `None` if another writer holds it.
    #[inline]
    pub fn try_write(&self) -> Option<SeqWriteGuard<'_, A>> {
        let seq = self.0.load(Ordering::Relaxed);
        if seq & 1 != 0 {
            return None;
        }
        self.0
            .compare_exchange(
                seq,
                seq.wrapping_add(1),
                Ordering::Acquire,
                Ordering::Relaxed,
            )
            .ok()?;
        A::release_fence();
        Some(SeqWriteGuard {
            word: &self.0,
            publish: seq.wrapping_add(2),
        })
    }

    /// Claim the writer side, backing off while another writer holds it.
    ///
    /// For writers whose peers are other short host critical sections (no
    /// writer blocks or calls out while holding the word).
    #[inline]
    pub fn write(&self) -> SeqWriteGuard<'_, A> {
        loop {
            if let Some(guard) = self.try_write() {
                return guard;
            }
            A::spin_loop();
        }
    }
}

/// Exclusive writer access to one [`ExclusiveSeq`]; publishes the next even
/// sequence on drop.
#[derive(Debug)]
#[must_use = "dropping the guard immediately publishes an empty write"]
pub struct SeqWriteGuard<'a, A: SeqAtomic = AtomicU64> {
    word: &'a A,
    publish: u64,
}

impl<A: SeqAtomic> Drop for SeqWriteGuard<'_, A> {
    #[inline]
    fn drop(&mut self) {
        self.word.store(self.publish, Ordering::Release);
    }
}

/// Fixed-capacity byte buffer stored as `WORDS` 64-bit atomic words (`WORDS * 8` bytes).
///
/// Readers and writers access bytes exclusively through relaxed atomic word
/// loads and stores inside a sequence section, so lock-free readers never
/// form a `&[u8]` reference over memory a concurrent writer may overwrite:
/// each word is loaded into a reader-owned register before it is compared
/// or copied.
#[repr(C)]
#[derive(Debug)]
pub struct SeqByteBuf<const WORDS: usize, A = AtomicU64>([A; WORDS]);

impl<const WORDS: usize> SeqByteBuf<WORDS, AtomicU64> {
    #[inline]
    pub const fn new() -> Self {
        Self([const { AtomicU64::new(0) }; WORDS])
    }
}

impl<const WORDS: usize, A: Default> Default for SeqByteBuf<WORDS, A> {
    #[inline]
    fn default() -> Self {
        Self(core::array::from_fn(|_| A::default()))
    }
}

impl<const WORDS: usize, A: SeqAtomic> SeqByteBuf<WORDS, A> {
    #[inline]
    pub const fn from_words(words: [A; WORDS]) -> Self {
        Self(words)
    }

    #[inline]
    pub const fn capacity_bytes() -> usize {
        WORDS.saturating_mul(core::mem::size_of::<u64>())
    }

    /// Write `src` into the buffer using relaxed 64-bit word stores.
    ///
    /// Returns `false` without mutating the buffer if `src.len()` exceeds
    /// [`Self::capacity_bytes`]. Callers must hold the writer side of the
    /// sequence word that guards this buffer.
    #[inline]
    pub fn write_slice(&self, src: &[u8]) -> bool {
        if src.len() > Self::capacity_bytes() {
            return false;
        }
        for (slot, chunk) in self.0.iter().zip(src.chunks(8)) {
            let mut word_bytes = [0u8; 8];
            if let Some(prefix) = word_bytes.get_mut(..chunk.len()) {
                prefix.copy_from_slice(chunk);
            }
            slot.store(u64::from_le_bytes(word_bytes), Ordering::Relaxed);
        }
        true
    }

    /// Copy `dst.len()` bytes out of the buffer using relaxed 64-bit word loads.
    ///
    /// Returns `false` if `dst.len()` exceeds [`Self::capacity_bytes`]. Callers
    /// must validate the guarding sequence word after this call before
    /// trusting the contents of `dst`.
    #[inline]
    pub fn read_into(&self, dst: &mut [u8]) -> bool {
        if dst.len() > Self::capacity_bytes() {
            return false;
        }
        for (slot, out) in self.0.iter().zip(dst.chunks_mut(8)) {
            let word_bytes = slot.load(Ordering::Relaxed).to_le_bytes();
            if let Some(prefix) = word_bytes.get(..out.len()) {
                out.copy_from_slice(prefix);
            }
        }
        true
    }

    /// Compare the first `expected.len()` bytes against `expected`, loading
    /// each word into a reader-owned value (no stack copy of the buffer).
    ///
    /// Returns `false` if `expected.len()` exceeds [`Self::capacity_bytes`] or
    /// any byte differs. Callers must still validate the guarding sequence
    /// word after a `true` return before trusting the match.
    #[inline]
    pub fn eq_slice(&self, expected: &[u8]) -> bool {
        if expected.len() > Self::capacity_bytes() {
            return false;
        }
        for (slot, chunk) in self.0.iter().zip(expected.chunks(8)) {
            let word_bytes = slot.load(Ordering::Relaxed).to_le_bytes();
            if word_bytes.get(..chunk.len()) != Some(chunk) {
                return false;
            }
        }
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn seq_word_transitions_odd_during_write_and_advances_even_on_end() {
        let seq = SeqWord::new();
        assert_eq!(seq.load(Ordering::Acquire), 0);
        assert!(seq.unchanged_since(0));

        seq.begin_write();
        let odd = seq.load(Ordering::Acquire);
        assert_eq!(odd, 1);
        assert!(!seq.unchanged_since(0));

        seq.end_write();
        let even = seq.load(Ordering::Acquire);
        assert_eq!(even, 2);
        assert!(!seq.unchanged_since(0));
        assert!(seq.unchanged_since(2));

        // Wraparound from u64::MAX - 1 -> u64::MAX -> 0 stays panic-free and even.
        let near_max = SeqWord::from_atomic(AtomicU64::new(u64::MAX - 1));
        near_max.begin_write();
        assert_eq!(near_max.load(Ordering::Acquire), u64::MAX);
        near_max.end_write();
        assert_eq!(near_max.load(Ordering::Acquire), 0);
    }

    #[test]
    fn exclusive_seq_excludes_writers_and_rejects_a_ticket_across_any_write() {
        let seq = ExclusiveSeq::new();
        let ticket = seq.read_begin().expect("even word yields a ticket");
        assert!(seq.validate(ticket));

        let guard = seq.try_write().expect("first writer claims the word");
        // A second writer and a new reader both see the claim.
        assert!(seq.try_write().is_none());
        assert!(seq.read_begin().is_none());
        assert!(!seq.validate(ticket));
        drop(guard);

        // Invalidate-then-refill: two complete writes after the ticket. The
        // word never returns to the ticket's value, so the ABA is refused.
        drop(seq.write());
        assert!(!seq.validate(ticket));
        let fresh = seq.read_begin().expect("published word is even");
        assert_ne!(fresh, ticket);
        assert!(seq.validate(fresh));

        // Wraparound stays even and panic-free.
        let near_max = ExclusiveSeq::from_atomic(AtomicU64::new(u64::MAX - 1));
        let before = near_max.read_begin().expect("even");
        drop(near_max.write());
        assert!(!near_max.validate(before));
        assert!(near_max.read_begin().is_some());
    }

    #[test]
    fn seq_byte_buf_round_trips_and_compares_all_word_boundaries() {
        let buf = SeqByteBuf::<32>::new();
        assert_eq!(SeqByteBuf::<32>::capacity_bytes(), 256);

        let mut pattern = [0u8; 257];
        for (i, b) in pattern.iter_mut().enumerate() {
            *b = (i as u8).wrapping_mul(37).wrapping_add(11);
        }

        assert!(!buf.write_slice(&pattern));
        assert!(!buf.eq_slice(&pattern));
        let mut oversized = [0u8; 257];
        assert!(!buf.read_into(&mut oversized));

        // Write full 256 bytes first, then overwrite with shorter slices to
        // verify partial trailing words do not corrupt shorter comparisons/reads.
        for &len in &[256usize, 255, 17, 16, 15, 9, 8, 7, 1, 0] {
            let slice = &pattern[..len];
            assert!(buf.write_slice(slice));
            assert!(buf.eq_slice(slice));

            let mut out = [0xee_u8; 256];
            assert!(buf.read_into(&mut out[..len]));
            assert_eq!(&out[..len], slice);

            if len > 0 {
                let mut mutated = [0u8; 256];
                mutated[..len].copy_from_slice(slice);
                mutated[len - 1] ^= 0x01;
                assert!(!buf.eq_slice(&mutated[..len]));

                mutated[len - 1] = slice[len - 1];
                mutated[0] ^= 0x80;
                assert!(!buf.eq_slice(&mutated[..len]));
            }
        }
    }
}
