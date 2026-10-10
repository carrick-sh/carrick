//! Native address-context custody retained for each admitted MM.
//! This stores architecture incarnations, never process rows or MM policy.
use carrick_guest_arch::{AddressContext, MmGeneration, RootGpa};
extern crate alloc;
use alloc::collections::BTreeMap;
use core::num::NonZeroU64;

#[derive(Clone, Copy, Eq, PartialEq, Ord, PartialOrd)]
struct ContextMm(NonZeroU64);

/// Live contexts by MM. A root has at most one live owner; the check scans
/// the live MMs (bounded by the address-space table) at admission only.
#[derive(Default)]
pub struct LiveContexts {
    by_mm: BTreeMap<ContextMm, AddressContext<RootGpa>>,
}

impl LiveContexts {
    pub const fn new() -> Self {
        Self {
            by_mm: BTreeMap::new(),
        }
    }
    pub fn admit(&mut self, context: AddressContext<RootGpa>) -> bool {
        let mm = ContextMm(context.mm.raw());
        if let Some(existing) = self.by_mm.get(&mm) {
            return *existing == context;
        }
        if self.by_mm.values().any(|live| live.root == context.root) {
            return false;
        }
        self.by_mm.insert(mm, context);
        true
    }
    /// Forget a retired fork child's live context. Its root page returns to
    /// the carrier's fork stock and may be loaned to the next child, whose
    /// admission must then succeed; the retired MM never authenticates
    /// again. False (and nothing removed) unless `mm` is live on `root`.
    pub fn retire(&mut self, mm: MmGeneration, root: RootGpa) -> bool {
        if self.authenticate(mm, root).is_none() {
            return false;
        }
        self.by_mm.remove(&ContextMm(mm.raw()));
        true
    }
    pub fn authenticate(&self, mm: MmGeneration, root: RootGpa) -> Option<AddressContext<RootGpa>> {
        self.by_mm
            .get(&ContextMm(mm.raw()))
            .copied()
            .filter(|context| context.root == root)
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;
    use carrick_guest_arch::{ContextGeneration, FrameGpa};
    use core::num::NonZeroU64;
    fn context(mm: u64, root: u64) -> AddressContext<RootGpa> {
        AddressContext {
            mm: MmGeneration::new(NonZeroU64::new(mm).unwrap()),
            root: RootGpa::page_aligned(FrameGpa::new(root)).unwrap(),
            generation: ContextGeneration::new(NonZeroU64::MIN),
        }
    }
    #[test]
    fn two_live_native_contexts_keep_exact_roots() {
        let parent = context(11, 0x1000);
        let child = context(12, 0x2000);
        let mut contexts = LiveContexts::new();
        assert!(contexts.admit(parent));
        assert!(contexts.admit(child));
        assert_eq!(contexts.authenticate(parent.mm, parent.root), Some(parent));
        assert_eq!(contexts.authenticate(child.mm, child.root), Some(child));
        assert_eq!(contexts.authenticate(parent.mm, child.root), None);
        assert_eq!(contexts.authenticate(child.mm, parent.root), None);
        assert!(!contexts.admit(context(13, parent.root.address().raw())));
        assert!(!contexts.admit(context(11, 0x3000)));
        assert_eq!(contexts.authenticate(parent.mm, parent.root), Some(parent));
    }

    /// Fork stock reuse: a retired child's root page is loaned to the next
    /// child. Its context must be admitted, or that child's first syscall
    /// capture finds no live context for its MM.
    #[test]
    fn retired_child_root_is_admitted_for_the_next_child() {
        let parent = context(11, 0x1000);
        let first = context(12, 0x2000);
        let second = context(13, 0x2000);
        let mut contexts = LiveContexts::new();
        assert!(contexts.admit(parent));
        assert!(contexts.admit(first));
        assert!(!contexts.admit(second), "a live root has one owner");
        // Only the live MM on its own root retires.
        assert!(!contexts.retire(first.mm, context(12, 0x3000).root));
        assert!(contexts.retire(first.mm, first.root));
        assert!(!contexts.retire(first.mm, first.root));
        assert_eq!(contexts.authenticate(first.mm, first.root), None);
        assert!(contexts.admit(second));
        assert_eq!(contexts.authenticate(second.mm, second.root), Some(second));
        assert_eq!(contexts.authenticate(parent.mm, parent.root), Some(parent));
    }
}
