//! Native address-context custody retained for each admitted MM.
//! This stores architecture incarnations, never process rows or MM policy.
use carrick_guest_arch::{AddressContext, MmGeneration, RootGpa};
extern crate alloc;
use alloc::collections::BTreeMap;
use core::num::NonZeroU64;

#[derive(Clone, Copy, Eq, PartialEq, Ord, PartialOrd)]
struct ContextMm(NonZeroU64);
#[derive(Clone, Copy, Eq, PartialEq, Ord, PartialOrd)]
struct ContextRoot(u64);

#[derive(Default)]
pub struct LiveContexts {
    by_mm: BTreeMap<ContextMm, AddressContext<RootGpa>>,
    root_owner: BTreeMap<ContextRoot, ContextMm>,
}

impl LiveContexts {
    pub const fn new() -> Self {
        Self {
            by_mm: BTreeMap::new(),
            root_owner: BTreeMap::new(),
        }
    }
    pub fn admit(&mut self, context: AddressContext<RootGpa>) -> bool {
        let mm = ContextMm(context.mm.raw());
        let root = ContextRoot(context.root.address().raw());
        if let Some(existing) = self.by_mm.get(&mm) {
            return *existing == context;
        }
        if self.root_owner.contains_key(&root) {
            return false;
        }
        self.root_owner.insert(root, mm);
        self.by_mm.insert(mm, context);
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
}
