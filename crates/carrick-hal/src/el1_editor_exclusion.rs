//! Borrow-only proof that the host holds an MM's guest EL1 editor exclusion.
//!
//! The value lives in the foundational guest-memory crate so the mutation
//! interface can require it without introducing a HAL dependency cycle.

pub use carrick_guest_mem::{El1EditorExcluded, HeldEl1EditorExclusion};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn registered_exclusion_lends_only_its_exact_borrow() {
        let spaces = Box::new(carrick_sched_core::AddressSpaces::new());
        let index = spaces.publish_closed(41, 0x1000, 0).expect("publish");
        let excluded = spaces.raise_and_wait_for_editor(index, || {});
        let held = HeldEl1EditorExclusion::register(&excluded);
        assert_eq!(held.mm(), 41);
        assert_eq!(held.license().mm(), 41);
        std::thread::scope(|scope| {
            scope
                .spawn(|| assert_eq!(held.license().mm(), 41))
                .join()
                .unwrap();
        });
        drop(held);
        spaces.lower(index);
    }
}
