//! Test-only fixture support for the native process runtime.

use super::*;

/// Existing low-level fixtures publish identities directly. Supply their
/// claims explicitly in fixture setup, never during production admission.
#[allow(clippy::unwrap_used)]
pub(crate) fn seed_fixture_namespace<C: ProcessContext>(
    zone: &ZoneTables<C>,
    current: &CurrentTask,
    page: &ThreadLifecyclePage,
) {
    let binding = crate::common_entry::execution_binding(current);
    zone.namespace()
        .with_view(&carrick_sched_core::ShortLockSpin, |ns| {
            let root = binding.task.raw() as i32;
            let domain = ns.visible_domain(root).unwrap_or_else(|| {
                VisibleNamespace::new(NonZeroU32::new(root as u32).unwrap(), NonZeroU32::MIN)
            });
            let first = ns.counts().reserved_numbers == 0;
            if !ns.is_reserved_number(root) {
                ns.reserve_exact(root, ClaimKind::Task).unwrap();
                if first {
                    ns.set_next(root.checked_add(1).unwrap());
                }
            }
            ns.bind_visible_domain(root, domain).unwrap();
            ns.advance_visible_past(
                domain,
                VisibleIdentity::from_existing_member(
                    NonZeroU32::new(current.visible_pid().unwrap()).unwrap(),
                ),
            )
            .unwrap();
            for index in 0..page.entry_count() {
                let Some((generation, state)) = page.state(index) else {
                    continue;
                };
                if !matches!(
                    state,
                    carrick_el1_abi::EntryState::Born | carrick_el1_abi::EntryState::Published
                ) {
                    continue;
                }
                let entry = EntryRef::new(index as u32, generation);
                let Some(identity) = page.identity(entry) else {
                    continue;
                };
                if identity.tid == 0 {
                    continue;
                }
                if !ns.is_reserved_number(identity.tid as i32) {
                    ns.reserve_exact(identity.tid as i32, ClaimKind::Thread)
                        .unwrap();
                }
                ns.bind_visible_domain(identity.tid as i32, domain).unwrap();
                if let Some(visible) = NonZeroU32::new(identity.visible_tid) {
                    ns.advance_visible_past(domain, VisibleIdentity::from_existing_member(visible))
                        .unwrap();
                }
            }
        });
}

#[cfg(test)]
impl<'a, M: Clone, C: ProcessContext> NativeProcessRegistry<'a, M, C> {
    /// Release all registrations before a fixture returns its metadata mappings.
    #[cfg(not(target_os = "macos"))]
    pub(crate) fn unregister_zone_for_test(&self, zone: &ZoneTables<C>) {
        let carrier = core::ptr::from_ref(zone).addr();
        let groups: Vec<_> = self
            .state
            .lock()
            .groups
            .iter()
            .filter(|(key, _)| key.0 == carrier)
            .map(|(_, (runtime, process))| (runtime.clone(), *process))
            .collect();
        for (runtime, process) in groups {
            self.unregister_process(&runtime, process);
        }
    }
}
