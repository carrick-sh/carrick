//! ISA-neutral access to a live stage-1 descriptor graph.

use crate::descriptor_refusal::DescriptorRefusal;

/// Hardware access to one live stage-1 table graph by table physical address.
pub trait LiveDescriptorWords {
    /// Load one descriptor; reject addresses outside the admitted table arena.
    fn load(&self, pa: u64) -> Result<u64, DescriptorRefusal>;
    /// Replace exactly `current` by `new`; false means editor exclusion failed.
    fn compare_exchange(&self, pa: u64, current: u64, new: u64) -> Result<bool, DescriptorRefusal>;
    /// Store into a granted table page unreachable by hardware walkers.
    fn store_unlinked(&self, pa: u64, value: u64) -> Result<(), DescriptorRefusal>;
    /// Make earlier stores visible to table walkers before linking the page.
    fn publish_barrier(&self);
    /// Invalidate this MM's translation for `[va, va + len)`.
    fn invalidate_range(&self, va: u64, len: u64);

    /// Opt in to scanning residency occupancy after a failed publication.
    fn observe_residency_failure(&self) -> bool {
        false
    }

    fn descriptor_diagnostic(&self, _event: DescriptorDiagnostic) {}
}

/// Where a descriptor plan stopped. A failed walk reports work counted so far.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum DescriptorPlanRefusalSite {
    Walk = 1,
    TableGrants = 2,
    JournalReserve = 3,
    Apply = 4,
}

/// Read-only observations from the live descriptor and grant executors.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DescriptorDiagnostic {
    ResidencyPublishedBeforeRefusal,
    PlanRefused {
        site: DescriptorPlanRefusalSite,
        reason: DescriptorRefusal,
        op_kind: u64,
        live_stores: usize,
        table_grants: usize,
    },
    ResidencyRefused {
        mm_key: u64,
        va: u64,
        len: u64,
        slots_used: usize,
        slots_total: usize,
    },
}

/// Attach an operation-scoped observer to the same live words and editor.
pub struct ObservedDescriptorWords<'a, W: ?Sized> {
    pub words: &'a W,
    pub observe: Option<&'a dyn Fn(DescriptorDiagnostic)>,
}

impl<W: LiveDescriptorWords + ?Sized> LiveDescriptorWords for ObservedDescriptorWords<'_, W> {
    fn load(&self, pa: u64) -> Result<u64, DescriptorRefusal> {
        self.words.load(pa)
    }

    fn compare_exchange(&self, pa: u64, current: u64, new: u64) -> Result<bool, DescriptorRefusal> {
        self.words.compare_exchange(pa, current, new)
    }

    fn store_unlinked(&self, pa: u64, value: u64) -> Result<(), DescriptorRefusal> {
        self.words.store_unlinked(pa, value)
    }

    fn publish_barrier(&self) {
        self.words.publish_barrier();
    }

    fn invalidate_range(&self, va: u64, len: u64) {
        self.words.invalidate_range(va, len);
    }

    fn observe_residency_failure(&self) -> bool {
        self.observe.is_some()
    }

    fn descriptor_diagnostic(&self, event: DescriptorDiagnostic) {
        if let Some(observe) = self.observe {
            observe(event);
        }
    }
}

/// What the exact grant executor observed before publishing the refusal.
/// The event is optional because earlier authorization checks can refuse
/// without entering the descriptor planner or residency publisher.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct GrantRefusalTrace {
    pub residency_published: bool,
    pub event: Option<DescriptorDiagnostic>,
}

impl GrantRefusalTrace {
    pub fn record(&mut self, event: DescriptorDiagnostic) {
        match event {
            DescriptorDiagnostic::ResidencyPublishedBeforeRefusal => {
                self.residency_published = true
            }
            _ => self.event = Some(event),
        }
    }

    pub(crate) fn words(self) -> [u64; 7] {
        let [kind, a, b, c, d, e] = match self.event {
            Some(DescriptorDiagnostic::PlanRefused {
                site,
                reason,
                op_kind,
                live_stores,
                table_grants,
            }) => [
                1,
                site as u64,
                reason as u64,
                op_kind,
                live_stores as u64,
                table_grants as u64,
            ],
            Some(DescriptorDiagnostic::ResidencyRefused {
                mm_key,
                va,
                len,
                slots_used,
                slots_total,
            }) => [2, mm_key, va, len, slots_used as u64, slots_total as u64],
            _ => [0; 6],
        };
        [1 + u64::from(self.residency_published), kind, a, b, c, d, e]
    }

    pub(crate) fn decode([published, kind, a, b, c, d, e]: [u64; 7]) -> Option<Self> {
        let residency_published = match published {
            1 => false,
            2 => true,
            _ => return None,
        };
        let event = match kind {
            0 => None,
            1 => Some(DescriptorDiagnostic::PlanRefused {
                site: match a {
                    1 => DescriptorPlanRefusalSite::Walk,
                    2 => DescriptorPlanRefusalSite::TableGrants,
                    3 => DescriptorPlanRefusalSite::JournalReserve,
                    4 => DescriptorPlanRefusalSite::Apply,
                    _ => return None,
                },
                reason: DescriptorRefusal::from_code(u32::try_from(b).ok()?)?,
                op_kind: c,
                live_stores: usize::try_from(d).ok()?,
                table_grants: usize::try_from(e).ok()?,
            }),
            2 => Some(DescriptorDiagnostic::ResidencyRefused {
                mm_key: a,
                va: b,
                len: c,
                slots_used: usize::try_from(d).ok()?,
                slots_total: usize::try_from(e).ok()?,
            }),
            _ => return None,
        };
        Some(Self {
            residency_published,
            event,
        })
    }
}
