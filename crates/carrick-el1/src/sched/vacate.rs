//! The idle-exit seal and its sole constructor. Sibling scheduler modules
//! cannot manufacture the proof without performing the leave transition.
use crate::substrate::sched::ThreadCpu;
use carrick_el1_abi::{SlotId, ZoneTables};

/// Leave a process's translations before releasing its installed occupancy.
/// Service handoffs, scheduler idling and every idle exit to the host
/// ([`super::El1Exit::Idle`]) use the same ordered transition. The result is the
/// only constructor of [`VacatedSlot`].
pub fn leave_space(zone: &ZoneTables, slot: SlotId, cpu: &mut impl ThreadCpu) -> VacatedSlot {
    if zone.installed_space(slot) == 0 {
        return VacatedSlot { slot };
    }
    let idle = zone.spaces.idle_ttbr();
    if idle == 0 {
        // No maintenance root is published, so EL1 never installed a space
        // here (`enter_space` refuses without one): the word is a host
        // installer's, released by its own occupancy.
        return VacatedSlot { slot };
    }
    cpu.set_translation(idle, idle);
    zone.release_space(slot);
    VacatedSlot { slot }
}

/// Proof that EL1 has relinquished its installed space on `slot`.
/// When a nonzero occupancy word and a maintenance root are published, the
/// transition installs that root before clearing the word. An already vacant
/// word is accepted without reading the live root; the host owns initial root
/// setup. Without a maintenance root, `enter_space` cannot install a space and
/// this leaves any host-owned word untouched. This is not proof of a hardware
/// root observation or of vacancy in that host-owned case. Only
/// [`leave_space`] builds one; neither `Clone` nor `Copy`.
///
/// ```compile_fail,E0451
/// use carrick_el1::substrate::sched::VacatedSlot;
/// use carrick_el1_abi::SlotId;
/// let forged = VacatedSlot { slot: SlotId::new(0) };
/// ```
///
/// #1100: an idle exit that kept the word let the host's idle entry rewrite
/// the vCPU's root to the maintenance root under a word still naming the
/// space, and the next switch-in trusted the word and ran on the wrong root.
#[must_use]
#[derive(Debug, Eq, PartialEq)]
pub struct VacatedSlot {
    slot: SlotId,
}

impl VacatedSlot {
    pub fn slot(&self) -> SlotId {
        self.slot
    }
}
