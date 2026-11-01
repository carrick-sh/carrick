# Anonymous memory calls on both ISAs (#1095)

The shared reservation decoder, pending completion authentication and resident
permission/retirement entry points consume `AnonymousCallView`. ARM projects its
real `TrapFrame`; CPL0 retains a decoded `CanonicalCall`, CPU slot, return PC
and independent result word. The latter carries an explicit task-slice index
independently of the CPU slot. The x86 venue projects its single task at index
zero while retaining its actual CPU slot for editor ownership. No ARM register frame is
constructed by the x86 anonymous venue.

The semantic authorities are mprotect(2) and munmap(2), under the existing
`kernel.el1.anonymous-permissions`, `kernel.el1.anonymous-munmap` and
`kernel.el1.anonymous-reservations` contracts. There is one reservation owner
and one descriptor transaction per resident range edit. No host service is
introduced for either syscall. The existing `InitialWords` descriptor venue
publishes invalidation through the retained x86 root rendezvous when another
CPU is live, or the `MmuBackend` request/drain receipt otherwise. Physical
returns remain journaled until the existing inventory settlement.

The VM-free two-ISA binding runs the real shared reservation entry point with
both native decoders. It narrows a three-page private mapping, removes its
middle page, and checks EINVAL (22) and ENOMEM (12). A second live task in the
same MM observes the committed permission and split reservation state from a
bounded host thread. The same peer reads real fixture backing through live
production descriptor walkers, requires write denial after narrowing, and
requires the removed middle page to be inaccessible while both outer pages
remain readable. The shared engine drives the production ARM permission/retire
functions and x86 descriptor transaction engine over retained atomic tables.
Descriptor calls and operation sequences are counted; invalid calls must make
no descriptor calls. Exactly two modeled drains cover the two successful edits.
This proves descriptor and backing visibility, not hardware TLB contents;
real CPU instruction execution and retained shootdown remain the KVM binding.

Admitted main already serves delegated protect and retire operations in the
shared engine. Thus the issue's original unconditional-x86-ENOSYS diagnosis
cannot be claimed from the inspected snapshot alone. The non-delegated x86
venue hooks refuse before editing and increment
CARRICK_CPL0_ANONYMOUS_HOOK_REFUSALS. They cannot
produce CommitOwed: x86 has no host consumer for that obligation.

The x86 peer fixture and production X86AnonymousEditor share
edit_x86_anonymous, including intent admission and descriptor execution.
InitialWords::invalidate_range remains the production invalidation path.
Migration to mm::retirement ServedTable/StagedInvalidation remains
[#681 slice 5](https://github.com/carrick-sh/carrick/issues/681); this refactor
does not satisfy that acceptance item. The ARM drain count is a fixture
completion marker, not an invalidation witness.

The native projected-task witness also checks that CPU slot 7 owns editor 8
while looking up task slice index one, and that both resident entry points
bind an operation generation before editing. Applied to admitted-main entry
point signatures, the native view is rejected with E0308 (`&TrapFrame`
required). This is an API red witness, not a reproduced runtime ENOSYS.

The existing KVM binding is not runtime evidence for this refactor. No KVM,
HVF, hardware TLB or runtime behavior was verified in this follow-up.
Sparse munmap, PROT_NONE, partly mapped ranges and two-vCPU behavior remain
deferred on #1095. This work references that issue without closing it.
