# Anonymous memory calls on both ISAs (#1095)

The shared reservation decoder, pending completion authentication and resident
permission/retirement entry points consume `AnonymousCallView`. ARM projects its
real `TrapFrame`; CPL0 retains a decoded `CanonicalCall`, CPU slot, return PC
and independent result word. The latter projects one task at index zero while
retaining its actual CPU slot for editor ownership. No ARM register frame is
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
cannot be claimed from the inspected snapshot alone. The direct venue hooks
now use the same resident entry points as ARM. Under the exact-MM guard, those
entry points bind a synchronous operation generation before entering the x86
transaction; the delegated path retains its reservation sequence. Neither token
replaces the existing invalidation or physical-return authority.

The native projected-task witness also checks that CPU slot 7 owns editor 8
while looking up task slice index zero, and that both resident entry points
bind an operation generation before editing. Applied to admitted-main entry
point signatures, the native view is rejected with E0308 (`&TrapFrame`
required). This is an API red witness, not a reproduced runtime ENOSYS.

The KVM binding checks successful edits and errno answers, surviving outer
pages, and exact-PC SIGSEGV with the expected x86 P/W/U bits for a forbidden
write and a retired-page read. It requires zero host forwards, zero relevant
refusals and zero `CARRICK_CPL0_ISA_UNSUPPORTED_FORWARDS`, read atomically from
the symbol in the loaded production image. The resident x86 venue hooks remain
compile/inspection covered: all production initial MMs use the delegated owner.
