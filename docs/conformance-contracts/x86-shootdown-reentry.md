# X86 retained shootdown debt (`x86-shootdown-reentry`)

Surface: shared-MM page retirement on two live x86 KVM CPUs. Architectural
translation coherence requires a CPU to drain its old non-global translations
before using the edited address space. Carrick retains exact root/MM owner and
request generation; a stopped CPU can owe a published generation, but cannot
use that translation on reentry before native KICK settlement. A user #PF must
settle already published debt before reporting its fault doorbell.

The cheapest capable binding is the real KVM `cpl0_entry` fixture: the reader
warms the retired leaf, then signals running admission while waiting on a
fixture control byte. The selected hold releases that byte only after the
editor's unmap reaches rendezvous. The reader faults on a never-mapped address,
so neither forced ordering depends on incidental eviction of the warmed TLB.
Hold IPI until the first fault word to force fault-entry settlement; hold
publication until the complete record stops the reader to force reentry debt.
The latter must owe exactly generation 2 after serving generation 1, and must
serve generation 2 and increment the native KICK check once on reentry. The
original two-running-CPU fixture checks either exact served settlement or this
exact stopped debt followed by settlement. The retired-page load must fault.
The existing stopped CPL3 and CPL0 fixtures additionally witness absence of
stale bytes after reentry into either privilege level.

Budget: two CPUs, one editor and one reader, no retry, at most 32 editor exits,
fifteen fault words, and five seconds per guest interval and ordering hold.
The terminal fixture fault suffix emits one completion exit after unmasking
KICK; production keeps its terminal halt and contains no fixture hold polling.
No VM-free runner can witness real TLB contents. HVF signed execution and Docker
are outside this x86 KVM binding; this lane uses `CARRICK_REQUIRE_KVM=1`.
