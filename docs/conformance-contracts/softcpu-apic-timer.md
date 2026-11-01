# Software x86 local APIC and timer

`x86.softcpu.apic-timer` covers the xAPIC MMIO registers and fixed IPIs that
CPL0 code uses, interrupt priority and EOI, initial-count timers, and the
absolute `IA32_TSC_DEADLINE` timer. The clock is injectable; normal execution
uses the same monotonic clock for TSC reads and bounded HLT deadline waits.
A guest TSC write changes the guest offset, so a wait converts its deadline
back to the underlying clock's domain.

The VM-free tests execute CPL0 instructions through `SoftMachine`, including
MMIO loads/stores, CR8, WRMSR, STI, HLT and IRETQ. A periodic timer that misses
1, 1,000 or 1,000,000,000 periods must latch exactly one expiration and compute
the next deadline without replaying expired periods.

The two-vCPU fixture runs two live soft machines on host threads. The AP
announces APIC readiness through a PIO exit before the BSP starts; it then
waits for a guest-programmed IPI and returns a pong. Each CPU writes separate
scratch words, and the host reads the population only after joining both.
RAM is aligned atomic-backed storage retained by both memory handles. Page
tables are fixed; this fixture does not prove shared mutable page-table
retirement or cross-CPU TLB shootdown (#607).

`softcpu_apic_kvm` is a separate required KVM target. It runs the identical
image and compares every scratch result with SoftMachine. A ten-second
isolated-process bound covers blocking KVM_RUN and both joins. An inaccessible
KVM device fails that target; it never turns a SoftMachine result into a KVM
parity claim. Full kernel/carrier and signed end-to-end acceptance remain
outside this VM-free slice.

The resumed checkpoint did not compile against the current SoftMMU API.
After porting the fixtures, red-first tests observed a wait deadline of 6000
instead of 2000 after a guest TSC write, and an AP that ran beyond its HLT
without receiving an IPI, leaving the BSP halted. The fixes preserve parked
state and convert the deadline to the clock domain. Existing IDT fixtures
explicitly clear halted state when starting a fresh scenario.

Additional red-first reductions showed that CLI followed by HLT resumed with a
pending maskable IPI even though IF was clear, and lowest-priority delivery
broadcast to both CPUs. The HLT gate now requires IF; lowest-priority delivery
selects one enabled destination by its published PPR class, with APIC ID as a
deterministic tie break. A notification-race test forces a clock event between
the initial probe and mutex enrollment and requires the enrolled predicate to
observe it.
