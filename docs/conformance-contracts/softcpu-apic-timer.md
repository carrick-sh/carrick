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

KVM parity moves to a follow-up PR to keep this slice reviewable. The two-vCPU
SoftMachine fixture remains here. Full kernel/carrier and signed end-to-end
acceptance remain outside this VM-free slice.

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

Review regressions, all in the `softcpu_apic_timer` bindings:

- Before width guards, LIDT, FXRSTOR, FRSTOR and IDT-gate tests panicked on
  10, 512, 108 and 16-byte slices. The FP-operand test aborted on a 16-byte
  slice. All five now return guest #GP(0).
- The SSE page-crossing test returned #PF before the JIT fix; it now returns
  #GP(0). The single-page SSE load already returned #GP and stays covered.
- The reset-deadline test read back 2000 instead of zero before removing
  `lvt_timer_written`. It now reads zero and cannot fire after a mode switch.
- The timer HLT test waits for enrollment under the APIC mutex before
  advancing time. Omitting publication fails its bounded five-second
  assertion. Restoring it passes, without sleeps. The before-enrollment
  case proves an already-passed deadline returns without parking.

The crate suites and two-vCPU fixture pass; there are no `serial_host` cases.
Delivery modes, cluster broadcast, stale-kick HLT cost and KVM parity remain follow-ups.
