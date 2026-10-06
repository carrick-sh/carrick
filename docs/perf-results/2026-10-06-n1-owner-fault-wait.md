# N1 owner-fault admission wait

Base: `f365c35dc685f8c6e309687c5915a8e31b33295f`. This repair has no
signed verdict yet and does not establish parity with main `65098ea0e`.
The last exact signed stack, `fa98b9f9c`, remains red.

## Retained observation and root cause

Evidence lives under `/Volumes/carrick-build/evidence/n1-cm/`.
`fork-fa98b9f9c/first-remaining-fault.core` belongs to the retained signed
`artifacts/s5-el1_sched`; its carrier ring has 264 records and no read errors.
The fault is an MM5/TID17 TLS store at PC `0x29c604`, FAR `0x600041bbf8`.
Its stage-1 walk ends at an invalid level-2 descriptor, and the exact own
mailbox is DENIED for request 19. These are actual values, not a coherence
diagnosis.

Offline LLDB identified executor 0's engine `0x1710edc10`, MM5, with no
suspended EL1 stack. Its own service frame at host `0x10a99fce0` contains
ESR `0x43524d4d47520004` (`MM_PORTAL_GRANT_ESR`), slot 0, and
`x0=11, x14=3, x16=1, x17=84`: an Editor wait at revision 84.
`fault-retained-service-frame.json` retains all 36 frame words.
`fault-native-mailboxes.json` retains the matching fault and selection
generation 19. The older descriptor receipt in that grant slot is not the
current refusal and is not used to diagnose it.

The production owner-fault completion withdrew an unclaimed grant and
discarded the returned frame, lowering every such outcome to Refused. The
existing user-transfer completion already released speculative physical
custody and preserved this exact typed notification. The runtime also
recognized only Resolved/physical Pending when clearing the fault mailbox.
It had no fault-specific continuation for an owner notification.

The director was informed before changing this shared fault path. No
anonymous-brk, copyout policy, file-table lease, clone-TID or clear-child-tid
behavior changed. The terminal continuation remains a separate origin.

## Repair and contract

The native fault completion now uses the same unclaimed-grant decoder as
user transfer. Withdrawal and grant release precede wait handoff; descriptor
receipt settlement and its trace phases remain unchanged. Runtime completion
requires the wait's MM to equal the claimed request before clearing that exact
mailbox, and never publishes DENIED for admission contention.

The existing authenticated owner queue parks a host-only object record. A
distinct Fault continuation owns the exact thread/MM/execution generation,
without a syscall request, return value or restart. Ordinary saved CPU state
remains authoritative; no ZoneSave or guest register rewriting is introduced.
The existing ZoneWait cancels an unconsumed record on capture failure; the
existing consumer owns its one completion and free. A reserved signal crosses
completion and is serviced immediately at the saved fault boundary.

Contract: `kernel.el1.anonymous-first-touch`, with existing fork bindings.
Admission contention cannot turn an accessible Linux mapping into SIGSEGV.
One exact producer enrollment replaces refusal; no polling, retries,
serialization, wider timeouts, changed scale points or changed budgets.

## Red-first evidence

Under `main-match-20261005/`:

| Receipt | Behavioral negative |
| --- | --- |
| `fault-owner-wait-red.log` | Extracted unchanged native fault completion loses the Editor wait. |
| `fault-owner-response-red.log` | The runtime publishes DENIED for the newly carried owner wait. |
| `fault-owner-mm-red.log` | Before the boundary check, another live MM completes this fault wait. |
| `fault-owner-signal-red.log` | Removing only reservation retention loses the fault wake's signal. |

Compiler-error attempts are retained separately and confer no red or green
claim. The signal control is a reversal of the new handoff, not a claim that
the old stack already had a fault continuation.

Restored verification receipts are in `fault-owner-verify/`; final verification
after the MM check and signal reversal is in `fault-owner-final-verify/`:
two native completion tests, three fault continuation tests, 703 nonserial
runtime tests and six serial runtime tests pass (nine existing ignored).
Earlier wider verification also passes all 119 AArch64 tests, both neighboring
terminal captures, and the existing release-before-enrollment, exact-release
and closed-grant-gate witnesses. Contract validation reports 98 contracts,
16 claims and 175 surfaces; fmt-check and workspace all-target clippy pass.
Their layer is
VM-free: live EL0/MMU execution, fault retry across executor migration,
live signal delivery and signed main-result parity remain unqualified.

The earlier retained external owner-fault trace is incomplete and conveys no
closure. It also contains physical-binding declines not explained by this
repair. Fresh signed evidence must establish the next first failure rather
than assuming one correction covers every fork failure.
