# Exec admission custody (`process.exec.custody`)

The ARM slot-reuse witness also drives `prepare_adoption` and
`finish_exec_successor` with a real admitted notification source. It was red
at the raw gate-open assertion after slice 3. The production finish path
must open through its existing release venue, advance the Gate revision once
and install the successor before the test crossing refuses host settlement.
This component witness does not claim physical host settlement acceptance.


The shared `carrick-sched-core::process::exec::ExecOperationGuard` retains
admission until an already admitted sibling drain settles. Rollback resumes
siblings before release; after the no-return cut, dropping the guard terminates
siblings before release. The existing host Kernel exec transaction consumes this
implementation. The VM-free callback fixture observes exact ordering and one
disposition per drain, including two independently retained reservations.

This is a behavior-preserving extraction for #785. There is no new semantic
red-first claim: it does not bind ring exec, external image services, the FD
authority, nonleader promotion, or old-MM completion rejection. Those require
production native-owner witnesses and signed execution in the subsequent work.

EL1 `stage_exec_payload` (`crates/carrick-el1-linux/src/exec_stage.rs`) narrows
partial-chunk `UserCopy::copy_in` faults logarithmically while retaining valid
copied prefixes and resuming subsequent 256-byte chunks from the known-good
offset. VM-free bindings
`partial_chunk_fault_narrows_from_known_good_offset_without_recopying` and
`long_string_at_page_boundary_and_huge_argv_stay_within_copy_budget` pin
disjoint contiguous `copy_in` covers and linear `copy_in` call and probed-byte
budgets across page-boundary `MAX_ARG_STRLEN` strings and `argc` scaling
`[1, 16, 256, 2048]` (red before `#917`: 770 calls on a 64 KiB + 255B tail
fault and 1,025 calls on `MAX_ARG_STRLEN - 1`; green: `<= 272` and `<= 528`
calls).
