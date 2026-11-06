# Native fork reduction for #1742

The signed `go version` failure remains unresolved. This investigation found
an execution-authentication gap in the VM-free fixture, not a demonstrated
cause of the signed crash. No runtime behavior or refusal policy is changed.

## Scope and base

The investigation uses admitted main
`0d5dfaa508e5b92edbe2b18404cd2c7d4230f719`. Rebase onto
`refs/carrick/dispatch-main` was a no-op. This checkout did not contain the
previous worker's `383611e8b571` object or investigation document; no earlier
worker commit was removed. The director's evidence under
`/Volumes/CaseSensitive/carrick-evidence/1733/` is unavailable on this Linux
runner. The runner has `/dev/kvm`, but cannot execute the macOS HVF signed
artifact or the requested ten-run signed population.

## Two different snapshots must be distinguished

`Aarch64NativeProcessService::prepare_mm` in
`crates/carrick-el1-linux/src/aarch64_process.rs:2256` constructs a
`PortalOperation` from the parent's live reservation owner. At line 2290 it
captures that owner's mapping generation; the stock request at line 2292
also carries the entry's `AddressContext` and execution binding. These are
separate authorities, even when their generation values happen to agree.

* `CoreMmPortal::prepare_fork` in
  `crates/carrick-el1-linux/src/mm_portal/fork.rs:302` validates the captured
  reservation incarnation, mapping generation and operation sequence.
  Publication separately checks captured descriptor words and the reservation
  snapshot in `crates/carrick-core/src/mm/fork.rs:354`.
* Physical stock settlement authenticates the loan's captured
  `GrantExecution` against the current execution. The equality at
  `crates/carrick-hal/src/fork_stock.rs:186` includes CPU, execution binding,
  MM, root and context generation. `settlement_loan` at line 2008 rejects a
  mismatch before consuming admitted custody.

Thus `Prepare`/`Publish` stale-owner reports and an admitted settlement refusal
are not evidence of the same mismatch. The reported stage alone does not name
which field changed or prove that the transition was legitimate.

## What the VM-free harness lacks

`PhysicalStock::loan` in
`crates/carrick-el1-linux/src/aarch64_process_tests/native_retirement_tests.rs:214`
constructs `GrantExecution` from the request and saves it in `self.execution`.
`reserve` at line 228 and `commit` at line 263 pass that saved execution back
to the real shared `ForkStock` owner. The enclosing
`TestStockCrossing::cross_fork_stock` ignores its CPU argument and does not
reconstruct the stopped execution for each crossing.

Production instead calls `stopped_execution` at
`crates/carrick-vmm-hvf/src/metadata_grant.rs:1703` on each stock crossing.
That reads the stopped slot's task and zone; `root_execution` at line 2664
uses the live execution binding, installed MM, hardware TTBR and
`task.root_generation()`.

The fixture can exercise real reservation changes and shared physical-stock
accounting, but it cannot currently witness a discrepancy between a retained
loan and a newly authenticated stopped execution across two live processes.
It also does not execute the guest's shared-stack vfork instructions or the
HVF entry/resumption path. Setting a synthetic refusal, or simply changing a
saved generation, would demonstrate rejection without proving that a valid
production transition causes it. No red-first reproduction was established.

## Required next evidence

Use the director's signed failure to compare the loan and settlement's exact
CPU, task/execution/thread generations, MM, root and context generation. For
`Prepare` and `Publish`, compare the captured and current reservation
incarnation, mapping generation, operation sequence and descriptor read set.
Retain the other live process's identity and the transition responsible for
each changed field. The existing native-fork refusal and stock diagnostics
are starting points; use `carrick trace`, not logging in the guest path.

A VM-free binding would need a crossing that derives current execution from
an explicitly selected live slot/task at every Loan, Reserve and Commit,
checks its installed root, and drives a real transition between those
crossings. It must preserve two independently live process identities and
enter through the production native-process boundary. Only then can a test
separate legitimate re-admission from stale/reused authority. Removing
execution equality, mapping all stale errors to Busy, or retrying an already
published birth is not justified by this investigation.

Acceptance remains open: identify the actual stale authority and transition,
prove the production-entry witness red first, fix its owner, and run ten
signed `go version` executions on one identified artifact with all ten starts,
outputs and exits counted. Native tests and compile checks cannot replace
that population.
