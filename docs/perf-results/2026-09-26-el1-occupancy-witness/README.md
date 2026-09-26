# Occupancy witness repair

Source `77b044194e2c5e458fa1b3c383c54446eacf0982` integrates worker commits
`ace5de9f0` and `1081e2d5e` as `8bafb145b` and `77b044194`.
The witness now rejects failed memory edits, zero completed edit cycles, worker
join failures and unsuccessful child reaping. Fork children check every allocated
writer page using storage allocated before fork; the original dynamic writer
population is preserved. Writer mapping cleanup is checked.

Director independently verified 16 host-only report tests, fixture cross-build,
embed test compilation, Clippy and formatting. Worker red/green instrument
receipts are retained. One review round removed an introduced 128-writer cap and
added checks for insufficient/odd writer counts.

Native arm64 Ubuntu Docker completed first with the frozen fixture: both
processes completed 150 forks with 20 writers, positive successful editor counts
and zero failures. Image identity and both streams are retained. Oracle command:
`docker run --rm --platform linux/arm64 --name el1-occupancy-oracle-20260926
--mount type=bind,source=<frozen-fixture>,target=/el1-sched,readonly ubuntu:24.04
/usr/bin/timeout 240s /bin/sh -c '/el1-sched mm-occupancy 150'`.
The container exited and was removed before Carrick ran.

Signed command: `CARRICK_RUN_ID=el1-occupancy-witness-20260926
CARRICK_CONTRACT_ID=kernel.mm.address-space-occupancy RUSTC_WRAPPER=
./scripts/test-signed.sh carrick-embed el1_sched_mm_occupancy_two_processes
--exact --nocapture`. It passed with eight writers per process and 150 forks:
child 938 successful edits, parent 997, all failure counters zero. Negative
entitlement control passed; both scoped run IDs had zero remaining processes.

The frozen signed executable is
`target/el1-completion/occupancy-witness/signed-frozen`. SHA-256:
`caa34afd102077cac765af993ad997d3fd5ebf8064f119f955b45a862ebd9df7`.
The artifact receipt also records CDHash, LC_UUID, entitlement and DOF presence.
The oracle and signed-build fixture SHA-256 are identical:
`f02bb98f4cda3d78b2543a292d03097df5b80603bc815f3cd5623411bf001d6b`.

The same signed executable then passed three separate controls with
CARRICK_EL1_SCHED=0, CARRICK_EL1_FUTEX=0, and CARRICK_HVF_GIC=0. Each ran exactly
one test, checked both role reports and completed scoped cleanup with zero
remaining processes. controls.json and run-controls.py retain exact environment,
commands and per-run SHA-256. No rebuild or re-sign occurred between controls.

This closes the narrower witness repair. It is not full occupancy-contract
closure, EL1 memory acceptance, or a performance comparison: the Docker and
Carrick runs used their respective default CPU populations. Full el1 suite,
probe/smoke/full promotion, live-table authority, first-touch execution,
elastic return and paired ecosystem measurements remain open.

At `771e804d5`, integrated `RUSTC_WRAPPER= just lint-domains` exited zero. The
host-authority census explicitly remains partial for Linux, FreeBSD and NetBSD
profiles. The complete log is `integrated-lint.log`. Reconciliation preserved
all 588 authority rows without position or content changes.
