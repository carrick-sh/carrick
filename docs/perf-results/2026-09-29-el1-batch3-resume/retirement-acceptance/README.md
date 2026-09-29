# Corrected terminal retirement candidate acceptance

Source: b5a751775cc9501ffec33c7a724053f8a33777a6, containing the red-first
population correction d914c57ce. Full `RUSTC_WRAPPER= just ci` passed, then
`just build` built and signed the new CLI. Reconciliation retained all 595
macOS authority rows, with no position changes. Other host profiles remain
unqualified and x86 is deferred.

The fixed Go20 population passed 20 unique MATCH rows with successful
Carrick and native-Linux verdicts, BUILD_OK in every raw stdout, no known or
new diffs, and no retries or serial confirmation. Normal harness deadlines
and worker settings were preserved. All 40 raw streams are retained here.
The oracle is the previously fresh native ARM64 result: 1228 ms. Docker
image inspection and registry HEAD both verified image digest
357a08793e683c6a174d3955c704a5194e825f38fcdcb91d1d4ee2bccd6b188b
before the run. No Docker workload overlapped guest execution.

CLI identity is recorded in identity.json, codesign.txt and load-commands.txt.
Its SHA256 stayed unchanged across all 20 runs. An exact executable copy is
retained in target/el1-resume-b3/retirement-acceptance/carrick. The previous
failing CLI is separately retained under its SHA256 in
 target/el1-resume-b3/arm64-acceptance/tested-executables/.
Post-population process census found no matching guest, helper or harness;
Docker had only the two existing registry services.

Carrick elapsed times were 1681–2092 ms versus the cached 1228 ms oracle.
These observations are not controlled paired performance acceptance.

This closes this candidate's fixed Go population, not retrospective attribution
of conf-20571-c00 and not all batch-3 lifecycle obligations. The original red
receipt is preserved under arm64-acceptance/workloads. The broader EL1/probe
receipts belong to the previous executable and do not transfer to this one.
Next: signed regression qualification of this exact candidate, remaining
lifecycle interleaving/structural witnesses, and the final batch gates before
local integration. Memory foundations and all later ARM64 stages remain open.
