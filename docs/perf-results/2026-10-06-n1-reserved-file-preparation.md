# N1 reserved file preparation: E admission repair

This repairs the demonstrated file-mmap admission failure on parent
`5ca12d5d765e5fe5ae828293b93a5e9be7d9ab33`. It is not signed landing acceptance.
The exact-parent cycle and all preparation evidence are retained at
`/Volumes/carrick-build/evidence/n1-cm/fork-5ca12d5d7/`.

## Signed parent result against main

Main baseline: `65098ea0e4a899f91ba047f6e380a26fbd56208a`.
`results.tsv` contains eight signed workloads and three refusal traces.
The workloads finished with **1 PASS, 7 FAIL**. Among the three affected
main-pass workloads, elf-errno passed; host-buffers and inotify failed.
Among the five accepted fork reds, only ptrace retained main's first failure.

| Workload | Parent result and first failure |
| --- | --- |
| concurrent VMA ops | FAIL: child incomplete after parent workload succeeds |
| fixed-over-COW | FAIL: round 0 parent-wait-f handshake |
| ptrace traceclone | FAIL: errno 38, options false, matching main |
| spawn slope | FAIL: spawn errno 11, followed by stdout errno 14 |
| fork COW | FAIL: signal 11, exit 139, empty stdout |
| host-buffers | FAIL: reuse-file-map returns -12 |
| inotify churn | FAIL: libpython shared-object segment cannot map, exit 127 |
| elf-errno | PASS |

The three required refusal traces each closed with two child completions,
zero refusals, and no trace errors or bound termination. Their workloads
still failed. All eleven scoped cleanup receipts reported zero remaining
processes. The forced embedded EL1 image hashes and nine retained artifact
identities are in `el1-image-freshness.json` and the artifact receipts.

Full signed acceptance did not execute. The initial collector rejected an
inherited scope descriptor before starting tests; its descriptor inheritance
was corrected. The director then ordered E, A and D repairs before that gate.

## Diagnosis and correction

The retained-artifact file-map trace reported:

```text
mmap-lowering-error va=0x6000004000 len=16384 offset=0
error=host mapping operation failed: HVPatch private file backing: hypervisor operation failed: admitted owner MM cannot enter host sparse publication
mmap-lowering outcome3
```

The workload completed with the error, but that diagnostic tracer did not
exit. Explicit scoped cleanup is retained; this diagnostic has incomplete
trace closure. LLDB captured `refusal.core` in the actual carrier at the mmap
refusal: errno 12, "temporary writable protection failed while loading file
content". The writer breakpoint did not fire in that reducer.

The kernel had minted a reserved-owner proof only for content copying.
Earlier native backing preparation and protection entered the legacy host
publication gate, which correctly refuses an admitted EL1 owner.

Carry the existing borrowed proof through file-view preparation and the
existing guest descriptor publication transaction. Validate carrier, MM,
incarnation, ASID, live root, descriptor ownership and containment; retain
the caller's mutation exclusion rather than acquiring a second pause.
Mutable file views retain their live page-cache provenance and page COW arms.
File protection uses the same authenticated opaque reservation. SplitView
forwards both methods. Initial roots authenticate their exact live binding
without requiring an unrelated pooled-root lease. Deferred protection pins
the selected physical table arenas instead of relabeling a boot lookup.

## Red-first and limits

`filemap-diagnosis/` contains these qualified VM-free reds and their greens:

| Witness | Qualified red |
| --- | --- |
| kernel retired reservation/file mapping | mmap returns errno 12 |
| native mutable file preparation | admitted owner cannot enter host sparse publication |
| initial root authentication | Unsupported despite the exact live binding |
| split adapter | backing Ok(false), reserved protection Unsupported |
| two live roots / deferred protection | selected-root shadow differs from stale boot-root live words |

Negative controls reject wrong carrier, MM, incarnation, range, stale runtime
root and host descriptor ownership. A single EL1 descriptor refusal restores
inventory, aliases, owner keys and live table bytes without a pending receipt.
Clean mutable-file pages follow subsequent file writes. Ordinary publication
remains closed without its original admission. These local witnesses do not
prove final guest permissions, live guest COW or signed parity.

The serial runtime suite passes 710 tests, with 9 ignored; the serial HVF
suite passes 755 tests, with 3 ignored. Kernel tests pass 2488 in the parallel
partition and 176 in the serial partition, with 1 ignored. Contract validation checks 98
contracts, 16 claims and 175 surfaces. Workspace clippy passes.
The invalid parallel runtime invocation and the initial native-test cleanup
failure are retained, not erased: the former ignored the serial harness;
the latter omitted the newly published file owner from fixture cleanup.

Two inherited EOF behaviors remain separate red-first work: a file prefix can
commit before its anonymous suffix fails, and a wholly-beyond-EOF reserved
mapping can decline native preparation then fail eager copying. Whole-request
rollback is not claimed. A fresh exact bundle, forced image rebuild and signed
requalification remain required. The director transferred clone-TID and
file-table ownership to this lane; the next repair order is A, then D.
