# N1 fork gate at 50d648e76 and anonymous owner fault selection

## Exact signed receipt

Source: `50d648e766fcea5303f205ed9fcccc20d80b2f16`, before rebasing onto
the director's integrated `229194ae6488e846ce2ceabad59b4703e619a8fb`.
Evidence: `/Volumes/carrick-build/evidence/n1-cm/fork-50d648e76/`;
`results.tsv` contains all five signed cases and three traces.

The supplied fixture tarball SHA-256 was
`e563c4dfbdf3b9e2f675dc6c26fc177e6ffa0d36e461a9675a5f09d2ab66a284`.
Restoration verified all 1,133 entries against exact source inputs. Under
the exclusive host lease, touching `crates/carrick-el1-image/build.rs`
forced fresh nested EL1 builds. Full image bytes matched all six retained
Mach-O executables:

- Signed test image, 447,544 bytes:
  `9343a73f8098f7dffc0a993826fef8a424d2612d7ff8356aef75efa52a8a28db`.
- CLI image, 443,304 bytes:
  `a088edb6bb7ea7b4d3dc2e16aed447645f24753c4c0d0665e94417a07bd31d4f`.

`el1-image-freshness.json`, artifact hashes, signatures, entitlements,
LC_UUID, DOF load commands, raw image copies and symbol ELFs are retained.
All eight scoped cleanups returned zero; all retained binaries and fixture
inputs kept their recorded hashes through the cycle.

## Results versus ba202b08e

All five previously stopped at child identity bootstrap. All five now pass
that point. **None passes overall.** These failures occur before the workload
or serving/exit-budget closure recorded for the earlier main comparison.

| Test | First failure at 50d | Result |
| --- | --- | --- |
| `el1_delegated_root_concurrent_vma_ops` | Eight parent rounds complete with zero mismatches; summary `parent_ok=true child_ok=false`; traced child exits 139 | libtest 101 |
| `el1_delegated_root_map_fixed_over_cow_pages` | Parent round 0 `parent-wait-f`; traced child exits 139 | libtest 101 |
| `el1_thread_lifecycle_ptrace_traceclone` | Initial stop works; setting options reports errno **38**, with no clone event | libtest 101 |
| `el1_thread_lifecycle_spawn_slope` | `kernel::terminal_settlement`: task 2 changed after exit preparation | carrier SIGABRT 6 |
| `el1_fork_cow_resolves_in_guest` | Warmup fork succeeds; measured 16-page case exits 139 / SIGSEGV 11 after 16 in-guest COW resolutions | libtest 101 |

The VMA, fixed-over-COW and ptrace runs do not reproduce the earlier child
vvar COW refusal. This does not close their later failures. Ptrace and spawn
are left to integration, as directed; file-table lease and clone-TID code
remain outside this change.

Each of the three refusal traces qualified its controls and printed:

```text
OWNERFORKREFUSAL1|summary|closed_children=2|refusals=0|guest_results=2|witness_closed=1|errors=0|bounded=0
```

There are no refusal/check-ID/arena companion rows because no owner Fork
refusal was observed. Trace exit zero describes the instrument; all three
traced workloads still fail. The trace results are not signed passes.

## First remaining anonymous fork failure

Two diagnostic launches of the unchanged retained fixed-over-COW artifact
stop at the actual guest fault and grant refusal, respectively. They are
diagnostics, not retries for closure. `fixed-fault.core`,
`grant-refusal.core`, their LLDB transcripts and source snapshots are retained.
The event ring is complete: 93 entries, no gaps/errors in the fault capture.

The child (tid 2, MM 3) reads `0x6000016000`, the first page of its first
`MAP_FIXED` replacement. PC is `0x25021c`; ESR `0x92000007` describes an L3
read translation fault. The exact leaf is `0x03e0009b40116fc2`: invalid,
private and **Retired**, not Prepared or COW-armed. Bit 55 has different
meanings depending on VALID; interpreting it alone would misdiagnose COW.

The typed core walk retains old physical backing at
`(0x9b40100000, 0x24000)`, frame 38, mapping 146, owner generation 4,
inside the existing 1 MiB native allocation. The host legacy grant plan
starts at `0x6000002000` and spans 36 pages. It crosses inherited prepared
neighbors outside the fresh replacement. LLDB stops before publication
rollback with `DescriptorRefusal::Occupied`. The event ring then records
`FIRST_TOUCH ... resident=backend-refused` followed by SIGSEGV.

N1 deliberately drops inherited host residency during fork. Reintroducing
it would restore a second MM authority. The existing first-touch owner
handoff was file-only, so anonymous faults fell into that legacy host plan.

## Red-first correction on the integrated owner

The director approved generalizing the existing owner handoff and required
window selection in `carrick-core`, shared by both ISAs. The correction uses
the current admitted reservation and live descriptors under the exact MM
editor. Its window stays inside the reservation, stops at prepared/resident
neighbors, and retains batching over contiguous unbacked pages. Anonymous
windows carry no host byte source; file windows keep the retained source.
The existing physical grant, journal, revalidation, receipt and scheduler
completion protocol remains the publication path.

Red witnesses:

- `owner_fork_anonymous_first_touch_excludes_inherited_prepared_neighbors`
  fails at the anonymous handoff assertion before the fix. It performs a
  real owner fork and child replacement and preserves the parent's exact
  incarnation, reservation generations and descriptor image.
- Both core ISA witnesses fail because the selected supply window includes
  the resident predecessor. Their green versions check the hardware-fault
  grant record too. Separate batching cases require the whole unbacked
  four-page reservation and bound descriptor work.

Receipts: `owner-fault-red.log`, `core-owner-fault-red.log`, and
`owner-fault-focused3.log`. The latter passes 4 core fault witnesses,
12 shared owner/x86 tests, 64 EL1 portal tests and 26 EL1 fault tests.
The signed correction requires a new exact fixture bundle; the 50d signed
receipt above cannot verify the new implementation. Full signed acceptance
and Docker were not run in this worker lane.
