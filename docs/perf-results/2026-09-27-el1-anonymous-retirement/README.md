# EL1 anonymous retirement acceptance

This directory binds the `kernel.el1.anonymous-retirement` contract to source
commit `8b1af0a1963a339e9f8182ab429362543509a021`. The checkpoint makes fixed
anonymous replacement retire its previous physical frame grants, return those
grants to the global inventory, safely reuse them, and rearm first touch without
page-granular host work.

## Impact

The red scale witness completed Linux-visible reads and writes but required
1.5000 host exits per added page per round. The committed signed witness needs
0.0033 and 0.0018 exits per added page per round, a 455x to 833x reduction in
the incremental slope. At 4,096 pages, total exits fell from 24,631 to 101.

Every committed signed scale returns exactly as many grants and bytes as it
receives, and every scale reuses a returned physical extent:

| Pages | Rounds | Host exits | Grants / returns | Reused | Bytes granted / returned |
|---:|---:|---:|---:|---:|---:|
| 256 | 4 | 69 | 5 / 5 | 2 | 4,243,456 / 4,243,456 |
| 1,024 | 4 | 79 | 13 / 13 | 7 | 16,826,368 / 16,826,368 |
| 4,096 | 4 | 101 | 37 / 37 | 26 | 67,158,016 / 67,158,016 |

This closes the retirement substrate for the EL1 memory migration. It does not
yet move `mmap`, `munmap`, or permission changes wholly into EL1; those remain
later increments in the accepted plan.

## Red-first diagnosis

`red-unwired-stats.log` proves the new signed contract failed before production
grant accounting was wired. `instrumented-red.log` then proves the prior path
was semantically correct but structurally red at a 1.5000 exit slope.
`green-fixed-rearm-2.log` and `boundary-red.log` preserve the harder semantic
failure found after fixed replacement was made lazy: a page expected to contain
its own value observed a value from page 523.

The production host keeps an owned page-table software image and explicitly
publishes dirty words into the live backing shared with the EL1 editor. A
reclaimed L3 page could be cached as free in the host image and subsequently
receive an EL1 descriptor in the live backing. Reusing that page published only
the newly touched descriptors, so an untouched stale live descriptor could
alias a different page. The fix re-zeroes and publishes the complete table at
free-list handout, then installs the new partial contents.

The red-first VM-free regression is
`owned_host_image_reuse_clears_live_descriptors_written_by_an_el1_editor`.
It observed a live translation where `None` was required before the fix and
passes with the complete-table publication.

## Bound acceptance

- `signed-scale-green.log` is the committed signed three-scale witness. It
  reports zero-fill, write/read verification, unmap/replacement, the structural
  slopes above, a passing unentitled negative control, and zero scoped Carrick
  processes after cleanup.
- `signed-artifacts.jsonl` binds that execution to source commit `8b1af0a19`,
  executable SHA-256 `38605328eb2bb6292072b2408b973bc5cefdade585ad98b658aa3ba96e369fae`,
  CDHash `4ee9d2e9acfacefbda26018335414fccb8982488`, LC_UUID
  `0EC8C4FC-EFF3-38DD-A031-5E5B074D27DE`, the hypervisor entitlement, and the
  `__dof_carrick` section.
- `boundary-green.log` is the same committed implementation under the durable
  DTrace lifecycle screen. Its final summary is 35 anonymous-arena translation
  faults, 23 frame-grant plans, 15 stage-2 maps, 29 unmaps, target exit, zero
  errors and zero drops. All four post-sync boundary walks have an invalid L3
  descriptor; none exposes stale backing.
- `docker-{256,1024,4096}.out` are same-source runs on native arm64 Docker. Each
  reports `zero=true writes=true unmaps=true`; all corresponding stderr files
  are empty.

`artifact.txt` records the final signed CLI identity, `docker-image.txt` records
the pinned oracle, and `fixture.sha256` records the exact same-source fixture.
`gate-status.md` records the source gates and two inherited repository failures.

## Evidence hashes

- `instrumented-red.log`: `9a94a7f6935337af15880974cf12dc6ddee84da8fd56a1af81b99de10cd3fa30`
- `boundary-red.log`: `7503530c3f4a543b5ee60004143fdb471d99c44f6e1585cc2dbfe6fdc8e95fe6`
- `signed-scale-green.log`: `37ae56c16867cb7c0ad68d0d829576f8c6042fce109d2ccf83aca379aa26e574`
- `boundary-green.log`: `6e9b9333a8adcc6dd2699993f19a804131562200c44681dfa0a0d81967088145`
- `signed-artifacts.jsonl`: `afad7b8ede3bd843afed23355bdfef1a41e9405a1edd9e8a916c7e44fd28f2de`
