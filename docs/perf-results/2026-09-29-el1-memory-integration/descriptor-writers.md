# Production descriptor conversion worklist

Source review at alias-caller development on parent `ec366760f`. This worklist
orders the known activation blockers; it does not replace final compiler-backed
writer closure, rollback-path review or signed ownership acceptance.

| Production path | Current state / remaining work |
|---|---|
| Prepared host copyout | Caller connected through verified Publish/Write and exact-MM residency commit; signed activation pending |
| `perform_frame_cow` | Local shapes connected to CowRepoint and owned grant/reuse backing; successful full carrier/hardware composition pending |
| Engine `repoint_private`, `repoint_shared_leaf` | Connected to MapAlias through driving vCPU, pinned backing and metadata after receipt; full caller execution pending |
| Backend `publish_shared_repoint` | Duplicate writer removed; read-only mapping verification plus metadata |
| Backend `publish_private_repoint` | Metadata only; verifies completed mapping |
| `prepare_el1_frame_grant` replacement branch | Guarded: old alias/owner retirement needs descriptor completion ordering |
| `materialize_retired_reuse` | Guarded host descriptor publication and rollback; next backing-reuse conversion |
| `sparse_materialization::publish_replacing` | Guarded host replacement and rollback |
| `perform_foreign_cow_transaction` | Guarded foreign-MM descriptor publication; needs exact foreign-MM driving/completion authority |
| Engine `mark_bus_fault`, `protect_range`, `restore_shared_identity` | Host edit funnel still used; convert current permission/tag/alias semantics |
| Engine `discard_private_anonymous`, `unmap_range`, `unmap_alias_range` | Host edit funnel still used; retain discard/retirement/backing completion ordering |
| Engine `ensure_sparse_mmap_backing`, `map_private_file_backed`, `map_host_alias` | Remaining host preparation/publication calls; distinguish metadata-only reservations from live writes |
| Engine `publish_el1_frame_grant`, fork arming in `build_process_spec` | Guest routes exist; audit all host branches and rollback paths before census closure |
| Engine `configure_process_asid`, `prepare_core_snapshot`, exec rebuild and offline image installation | Classify offline construction separately; convert any remaining live writes and preserve exact-root publication |

Next implement replacement-grant/retired/sparse publication using the same
transaction machinery. Keep unknown/partial completion fail-closed. Do not add a
second copy transport, weaken admission or start unrelated IPC captures.

After all live writer and rollback routes are accounted for, activate the full
lane and run the first signed two-MM copyout/COW/protection/retirement witness.
Then join production anonymous reservation policy/lifecycle and qualify complete
memory ownership with pause removal, correctness, work and workload-cost gates.
