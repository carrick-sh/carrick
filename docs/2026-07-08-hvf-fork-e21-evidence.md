# HVF Fork Floor E2.1 Lifecycle Decomposition Evidence

Date: 2026-07-08

This records the E2.1 follow-up to
`docs/2026-07-08-hvf-fork-e2-evidence.md`.

## Verdict

The dominant isolated non-stage-2 phase is the real host `fork(2)` inside the
shared AArch64 engine, not HVF stage-2 replay, VM/vCPU create, VM/vCPU destroy,
register restore, sibling quiesce, or post-rebuild child repair.

In the one-fork `clonebasic` trace, host `fork(2)` took 2453 us on the parent
side and 2559 us on the child side. The full Carrick-only `perf_fork` run for
the same instrumented binary measured p50 3226.833 us and p95 3620.000 us, so
the host process clone accounts for most of the current fork floor.

The next implementation track should be **host-fork/RSS reduction**, with one
narrow prerequisite: split runtime phase 0/5 because it measured 1297 us in the
single DTrace sample and currently bundles several pre-engine operations. Do not
prioritize lazy stage-2 replay, VM/vCPU create optimization, teardown/quiesce
optimization, or admission-path cleanup on the current evidence.

## Instrumentation Added

E2.1 adds `fork__lifecycle` as a five-argument USDT probe:

- `role`: subsystem/side
- `phase`: role-local lifecycle phase
- `elapsed_us`: elapsed time for the just-finished phase
- `a`/`b`: phase-specific counts, return codes, or identifiers

The five-argument shape is intentional. The E2 probe work found that macOS
DTrace reports a sixth argument as zero in this provider path.

### Role Map

| Role | Meaning |
|---:|---|
| 0 | runtime parent/common |
| 1 | runtime child |
| 2 | AArch64 engine parent/common |
| 3 | AArch64 engine child |
| 4 | HVF backend parent/common |
| 5 | HVF backend child |

### Phase Map

| Role | Phase | Meaning |
|---:|---:|---|
| 0 | 0 | fork token acquired |
| 0 | 1 | topology lock acquired |
| 0 | 2 | sibling quiesce drain complete |
| 0 | 3 | macOS/HVF `VCPU_LIVE` drain complete |
| 0 | 4 | exit-cleanup drain complete |
| 0 | 5 | pre-engine bookkeeping complete |
| 0 | 6 | engine fork call returned in parent |
| 0 | 7 | parent runtime repair complete |
| 0 | 9 | vfork parent suspend complete |
| 1 | 6 | engine fork call returned in child |
| 1 | 8 | child runtime repair complete |
| 2 | 0 | vCPU snapshot complete |
| 2 | 1 | `freeze_ram_for_fork` complete |
| 2 | 2 | page-table manager clone complete |
| 2 | 3 | host `fork(2)` returned in parent |
| 2 | 4 | parent rebuild hook complete |
| 3 | 3 | host `fork(2)` returned in child |
| 3 | 5 | child rebuild hook complete |
| 3 | 6 | child engine-local state reset complete |
| 4 | 0 | vfork `VM_INHERIT_SHARE` loop complete |
| 4 | 1 | parent descriptor capture complete |
| 4 | 2 | child descriptor construction complete |
| 4 | 3 | `hv_vcpu_destroy` complete |
| 4 | 4 | `hv_vm_destroy` complete |
| 4 | 5 | descriptor stash complete |
| 4 | 11 | parent `create_vm_with_admission` complete |
| 4 | 12 | parent `create_vcpu_with_permit` complete |
| 4 | 13 | parent counter/handle replacement complete |
| 4 | 14 | parent protection/page-table metadata reset complete |
| 4 | 15 | parent vfork `VM_INHERIT_COPY` restore complete |
| 4 | 16 | parent register restore complete |
| 5 | 10 | child admission reset complete |
| 5 | 11 | child `create_vm_with_admission` complete |
| 5 | 12 | child `create_vcpu_with_permit` complete |
| 5 | 13 | child counter/handle replacement complete |
| 5 | 14 | child protection/page-table metadata reset complete |
| 5 | 16 | child register restore complete |
| 5 | 17 | child DTrace re-register complete |
| 5 | 18 | child vDSO RNG stamp complete |

## Measurements

| Measurement | Result | Evidence |
|---|---:|---|
| `perf_fork` p50 | 3226.833 us | `target/conformance/logs/hvf-fork-e21/perf_fork-cr-e21-perf-fork-20260707-193820.log` |
| `perf_fork` p95 | 3620.000 us | same log |
| `perf_fork` min | 2996.500 us | same log |
| `perf_fork` iterations | 300 | same log |
| `perf_fork_exec` p50 | 8159.209 us | `target/conformance/logs/hvf-fork-e21/perf_fork_exec-cr-e21-perf-fork-exec-20260707-193833.log` |
| `perf_fork_exec` p95 | 9487.792 us | same log |
| `perf_fork_exec` min | 7337.083 us | same log |
| `perf_fork_exec` iterations | 200 | same log |
| DTrace one-fork probe | `clonebasic`, rc 0 | `target/conformance/logs/hvf-fork-e21/fork-phases-cr-e21-dtrace-clonebasic-20260707-193846.log` |
| parent fork-pre-to-post | 3070 us | same DTrace log |
| child fork-pre-to-post | 3582 us | same DTrace log |
| parent post-to-exit | 1387 us | same DTrace log |
| child post-to-exit | 158 us | same DTrace log |

`post-to-exit` is a DTrace-derived interval from `fork-post` to the final
`guest-exit` marker. It is useful for bounding child `_exit` and parent
wait/reap-visible work in the focused probe, but it is not a pure syscall phase.

## Lifecycle Timing Sample

The following table is from the single `clonebasic` DTrace sample. Values are
microseconds.

| Phase | Parent | Child | Interpretation |
|---|---:|---:|---|
| runtime fork token/topology/quiesce/`VCPU_LIVE`/exit cleanup | 0 | n/a | no sibling pressure in this sample |
| runtime pre-engine bookkeeping | 1297 | n/a | broad bucket; needs E2.2 sub-split |
| AArch64 vCPU snapshot | 9 | n/a | non-material |
| HVF child descriptor construction | 156 | n/a | non-material |
| `hv_vcpu_destroy` | 20 | n/a | non-material |
| `hv_vm_destroy` | 93 | n/a | non-material |
| `freeze_ram_for_fork` total | 317 | n/a | includes HVF teardown above |
| AArch64 page-table manager clone | 111 | n/a | non-material |
| host `fork(2)` | 2453 | 2559 | dominant isolated phase |
| `create_vm_with_admission` | 44 | 44 | non-material |
| `create_vcpu_with_permit` | 33 | 365 | child side visible but not dominant |
| stage-2 local replay | 91 | 118 | still non-material after E2 |
| total `fork_rebuild` | 185 | 586 | below host fork and broad pre-engine bucket |
| register restore | 1 | 1 | non-material |
| AArch64 rebuild hook | 197 | 598 | child total includes HVF rebuild |
| engine-local child reset | n/a | 12 | non-material |
| runtime parent/child repair | 25 | 95 | non-material |

The DTrace log also recorded 14 local mapping descriptors and 14 local
`hv_vm_map` calls per side, with zero sibling replay candidates/maps.

## Verification Commands

- `cargo fmt -p carrick-observability -p carrick-aarch64 -p carrick-runtime -p carrick-vmm-hvf`
  - Result: passed.
- `cargo check -p carrick-observability -p carrick-aarch64 -p carrick-runtime -p carrick-vmm-hvf`
  - Result: passed.
- `just build`
  - Result: release build passed and re-signed `target/release/carrick`.
- `scripts/build-probes.sh`
  - Result: exited 0 and built the required aarch64 probe binaries.
- `otool -l target/release/carrick | grep dof`
  - Result: `sectname __dof_carrick`.
- `codesign -d --entitlements - target/release/carrick`
  - Result: `com.apple.security.hypervisor` entitlement present.
- Carrick-only `perf_fork` run:
  `base64 -i conformance-probes/target/aarch64-unknown-linux-musl/release/perf_fork | timeout 180 target/release/carrick run ubuntu:24.04 --raw --fs host /bin/sh -c 'base64 -d > /tmp/p && chmod +x /tmp/p && /tmp/p'`
  - Result: p50 3226.833 us, p95 3620.000 us, rc 0.
- Carrick-only `perf_fork_exec` run:
  `base64 -i conformance-probes/target/aarch64-unknown-linux-musl/release/perf_fork_exec | timeout 180 target/release/carrick run ubuntu:24.04 --raw --fs host /bin/sh -c 'base64 -d > /tmp/p && chmod +x /tmp/p && /tmp/p'`
  - Result: p50 8159.209 us, p95 9487.792 us, rc 0.
- DTrace lifecycle sample:
  `sudo -n dtrace -q -s scripts/dtrace/fork-phases.d -c 'target/release/carrick run-elf conformance-probes/target/aarch64-unknown-linux-musl/release/clonebasic'`
  - Result: rc 0; host `fork(2)` 2453 us parent / 2559 us child.
- `scripts/run-probe.sh getrandomvdsofork`
  - Result: `MATCH getrandomvdsofork`, `child_reused=false`.
- `scripts/run-probe.sh vforkvmshare`
  - Result: `MATCH vforkvmshare`, `clone_vm_shared_write_visible=true`.

`scripts/run-probe.sh` performs its Carrick and Docker oracle phases
sequentially. No Carrick guest/probe and Docker oracle command were run
concurrently.

## Next Track

Proceed on host-fork/RSS reduction, not VM residency churn.

Concrete E2.2 handoff:

1. Add a pre-engine sub-split for runtime role 0 phase 5. It should separately
   time arena high-water publication, child pid/namespace allocation,
   `prepare_child_record_pre_fork`, pidfd/vfork pipe setup, `prepare_host_fork`,
   and paused-lock acquisition.
2. Add a host address-space footprint sample adjacent to role 2 phase 3. At
   minimum record Mach VM region count, guest arena high-water, and resident or
   dirty bytes immediately before `libc::fork`.
3. Re-run `perf_fork`, `perf_fork_exec`, and the one-fork DTrace sample across
   at least two footprint points: the current small `clonebasic` footprint and a
   larger guest-memory footprint generated without changing Carrick's
   one-Linux-process-to-one-host-process model.
4. Optimize only after that split. If host `fork(2)` scales with inherited
   address-space/RSS, pursue arena/RSS reduction or mapping-layout changes. If
   role 0 phase 5 remains independently large, optimize the specific runtime
   subphase that the E2.2 split identifies.

Rejected immediate tracks on current evidence:

- VM/vCPU create optimization: parent 44/33 us, child 44/365 us.
- Teardown/quiesce optimization: quiesce/drains were 0 us in this sample;
  `hv_vcpu_destroy`/`hv_vm_destroy` were 20/93 us.
- Lazy stage-2 replay or map coalescing: local replay was 91/118 us with 14 maps
  per side and zero sibling replay.
- Admission-path cleanup: admission/VM creation is below the millisecond-scale
  fork floor in this trace.
