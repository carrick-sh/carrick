# HVF Fork Floor E3 Host Fork RSS Attribution Evidence

Date: 2026-07-08

This follows `docs/2026-07-08-hvf-fork-e22-evidence.md`.

## Verdict

E3 does **not** identify a safe generic host-fork/RSS reduction for ordinary
`fork(2)`.

The 256 MiB footprint increase is attributable to class `1`, the private guest
mmap arena. In the large DTrace sample, class `1` accounted for
268,468,224 resident bytes versus 16,384 resident bytes in the small sample.
Its flags were `13`, meaning `CHILD_OBSERVES | COW_COPY | GUEST_WRITABLE`.

That footprint is required by ordinary Linux fork semantics: after `fork(2)`,
the child must be able to read the parent's private writable mmap bytes until
one side writes and COW splits the page. Carrick cannot discard the mapping,
mark it `VM_INHERIT_NONE`, or avoid the inherited COW view for the generic fork
path without breaking the one-Linux-process-to-one-host-process model or Linux
fork observability.

No first reduction is implemented in this pass. The next implementation track
should be a semantics-narrow reduction: implement guest-visible
`MADV_DONTFORK`/`MADV_DOFORK` inheritance metadata and apply non-inheritance only
to guest-marked ranges, then measure workloads that opt into that behavior.
Plain `fork()` remains RSS-dependent by design.

Do not pivot to VM/vCPU create, teardown, admission, or stage-2 replay on this
evidence. The E3 class table confirms E2.2's direction: the scaling resident
footprint is child-observable private guest memory, not a rebuild-stage replay
artifact.

## Instrumentation Added

- `fork__footprint__class(class_id, region_count, scan_bytes, resident_bytes,
  flags)`.
- `Aarch64Vmm::emit_fork_footprint_attribution(&self, arena_high_water)`, called
  immediately after the existing total `fork__footprint` sample and before
  `libc::fork`.
- HVF-only class attribution from `HvfVmState::mappings`.
- `mincore`-based resident-page counting over live host mappings. macOS dirty
  bytes are not available through the stable interface used here; resident bytes
  plus inheritance flags are the closest repo-local evidence.
- A USDT is-enabled trigger wrapper, so the expensive `mincore` class scan runs
  only when DTrace enables `fork-footprint-class`. Normal perf probes do not pay
  the class scan.
- `scripts/dtrace/fork-phases.d` now prints and aggregates class rows.

## Mapping Class Legend

Flag bits:

- `1`: `CHILD_OBSERVES`
- `2`: `PARENT_SHARED`
- `4`: `COW_COPY`
- `8`: `GUEST_WRITABLE`
- `16`: `CHILD_SNAPSHOT`

| Class | Meaning | Flags Observed | Child requirement |
|---:|---|---:|---|
| 1 | private mmap arena | 13 | ordinary fork child must observe parent bytes |
| 2 | private heap | 13 | ordinary fork child must observe parent bytes |
| 3 | private overlay | 13 | ordinary fork child must observe parent bytes |
| 5 | private writable other | 13 | ordinary fork child must observe parent bytes |
| 6 | private read-only/internal | 5 | child must observe runtime/guest bytes |
| 7 | shared aperture | 11 | child must observe the shared object |
| 9 | private page tables | 17 | child receives an explicit sparse snapshot |

## Performance Measurements

Final E3 logs are under `target/conformance/logs/hvf-fork-e3/`.

| Probe | Footprint | p50 us | p95 us | min us | Iters | Log |
|---|---:|---:|---:|---:|---:|---|
| `perf_fork` | 0 MiB | 3687.292 | 3858.541 | 3356.750 | 300 | `perf_fork-small-final.log` |
| `perf_fork` | 256 MiB | 5042.375 | 5422.583 | 4865.958 | 300 | `perf_fork-large-final.log` |
| `perf_fork_exec` | 0 MiB | 8464.000 | 9309.792 | 7865.291 | 200 | `perf_fork_exec-small-final.log` |
| `perf_fork_exec` | 256 MiB | 10957.500 | 12174.667 | 10011.792 | 200 | `perf_fork_exec-large-final.log` |

The final p50 footprint deltas were:

- `perf_fork`: +1355.083 us
- `perf_fork_exec`: +2493.500 us

## Focused DTrace Samples

DTrace class attribution intentionally enables the expensive `mincore` scan.
Use the role `2/3`, phase `3` lifecycle values for host `fork(2)` timing; the
`fork-pre` to `fork-post` interval includes the diagnostic scan and is not
comparable to E2.2's ungated one-fork interval.

| Sample | Host fork parent us | Host fork child us | VM regions | Arena high-water | Resident bytes | Log |
|---|---:|---:|---:|---:|---:|---|
| small `clonebasic` | 2136 | 2243 | 389 | 412316876800 | 41468552 | `fork-phases-small.log` |
| `clonebasic -- 256` | 6532 | 6618 | 389 | 412585316352 | 309969736 | `fork-phases-large.log` |

### Footprint Class Table

| Class | Small regions | Small scan bytes | Small resident bytes | Large regions | Large scan bytes | Large resident bytes | Flags |
|---:|---:|---:|---:|---:|---:|---:|---:|
| 1 | 1 | 16384 | 16384 | 1 | 268455936 | 268468224 | 13 |
| 2 | 1 | 134217728 | 16384 | 1 | 134217728 | 16384 | 13 |
| 3 | 1 | 2147483648 | 0 | 1 | 2147483648 | 0 | 13 |
| 5 | 3 | 9011200 | 9011200 | 3 | 9011200 | 9011200 | 13 |
| 6 | 6 | 98304 | 98304 | 6 | 98304 | 98304 | 5 |
| 7 | 1 | 2147483648 | 0 | 1 | 2147483648 | 0 | 11 |
| 9 | 1 | 1835008 | 1835008 | 1 | 1835008 | 1835008 | 17 |

The class `1` resident delta was 268,451,840 bytes. The process-wide resident
delta was 268,501,184 bytes. That accounts for the E2.2 RSS scaling surface
within page-rounding and non-guest process noise.

## Reduction Decision

No safe generic reduction exists for the measured growth class:

- Class `1` is private, guest-writable mmap arena state.
- The child must observe these bytes after ordinary `fork(2)`.
- Carrick already maps the backing as host `MAP_PRIVATE`; the child rebuild
  borrows the inherited COW view rather than eagerly copying the arena.
- Avoiding this RSS in generic fork would require changing Linux fork semantics
  or predicting a future `execve`, which is not available at the fork boundary.

Concrete handoff:

1. Implement Linux `MADV_DONTFORK`/`MADV_DOFORK` metadata in the runtime mmap
   state.
2. Teach the HVF fork descriptor path to exclude only guest-marked
   `MADV_DONTFORK` ranges or apply `VM_INHERIT_NONE` to those host subranges.
3. Add a conformance probe proving that a DONTFORK private mapping is absent in
   the child while ordinary private mappings remain visible.
4. Re-run the E3 perf/DTrace gate with a workload that opts into DONTFORK.

Fork+exec can only be reduced through an explicit semantic signal such as
`vfork`/`CLONE_VFORK` or guest-requested non-inheritance. Plain `fork()` cannot
be specialized just because the child later calls `execve`.

## Verification Commands

- `cargo test -p carrick-vmm-hvf --lib fork_footprint_classifies_guest_mapping_roles`
  - Result: passed after red-first compile failure for missing classifier symbols.
- `cargo check -p carrick-observability -p carrick-aarch64 -p carrick-vmm-hvf`
  - Result: passed.
- `cargo fmt -p carrick-observability -p carrick-aarch64 -p carrick-vmm-hvf`
  - Result: passed.
- `just build`
  - Result: release build passed and re-signed `target/release/carrick`.
- `scripts/build-probes.sh`
  - Result: exited 0 and built AArch64 Linux probe binaries; existing probe
    warnings were emitted.
- `otool -l target/release/carrick | rg -a 'dof|__dof_carrick|segname|sectname'`
  - Result: `sectname __dof_carrick` present.
- `codesign -d --entitlements - target/release/carrick`
  - Result: `com.apple.security.hypervisor` entitlement present and true.
- Carrick-only `perf_fork`, small:
  `base64 -i conformance-probes/target/aarch64-unknown-linux-musl/release/perf_fork | timeout 240 target/release/carrick run ubuntu:24.04 --raw --fs host /bin/sh -c 'base64 -d > /tmp/p && chmod +x /tmp/p && /tmp/p'`
  - Result: p50 3687.292 us, p95 3858.541 us, rc 0.
- Carrick-only `perf_fork`, 256 MiB:
  `base64 -i conformance-probes/target/aarch64-unknown-linux-musl/release/perf_fork | timeout 300 target/release/carrick run ubuntu:24.04 --raw --fs host /bin/sh -c 'base64 -d > /tmp/p && chmod +x /tmp/p && FORK_MEM_MB=256 /tmp/p'`
  - Result: p50 5042.375 us, p95 5422.583 us, rc 0.
- Carrick-only `perf_fork_exec`, small:
  `base64 -i conformance-probes/target/aarch64-unknown-linux-musl/release/perf_fork_exec | timeout 300 target/release/carrick run ubuntu:24.04 --raw --fs host /bin/sh -c 'base64 -d > /tmp/p && chmod +x /tmp/p && /tmp/p'`
  - Result: p50 8464.000 us, p95 9309.792 us, rc 0.
- Carrick-only `perf_fork_exec`, 256 MiB:
  `base64 -i conformance-probes/target/aarch64-unknown-linux-musl/release/perf_fork_exec | timeout 360 target/release/carrick run ubuntu:24.04 --raw --fs host /bin/sh -c 'base64 -d > /tmp/p && chmod +x /tmp/p && FORK_MEM_MB=256 /tmp/p'`
  - Result: p50 10957.500 us, p95 12174.667 us, rc 0.
- Small DTrace:
  `timeout 240 sudo -n /usr/sbin/dtrace -q -s scripts/dtrace/fork-phases.d -c 'target/release/carrick run-elf conformance-probes/target/aarch64-unknown-linux-musl/release/clonebasic'`
  - Result: rc 0; host fork 2136 us parent / 2243 us child; class rows emitted.
- Large DTrace:
  `timeout 240 sudo -n /usr/sbin/dtrace -q -s scripts/dtrace/fork-phases.d -c 'target/release/carrick run-elf conformance-probes/target/aarch64-unknown-linux-musl/release/clonebasic -- 256'`
  - Result: rc 0; host fork 6532 us parent / 6618 us child; class rows emitted.
- `scripts/run-probe.sh clonebasic`
  - Result: `MATCH clonebasic`, rc 0.

No Carrick guest/probe and Docker oracle command were run concurrently.
`scripts/run-probe.sh clonebasic` ran its Carrick and Docker phases
sequentially.
