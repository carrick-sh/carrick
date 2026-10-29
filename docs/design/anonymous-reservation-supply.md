# Anonymous reservation supply: #898 diagnosis and proposed correction

This is a diagnostic slice, not a runtime fix. The VM-free budget witness is
expected to fail until reusable physical supply exists. No budget is widened.

## Main path

Source inspected: GitHub main `bdfa2b062cde08cd33cf8ae91c94636cdfd8560d`.
The signed report on #898 records 200/589 exits for 64/256 reservations,
flat forwarded mmap/brk and successful guest output. This worker cannot run
HVF or Docker on ctb-w3.

The fixture interleaves mmap and a first write/read for each 1/2/3/4-page
reservation (`fixtures/embed-el1-sched/src/main.rs`, `anonymous_reservations`).
The shared anonymous dispatcher admits the reservation without backing.
First write faults:

1. `crates/carrick-el1/src/fault.rs:1423` probes prepared residency. A new
   reservation has none. The owner-supply branch at `:1487` takes the MM editor
   and root, then calls `select_fault_window` at `:1513`.
2. `crates/carrick-core/src/mm/fault.rs:141` asks the reservation authority for
   a transfer fault plan. In `reservation/root.rs:1712-1719` the aligned bulk
   window is clipped to **one node**. A small mapping cannot borrow the target
   size beyond its own range. Authentication at `:1740-1761` intentionally
   requires the plan to fit that same mapping incarnation.
3. `crates/carrick-core/src/mm/frames.rs:12` clips further around occupied
   descriptors. It cannot enlarge the selected reservation. The fault path
   publishes the selection at `crates/carrick-el1/src/fault.rs:1545` and returns
   Forward. `carrick-el1-linux/src/dispatch.rs:1161-1171` captures that exact
   selection sequence before park, then `:1224-1227` submits the Fault service.
   Native transport consumes it via `ServiceTicket::take_fault_selection`
   (`carrick-core-abi/src/service.rs:1447`).
4. `crates/carrick-vmm-hvf/src/metadata_grant/native_service.rs:679` routes
   Backing to `supply_backing`. At `:854-881`, anonymous publication length is
   the selected range, allocation is rounded to COW compound size, and a new
   extent is allocated. At `:936-947`, Prepare publishes only that selected
   range. Spare rounded bytes do not become guest-spendable stock.
5. `crates/carrick-core/src/mm/frames.rs:215` serves the grant: exact-generation
   authentication, occupancy check, residency publication and descriptor
   execution. It rejects publication beyond the selected range (`:270`).

Thus every new small reservation in this sequential workload needs physical
supply. This is a production backing-service lower bound, independent of
metadata refills or maintenance exits. Source analysis does not attribute the
entire measured ~2.026 exit slope: exit-class capture on the exact signed
artifact is still required. Existing native-fault-supply probes distinguish
Backing/Cow/Unselected and include range length. The VM-free reduction uses
bootstrap metadata and preinstalled descriptor tables to isolate backing
requests from metadata refills and table provisioning.

## VM-free red witness

`anonymous_reservation_first_touch_service_budget` lives in the existing
`carrick-el1-linux::aarch64_process_tests::native_fault_supply_tests` harness.
At 64/256/1024 it interleaves production anonymous dispatch, production fault
selection including the live descriptor scan, and production grant settlement.
It counts actual published physical-supply selections, supplies isolated
synthetic physical extents through Prepare, authenticates against the live
reservation owner, consumes each grant receipt and checks committed, distinct
private leaves retained across subsequent grants.

The backend fixture supplies memory/table storage; it does not emulate guest
instructions or measure host-exit classes. The counter is a lower bound on
service requests: the native intake, park/wake/ACK transport and HVF allocation
are not executed here. A service budget failure is conclusive; passing this
binding alone cannot certify the signed total-exit slope. First-touch readback,
physical zeroing and actual first-write execution remain signed obligations.
The assertion uses the signed contract's unchanged strict <1/8 slope.

The completed main-source run reports:

| Reservations | Backing requests |
|---:|---:|
| 64 | 64 |
| 256 | 256 |
| 1024 | 1024 |

Every reservation and grant completed; the strict budget then failed with
`delta=192/192, required <1/8` (exit 101). The witness is active and intentionally
red in this diagnostic draft. Command:
`cargo test -p carrick-el1-linux --lib anonymous_reservation_first_touch_service_budget -- --nocapture`.

## Proposed fix and why it exceeds the focused implementation slice

Simply broadening the mapping-bound grant across holes fails exact-node
authentication. Coalescing only existing nodes cannot cover reservations
created later in this interleaved sequence. Raising grant target size does not
remove the per-node clip. Prepared stock requires explicit lifetime and
authentication rules before it can safely cover those future reservations.

Reuse the existing first-touch stock mechanism, moving its authority into the
shared ring path rather than adding another allocator:

- `carrick-kernel/src/dispatch/mem/fault.rs:555` already has
  `try_root_grant_for_page`: it includes eligible arena holes, excludes occupied
  and owed-return spans, and limits stock to a half-window to avoid whole-block
  publication that cannot be partially retired. Move this policy into the
  neutral reservation/frame owner; do not copy it or forward native faults to
  that host policy. File-backed mappings keep their exact source windows.
- Introduce a typed distinction between a mapping-bound supply window and
  private stock. Stock authentication must validate the fault node incarnation,
  every covered node/hole, pending reservations, owed returns and live
  descriptors under the same editor. The existing single-node
  `authenticate_transfer_fault` must keep its current exact-range guarantee.
- Publish zero private stock as invalid prepared descriptors and retained
  residency, with only the faulting permitted page made live. A hole must still
  fault and decline in `root_fault_admission`; a new reservation must adopt
  stock using the existing `memory.rs:993-1058` path, which re-permissions
  prepared leaves before metadata commit. Keep prepared leaves page-sized so
  partial permission, fixed replacement and retirement remain supported.
- Retain unused stock in the native MM's physical custody. The host-dispatcher
  implementation already tracks stock and returns root holes at reconciliation
  (`mem/el1_reservations/returns.rs:70`). Move that ownership/return rule into
  shared custody too. The native path must not leave stock invisible to fork,
  exec or exit. Fork must never give both MMs writable ownership of an unused
  page. Cancellation and failed publication release physical custody only
  after rollback proves no reachable leaf remains.
- Replenish on window exhaustion through the existing asynchronous physical
  service. With 1 MiB half-windows, the 10 MiB fixture population needs roughly
  ten grants, rather than 1024. Derive a page-proportional bound that accounts
  for window boundaries and holes; do not hardcode these observations.
- Share stock planning/authentication/returns between ARM and x86. Per-ISA
  code retains descriptor mechanics only. Do not enable a default-off second
  path, preallocate a huge arena, or use a shared-zero COW source.

The existing adoption mechanism reduces the work but does not make broadening
`window.range` safe: the native wire type, authenticator, grant application and
physical-retention lifecycle currently all assume one node. Moving the host
stock policy and retirement authority, changing that protocol, and proving
concurrent fixed replacement/fork/rollback exceeds a credible ~1.5k-line fix.

Suggested sequence: (1) move stock eligibility and retained lifetime to the
shared owner with two-live-MM and rollback witnesses; (2) integrate typed native
stock grants and existing adoption, turning this red budget green; (3) complete
signed lifecycle/return acceptance and artifact promotion. Use a native PR
stack for dependent slices, with no copied policy between layers.

Acceptance remains: this service slope green at all three scales, existing
fault/permission/fork/retirement contracts green, signed anonymous-reservation
exit slope <0.125 with full exit classes, signed semantic readback and native
ARM64 Docker differential, then exact-artifact probe/smoke/full promotion.
