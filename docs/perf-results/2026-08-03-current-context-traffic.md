# Current-default exact JIT context-traffic census

Date: 2026-08-03

Decision: STOP. Exact 64-bit DsrContext traffic is 16.0730% and 16.1738% of
projected total cold-build CPU in two accepted captures, but that aggregate is
not one production mechanism. The largest source-distinct class, x17 authority
traffic through slot 1128, is 7.0008% and 7.1812%. No correctness-preserving,
non-overlapping class clears the campaign's 10% opportunity gate in both
captures, so no emitted-code candidate was implemented.

## Question and authority

The older sampled-shape record grouped every x28-based 64-bit access and
projected the group near 15% of total CPU. That was enough to justify a more
exact census, not enough to justify removing a save or restore. The current
instrument joins sampled JIT PCs to authenticated retirement snapshots and
reports the exact instruction word, context slot, physical register, and
direction. A source audit then decides which rows share one mechanism.

The portable command is:

    carrick debug jit-shape-census TRACE --snapshots DIR \
      --jit-share-of-total 0.46505

The projection input is the corrected current-default share of total CPU spent
executing emitted code. It is retained in every report and is not inferred from
the traced run.

## Accepted captures

Both captures used the cold go-build workload from
localhost:5005/carrick-go-conformance:1.24 under the shipped native defaults.
Each ended naturally with exactly one BUILD_OK, WORKLOAD_NS, workload ok, and
SHAPE1 completion record. Both had zero copyin errors, zero bounded
termination, complete target-exit receipts, and no scoped survivors.

| evidence | capture A | capture B |
|---|---:|---:|
| total samples | 24,211 | 24,129 |
| JIT samples | 12,236 | 12,246 |
| non-JIT samples | 11,975 | 11,883 |
| authenticated snapshot PIDs | 71 | 71 |
| indexed blocks | 1,224,530 | 1,224,375 |
| own sample joins | 12,236 | 12,244 |
| unique ancestor joins | 0 | 2 |
| missing joins | 0 | 0 |

The store content manifest for each isolated lane was byte-identical before
and after its accepted capture. Capture A's manifest SHA-256 was
12a58e1e88db644174c638bf4bcdd9f7af066e159517948c3f1ab5a457ab93e0;
capture B's was
563cb2dfeca4b0087c3406d4fb291d1ff825999b377df1f519688fd5014a25e8.
This closes the pilot flaw in which the store population had not been frozen
before tracing.

The traced workload times, 13.947 s and 13.967 s, are perturbation metadata
only. They are not an end-to-end performance result.

## Exact results

Shares below project exact sampled instruction counts onto total cold-build CPU
using jit_share_of_total_cpu = 0.46505.

| source-distinct row group | capture A | capture B | disposition |
|---|---:|---:|---|
| all exact 64-bit context traffic | 16.0730% | 16.1738% | aggregate only; multiple mechanisms |
| x17 authority, slot 1128 load plus store | 7.0008% | 7.1812% | below gate |
| host bias, slot 1192 x19 load | 4.1617% | 4.3102% | below gate |
| rewrite scratch, slot 1120 x17 load plus store | 1.8053% | 1.7469% | below gate |
| indirect x15 scratch, slot 1160 load plus store | 0.6765% | 0.7025% | below gate |
| guest virtual x28, slot 224 into x17 | 0.9768% | 0.8355% | guest state, not removable |
| indirect-cache pointer, slot 1272 x15 load | 1.0224% | 0.9988% | below gate |

The exact x17-materialization encoding family projects to 7.8940% and 7.6103%.
It is not a semantic mechanism: literal guest writes to virtual x17 share that
encoding. It therefore cannot be added to the slot-1128 class, and the earlier
source-bound trusted-route census independently limited all route copies to
7.9971% and 7.9267%.

## Source audit

- DsrContext layout constants and offset assertions bind slots 1120, 1128,
  1160, 1192, and 1272 in
  crates/carrick-dsr-aarch64/src/gateway.rs.
- emit_internal_fallthrough_edge uses physical x17 for a virtual branch
  condition, publishes/restores the authoritative virtual x17 through slot
  1128, and records RestoreGuestX17 recovery for every emitted word.
- The lean block guard and terminal exit use the same slot-1128 authority
  channel. Async signal recovery makes compiler-style dead-register reasoning
  insufficient: the guest value must remain recoverable at every recovery
  point.
- emit_reserved_biased_memory loads host bias into x19 from slot 1192.
- emit_indirect_exit uses x15 scratch at slot 1160 and loads the indirect-cache
  pointer from slot 1272.
- Slot 1120 is the general rewrite scratch channel; slot 224 is guest virtual
  x28 state. These are not the slot-1128 edge mechanism.

The source audit refutes treating the 16% aggregate as one liveness-elidable
borrowed-register class. It also shows why a Go-specific observation about R17
allocation is not sufficient to remove the recovery channel without a broader
architectural proof.

## Provenance and receipts

- source authority: cacda86854f3c55a59802f16e8161b172e8d107f
- signed binary SHA-256:
  67ac424a88fb14f3b4f131831b7293bd9ccfe8da43a3ff2f9e885ab2f7bcb794
- Mach-O UUID: 7A0140A6-894D-34D1-B774-6A395266601B
- D program SHA-256:
  e40134bb81e4a6471f4fed81a53c961816f64b2f54a7a577171fc220905daf7e
- image digest:
  sha256:357a08793e683c6a174d3955c704a5194e825f38fcdcb91d1d4ee2bccd6b188b
- capture A trace SHA-256:
  ac2f694c3ba15e72c3bae14d4dae2de3d99eb8cccb3142e8215a26906a26eebc
- capture A snapshot-manifest SHA-256:
  66656514eac7c5e5c9794c0377746f3cbf3aeded86f1191a2fd85e5a8fafb499
- capture A census SHA-256:
  81918e7f8da429fc09f19b4f7b4c6835c7ce12b4e7cff767f4775a215a09f3c6
- capture B trace SHA-256:
  7a8992d7d5a1911f68fc17c45c7ad8073d6b05d8e4ee8ef08420f25000b3e700
- capture B snapshot-manifest SHA-256:
  be5acc3da83afdfd4d3db6546e01b1a5b585291f2974d385b9a24cec978e80b3
- capture B census SHA-256:
  c14fda30010e122a202ff738a28b39658f510b876fffe4261009ee2537276719

The signed binary passed designated-requirement validation and retained the
__dof_carrick section. RUST_TEST_THREADS=1 just ci passed at the source
authority. Host power and thermal state were recorded as metadata only.

Raw trace, snapshot, manifest, census, and workload receipts remain under:

- target/perf/current-context-a-cacda868/
- target/perf/current-context-b-cacda868/

They are intentionally not committed.

## Next decision

Refresh current-default kernel and memory attribution with the existing
native-wall and fault-address DTrace profiles. Bind fault pages to guest
mappings versus Carrick or libmalloc allocations, and apply the same rule:
implement only a source-backed mechanism worth at least 10% of total build CPU
in two agreeing captures. If guest page management dominates, compare the
Linux intent with Go's Darwin allocator lowering before proposing a host
primitive.

Eager whole-image translation remains a deferred future design. It may
amortize complete eligible images, but it cannot replace incremental handling
for JIT-on-JIT code.
