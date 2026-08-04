# Current-default exec/exit attribution

**Date:** 2026-08-03  
**Scope:** shipped-default Darwin/AArch64 native DSR  
**Decision:** **stop this line; the cold build does not clear the 10% gate**

## Question and authority

Does Carrick's fork/exec/exit/reap lifecycle provide at least 10% of end-to-end
cold-`go build` CPU, with the 20-exec `compile -V` workload naming the same
dominant segment?

The accepted captures use clean source
`d0db17970c4b4286f2fef13c5586c73e3e94a132` and its newly linked, signed
release executable:

- SHA-256 `57343c865ba07ee9e56890f6c9a8f095c9d541548f7a48a42abbe4b551c561f6`;
- Mach-O UUID `FFA89D28-EB3A-30F8-9CAF-82DC24E5CC94`;
- ad-hoc signature valid, hypervisor entitlement present, and
  `__DATA_CONST,__dof_carrick` present; and
- image
  `localhost:5005/carrick-go-conformance@sha256:357a08793e683c6a174d3955c704a5194e825f38fcdcb91d1d4ee2bccd6b188b`
  (`arm64`).

Every run used a new, initially empty `CARRICK_DSR_STORE_DIR`; the persistent
store remained default-on and Tier D remained default-off. No DTrace consumer
was attached. `CARRICK_EXEC_STAMPS` is itself diagnostic instrumentation: each
seam performs metric reads and one append write. The accepted workload walls
are therefore not a replacement scoreboard. The CPU opportunity result is
conservative for a stop decision because any stamp cost included in a measured
segment can only inflate that segment.

Power was AC with no recorded thermal, performance, or CPU-power warning.
Power source is metadata, not an acceptance gate. Preflight load averages were
1.75-2.75; no Carrick workload was active and the largest ambient process was
below 13% of one CPU. All four workloads printed one `WORKLOAD_NS` and
`BUILD_OK`, returned zero, and left zero run-ID-scoped Carrick processes.

## Instrument and decision formula

Commit `868a551d` replaced the old timestamp-only `EXECSTAMP1` export with
typed `EXECSTAMP2` records. They carry monotonic time, process and calling-
thread CPU, exact fork links, exact child PID/status/`wait4` rusage, a normal
runtime-return seam, and one top-level run-complete record whose
`RUSAGE_SELF + RUSAGE_CHILDREN` is the complete invocation CPU denominator.
`carrick debug exec-stamp-census` accepts only exact v2 records and rejects
missing, duplicate, regressing, ambiguous, unsuccessful, or unreaped
lifecycles.

The strict measured opportunity is the additive, non-overlapping CPU in:

1. parent calling-thread CPU from clone-enter to clone-parent-return;
2. child process CPU from execve-dispatch through runtime-ready;
3. process CPU from exit-begin through runtime-return/pre-host-exit;
4. runtime-return through pre-host-exit; and
5. the exact post-exit residual for leaf children from child `wait4` rusage.

The child-start to execve-dispatch window is reported separately. It combines
Carrick post-fork repair with guest pre-exec execution, so treating all of it as
Carrick-removable CPU would be an unsupported upper bound. Concurrent wall
intervals are unioned rather than summed, and the resulting workload share is
explicitly labelled an upper bound; it is not used for the decision.

## Fail-closed coverage finding

The first v2 20-exec capture, at `868a551d`, completed the workload but was
rejected:

```text
Error: pid 23942 exit-begin has no terminal runtime stamp
parser_rc=1
```

After host self-reexec, the fork-child process static resets. When a spawned
guest thread owned `exit_group`, its native thread closure called raw `_exit`
after `exit-begin`, bypassing both the initial thread's runtime-return seam and
the CLI pre-host-exit seam. Commit `d0db1797` adds the two final append records
at that irreversible spawned-thread `_exit` boundary, with a real fork/exit
regression test. The rejected stamp file is
`target/perf/exec-exit-v2-20exec-a-868a551d/stamps.txt` (SHA-256
`a7a84f4a092284304e500d722e39935bdf7958fcd16e686ac990844436c616b1`);
the rejection receipt is SHA-256
`a706bc35666cc1328ee1fa388fdebd673335277d4d3be42177a3cf9ba6dc8ef7`.
No number from that capture enters the accepted result.

## Accepted results

### 20-exec mechanism cross-check

Both independent runs reconstructed 357 records, 22 exec chains, 22 fork
pairs, 22 successful terminal reaps, 22 leaf residuals, and the single
unreaped container root exactly.

| metric | A | B | mean |
|---|---:|---:|---:|
| workload wall | 1.4607 s | 1.4632 s | 1.4620 s |
| complete invocation CPU | 3.0631 s | 3.0020 s | 3.0325 s |
| strict lifecycle CPU | 0.6002 s | 0.5989 s | 0.5996 s |
| strict lifecycle share | **19.596%** | **19.951%** | **19.774%** |
| exec-total share | **16.551%** | **17.057%** | **16.804%** |
| old-image exec share | 8.317% | 8.617% | 8.467% |
| host exec share | 2.566% | 2.595% | 2.580% |
| resume share | 5.668% | 5.846% | 5.757% |
| child-to-exec share (excluded) | 2.267% | 2.321% | 2.294% |

The micro clears 10% stably, and names exec-total—not fork, exit, reap, or the
child-to-exec window—as its dominant segment.

### Cold `go build` gate

The canonical one-file cold-`GOCACHE` workload produced 70/69 exec chains and
71/70 fork/reap pairs. Each run reconciles every relationship and terminal
record exactly; the differing process population is real per-run Go behavior,
not export loss.

| metric | A | B | mean |
|---|---:|---:|---:|
| workload wall | 10.7225 s | 11.1924 s | 10.9574 s |
| complete invocation CPU | 26.4729 s | 26.4579 s | 26.4654 s |
| strict lifecycle CPU | 2.3448 s | 2.3259 s | 2.3354 s |
| strict lifecycle share | **8.858%** | **8.791%** | **8.824%** |
| exec-total share | **5.030%** | **4.935%** | **4.983%** |
| fork share | 2.634% | 2.537% | 2.586% |
| exit-runtime share | 0.778% | 0.797% | 0.788% |
| runtime-unwind share | 0.025% | 0.025% | 0.025% |
| leaf post-exit share | 0.391% | 0.496% | 0.443% |
| child-to-exec share (excluded) | 9.240% | 10.047% | 9.644% |

The cold build fails both required conditions:

- the strict process-lifecycle opportunity is below 10% in both runs; and
- the micro's dominant exec-total segment is only about 5% on the build.

The mixed child-to-exec window does not rescue the line: its two-run mean is
below 10%, it is not pure Carrick CPU, and it is only about 2.3% on the
20-exec cross-check. No production hypothesis is selected.

## Raw artifact binding

All paths below are target-only. Hash columns bind the raw stamp stream, parsed
report, successful stdout receipt, and zero-survivor reap receipt.

| run | stamps SHA-256 | report SHA-256 | stdout SHA-256 | reap SHA-256 |
|---|---|---|---|---|
| `exec-exit-v2-20exec-a-d0db1797` | `b4110e3c2bb2d03b547025e629ee23ebc782066cedd9205b82ff5676415e513c` | `7078e74c08c3c1e1327dcfd8ba170b68ce17a4b691f87e59086bcae6e9f85990` | `fab2e8e384b607cfbaad28b2fc56218f87ab06adbed3385cb7858e47c8c5371b` | `4030c9609bf74b3ca7bc6c0a3fe17c5549279a7fc7ce280195cd072bc73f9090` |
| `exec-exit-v2-20exec-b-d0db1797` | `7144160cb9fa1398bce195b1fc29543c18339294d9309f6993d1ee140b138ac3` | `7bf979f7b10cefb6760d72760fc10a6b49d3b45eaa3d646dac374296d15e4d9f` | `69450098cada408dea4a70f63c5c2b7bb616c4b7f778682c4911ad695d12ac25` | `ad593a1f3b24f1c5500b5d3dc1f9bc8a2dc2bbe8134da3549268c6750963db6e` |
| `exec-exit-v2-build-a-d0db1797` | `313e15dd138e74a287cce161a729e7782b2ac9631f84c57e202be651a3a88aa9` | `625b01665164e57c85520a59f8571cffc67ac30fce3e58c83c5aefa90a910252` | `c111dab953a4203dbbadab5a8fcc2de5b9ed637ab336abaafd1f5cfe9bfea117` | `a917476d0a42faddffff8302bd810c38fdc5109be106c0f06b8c986523750d0c` |
| `exec-exit-v2-build-b-d0db1797` | `26e03395fde7f29db067707aeb40d3f7bb5e1a1f81ce4238f22dc6d8af405747` | `f2f9d84f81ec948c5e6b4f98fcc259b3a6f8f1d6ee38a2d080fe90cfac2b15b5` | `a64ec74a63f97a08d28e9297a618031086e7ac44aa64abcab49a6662f450ec38` | `3a72a9104f0f2c47d0b78bac984c47dabbaf72558a33333927ed1ee903cc9409` |

## Consequence

Keep the exact opt-in exporter and fail-closed census: they turned a silent
multi-threaded exit hole into a rejected capture and then reconciled four
independent process trees. Do not pursue an exec/exit production change from
this evidence, and do not change the official 10.4446x shipped-default
scoreboard.

The next measured candidate returns to the remaining emitted-code residue.
The current default shape census identifies 33.7% of executed emitted
instructions as Carrick save/restore traffic for four borrowed physical
registers, about 15% of total build CPU. The next bounded attribution is the
aggregate subset of that traffic which block liveness can prove unnecessary,
starting at the internal-fallthrough x17 seam and then applying the same proof
to the other borrowed registers. An x17-only candidate is not preselected:
the existing census projects x17 at only about 6.8% of total build CPU, below
the campaign gate. This is distinct from the rejected trusted-entry route
copies. A production candidate exists only if a current-default mechanism
census shows at least 10% total-CPU opportunity across a correctness-preserving,
non-overlapping class, after which it still requires a controlled end-to-end
gate.
