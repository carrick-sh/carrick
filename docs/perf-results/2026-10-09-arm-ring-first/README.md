# ARM ring-first signed closure

Code checkpoint: `0601bee006f9509295183b3e1e7398b01d631e4c`.
Contract: `kernel.el1.arm-ring-first-crossing`.
Subsequent evidence commits do not change runtime or witness source.

## Diagnosis and red-first evidence

The inherited `target/ringswitch-hang-bt.txt` identifies the strict witness
with idle vCPUs. ARM's entry supplies no process venue; shared exit declines
home/last-thread terminal notifications. The strict crossing set refused
those notifications. The VM-free terminal witness returned `Served` instead
of `Forward` before correction. Per director ruling, ARM now admits declined
exit/exit_group notifications as x86 does (118 eligible ARM crossings).
An in-ring owner still gets the first opportunity to serve them.

Independently, aperture control and the service-copy L3 table both started at
`0x1B_0000`. Strict configuration wrote bit 3 into the first L3 descriptor.
The disjoint-geometry test failed before correction. The control record now
starts at `0x1B_2000`, after the complete service-copy table; alignment and MM
portal bounds are compile-time checked. The ABI hash covers control geometry
and semantics (`0x06e229185340f7fb`). An aligned `TestEl1Region` witness
initializes slot-zero idle descriptors, toggles both settings and reclaims
that slot after each setting.

Making `PendingFamilies::crossing_set` required first produced E0046 in x86
`NativeLane`; both x86 contexts now explicitly name the X86 set. No default
ARM selector remains.

The inherited rseq witness was explicitly replaced with the registered raw
fixture `carrick-linux-aarch64-ring-first`. It checks getuid, getpid, clock,
five-second ppoll readiness, stdout and exit_group without libc startup.
Unexpected terminal return traps rather than spinning.

## Typed policy and carrier scope

The inherited backend environment read added a new authority-debt cohort;
its actual-base rejection is retained in `authority-delta-failure.txt`.
Per director ruling, the engine now resolves the exact `=0` spelling from
the CLI's existing host-environment snapshot into `ArmRingFirst`.
Embed callers select the typed option directly. Frozen containers, prepared
runs and boot-image builders preserve it; the backend only writes the mapped
aperture. The new environment read and its introduced ceiling were removed.

The builder-freeze witness first failed with `None` instead of `Some(Strict)`;
then it passed for both settings. The engine snapshot/override and boot-region
preservation tests pass. CLI launch and relaunch explicitly request snapshot
resolution. Non-HVF branches explicitly consume this ARM-only option.

The aperture is carrier-wide. A later explicit-carrier root must match the
published policy; conflicts fail before mapping without changing live state.
The VM-free guard first wrongly accepted Strict -> OptOut, then passed both
conflict directions. This conservative admission rule was posted to the
director; no reply was received before finishing. The signed pair uses fresh
implicit carriers, rather than exercising mixed-policy admission live.

## Focused verification

All required commands exited zero:

- `cargo test -p carrick-personality-linux`: 34 unit + 48 integration tests.
- `cargo test -p carrick-el1 --lib`: 318 tests.
- `cargo test -p carrick-el1-abi`: 125 tests.
- `just test-kernel-semantics`.
- `just clippy` and `just fmt-check`.
- `CARRICK_AUTHORITY_BASE=dfc9100e277339016f537ba09e2b475470c953b6 just lint-domains`:
  source and full native compiler census passed, 1,232 counters, PR-base
  ratchet passed, no new cohort. Executed profiles: macos-cli-default,
  macos-runtime-default, macos-hvf-default. Six Linux/BSD profiles remain
  pending on this Mac; this is not full matrix completeness.

Additional tests/checks passed: four HVF hatch tests, the builder-freeze,
engine policy, boot-region preservation and raw-clock opcode-routing tests,
embed witness compile check and release musl fixture compile check.
The first debug-profile fixture check failed because this no_std fixture's
abort panic strategy is set in release; release checking passed.
The source gate correctly rejected an earlier census whose source changed
while the carrier guard was being edited; the final stable census passed.

## Signed verdicts

The first corrected-runtime artifact completed both guests in 0.07 seconds
with the expected getuid and terminal counts, but both tests failed my
incorrect `forwarded[113] == 1` assertion. Default raw monotonic clock reads
use the EL1 fast path, confirmed by the existing VM-free opcode-routing test.
The witness now requires **zero** clock host forwards. This strengthens the
work budget; runtime behavior was not changed to satisfy the assertion.
The failed artifact identity and output are retained in
`signed-clock-assertion-red-identity.json` and `signed-clock-assertion-red.txt`.
No unchanged artifact was retried.

Final command:

```sh
CARRICK_RUN_ID=ring-switch-20261009-0601bee00-2 CARRICK_CONTRACT_ID=kernel.el1.arm-ring-first-crossing just test-embed arm_ring_first_ --nocapture
```

| Setting | Verdict | getuid refused / forwarded | exit_group refused / forwarded | clock forwards |
| --- | --- | --- | --- | --- |
| Strict (default) | PASS | 1 / 0 | 0 / 1 | 0 |
| OptOut (exact `=0` policy) | PASS | 0 / 1 | 0 / 1 | 0 |

Both tests ran on the same signed executable and completed in 0.10 seconds.
The total recipe took 343.37 seconds including build/sign/admission work.
The signed builder unit test and unentitled HV_DENIED negative control also
passed. Harness cleanup, CLI-suffix cleanup and the explicit post-run
`scripts/sudo/kill.sh ring-switch-20261009-0601bee00-2` all reported **zero
survivors**. Neither run exceeded ten minutes.

Signed test executable SHA-256:
`7f9f962b51aa2acafde1bf8dccb284ce2e8ca0218a5cda1381c16dc0a8da7f51`.
CDHash: `1d6c8a0b7b87cd9e77d295f4aa807c362593ee2c`.
LC_UUID: `287625A8-1796-3A72-B4C5-88CB7DFA9604`.
Hypervisor entitlement and `__dof_carrick`: present.
Exact executable retained locally at
`target/ringswitch-verified-arm-ring-first-signed`.
The rebuilt CLI contains the `ARM ring policy conflict` marker.
Guest ELF SHA-256: `5af2b32e04acc9e3c14b39e7e58f487c8d62af0bac55682c0624c88303d25f79`.

The published f8068568ecb88d276ee346805fe07b0fb70a965d bundle verifies all 1,134
executables against the final code checkpoint by input identity
`b600ef0ca57ce49c6d03dcd6f042996db1c13294574caff919611b0f05cbfff6`.
Archive SHA-256:
`0dbfda4f0fc75e58603a5f4171a61da131124cc65bfc7e8d4b372c3c5380fb1d`.
The typed-policy and witness-assertion changes did not change fixture inputs.

`signed-artifacts.jsonl` is the unmodified successful runner receipt;
`signed-result.json` and `signed-verdicts.txt` preserve invocation, counters
and cleanup. Raw local logs remain under `target/ringswitch-*.log`.
Full batch acceptance, Docker and ecosystem promotion are director-owned and
were not run here. No runtime ratio or complete Linux coverage is claimed.
