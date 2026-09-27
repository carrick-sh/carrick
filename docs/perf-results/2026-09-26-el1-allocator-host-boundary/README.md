# EL1 metadata allocator host-boundary acceptance

This receipt closes the allocator's synchronous-host-wait and concurrent
single-flight progress requirements on source
`d31f0705504dd6dede35c6b4300dad9af196008d`.

The exact signed command was:

```text
CARRICK_RUN_ID=el1-allocator-all-green-3-20260926 RUSTC_WRAPPER= \
  just test-embed el1_metadata_allocator_ --nocapture
```

All three invoked witnesses passed together:

- sequential 10 MiB growth beyond the 9 MiB bootstrap, complete return,
  host refusal, preserved live data, and successful retry;
- four concurrent allocator users for 16 rounds while 1,024 unrelated
  host-served `uname` calls completed, with no capacity denial and exact
  grant/return byte equality;
- real growth and return with `inline_hvc_traps == 0`, proving metadata host
  work used the ordinary pending-host-work boundary rather than synchronous
  `HVC #6` from masked EL1.

The entitlement negative control passed. Cleanup reported zero processes for
both `el1-allocator-all-green-3-20260926` and its `-cli` scope. The raw run is
[`signed-all-green.log`](signed-all-green.log), and the harness receipt is
[`signed-artifacts.jsonl`](signed-artifacts.jsonl).

## Exact tested artifact

- signed test executable:
  `target/release/deps/el1_sched-f0f1569da0c4c729`
- executable SHA-256:
  `03163bb3320e3c8004d01cd719b437fe8f8b070c3d06ea6b8f6238e0936aaef2`
- CDHash: `2628dae16e3ab3e2d38176b14c47a5c3c3408be7`
- LC_UUID: `56026F4C-AB46-34C3-8C20-6245E23A5FC0`
- signature identifier: `el1_sched-f0f1569da0c4c729.tmp.70991`
- entitlement: `com.apple.security.hypervisor = true`
- `__TEXT,__dof_carrick`: present, size `0xc27c`
- signed CLI SHA-256:
  `76dd358f7ce6d089819176b380dbc86e2472b16fb9d6ac186af0bdeb069a0ea4`
- Linux fixture SHA-256:
  `01656c4a7944507845ed7c12011f0e02e702ebf757a5f9fb066e7cdf8cfff7b4`
- harness receipt SHA-256:
  `ba238c28c98fdb81d9edfb02a038034ff62fe4f9ceba8a0fab00861a5bee15ad`
- raw green log SHA-256:
  `922f6382148d35ec18eefda42c5c58561047b0a96f7c14e90840232304bda0b7`

Frozen copies of the executable, CLI, fixture, and receipt remain under
`target/el1-completion/allocator-all-green-3/frozen/`; rebuilding or re-signing
the working artifacts does not alter this receipt.

## Decisive progress red

Source `3794e3a2abe530039c1a13bdeb6be15932ff0463` removed transient terminal
allocation errors but still exhausted the descriptor-derived 258-entry bound
in 12 concurrent phases. Every failure was `0xCA880501`; every per-round and
final drain completed. That isolated an EL1-only starvation mode: a participant
that lost mailbox publication did not force a host boundary while the global
request remained pending. The raw signed red is
[`signed-starvation-red.log`](signed-starvation-red.log), SHA-256
`846286bad31718c0985e2a34c55be7ee83c49e4ea3cf4119cf5e714ab0ffb069`.

The green source marks every allocator participant that observes unfinished
carrier-wide work as pending host work. The host services at most the one
single-flight request after the allocator stack and lock have unwound.

This is allocator acceptance evidence. It does not claim shared MMU
publication, anonymous first-touch closure, a better host-exit slope, memory
checkpoint acceptance, or the end-to-end 2x workload target.
