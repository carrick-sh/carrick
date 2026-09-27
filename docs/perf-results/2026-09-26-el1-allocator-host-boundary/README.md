# EL1 metadata allocator host-boundary acceptance

This receipt closes the allocator's synchronous-host-wait and concurrent
single-flight progress requirements on source
`ef57645821299226da00ad4bf4b676c2ba7c8bb4`.

The exact signed command was:

```text
CARRICK_RUN_ID=el1-allocator-final-receipt-ef5764582-20260926 RUSTC_WRAPPER= \
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
both `el1-allocator-final-receipt-ef5764582-20260926` and its `-cli` scope. The
raw run is [`signed-final-ef5764582.log`](signed-final-ef5764582.log), and the
harness receipt is
[`signed-final-artifacts.jsonl`](signed-final-artifacts.jsonl).

## Exact tested artifact

- signed test executable:
  `target/release/deps/el1_sched-f0f1569da0c4c729`
- executable SHA-256:
  `eb7b3e20a4808141e57cc98ea6c2a7131f84ba2610c4f78f93f20f974f7d5cb6`
- CDHash: `8e121283ee847d774c632ae16afc8c283def237d`
- LC_UUID: `93E349B9-74E7-373D-B5B0-44F6B21D0504`
- signature identifier: `el1_sched-f0f1569da0c4c729.tmp.76958`
- entitlement: `com.apple.security.hypervisor = true`
- `__TEXT,__dof_carrick`: present, size `0xc27c`
- signed CLI SHA-256:
  `234362e8d2ac4903913e7b28324cf1d8d3b54dcf51144d5b216139ee2def2ff4`
- Linux fixture SHA-256:
  `01656c4a7944507845ed7c12011f0e02e702ebf757a5f9fb066e7cdf8cfff7b4`
- harness receipt SHA-256:
  `aa54c8310d31b182554f8ac70873092f94ee649ba6eb94b96b67b242a2bc97d7`
- raw green log SHA-256:
  `e517ae08e595fbfa608c99a33a01dfef082691fa5def1bda87ac5aa89a2dcb3d`

Frozen copies of the executable, CLI, fixture, and receipt remain under
`target/el1-completion/allocator-final-ef5764582/frozen/`; rebuilding or re-signing
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

## Checked arithmetic red

Source `548aa42382ac0aca8e2c737f984d772d07503b43` added two behavioral
controls before changing the allocator. An oversized guest layout panicked in
alignment arithmetic, and an oversized host request panicked while deriving
its extent size. The failing transcripts are
[`arithmetic-guest-layout-red.log`](arithmetic-guest-layout-red.log) and
[`arithmetic-host-grant-red.log`](arithmetic-host-grant-red.log); their source
identity is retained in
[`arithmetic-red-source-head.txt`](arithmetic-red-source-head.txt).

The corrected path rejects unrepresentable guest layouts without changing
allocator state, rejects invalid host sizes before reserving the aperture, and
exhausts metadata tokens without issuing zero or wrapping. The VM-free work
contract now records the allocator's existing constant bounds at scales 1, 8,
32, and 128: at most two bin checks, block inspections, splits, and merges,
with exactly 64 KiB of admitted capacity per scale unit. The exact final signed
run above covers the changed source after these controls were green.

This is allocator acceptance evidence. It does not claim shared MMU
publication, anonymous first-touch closure, a better host-exit slope, memory
checkpoint acceptance, or the end-to-end 2x workload target.
