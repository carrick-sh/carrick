# Owned host handback transfer

Base `276793fb4`, branch `integ/batch3`. This is an unaccepted lifecycle
checkpoint under controller A; steps 4-5 of the handback-publication plan
remain open. No signed execution is claimed for this changed source.

## Correction and witnesses

Host-bound producers now claim an explicit Transferring state and retain a
non-copyable HostTransfer until their queue/payload mutations finish. Host
wake batches retain that token until original bucket locks are released and
remaining waitv entries are unlinked. Cancellation atomically requests
retirement from the producer and returns Deferred; it cannot free the record
under cleanup. Signal/control requests during a detached relocation prevent
its guest placement, leaving the completing producer to hand back readiness.

The transfer publishes Host only as its last record operation, or frees a
cancelled record without exposing Host. Current-record retirement no longer
asks the runtime to free an already-retired record. Kernel readiness/control
consumers defer while a producer owns the transfer. Shared ABI hashing covers
the new claim encodings, despite unchanged record layout.

`before.log` repeats both original host reds on this baseline. They are now
ordinary tests: the cancellation witness retains the replacement-corruption
assertion on the old AlreadyHost path; on the new Deferred path it requires
the producer to finish Stale, retire the original and release its slot.
Additional positive/negative controls cover a two-entry waitv transfer and a
control request defeating guest relocation. Existing callback/batch identity
witnesses still require the original incarnation after reuse.

## Validation and limits

- Scheduler core: 58 passed; EL1 host tests: 74 passed; ABI: 32 passed.
- Kernel/semantics: 2,459 passed, one existing ignore, 21 binaries.
- Kernel serial-host: 109 passed (four nested child runs also passed).
- Runtime serial library: 630 passed, eight existing ignores.
- Affected core/EL1/kernel/runtime all-target Clippy with warnings denied
  passed; compile-check passed; registry 68 contracts passed.
- A first sandboxed compile-check could not generate USDT after macOS denied
  provider discovery. The unrestricted compile-check succeeded; no source
  workaround or disabled observability was used.

The remaining audit is substantive: raw-index frees and reads after live()
(including discard callbacks, service adoption and context restore), OnCpu
request/cancel flag lifetime, sequence-wrap authentication, and exact
scheduler handback wake targeting. Do not infer those are safe from the new
producer token. No historical Python/otmp attribution, WorkObservation
binding, fresh signed gate, complete batch acceptance or performance closure
is claimed. The earlier signed receipt at 40a707ba0 belongs to older code.
