# HVPatch root-exec stage-2 transaction receipt

## Frozen red

Source `803da1296ce07ee463e63ab78d59354cf697fd50`, signed binary SHA-256
`b0ea630d0077649e98be40ee6dbf1f8a54e64b1a7f8393033ac5532233a10ecb`.
The focused `node-app-smoke` run used one cached oracle and zero Docker runs.
It failed before TAP:

```text
HVPatch exec mapping IPA 0x100000000 size 1523712 has no owning lease
```

The exact artifact identity is in `red-binary-identity.txt`; the classified row
and raw stderr are `node-app-red.jsonl` and `node-app-red.err`.

## Dynamic attribution

`exec-replace-stages-red.raw` is the scoped
`hvpatch-phase4-exec-replace-stages.d` capture. It has nonzero events, zero
DTrace errors, and reaches FramePlan, PrivateFileArtifacts,
AddressSpaceTeardown, AliasCleanup, DropBackings and PageTables, but never
MapBackings.

`global-frame-stage2-red.raw` is the existing global-frame inventory capture.
It records the predecessor identity edge at IPA `0x100000000`, its successful
unmap, every other predecessor unmap, and no successor map after teardown. This
script is intentionally unscoped and has no in-band drop/closure summary; the
capture is retained as edge evidence, not as proof that an absent event did not
happen.

The source invariant closes the attribution: the root mm has no root slot; the
old planner returned an empty lease map on that branch, while persistent exec
required one lease per non-sparse materialization. Child execs did not expose
the bug because their mm has a root slot.

## Failure-transaction proof

The replacement planner now gives root exec a fresh global-frame generation,
including its TTBR root. This avoids colliding with identity frames retained by
a live child. Replacement host backings are prepared before teardown; backend
inventory, owners and mapping rows remain unchanged while the reversible
stage-2 switch runs. If a replacement map fails, the switch removes every
successor edge and reinstalls the exact predecessor edges before returning the
error. Only a successful switch retires predecessor inventory and publishes
successor owners.

The deterministic unit tests inject failure after zero and one successor maps.
The focused live runs produced Linux SIGSEGV terminal status (`139`) with only
the named injected error and no EL1 maintenance failure or host abort; their
stderr is `fail-after-0.err` and `fail-after-1.err`.

Two focused topology reducers also passed on the signed candidate:

```text
/bin/sh -c 'exec /bin/sh -c "exec /bin/true"'          rc=0
/bin/sh -c '/bin/sleep 2 & exec /bin/true'             rc=0
```

The first covers two consecutive root execs; the second root-execs while a
fork child is live.

## Next distinct blocker

After the exec transaction fix, `node-app-smoke` reaches its real TAP producer
but the inner Node command hits its own 120-second timeout. That is a separate
runtime mechanism and is not treated as closure of the Node rows. The Docker
`node-libuv` arm also remains separately invalid because its non-root launch
cannot perform the wrapper's required `chown`/`setgid` setup.
