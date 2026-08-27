# `carrick-conformance-next`

Self-hosted conformance framework for Carrick built on `carrick-embed`.

## Overview

`carrick-conformance-next` runs Linux conformance suites directly from host-native
`#[test]` runners using `carrick-embed`'s `TestContainer` and `AuditObserver`.
Instead of relying only on text output diffing against child CLI subprocesses,
in-process conformance tests directly inspect syscall outcomes, process lifecycle
events, and stdout/stderr stream separation.

The external Docker oracle (`carrick-conformance`) remains the verdict authority
throughout migration; `carrick-conformance-next` verifies parity and reproduces
existing gate verdicts.

## Authoring policy

All new generic probe coverage must be added to this crate and executed
in-process through `carrick-embed`. Do not add `std::process::Command`, invoke
`carrick run`, or extend the legacy generic runner. Docker is used deliberately
to refresh committed oracle results; it is not a dependency of the ordinary
cached feedback loop.

Legacy execution is limited to the reviewed exceptions recorded in
`scripts/conformance/retained-generic-probes.txt`, audited dedicated runners
blocked on missing public embed APIs, and the explicit CLI process-boundary
contract. Run the public probe gate with `just conformance-probes`.

This policy is mechanically checked by
`scripts/conformance/check-next-strategy.py`, which runs under
`just lint-domains`. The shard inventory tests additionally require every
eligible generic probe to appear in the exact three-way partition, and cached
oracle loading fails closed when a probe source changes.

## Running Tests

Guest-running tests boot real HVF virtual machines and require the hypervisor
entitlement. Run them via the signed test recipe:

```bash
just test-conformance-next
# or directly:
./scripts/test-signed.sh carrick-conformance-next
```
