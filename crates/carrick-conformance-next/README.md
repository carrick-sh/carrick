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

## Running Tests

Guest-running tests boot real HVF virtual machines and require the hypervisor
entitlement. Run them via the signed test recipe:

```bash
just test-conformance-next
# or directly:
./scripts/test-signed.sh carrick-conformance-next
```
