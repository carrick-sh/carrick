# Signed fault-entry red

At `f38d78b9101d8eb85e2b1f0d6f76edbd642e0a6a`, the final fixture and counter
instrumentation are present but the old dispatcher and vectors remain.
The named signed test fails specifically because the fault-entry counter is
zero. Its preceding fixture success, exact stdout check, signal/retry/GPR/SP
checks all passed. The unentitled negative control passed and both scoped
cleanup counts are zero.

`identity.json` identifies the frozen signed executable, its entitlement and
DOF section. The fixture SHA-256 equals the native-tested final worker
fixture exactly. The signed runner exits 1 and does not publish a success
receipt for this red; this directory preserves the actual failure log and
independently captured artifact identity instead.

The reviewed implementation was then merged as `6ba233953`, and the same
fixture is now under signed green validation. No green result is asserted
by this red receipt.
