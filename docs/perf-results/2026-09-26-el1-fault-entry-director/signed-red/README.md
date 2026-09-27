# Signed fault-entry red

At `d409be2c71d918d0509f429a3d67cdd5a15f914c`, the final fixture and counter
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

The reviewed implementation was then merged as `0c30348a2`, and the same
fixture is now under signed green validation. No green result is asserted
by this red receipt.
