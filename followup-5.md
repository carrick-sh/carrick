title: resolve x86 Go exec ENOSYS and separate version fault
parent: #2271

Evidence from the prior-round PR receipts (not rerun in round 2):
go-hello exits 126 on main e2e10d32a and round-1 head 905ed7c95 with sh: 1: go: Function not implemented. go-version exits 125: main reports FaultDoorbellWord(14), head reports kernel fault policy refused reason 9. These are distinct next stops; no claim that IPC parity fixes them.

Acceptance:
Use bounded carrick tracing to identify the failing exec ordinal and ownership boundary, then add a production-entry red witness and implement through the shared exec owner. Verify go-hello output and go-version separately with exact source/binary identity. No fake success or enlarged timeout.

Clean room: consult specifications and man pages; do not read copyleft source.
