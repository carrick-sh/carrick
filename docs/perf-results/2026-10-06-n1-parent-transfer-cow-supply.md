# N1 parent transfer: exact child COW supply

The exact `3804e37e773ec63be321737a0a18f9d61f4717c6` signed cycle
still fails `el1_transparent_fork_exec_shared_backing`, which passes on main
`65098ea0e4a899f91ba047f6e380a26fbd56208a`. Its first failure remains
`owner parent transfer refused`. Evidence is retained under
`/Volumes/carrick-build/evidence/n1-cm/fork-3804e37e7/`.

The carrier breakpoint in `stage_with_loan`, after releasing its CPU loan,
captures the owner result during `bootstrap_hvpatch_process_child` SETTID:

```text
PARENTSELECTDEBUG1 errno=11 tag=2 detail=0 revision=0 fork_sequence=0
target carrier=1 mm=3 incarnation=1 address=0x6000002fd0 len=4
```

The selected page is `0x6000002000`, range `0x6000002000..0x6000003000`,
with Linux RW intent. Tag 2 names COW stock, rather than an owner wait.
FINISH has already completed, so this write has no pending-fork sequence.
The synchronous parent loop discarded every supply request together with
its owned cursor. LLDB's diagnostic used the default cached image environment;
the separate signed test cycle supplies the qualified main-parity result.
The retained core and event ring contain no ring read errors.

Handle this specific physical COW request with the existing
`user_transfer::supply` and exact target custody. SELECT has already dropped
the owner editor; native stock provision does not edit descriptors or borrow
a CPU. Keep the same `OwnedUserTransfer` and copied prefix, then select again.
EL1 still owns COW copying, descriptor publication and permission decisions.
A declined supply fails closed. Other physical, retirement, owner-wait and
metadata outcomes remain unsupported by this synchronous parent operation;
this change does not claim a general post-fork asynchronous continuation.

The existing native refill witness verifies one exact-MM physical inventory
grant, no peer grant, and no duplicate allocation while stock is ready.
The fork-scope witness verifies that a fresh post-FINISH transfer retains no
obsolete pending-fork capability. These do not execute the production loop.
The signed failure above is its behavioral red; green signed qualification
requires a newly published exact bundle. No budget or wait bound changed.

Host verification passes 119 AArch64 unit tests and the one native refill
test. Contract validation, fmt-check and workspace clippy pass. Logs are in
`/Volumes/carrick-build/evidence/n1-cm/parent-cow-supply/`.

The same three-test cycle remains **0/3 main-pass matches**: host-buffers now
faults on its first guest file store before fork, while inotify still returns
loader ENOMEM. Those E failures and clone-TID/file-table work remain open.
Full signed acceptance has not executed.
