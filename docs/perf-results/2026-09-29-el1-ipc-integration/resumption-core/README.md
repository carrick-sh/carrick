# Remaining IPC stall: captured progress state

Preserved signed source8c9617950, SHA256
90f727e06005f80de57b63de11c55e824527915e8398bee8cb197bd0275082b0.
Run el1-ipc-lldb-20260929 stalls at pipe8. Carrier8177, core preserved at
/private/tmp/el1-ipc-lldb-8177.core (root-owned,33MiB). LLDB attached live,
saved modified memory and all stacks, then detached. First batch stopped
at a missing optional symbol lookup; second batch saved the core.
Rootless core open and sudo-python failed; LLDB Python read the core.

One IPC directory found at VA0x102b1c000, core offset0x25a000. Header
magic/version/state valid; layout hash0xdb76683c8df6451e exactly matches
the linked ABI layout helper. Derived repr(C) offsets: objects147648,
operations344320; object size192, operation slot136. The script uses this
core-specific offset and must not be reused blindly on another core.

Objects2/3 are unlocked pipes with zero used/unread bytes, live reader and
writer counts1. Request read/write sequences113/113; response112/112.
Operations4#277 and9#242 are live reads, len8,written0, objects3#0 and2#0,
tasks9/11,mms5/6,fds9/7. This rules out unread bytes stranded in this
captured pair; it does not prove exactly where progress was lost/replayed.

Scoped cleanup0; handle63151 terminal137, captures terminal. No acceptance.
Two consecutive supporting intervals trigger reassessment: stop live captures.
Next bounded reduction is completed-operation resumption across host handback
and scheduler switch. If nondiscriminating, retain blocker and move to
independent blocked descriptor lifetime work instead of expanding diagnostics.
