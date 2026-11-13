title: native exec census: x86 counts a handed-off child exec as served, ARM counts nothing
parent: #2273

When the ring owner takes a fork child's exec, the x86 CPL0 entry records
`served[nr]` (`native_exec_call`, `crates/carrick-x86-cpl0/src/linux_personality.rs`).
The #2235 live-parent witness uses that count as its "reached execve" census.
ARM's native exec begin (`begin_native_service`, `crates/carrick-el1-linux/src/dispatch.rs`)
records neither served nor refused for a successful exec, so the two ISAs'
census populations differ for the same call.

Acceptance: one neutral rule for when a native exec counts as served,
recorded by the shared owner on both ISAs, with an ARM witness and the x86
witness unchanged.
