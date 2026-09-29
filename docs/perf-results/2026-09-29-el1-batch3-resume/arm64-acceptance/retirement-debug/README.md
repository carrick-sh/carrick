# Bounded Go retirement diagnostic

The fixed acceptance population remains red: `conf-20571-c00` attempted
terminal retirement of frame 2697 while mappings remained live.

A separate debug-entitled copy of the tested release executable ran the
same pinned ARM64 Go workload at most 20 times, stopping on any nonzero
exit. All 20 completed with BUILD_OK; no fatal or deadline triggered a
capture. No core was produced. This is a negative reproduction result,
not acceptance and not evidence that the original failure disappeared.

The runner used a 5-second deadline and 60-second fatal hold for LLDB
capture. The executable text section matches the release artifact; signing
identity differs as recorded in identity.json. Both full executable hashes
were rechecked afterward and unchanged. Post-population process census
found no matching guest, helper, or debugger processes.

Sampling stops here. Next: a deterministic two-MM interleaving test covering
the authority-count query, backend retirement planning and kernel commit.
The inspected detached path acquires FrameRegistryGuard only for kernel
publication, after VMM staging. This supports a race hypothesis but does
not yet establish causation for the observed Go failure. Preserve the
FrameStillMapped refusal; do not waive, retry, or serialize the workload.
