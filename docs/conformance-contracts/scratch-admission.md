# Scratch admission

`host.vfs.scratch-admission` protects Linux case-sensitive pathname identity
at the host scratch boundary. Signed gate startup checks the configured home before
running tests. Host-only acceptance and VM-free backend construction do not
require case-sensitive storage; guest execution admits the selected root. An explicit home wins; the default admits only internal, non-removable conventional storage, then
tries the home and temporary candidates in order. No usable candidate yields
one early signed-phase error naming `CARRICK_HOME`. An unusable explicit home never falls back.

The shared VFS probe bounds the caller's wait, including directory creation and
cleanup, to two seconds. A blocked filesystem worker can remain detached; the
deadline cannot cancel kernel I/O. Internal storage configuration is still
required. The override resolver witness counts conventional accesses and
requires zero. The stalled-probe witness checks that the resolver returns while
the worker is still blocked, then releases and joins its completion protocol.

A timed-out probe also refuses VM-free backend construction, so construction
cannot retry I/O on a stalled disk. A completed insensitive probe may be used
for VM-free work. The temporary fallback is scoped to the effective user ID.
The smoke comparison selects its image cache with `--store`, preserving the
same scratch configuration and resolution order as library execution.

The acceptance entry-point witness runs against an isolated clean repository.
It first proves that host-only acceptance reaches a host step with the same
unusable override.
On a case-insensitive temporary volume it leaves scratch writable and proves
that the real probe rejects it before any phase starts. On case-sensitive hosts
it supplies an unusable override to exercise the same early refusal. A separate
preflight command witness validates a real case-sensitive home when available.
The signed runner uses that command before building or executing test binaries.
Native macOS and signed acceptance evidence remain required before landing.

Resolver witnesses also require an external/USB-like conventional volume to
perform zero case probes there, an internal case-sensitive one to win, and
a case-insensitive home to fall through to temporary storage. Volume metadata
and the case probe share the same deadline. Native macOS volume-property
classification still requires a live check on the signed host.
