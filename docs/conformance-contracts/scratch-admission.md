# Scratch admission

`host.vfs.scratch-admission` protects Linux case-sensitive pathname identity
at the host scratch boundary. Gate startup checks the configured home before
running any tests. An explicit home wins; an unusable default yields one error
naming `CARRICK_HOME` and never falls back to `/Volumes/carrick`.

The shared VFS probe bounds the caller's wait, including directory creation and
cleanup, to two seconds. A blocked filesystem worker can remain detached; the
deadline cannot cancel kernel I/O. Internal storage configuration is still
required. The override resolver witness counts conventional accesses and
requires zero. The stalled-probe witness checks that the resolver returns while
the worker is still blocked, then releases and joins its completion protocol.

The acceptance entry-point witness runs against an isolated clean repository.
On a case-insensitive temporary volume it leaves scratch writable and proves
that the real probe rejects it before any phase starts. On case-sensitive hosts
it supplies an unusable default to exercise the same early refusal. A separate
preflight command witness validates a real case-sensitive home when available.
The signed runner uses that command before building or executing test binaries.
Native macOS and signed acceptance evidence remain required before landing.
