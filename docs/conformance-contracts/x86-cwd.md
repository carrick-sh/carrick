# x86 cwd ownership (#1714 slice 2)

Contract: `kernel.native.host-file-venue`, with the crossing policy bound by
`kernel.el1.arm-ring-first-crossing`.

Linux authority: getcwd(2), chdir(2), fork(2), openat(2). A fork inherits the
parent's cwd by value; independent processes keep separate filesystem contexts.
The host-served root's dispatcher remains its authority. Descendants use the
shared process graph's TaskFs and existing native host-file chdir completion.

Production KVM witnesses in `cpl0_initial_mm`: root cwd/relative open agreement,
fork inheritance followed by child-only chdir, and two live processes changing
cwd independently. Each directory has a different marker byte so opening a
stale relative path cannot pass merely because both files exist. Native Linux
executes each identical freestanding ELF before Carrick. The bounded work is
one root seed capture per root fork and one native lookup per descendant chdir;
no polling, retries, or extra readiness objects are introduced.

The synchronous x86 seed transport authenticates the stopped initial MM and
retained supervisor storage, releases physical custody while the shared host
resource owner captures cwd/root, and authenticates the same execution again
before publishing the record. The decoder is shared with ARM. The process graph
remains the authority deciding which fork needs a root seed. A fork of a
non-root process copies that process's existing TaskFs without a host seed.

The two-live-process witness uses pipe-close/poll notifications, since x86
in-zone pipe byte I/O remains #1756. Both vCPUs are admitted for the concurrent case. Each process changes cwd
and closes its notification pipe before waiting for the peer's close; both
then re-check their own values before exiting. Native outputs share an already
touched BSS page; an untouched wait4 output page returned EFAULT (related evidence is on #2101).
