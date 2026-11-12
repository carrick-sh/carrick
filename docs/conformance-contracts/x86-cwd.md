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
