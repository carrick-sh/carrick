# Inherited host descriptions after root redirection (#1410)

Contract: `kernel.native.host-file-venue`, with
`kernel.el1.ipc-fd-authority` retaining the existing descriptor ownership and
allocation budgets. Linux `dup(2)` and `fork(2)` require a restored stdout and
an inherited redirected file to retain the same open description, independently
of whether the parent still has a descriptor for it.

The native-process witness runs the root's production dup, open, write,
restore and close dispatch, then the production native fork entry. The child's
published table is served by the public carrier file entry. It requires exactly
`y\n` on the run's stdout even after the root closes fd 1. Kernel venue tests
also cover `/tmp/f` redirection, persistent redirection and final resource
release. These are VM-free witnesses, not signed guest execution.

Publication retains the service view as physical custody, not as an extra host
fd. Final host close removes the forwarding publication before releasing its
pin. A pinned ring resource lends a temporary functional lease while the
existing description cores execute; it can do so after host fd count reaches
zero because the resource's physical hold has prevented close. Final ring
retirement releases that view and backing. The lifecycle witness checks both
the resource count and the destruction of the retained view, preventing a
publication backlink from silently becoming a leak.

No new operation or host crossing is introduced. Descriptor selection remains
in the ring table and uses the existing one-pin service lookup. In-zone objects
retain their existing routes. Signed refused-crossing/counter diagnosis,
`echo x > /tmp/f; /bin/echo y`, Docker parity, runtime ratios and signed
promotion remain required on the director's Mac; this Linux worker cannot
claim that evidence.

The review also found that serving inherited files requires observing the
ring's mutable flags. A non-owning mode observation uses the exact OFD key and
a weak host owner, with generation checks around the atomic mode read. It
neither selects an fd nor extends resource lifetime. Thus child `F_SETFL`
changes remain visible after parent close without creating an owner cycle.
The core reuse witness rejects a retired or recycled incarnation.

The signed binding `el1_fork_exec::native_child_stdout_after_root_builtin_redirection`
runs `/bin/sh -c 'echo x > /tmp/f; /bin/echo y; exit $?'` through
`ContainerBuilder::run_blocking`, requiring exit zero and exactly `y\n`. It reports and rejects child write
policy and venue refusal counters, so a signed red run can distinguish the
refusal populations.
The trailing `exit` prevents a last-command exec optimization from bypassing
fork inheritance. It constructs no carrier write records. Run it with
`CARRICK_TEST_TARGET=el1_fork_exec just test-embed native_child_stdout_after_root_builtin_redirection`.
This binding is added but has not been run on this Linux worker. Signed
red-first execution, refusal attribution and native ARM Docker parity remain
blocking acceptance evidence; this change is **Part of #1410** and stays draft.
