# Live thread stock growth (#2734)

The existing `kernel.el1.thread-lifecycle` contract covers Linux `clone`,
raw `exit`, `exit_group`, and futex-based clear-tid joins. Linux `clone(2)`
and `pthread_create(3)` allow resource-limit refusals. The size of Carrick's
initial lifecycle page is not a guest resource limit.

The production CPL0 fixture runs in the root and a forked child. Each process
creates sixteen live workers that wait on a futex. The parent observes each
worker reaching its wait, joins another worker after its raw exit, and calls
`exit_group` with the original workers still live. The root reaps the forked
child with `wait4`. In the churn modes the leader creates and joins twenty-four
workers in sequence. The isolated guest checks consecutive TIDs without assuming
an absolute starting TID. Status 100 plus the zero-based clone index identifies
an EAGAIN. The same assembly also runs on native x86 Linux as a semantic check.

The short ninth-clone variant permits at most 256 carrier exits across setup,
nine births and group teardown. The production fixture also checks that the
ring records zero clone refusals. This is a whole-run ceiling for the short
workload. It does not measure an individual HVF clone or establish a timing ratio.

The ARM VM-free binding uses the existing production syscall frame and native
fork loan to exercise sixteen coexisting births and their retirement. Signed
HVF root and child runs are separate evidence.
