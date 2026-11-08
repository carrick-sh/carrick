# Shared PID/TID authority (#1838)

`kernel.el1.thread-lifecycle` and `process.native.arm-admission` retain their
existing Linux semantic and work-budget bindings. Host and native births
must share one namespace table: neither a live thread nor an unreaped child
may have its internal number issued to another birth. Visible allocation
uses the exact host-admitted namespace domain, including its incarnation.

The zone table has 8192 nodes (one null sentinel), occupies 393296 bytes,
and never grows. Each node carries either one internal number's role
claims/domain or one visible namespace cursor. The AVL implementation keeps
lookup and claim/release logarithmic, with a fixed non-recursive update
path. Bootstrap adoption preflights capacity and collisions before copying
claims under the leaf lock; allocation and freeing the local storage happen
outside that lock. Host tokens retain their original authority cell across
bind, so their drops release into the same table as ring claims.

The production ARM entry witnesses keep two host-born siblings live, fork,
check child getpid/gettid, exit with status 23, and reap through wait4. Other
variants check reverse host allocation, host reuse after reap, actual lock
contention, and fixed-table exhaustion returning errno 11 followed by
recovery after reap. The contention observer exists only in test/host-test
builds, does not change the shared layout, and observes a failed acquisition;
the host releases only after that observation. All coordination is bounded.

Root admission claims only previously issued numbers. Thread claim release
and stock replenishment follow clear-child-tid notification. Zone mode refuses
boot export rather than leaving a second transferable owner. These VM-free
checks do not prove the signed Node workload or attribute its carrier crash;
paired signed proof and merge-group acceptance remain required.

The review regressions in #1841 are covered at production root admission:
`production_unmapped_root_{early,late}_bind_admits_and_forks` boots a
`for_prepared_launch` container without a PID region, binds the zone before
or after bootstrap, and calls native admission without fixture namespace
seeding. Host reservations remain live across native fork. The child PID and
leader TID must equal the internal claim and avoid those reservations.
`production_root_domains_retire_after_{bootstrap,cancel}` checks initial
root retirement and four cancelled `prepare_container_root` operations. Each
namespace retirement must return the cursor count to baseline, and each
cancelled preparation must return all number claims to baseline.

Unmapped launches bind a cursor-free domain at root preparation. Native fork
and thread stock bind their reserved internal claim and derive the visible
number from that same claim. Remapped launches retain the incarnation-keyed
cursor. Root membership preparation now attaches the namespace's registry
owner and binds the domain while holding the namespace lifecycle lock, the
same ownership path used by later members. Retirement therefore cannot miss
a cursor created by either bootstrap or a cancelled later root.
