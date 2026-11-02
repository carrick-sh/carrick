# Core-class signal termination without a core

Issue #1442 binds `process.native.terminal-child` to the mounted x86 KVM
`x86_signal_abort.S` oracle and the existing two-process production delivery
witness `arm_wait4_reports_default_core_signal_from_production_delivery`.

Linux `wait(2)` reports WCOREDUMP and CLD_DUMPED when a core was actually
produced. The native oracle disables RLIMIT_CORE and observes SIGABRT as
CLD_KILLED (2), status 6, without bit 7. The native in-ring exit owner does
not publish core files, so its default core-class action must likewise report
signal termination without claiming a dump. This decision belongs to the
shared native owner, used by ARM and x86. Signal policy still identifies
core-class actions; it does not attest to file publication.

The VM-free parent/child witness drives production SIGSEGV delivery, observes
the zombie with waitid WNOWAIT, then consumes it with wait4 and checks ECHILD
on a second reap. It requires CLD_KILLED and status 11 with no core bit. The
existing retirement and zero-redispatch budgets remain unchanged. Signed ARM
execution and broader artifact promotion remain director gates.

The adjacent IPC fixture correction changes only oracle credential setup:
keep a nonzero native uid obtained with getuid, or drop root to uid 1000.
The queue's permission-zero EACCES (13), owner send/receive, and IPC_RMID
checks remain the same. The exact same ELF runs natively and through KVM.
