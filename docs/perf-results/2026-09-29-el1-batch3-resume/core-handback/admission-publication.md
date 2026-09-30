# Admission fixture publication ordering

While validating the core handback API changes on top of `b9d7fc35e`,
`just test-kernel` reported one failure: `exec_table_capacity_refuses_new_admission`
received `Unavailable` instead of `Rejected` from its first submitter after
five seconds. The complete failing log is `admission-publication-red.log`.
No production control-admission code had changed.

`ExecRuntime::admit` inserts `Pending` under its table lock, releases that
lock, enqueues `ExecWork`, then invokes the installed waker. The test waited
only for `query() == Pending`, so `try_take()` could return None before the
sender enqueued its work. Dropping that None rejected nothing. The submitter
subsequently hit the existing five-second admission deadline.

The fixture now waits on a channel signalled by the existing publication
waker and requires the first work item to exist before dropping it. Its
third admission uses the same publication edge. Capacity, deadlines, duplicate
rejection, and every outcome assertion are unchanged. This replaces the
fixture's unbounded status polling with a bounded causal notification; it
changes no runtime semantics and does not serialize a guest workload.

The focused test passed (`admission-publication-green.log`). The subsequent
complete kernel/semantics run passed 2,459 tests with one existing ignore.
This is a fixture repair, not evidence attributing either historical batch3
failure to admission control.
