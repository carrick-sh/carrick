# follow-up: vfork from a host-loaded root returns at once (parent not suspended)

**Labels:** follow-up, conformance (guest-visible ordering)

`NativeProcessEntry::fork` (`crates/carrick-el1-linux/src/native_process_runtime.rs`, the `fn fork` impl of the process venue)
downgrades `ProcessForkParent::SuspendedUntilExecOrExit` to `Runs` when the caller's record is not native-owned, i.e. the
host-loaded root. Linux suspends a vfork parent (`CLONE_VFORK`) until the child execs or exits. Under the downgrade the
root and its child run concurrently on copy-on-write copies of the same memory.

Why it matters now: Go's vfork passes a zero child stack (`rawVforkSyscall(SYS_CLONE, CLONE_VM|CLONE_VFORK|SIGCHLD, 0, ...)`),
so the parent and child immediately take first-write faults on the *same* stack pages, with every signal blocked in the
parent (`runtime_BeforeFork`). glibc's posix_spawn gives its child a separate stack, which is a possible reason py-subproc
does not see this. go-version (root `go`) is the only scoreboard row on this path: it dies with a bare SIGSEGV (139), while
go-hello's `go` (a native child of `sh`) takes the suspended path and fails differently (EFAULT). Candidate cause for #2276,
pending a signed trace (`scripts/dtrace/go-sidecar-fault.d`).

Acceptance: a root vfork parent stays suspended until its child's exec is admitted or the child exits (or an
equivalent proof that concurrency here is not guest-visible), with a two-live-process witness that has the child write
the parent's stack page before exec.
