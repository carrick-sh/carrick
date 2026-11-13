# x86 py-subproc: the parent's read of the exec-status pipe returns ENOSYS

Found on #2250 (#1482) head `38a4a0024`, x86 KVM, release build. With the
#2217 brk SIGSEGV fixed, the scoreboard row `py-subproc` now runs
`subprocess.run(...)` up to the fork+exec and then exits 1:

```
File "/usr/local/lib/python3.12/subprocess.py", line 1908, in _execute_child
    part = os.read(errpipe_read, 50000)
OSError: [Errno 38] Function not implemented
```

The parent's `read(2)` of the CLOEXEC exec-status pipe after `fork` is
answered ENOSYS on x86. This is not investigated yet: it is either a read on
a pipe the parent shares with a forked child, or a read that blocks until
the child's exec closes the write end. Evidence:
`/var/tmp/ev/sb/head.json.rows/py-subproc.err` on the worker VM.
Acceptance: a red-first KVM witness (a pipe2 + fork + child exec + parent
read) and then the `py-subproc` row.
