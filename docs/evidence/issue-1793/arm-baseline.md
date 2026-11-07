https://github.com/carrick-sh/carrick/issues/231#issuecomment-6699018593

**Ecosystem scoreboard after #1779: 3 of 8 on main `71c57e1066`, up from 1 of 8 on `49ab5c89cc` (carrick-87).** Freshly built signed binary (sha256 `88070ad060fc35de…`, hypervisor entitlement present). Each result checked against its saved stdout and stderr.

| workload | `49ab5c89cc` | `71c57e1066` | what happened now |
|---|---|---|---|
| Go `go version` | FAIL | **PASS** | `go version go1.24.13 linux/arm64` |
| Go `go run hello.go` | FAIL | FAIL | carrier fatal `entry_binding … reason=EntryBinding` when `go` forks the build (#887) |
| CPython start | PASS | PASS | `3.12.13` |
| CPython thread | FAIL | **PASS** | `thread-ok`: **#1779's futex fix, confirmed** (was glibc "futex facility returned an unexpected error code") |
| CPython fork | FAIL | FAIL | correct output, then SIGSEGV at exit (#1733) |
| CPython subprocess | FAIL | FAIL | correct output, then SIGSEGV at exit (#1733) |
| Node `process.version` | FAIL | FAIL | **new defect, #1791:** V8's read-write-execute `mprotect` of its 256 MiB code range is refused ("admitted owner MM cannot enter host sparse publication"), so V8 aborts with "Failed to reserve virtual memory for CodeRange" |
| Node child process | FAIL | FAIL | same as above |

**The three blockers left, in order:**
1. **#887: the `entry_binding` carrier fatal on fork/exec.** It stops `go run` and any forking shell in the Node image. Next: a signed core and ring capture on the director Mac.
2. **#1791: Node can't reserve its JIT code range.** Filed just now as a `main-defect`; a lane is starting.
3. **#1733: CPython crashes at exit after fork or subprocess.**

**A correction to the previous scoreboard:** it listed Node as failing on #887's fatal. That run measured the wrong program. This conformance image has no `node` binary, only `node24` and `node26`, and my checks didn't find them. The real first failure is #1791. Script fixed.

