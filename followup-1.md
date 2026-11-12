# Follow-up 1: the audit observer records no native-child syscalls, so probe cases stay red after a guest-visible fix

**Found by:** #2206 worker (PR #2214).

**What happens:** `run_with_audit` installs an `AuditObserver` (`require_fast_path_visibility`). Calls a fork child makes through the native host-file venue, or that are served in ring, produce no `AuditEvent`. Every probe case that asserts on a child's syscall therefore fails *after* its run succeeds:

- case_21 `mkdir rd`: the run succeeds, then `expected return event for syscall "mkdirat", but none was recorded`.
- case_08 (`linkat`), case_10 (`truncate`/`ftruncate`), case_16 (`getdents64`), case_17 (`rename`) and case_06 (pipe `write` > 0) fail the same way.
- **case_05 and case_14 will too.** With PR #2214, `mkdir -p` runs, then the test asserts `mkdirat`, `chdir` and `getcwd` events from the child.

**Evidence:** run 43246641703 (`71985c0`, cloudmac-gate), `probe-cases.log` lines 562, 600, 670, 689 and 732.

**Decision needed:** should the carrier's `serve_native_host_file` (and the ring-served paths) emit observer events, or should these tests assert on guest-visible output and refusal counters instead? An observer that sees only host-task calls can't witness a ring-first kernel.

**Acceptance:** the cases above pass on both gate Macs, with no assertion weakened.
