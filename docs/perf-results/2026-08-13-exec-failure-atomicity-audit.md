# Does a failed `execve` leave the old image runnable? Mostly — and where it
# doesn't, the process dies as "command not found"

**Recorded 2026-08-13.** KX's remaining correctness clause was "does exec
failure leave the old image valid?", never checked. This is the audit. Findings
are read from source; the three load-bearing ones were re-verified by hand
against the cited lines, and that is noted per finding.

Linux's rule: `execve` either replaces the image completely or returns an error
with the caller unchanged and still running. Errors detected BEFORE the new
image is committed must return an errno; errors after must kill the process
rather than return.

## The commit point, and there are three transactions not one

The tree note "Kernel two-phase exec transaction LIVE" describes only the
innermost of three nested transactions.

| layer | prepare | commit |
| --- | --- | --- |
| kernel object graph | `kernel/exec.rs:159` | `kernel/exec.rs:342-346` |
| runtime / dispatcher | `vcpu_loop/exec.rs:203` | `vcpu_loop/exec.rs:360` |
| HVF stage-2 (guest-visible) | `trap.rs:6851` | `trap.rs:6632` — the first successful `hv_vm_unmap` |

**The true point of no return is `trap.rs:6632`.** Everything above it must
return an errno; everything below must not.

## What is correct

**Every errno case you would name is clean.** ENOENT, EACCES, ENOTDIR, ENOEXEC,
E2BIG, ELOOP and ENAMETOOLONG are all computed before any mutation and land on
one clean return at `vcpu_loop/exec.rs:487-498`, leaving the caller resumed and
untouched.

**The kernel layer is genuinely two-phase.** Prepare allocates a *new* `Mm`,
`Sighand`, `FileTable`, `ThreadResources` and replacement `Thread`, publishes
none of them, and `PreparedExec::Drop` (`kernel/exec.rs:64-73`) resumes parked
siblings and releases the reservation without touching the published graph.
CLOEXEC fds are a filtered *copy* (`kernel/objects.rs:987-1005`) with the real
host `close()` after commit; caught handlers are reset into a *fresh* table
(`objects.rs:323-337`); argv/stack are built host-side and become guest-visible
only after teardown. `every_exec_failpoint_preserves_published_generation`
(`kernel/exec.rs:838`) already pins all four failpoints as byte-identical.

## The bug: six pre-commit failures that kill the caller with exit 127

`handle_execve` returns `Result<(), RuntimeError>`. A `RuntimeError` propagates
to the closure boundary (`vcpu_loop/mod.rs:3617`) and the terminal handler maps
it to **exit code 127** — **verified by hand** at `vcpu_loop/mod.rs:3694`
(`Err(_) => assemble_run_result(&kernel, 127, None, 0, false)`). The guest sees
its process die where Linux would have returned an errno with it still running.

| # | site | trigger | reachable |
| --- | --- | --- | --- |
| B1 | `vcpu_loop/exec.rs:215` | clone-admission drain **5 s timeout** | yes, under load |
| B2 | `vcpu_loop/exec.rs:241-243` | sibling teardown **5 s timeout**; sibling panic | yes, under load |
| B3 | `vcpu_loop/exec.rs:253-266` | any `ExecError`; `prepare_vma_freeze` **1 s deadline** | yes |
| B4 | `vcpu_loop/exec.rs:277-312` | frame-inventory capacity | rare |
| B5 | `vcpu_loop/exec.rs:332-338` | staged-VMA ack, **1 s deadline** | yes, under load |
| B6 | `vcpu_loop/exec.rs:360` | `execve_rebuild` failing before its own teardown | rare |

**Verified by hand:** `vcpu_loop/exec.rs:215` (`close_clone_admission_for_exec(…)?`),
`:241` (`terminate_siblings_for_exec(…)?`) and `:253-266`
(`prepare_exec(…).map_err(RuntimeError::Configuration)?`) are each a `?` on a
`RuntimeError`, all three before the commit.

Four of the six are **wall-clock timeouts**, so this is load-dependent rather
than theoretical. Exit 127 is also actively misleading: it is exactly what a
shell reports for "command not found", so the failure hides inside shell
workloads as a plausible-looking error.

### Ordering defect behind it

**Verified by hand:** `terminate_siblings_for_exec` (`vcpu_loop/exec.rs:241`)
runs BEFORE `prepare_exec` (`:253`). The thread group is destroyed
irreversibly, and then six fallible steps follow. Even the current kill is the
wrong shape: exit 127 is `WIFEXITED`, where Linux past the point of no return
uses `force_sigsegv`, i.e. `WIFSIGNALED`.

### Latent pre-commit mutations

Masked today only because B5/B6 kill the process anyway, and **live the moment
B1–B6 are converted to errno returns**: host process title (`:318-320`),
`set_executable_identity` — `/proc/self/exe`, `cmdline`, `comm`, `environ` now
describe the not-yet-loaded image (`:321-323`), `reset_signal_handlers_on_execve`
wiping *live old threads'* altstack and handler frames (`:324-326`), and
`publish_exec_image_state` → `mem.reset_for_execve()` (`:331`) — with the
fallible `:332-338` after all of them.

The `:324-326` reset is *redundant* for the new image: the replacement thread's
signal state was snapshotted at prepare time (`kernel/objects.rs:2472-2492`).
Its only non-redundant effect is the host routed-handler reset. It is otherwise
pure destruction of the old image.

### One mutation that survives a CORRECT errno return

`runtime/exec.rs:126` calls `enter_binfmt` *inside* `load_execve_image`, which
can still fail ENOEXEC at `:136` or ENOENT at `:138`/`:145`. `enter_binfmt`
(`dispatch/mod.rs:3527-3534`) sets `binfmt_interpreted` and overwrites
`proc.argv`. So a Rosetta-redirected exec of a malformed x86-64 binary returns
ENOEXEC correctly and leaves `/proc/self/cmdline` showing the FAILED target.
This is the only case found where an errno-returning `execve` leaves
guest-observable state changed.

## Why nobody caught this: the coverage is all success-path

**19 exec probes, zero of which cover a failed exec.** `execvereset`,
`execthreads`, `execfromthread`, `proclife`, `execpermitchurn`, `fexecveprobe`
and the rest uniformly treat a failed exec as a *probe* bug — "if execve
returned, print the errno and `_exit`". `mtforkcorrupt.rs:84` is the only one
that execs a nonexistent path, from a forked child that immediately exits, and
never inspects post-failure state.

**LTP: only `ltp-execve05` is registered** (`carrick-conformance/src/main.rs:1426`),
itself a success-path checkpoint test. `execve01/02/03/04` and
`execveat01/02/03` are NOT registered — and `execve02` (ETXTBSY) and `execve03`
(errno differentiation) are precisely the "failed exec returns the right errno
and the caller lives" tests. `docs/2026-07-05-conformance-gap-fix-campaign.md`
already named them as targets.

**The kernel-layer window `kernel/exec.rs:323-346`** — post-drain, pre-publish —
has no failpoint and therefore no coverage; the last failpoint (`BeforePublish`,
`:317`) fires before the drain.

## Ranked work

1. **B1–B6**: give `handle_execve` an errno-returning exit for everything above
   `vcpu_loop/exec.rs:360`, and move `terminate_siblings_for_exec` down to just
   before it. Fixes the load-dependent process kills and the ordering defect
   together.
2. **The four pre-commit mutations** (`:318-331`), which become live bugs the
   instant 1 lands.
3. **`enter_binfmt`** (`runtime/exec.rs:126`) — the one leak past a correct
   errno return.
4. **Coverage**: one probe that fails an exec from the MAIN process and asserts
   fds, dispositions, mappings, argv and `/proc/self/exe` unchanged and the
   process still running; plus registering `ltp-execve02`/`execve03`. This is
   the cheapest high-value item here and it gates 1 — without it the fix cannot
   be shown red first.

## Honest scope

The strict Linux rule — *a pre-commit failure must not kill the caller* — is
**violated by B1–B6**. The narrower rule people usually test — *the named
errnos return cleanly* — **holds**. Post-commit sites that return `Err` instead
of aborting (`vcpu_loop/exec.rs:453`, `:459-463`, `trap.rs:7085-7145`, `:7160`)
never return an *errno*, so they do not break the guarantee, but they are
inconsistent with the abort discipline the surrounding code follows.
