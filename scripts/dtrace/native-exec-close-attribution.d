/*
 * The `--exec-backend native` in the recipe below is RETIRED: `hvpatch` is now
 * the only execution backend and the only accepted value. The invocation is
 * updated to the surviving form; whether this script's probe set still fires
 * on the HVPatch lane has NOT been re-qualified, and the measurements it cites
 * were taken on the native/DSR lane.
 * 
 * How many host close(2) does ONE guest execve cost, and is it really one
 * per-exec burst?  Native (DSR) lane.
 *
 * (a) WHAT IT MEASURES
 * -------------------
 * The 2026-08-06 build-lane amplification ledger
 * (`docs/perf-results/2026-08-06-build-lane-amplification-ledger.md` §4) found
 * 74,253 host `close(2)` inside the guest `execve` service window on a cold
 * `go build` -- 1,108 per exec, 7.4% of every host syscall in the run and its
 * largest count lever. AMP1 can say "inside the window"; it cannot say whether
 * that is ONE burst per exec or ONE LEAKED BRACKET holding ordinary build
 * traffic, and those two readings call for opposite work. This separates them
 * and is the instrument the fix is measured with.
 *
 *   EP|end=<class>|pid=|closes=|ns=   one line per phase-1 episode
 *   EP|section=episode                episodes by how they ENDED
 *   EP|section=closes                 closes by how the episode ended
 *   EP|section=errno                  close(2) errno histogram
 *   EP|section=perexec                quantize() of closes per exec
 *
 * A genuine per-exec sweep is every episode ending in `execve` with a tight
 * close count; a leaked bracket is a handful of episodes carrying tens of
 * thousands of closes over seconds. Both readings were live when this was
 * written; the receipts said sweep (67/67 episodes ended in a real host
 * `execve`, 63 of them 1,169-1,184 closes, `errno=0` on all 74,253).
 *
 * (b) PROVIDER ABI FACTS (qualified on macOS 27.0 build 26A5388g, Apple M4)
 * -----------------------------------------------------------------------
 *   1. `carrick*:::native-syscall-service-entry` arg0 IS the canonical AArch64
 *      syscall number; execve is 221. The entry/end pair is UNCONDITIONAL --
 *      no `CARRICK_DSR_PROFILE` gate -- unlike `carrick*:::dsr-cache-lifecycle`,
 *      which needs a probe sink installed and would silently never fire here.
 *      (Same qualification as `native-amplification.d`, which see.)
 *   2. `terminal_handoff()` (`native_darwin.rs:3214`) fires NO `-end` before the
 *      host execve, on purpose -- the handoff can still fail and reopen. So the
 *      pre-exec phase must be left at `syscall::execve:entry`, never by waiting
 *      for an `-end` that is not coming.
 *   3. `errno` in a `syscall:::return` clause is the authoritative failure
 *      signal. The SIGN OF arg0 IS NOT, and reading it as one inverted the
 *      first pass of this investigation: it reported the sweep as failing
 *      (EBADF) closes, i.e. a blind range walk, when every close in fact
 *      succeeds on a real inherited fd.
 *   4. D infers a thread-local's type from its first textual ASSIGNMENT, and
 *      the reporting clauses here must run BEFORE the assigning clauses on the
 *      same probe. The otherwise-inert `BEGIN` exists only to declare them;
 *      without it libdtrace refuses with "self->phase has not yet been declared
 *      or assigned" before any child spawns.
 *   5. Scope is `pid == $target || progenyof($target)`, NEVER `execname`:
 *      `carrick trace` runs libdtrace IN-PROCESS inside a `carrick` binary, and
 *      AGENTS.md records a profile that was 54% profiler for exactly that
 *      reason. A guest fork is a real host child, so `progenyof` is what makes
 *      the fork children -- which are where the sweep happens -- visible at all.
 *   6. NOT here: `ustack()`. ~70 self-reexec'd guest processes carry independent
 *      ASLR slides and libdtrace holds no handle for a grandchild, so `%k`
 *      prints raw hex. For call sites use the `native-openat-callers.d` shape
 *      (key every aggregation by `carrick*:::host-image-base` and symbolicate
 *      offline with `atos -l`).
 *
 * (c) PERTURBATION
 * ---------------
 * Low -- per-thread counters plus one printf per episode, no stacks, no string
 * keys. Counts are citable; WALL AND CPU ARE NOT (the traced fixture runs
 * 2-4x slower, the band `native-amplification.d` declares).
 *
 * USAGE
 * -----
 *   carrick trace --script scripts/dtrace/native-exec-close-attribution.d \
 *     -o target/perf/exec-close.raw \
 *     -- run --exec-backend hvpatch <image>@sha256:... /bin/sh -c '<workload>'
 *
 * Set `CARRICK_RUN_ID` and reap with `scripts/sudo/kill.sh "$CARRICK_RUN_ID"`.
 * The target must be `--exec-backend hvpatch`; under the VMM backend the service
 * probes never fire and every section comes back empty, which is a wrong-backend
 * error and not a zero result.
 */

#pragma D option quiet
#pragma D option aggsize=32m
#pragma D option bufsize=16m
#pragma D option dynvarsize=64m

/*
 * Declaration only -- see (b)(4). Assigns on the BEGIN thread and is otherwise
 * inert.
 */
BEGIN
{
	self->phase = 0;
	self->closes = 0;
	self->t0 = (uint64_t)0;
	self->cfd = 0;
}

/*
 * The four ways a phase-1 (pre-exec) episode can end. All four report, so a
 * leaked bracket cannot hide as a missing class. These MUST precede the
 * assigning clauses on the same probes.
 */
carrick*:::native-syscall-service-entry
/(pid == $target || progenyof($target)) && arg0 == 221 && self->phase == 1/
{
	printf("EP|end=reentry|pid=%d|closes=%d|ns=%d\n",
	    pid, self->closes, timestamp - self->t0);
	@episode["reentry"] = count();
	@closes["reentry"] = sum(self->closes);
}

carrick*:::native-syscall-service-entry
/(pid == $target || progenyof($target)) && arg0 != 221 && self->phase == 1/
{
	printf("EP|end=other-syscall|pid=%d|closes=%d|ns=%d\n",
	    pid, self->closes, timestamp - self->t0);
	@episode["other-syscall"] = count();
	@closes["other-syscall"] = sum(self->closes);
}

carrick*:::native-syscall-service-end
/(pid == $target || progenyof($target)) && self->phase == 1/
{
	printf("EP|end=service-end|pid=%d|closes=%d|ns=%d\n",
	    pid, self->closes, timestamp - self->t0);
	@episode["service-end"] = count();
	@closes["service-end"] = sum(self->closes);
}

syscall::execve:entry
/(pid == $target || progenyof($target)) && self->phase == 1/
{
	printf("EP|end=execve|pid=%d|closes=%d|ns=%d\n",
	    pid, self->closes, timestamp - self->t0);
	@episode["execve"] = count();
	@closes["execve"] = sum(self->closes);
	@perexec = quantize(self->closes);
}

/* --- state transitions --- */

carrick*:::native-syscall-service-entry
/(pid == $target || progenyof($target)) && arg0 == 221/
{
	self->phase = 1;
	self->closes = 0;
	self->t0 = timestamp;
}

carrick*:::native-syscall-service-entry
/(pid == $target || progenyof($target)) && arg0 != 221/
{
	self->phase = 0;
}

carrick*:::native-syscall-service-end
/pid == $target || progenyof($target)/
{
	self->phase = 0;
}

syscall::execve:entry
/(pid == $target || progenyof($target)) && self->phase == 1/
{
	self->phase = 2;
}

syscall::close:entry
/(pid == $target || progenyof($target)) && self->phase == 1/
{
	self->closes++;
	self->cfd = arg0 + 1;
}

syscall::close:return
/self->cfd/
{
	@byerrno[errno] = count();
	self->cfd = 0;
}

tick-1s
{
	secs++;
}

tick-1s
/secs >= 600/
{
	exit(0);
}

END
{
	printf("EP|section=episode\n");
	printa("EP|class=%s|episodes=%@d\n", @episode);
	printf("EP|section=closes\n");
	printa("EP|class=%s|closes=%@d\n", @closes);
	printf("EP|section=errno\n");
	printa("EP|errno=%d|count=%@d\n", @byerrno);
	printf("EP|section=perexec\n");
	printa(@perexec);
}
