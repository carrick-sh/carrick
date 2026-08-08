#pragma D option quiet
#pragma D option aggsize=16m
#pragma D option dynvarsize=8m

/*
 * tier-d-wait-idle-cadence.d -- detect timer-driven Tier-D poll redispatch.
 *
 * WHAT IT MEASURES
 * ----------------
 * Tracks Carrick's io-wait USDT intervals and the host poll/poll_nocancel calls
 * they contain for the launch-owned process tree. The decisive regression
 * counter is `unbounded-poll-zero`: a host poll returned 0 while Carrick had
 * declared the guest wait unbounded (`io-wait-begin timeout_ms == -1`). Such a
 * return can only come from an internal timeout; an event-driven unbounded poll
 * returns positive readiness or EINTR/error, never a timeout result of zero.
 *
 * PROVIDER ABI QUALIFICATION
 * --------------------------
 * Qualified on Darwin/arm64 on 2026-08-08. Carrick `io-wait-begin` arguments
 * are (tid, fd_count, timeout_ms, fd0, events0, fd1); `io-wait-end` arguments
 * are (tid, result, fd_count, fd0, fd1, fd2). Darwin's syscall-provider return
 * arg0 is the syscall return value and `errno` is the return errno. `proc:::
 * create` child pid is `args[0]->pr_pid`.
 *
 * PERTURBATION
 * ------------
 * LOW-TO-MODERATE. It enables Carrick USDT plus host poll entry/return probes
 * and performs count/sum aggregations only. It is mechanism evidence, not wall
 * time authority. A valid capture ends naturally with live=0, timed-out=0,
 * probe-errors=0, at least one io-wait and at least one host poll.
 *
 * Usage:
 *   CARRICK_NATIVE_DIRECT=1 carrick trace \
 *     --script scripts/dtrace/tier-d-wait-idle-cadence.d \
 *     --trace-out /tmp/tier-d-wait-idle-cadence.out -- run ...
 */

dtrace:::BEGIN
{
    started = timestamp;
    seconds = 0;
    live = 1;
    completed = 0;
    timed_out = 0;
    probe_errors = 0;
    tracked[$target] = 1;
}

dtrace:::ERROR
{
    probe_errors++;
}

proc:::create
/tracked[pid] && !tracked[args[0]->pr_pid]/
{
    tracked[args[0]->pr_pid] = 1;
    live++;
}

proc:::exit
/tracked[pid]/
{
    tracked[pid] = 0;
    live--;
}

proc:::exit
/completed == 0 && live == 0/
{
    completed = 1;
    exit(0);
}

carrick*:::io-wait-begin
/tracked[pid]/
{
    self->io_wait = 1;
    self->io_timeout_ms = (int64_t)arg2;
    self->io_started = timestamp;
    @io_wait_begin[(int)arg1, (int64_t)arg2, (int)arg4] = count();
}

carrick*:::io-wait-end
/tracked[pid] && self->io_wait/
{
    this->duration = timestamp - self->io_started;
    @io_wait_end[(int)arg1, self->io_timeout_ms] = count();
    @io_wait_ns[(int)arg1, self->io_timeout_ms] = sum(this->duration);
    @io_wait_max_ns[(int)arg1, self->io_timeout_ms] = max(this->duration);
    self->io_wait = 0;
    self->io_timeout_ms = 0;
    self->io_started = 0;
}

syscall::*poll*:entry
/tracked[pid] && self->io_wait/
{
    self->host_poll = 1;
    self->poll_unbounded = self->io_timeout_ms == -1;
    @host_poll_entry[probefunc, self->poll_unbounded] = count();
}

syscall::*poll*:return
/tracked[pid] && self->host_poll/
{
    @host_poll_return[probefunc, self->poll_unbounded, (int)arg0, errno] = count();
    @unbounded_poll_zero = sum(self->poll_unbounded && (int)arg0 == 0 && errno == 0);
    self->host_poll = 0;
    self->poll_unbounded = 0;
}

tick-1s
{
    seconds++;
}

tick-1s
/seconds >= 15/
{
    timed_out = 1;
    exit(0);
}

dtrace:::END
{
    printf("TIERDWAIT1|section=io-wait-begin\n");
    printa("TIERDWAIT1|begin|fds=%d|timeout-ms=%d|events0=%#x|count=%@d\n", @io_wait_begin);
    printf("TIERDWAIT1|section=io-wait-end\n");
    printa("TIERDWAIT1|end|result=%d|timeout-ms=%d|count=%@d\n", @io_wait_end);
    printa("TIERDWAIT1|duration|result=%d|timeout-ms=%d|total-ns=%@d\n", @io_wait_ns);
    printa("TIERDWAIT1|max|result=%d|timeout-ms=%d|max-ns=%@d\n", @io_wait_max_ns);
    printf("TIERDWAIT1|section=host-poll\n");
    printa("TIERDWAIT1|poll-entry|name=%s|unbounded=%d|count=%@d\n", @host_poll_entry);
    printa("TIERDWAIT1|poll-return|name=%s|unbounded=%d|retval=%d|errno=%d|count=%@d\n", @host_poll_return);
    printa("TIERDWAIT1|unbounded-poll-zero=%@d\n", @unbounded_poll_zero);
    printf("TIERDWAIT1|complete|natural=%d|timed-out=%d|probe-errors=%d|live=%d|elapsed-ns=%d\n",
        completed, timed_out, probe_errors, live, timestamp - started);
}
