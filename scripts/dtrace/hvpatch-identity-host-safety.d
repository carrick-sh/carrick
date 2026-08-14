#!/usr/sbin/dtrace -qs
/*
 * Prove that HVPatch Linux task selectors stay inside Carrick's in-process
 * kernel and never become low-numbered Darwin kill(2) targets.
 *
 * Provider ABI qualified from carrick-observability on Darwin/arm64:
 * carrick*:::syscall-entry carries (uint64_t canonical_nr, char *name,
 * uint64_t *args), where arg2 addresses six contiguous u64 syscall arguments.
 * Canonical AArch64 Linux numbers are kill=129 and tgkill=131. Darwin's
 * syscall::kill:entry arg0/arg1 are the exact host pid selector and signal.
 *
 * The cohesive kernelidentity fixture must exercise positive init PID 1,
 * target 0, broadcast -1, a negative non-init process group, tgkill, and the
 * former early-xsig SIGCHLD shape. A Darwin kill aimed anywhere in the Linux
 * low-ID range [-63, 63] is fatal evidence, including signal-zero probes.
 * The fixture's task-scoped job-control proof must also populate exact guest
 * at least two exact guest SIGSTOP(19) sends and one SIGCONT(18) send. The
 * repeated stop must be discarded by continue generation; a completed target
 * with those populations proves both that rule and that the shared Darwin
 * carrier was never host-stopped.
 *
 * Perturbation: one USDT probe per guest syscall plus Darwin kill entry. The
 * fixture is tiny; results are correctness evidence, not timing evidence.
 * The strict Rust consumer rejects zero/missing selector populations, host
 * escapes, timeout, DTrace/provider errors, drops, interruption, or nonzero
 * target exit.
 */

#pragma D option quiet

dtrace:::BEGIN
{
    started = timestamp;
    guest_kills = 0;
    positive_one = 0;
    zero = 0;
    broadcast = 0;
    negative_group = 0;
    tgkills = 0;
    xsig_shapes = 0;
    stop_signals = 0;
    continue_signals = 0;
    host_low_kills = 0;
    bounded = 0;
    errors = 0;
    drops = 0;
    target_exited = 0;
    target_exit_seen = 0;
    target_exit_code = -1;
    target_exit_reason = 0;
    printf("HVPATCHIDENTITY1|header|version=1\n");
}

carrick*:::syscall-entry
/(pid == $target || progenyof($target)) && arg0 == 129/
{
    this->args = (uint64_t *)copyin(arg2, 48);
    this->selector = (int64_t)this->args[0];
    this->signal = (int64_t)this->args[1];
    guest_kills++;
    positive_one += this->selector == 1;
    zero += this->selector == 0;
    broadcast += this->selector == -1;
    negative_group += this->selector < -1;
    xsig_shapes += this->selector > 1 && this->signal == 17;
    stop_signals += this->signal == 19;
    continue_signals += this->signal == 18;
}

carrick*:::syscall-entry
/(pid == $target || progenyof($target)) && arg0 == 131/
{
    tgkills++;
}

syscall::kill:entry
/(pid == $target || progenyof($target)) && (int)arg0 >= -63 && (int)arg0 <= 63/
{
    host_low_kills++;
    printf("HVPATCHIDENTITY1|host-kill|host_pid=%d|host_tid=%d|target=%d|signal=%d\n",
        pid, tid, (int)arg0, (int)arg1);
}

dtrace:::DROP
{
    drops++;
}

dtrace:::ERROR
{
    errors++;
}

syscall::exit:entry
/pid == $target/
{
    target_exit_seen = 1;
    target_exit_code = (int)arg0;
}

proc:::exit
/pid == $target/
{
    target_exited = 1;
    target_exit_reason = arg0;
    exit(0);
}

profile:::tick-1sec
/timestamp - started > 90 * 1000000000/
{
    bounded = 1;
    exit(4);
}

dtrace:::END
{
    this->valid = guest_kills > 0 && positive_one > 0 && zero > 0 &&
        broadcast > 0 && negative_group > 0 && tgkills > 0 &&
        xsig_shapes > 0 && stop_signals >= 2 && continue_signals > 0 &&
        host_low_kills == 0 && bounded == 0 &&
        errors == 0 && drops == 0 && target_exited == 1 &&
        target_exit_seen == 1 && target_exit_code == 0;
    printf("HVPATCHIDENTITY1|summary|status=%s|guest_kills=%d|positive_one=%d|zero=%d|broadcast=%d|negative_group=%d|tgkills=%d|xsig_shapes=%d|stop_signals=%d|continue_signals=%d|host_low_kills=%d|bounded=%d|errors=%d|drops=%d|target_exited=%d|target_exit_seen=%d|target_exit_code=%d|target_exit_reason=%d\n",
        this->valid ? "ok" : "error", guest_kills, positive_one, zero,
        broadcast, negative_group, tgkills, xsig_shapes, stop_signals,
        continue_signals, host_low_kills,
        bounded, errors, drops, target_exited, target_exit_seen,
        target_exit_code, target_exit_reason);
}
