#pragma D option quiet
#pragma D option bufsize=4m
#pragma D option dynvarsize=16m
#pragma D option strsize=256

/*
 * Qualify the exact syscall/mach_trap spellings that terminate a controlled
 * thread or process without a matching return on this Darwin build.
 *
 * The hidden terminal fixture emits NUL-backed write markers. Only entries on
 * that marker's exact thread are candidates; ordinary returning calls after
 * the marker are negative controls and must match/clear normally.
 */

dtrace:::BEGIN
{
	thread_armed_seen = 0;
	thread_ok_seen = 0;
	process_armed_seen = 0;
	armed_tid = 0;
	returning_controls = 0;
	candidate_count = 0;
	lwp_exit_seen = 0;
	process_exit_reason = 0;
	timed_out = 0;
	violations = 0;
	active_provider[0] = 0;
	active_function[0] = "";
}

syscall::write:entry,
syscall::write_nocancel:entry
/pid == $target && arg0 == 1 && arg2 == 22 &&
    copyinstr(arg1) == "TERMINAL_THREAD_ARMED\n"/
{
	thread_armed_seen++;
	violations += thread_armed_seen == 1 && process_armed_seen == 0 ? 0 : 1;
	armed_tid = tid;
}

syscall::write:entry,
syscall::write_nocancel:entry
/pid == $target && arg0 == 1 && arg2 == 19 &&
    copyinstr(arg1) == "TERMINAL_THREAD_OK\n"/
{
	thread_ok_seen++;
	violations += thread_ok_seen == 1 && thread_armed_seen == 1 ? 0 : 1;
}

syscall::write:entry,
syscall::write_nocancel:entry
/pid == $target && arg0 == 1 && arg2 == 23 &&
    copyinstr(arg1) == "TERMINAL_PROCESS_ARMED\n"/
{
	process_armed_seen++;
	violations += process_armed_seen == 1 && thread_armed_seen == 0 ? 0 : 1;
	armed_tid = tid;
}

syscall:::entry
/pid == $target && tid == armed_tid &&
    (thread_armed_seen == 1 || process_armed_seen == 1)/
{
	violations += active_provider[tid] == 0 ? 0 : 1;
	active_provider[tid] = 1;
	active_function[tid] = probefunc;
}

mach_trap:::entry
/pid == $target && tid == armed_tid &&
    (thread_armed_seen == 1 || process_armed_seen == 1)/
{
	violations += active_provider[tid] == 0 ? 0 : 1;
	active_provider[tid] = 2;
	active_function[tid] = probefunc;
}

syscall:::return
/pid == $target && tid == armed_tid && active_provider[tid] != 0/
{
	violations += active_provider[tid] == 1 &&
	    active_function[tid] == probefunc ? 0 : 1;
	returning_controls += active_provider[tid] == 1 &&
	    active_function[tid] == probefunc ? 1 : 0;
	active_provider[tid] = 0;
	active_function[tid] = "";
}

mach_trap:::return
/pid == $target && tid == armed_tid && active_provider[tid] != 0/
{
	violations += active_provider[tid] == 2 &&
	    active_function[tid] == probefunc ? 0 : 1;
	returning_controls += active_provider[tid] == 2 &&
	    active_function[tid] == probefunc ? 1 : 0;
	active_provider[tid] = 0;
	active_function[tid] = "";
}

proc:::lwp-exit
/pid == $target && tid == armed_tid && thread_armed_seen == 1/
{
	lwp_exit_seen++;
	violations += active_provider[tid] != 0 ? 0 : 1;
	candidate_count += active_provider[tid] != 0 ? 1 : 0;
	printf("TERMINALQUAL1|candidate|schema=1|provider=%s|function=%s|scope=thread\n",
	    active_provider[tid] == 1 ? "syscall" : "mach_trap",
	    active_function[tid]);
	active_provider[tid] = 0;
	active_function[tid] = "";
}

proc:::exit
/pid == $target && process_armed_seen == 1/
{
	process_exit_reason = arg0;
	violations += tid == armed_tid && active_provider[tid] != 0 ? 0 : 1;
	candidate_count += tid == armed_tid && active_provider[tid] != 0 ? 1 : 0;
	printf("TERMINALQUAL1|candidate|schema=1|provider=%s|function=%s|scope=process\n",
	    active_provider[tid] == 1 ? "syscall" : "mach_trap",
	    active_function[tid]);
	active_provider[tid] = 0;
	active_function[tid] = "";
}

proc:::exit
/pid == $target/
{
	process_exit_reason = arg0;
	exit(0);
}

tick-5s
{
	timed_out = 1;
	exit(0);
}

dtrace:::END
{
	printf("TERMINALQUAL1|summary|schema=1|mode=%s|thread_armed_seen=%d|thread_ok_seen=%d|process_armed_seen=%d|returning_controls=%d|candidate_count=%d|lwp_exit_seen=%d|process_exit_reason=%d|timed_out=%d|violations=%d\n",
	    thread_armed_seen == 1 ? "thread" :
	    (process_armed_seen == 1 ? "process" : "unknown"),
	    thread_armed_seen, thread_ok_seen, process_armed_seen,
	    returning_controls, candidate_count, lwp_exit_seen,
	    process_exit_reason, timed_out, violations);
}
