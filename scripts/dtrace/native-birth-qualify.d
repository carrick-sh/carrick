#pragma D option quiet
#pragma D option bufsize=4m
#pragma D option dynvarsize=16m
#pragma D option strsize=256

/*
 * Launch-time proof that Darwin's PROC_PIDTBSDINFO start tuple is stable for
 * one process and distinguishes the exact child admitted by proc:::create.
 *
 * This program is intentionally fixture-only. The caller must run the hidden
 * __native-profile-birth-fixture through the same libdtrace launch path used
 * for the eventual victim and must also reject every consumer-side drop.
 */

dtrace:::BEGIN
{
	parent_pid = $target;
	parent_sec = (int64_t)0;
	parent_usec = (int32_t)0;
	parent_observations = 0;
	child_pid = 0;
	child_create_sec = (int64_t)0;
	child_create_usec = (int32_t)0;
	child_context_sec = (int64_t)0;
	child_context_usec = (int32_t)0;
	create_seen = 0;
	child_context_seen = 0;
	marker_seen = 0;
	child_exit_reason = 0;
	target_exit_reason = 0;
	timed_out = 0;
	violations = 0;
}

carrick*:::host-process-birth
/pid == $target && parent_observations < 2/
{
	violations += (uint32_t)arg0 == (uint32_t)pid ? 0 : 1;
	this->sec = (int64_t)arg1;
	this->usec = (int32_t)arg2;
	violations += this->sec > 0 && this->usec >= 0 &&
	    this->usec < 1000000 ? 0 : 1;
	parent_sec = parent_observations == 0 ? this->sec : parent_sec;
	parent_usec = parent_observations == 0 ? this->usec : parent_usec;
	violations += parent_observations == 0 ||
	    (parent_sec == this->sec && parent_usec == this->usec) ? 0 : 1;
	parent_observations++;
}

proc:::create
/pid == $target/
{
	create_seen++;
	violations += create_seen == 1 && child_pid == 0 ? 0 : 1;
	child_pid = args[0]->pr_pid;
}

carrick*:::host-process-birth
/pid == child_pid && child_pid != 0/
{
	violations += (uint32_t)arg0 == (uint32_t)pid ? 0 : 1;
	this->sec = (int64_t)arg1;
	this->usec = (int32_t)arg2;
	violations += this->sec > 0 && this->usec >= 0 &&
	    this->usec < 1000000 ? 0 : 1;
	child_create_sec = child_context_seen == 0 ?
	    this->sec : child_create_sec;
	child_create_usec = child_context_seen == 0 ?
	    this->usec : child_create_usec;
	child_context_sec = child_context_seen == 1 ?
	    this->sec : child_context_sec;
	child_context_usec = child_context_seen == 1 ?
	    this->usec : child_context_usec;
	violations += child_context_seen < 2 ? 0 : 1;
	violations += child_context_seen == 0 ||
	    (child_create_sec == this->sec &&
	    child_create_usec == this->usec) ? 0 : 1;
	child_context_seen++;
}

syscall::write:entry,
syscall::write_nocancel:entry
/pid == $target && arg0 == 1 && arg2 == 17 &&
    copyinstr(arg1) == "BIRTH_FIXTURE_OK\n"/
{
	marker_seen++;
	violations += marker_seen == 1 ? 0 : 1;
}

proc:::exit
/pid == child_pid && child_pid != 0/
{
	child_exit_reason = arg0;
}

proc:::exit
/pid == $target/
{
	target_exit_reason = arg0;
	exit(0);
}

tick-5s
{
	timed_out = 1;
	exit(0);
}

dtrace:::END
{
	printf("BIRTHQUAL1|schema=1|parent_pid=%d|parent_sec=%d|parent_usec=%d|parent_observations=%d|child_pid=%d|child_create_sec=%d|child_create_usec=%d|child_context_sec=%d|child_context_usec=%d|create_seen=%d|child_context_seen=%d|marker_seen=%d|child_exit_reason=%d|target_exit_reason=%d|timed_out=%d|violations=%d\n",
	    parent_pid, parent_sec, parent_usec, parent_observations,
	    child_pid, child_create_sec, child_create_usec,
	    child_context_sec, child_context_usec, create_seen,
	    child_context_seen, marker_seen, child_exit_reason,
	    target_exit_reason, timed_out, violations);
}
