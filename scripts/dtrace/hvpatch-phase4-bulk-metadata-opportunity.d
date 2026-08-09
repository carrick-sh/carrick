#!/usr/sbin/dtrace -qs
/*
 * Measure the cold-build opportunity for replacing Darwin directory iteration
 * plus scalar child metadata calls with getattrlistbulk(2) in the one-VM
 * hvpatch backend.
 *
 * WHAT IT MEASURES
 * ----------------
 * Typed hvpatch service begin/completion/clear probes join every selected host
 * operation to Linux guest PID, TID, ASID, and syscall number. The selected
 * Linux services are getdents64 (61) and newfstatat (79). While either service
 * is active this consumer records every Darwin syscall, the selected service's
 * duration, per-task populations, and immediate selected-service transitions.
 *
 * `newfstatat-after-getdents` is deliberately an UPPER BOUND: it means that the
 * same typed guest task completed at least one getdents64 earlier, not that the
 * stat necessarily names a child from that directory. A behavior candidate
 * must add field-for-field cache-hit accounting before claiming those calls as
 * removed. Zero selected services, zero host work, nested/orphaned/mismatched
 * windows, active thread exit, timeout, or a DTrace error fail closed.
 *
 * PROVIDER ABI QUALIFICATION
 * --------------------------
 * Qualified live on macOS 27.0 arm64 on 2026-08-09 with `dtrace -lvn`:
 * - syscall::getattrlistbulk:entry is
 *   (int dirfd, struct attrlist *, void *buf, size_t size, uint64_t options);
 * - syscall::getattrlistbulk:return is (int result, int error);
 * - syscall::getdirentries64:entry is
 *   (int fd, void *buf, user_size_t size, off_t *basep);
 * - syscall::getdirentries64:return is
 *   (user_ssize_t result, user_ssize_t error);
 * - syscall::fstatat64:entry is
 *   (int dirfd, user_addr_t path, user_addr_t statbuf, int flags);
 * - syscall::fstatat64:return is (int result, int error);
 * - hvpatch-syscall-service-begin is
 *   (int32_t guest_pid, int32_t guest_tid, uint32_t ASID, uint64_t nr);
 * - hvpatch-syscall-args immediately follows an enabled begin on the same host
 *   thread and is (uint64_t nr, uint64_t arg0, arg1, arg2, arg3). For the
 *   selected services arg0 is the Linux guest fd/dirfd;
 * - hvpatch-syscall-service is the same identity plus uint64_t duration_ns;
 * - hvpatch-syscall-service-clear repeats the four identity fields and is the
 *   only retirement boundary.
 *
 * Linux PID/TID/ASID are multiplexed identities. DTrace pid/tid remain Darwin
 * host identities and only bind host work to the active service window.
 *
 * PERTURBATION
 * ------------
 * HIGH. Every selected host syscall updates aggregates. Only same-instrument
 * counts, ratios, and ranks are citable; elapsed wall/CPU time is not. Retain a
 * behavior change only with an untraced same-binary ABBA.
 */

#pragma D option quiet
#pragma D option bufsize=32m
#pragma D option aggsize=96m
#pragma D option dynvarsize=64m

dtrace:::BEGIN
{
    started = timestamp;
    target_exited = 0;
    root_seen = 0;
    timed_out = 0;
    saw_selected = 0;
    saw_args = 0;
    saw_host = 0;
    saw_nested = 0;
    saw_orphan = 0;
    saw_mismatch = 0;
    errors = 0;
    self->active = (int32_t)0;
    self->guest_pid = (int32_t)0;
    self->guest_tid = (int32_t)0;
    self->asid = (uint32_t)0;
    self->nr = (uint64_t)0;
    self->args_seen = (int32_t)0;
    /* DTrace compiles clauses in source order: establish dynamic tuple types
     * before the begin clause reads them. The impossible zero identity is a
     * harmless sentinel and is never included in a typed guest-task row. */
    last_selected[(int32_t)0, (int32_t)0, (uint32_t)0] = (uint64_t)0;
    saw_getdents[(int32_t)0, (int32_t)0, (uint32_t)0] = (int32_t)0;
    enumerated_fd[(int32_t)0, (uint32_t)0, (int64_t)0] = (int32_t)0;
}

carrick*:::hvpatch-syscall-service-begin
/(pid == $target || progenyof($target)) &&
 ((uint64_t)arg3 == 61 || (uint64_t)arg3 == 79)/
{
    this->nested = self->active != 0;
    saw_nested = saw_nested || this->nested;
    @begin_state[this->nested, (uint64_t)arg3] = count();
    self->active = 1;
    self->guest_pid = (int32_t)arg0;
    self->guest_tid = (int32_t)arg1;
    self->asid = (uint32_t)arg2;
    self->nr = (uint64_t)arg3;
    self->args_seen = 0;
    saw_selected = 1;

    this->previous = last_selected[(int32_t)arg0, (int32_t)arg1,
        (uint32_t)arg2];
    @transition[this->previous, (uint64_t)arg3] = count();
    @task_service[(int32_t)arg0, (int32_t)arg1, (uint32_t)arg2,
        (uint64_t)arg3] = count();
    @newfstatat_after_getdents[(uint64_t)arg3 == 79 &&
        saw_getdents[(int32_t)arg0, (int32_t)arg1, (uint32_t)arg2] != 0] =
        count();
}

carrick*:::hvpatch-syscall-args
/(pid == $target || progenyof($target)) &&
 ((uint64_t)arg0 == 61 || (uint64_t)arg0 == 79)/
{
    this->is_active = self->active != 0;
    this->identity_match = self->nr == (uint64_t)arg0;
    saw_orphan = saw_orphan || !this->is_active;
    saw_mismatch = saw_mismatch || (this->is_active && !this->identity_match);
    @args_state[this->is_active, this->identity_match, (uint64_t)arg0] = count();
    saw_args = 1;
    self->args_seen = 1;

    /* arg1 is Linux arg0: getdents fd or newfstatat dirfd. The fd table is
     * process-scoped, so the opportunity key is guest PID + ASID + fd; TID is
     * still retained in the output but Go may move related work across it. */
    this->guest_dirfd = (int64_t)arg1;
    @guest_dirfd[self->guest_pid, self->guest_tid, self->asid,
        (uint64_t)arg0, this->guest_dirfd] = count();
    this->same_enumerated_fd = (uint64_t)arg0 == 79 &&
        enumerated_fd[self->guest_pid, self->asid, this->guest_dirfd] != 0;
    @newfstatat_after_same_dirfd[(uint64_t)arg0 == 79,
        this->same_enumerated_fd] = count();
    enumerated_fd[self->guest_pid, self->asid, this->guest_dirfd] =
        enumerated_fd[self->guest_pid, self->asid, this->guest_dirfd] ||
        (uint64_t)arg0 == 61;
}

syscall:::entry
/(pid == $target || progenyof($target)) && self->active/
{
    saw_host = 1;
    @host_syscall[self->nr, probefunc] = count();
    @task_host[self->guest_pid, self->guest_tid, self->asid, self->nr,
        probefunc] = count();
}

syscall::getdirentries64:return
/(pid == $target || progenyof($target)) && self->active/
{
    @selected_outcome[self->nr, "getdirentries64", errno] = count();
}

syscall::getattrlistbulk:return
/(pid == $target || progenyof($target)) && self->active/
{
    @selected_outcome[self->nr, "getattrlistbulk", errno] = count();
}

syscall::fstatat64:return
/(pid == $target || progenyof($target)) && self->active/
{
    @selected_outcome[self->nr, "fstatat64", errno] = count();
}

carrick*:::hvpatch-syscall-service
/(pid == $target || progenyof($target)) &&
 ((uint64_t)arg3 == 61 || (uint64_t)arg3 == 79)/
{
    this->is_active = self->active != 0;
    this->identity_match = self->guest_pid == (int32_t)arg0 &&
        self->guest_tid == (int32_t)arg1 && self->asid == (uint32_t)arg2 &&
        self->nr == (uint64_t)arg3;
    saw_orphan = saw_orphan || !this->is_active;
    saw_mismatch = saw_mismatch || (this->is_active && !this->identity_match);
    saw_mismatch = saw_mismatch || (this->is_active && !self->args_seen);
    @end_state[this->is_active, this->identity_match, (uint64_t)arg3] = count();
    @duration_ns[(uint64_t)arg3] = sum((uint64_t)arg4);
}

carrick*:::hvpatch-syscall-service-clear
/(pid == $target || progenyof($target)) &&
 ((uint64_t)arg3 == 61 || (uint64_t)arg3 == 79)/
{
    this->is_active = self->active != 0;
    this->identity_match = self->guest_pid == (int32_t)arg0 &&
        self->guest_tid == (int32_t)arg1 && self->asid == (uint32_t)arg2 &&
        self->nr == (uint64_t)arg3;
    saw_orphan = saw_orphan || !this->is_active;
    saw_mismatch = saw_mismatch || (this->is_active && !this->identity_match);
    @clear_state[this->is_active, this->identity_match, (uint64_t)arg3] = count();
    last_selected[(int32_t)arg0, (int32_t)arg1, (uint32_t)arg2] =
        (uint64_t)arg3;
    saw_getdents[(int32_t)arg0, (int32_t)arg1, (uint32_t)arg2] =
        saw_getdents[(int32_t)arg0, (int32_t)arg1, (uint32_t)arg2] ||
        (uint64_t)arg3 == 61;
    self->active = 0;
    self->guest_pid = 0;
    self->guest_tid = 0;
    self->asid = 0;
    self->nr = 0;
    self->args_seen = 0;
}

carrick*:::hvpatch-guest-lifecycle
/(pid == $target || progenyof($target)) && arg0 == 0/
{
    root_seen = 1;
}

proc:::lwp-exit
/(pid == $target || progenyof($target)) && self->active/
{
    printf("HVPATCH4BULK|error=thread-exit-active|host_pid=%d|host_tid=%d|guest_pid=%d|guest_tid=%d|asid=%u|nr=%llu\n",
        pid, tid, self->guest_pid, self->guest_tid, self->asid, self->nr);
    exit(2);
}

dtrace:::ERROR
{
    errors++;
    printf("HVPATCH4BULK|error=dtrace|epid=%d|action=%d|offset=%d|fault=%d|value=%#x\n",
        arg1, arg2, arg3, arg4, arg5);
    exit(3);
}

proc:::exit
/pid == $target/
{
    target_exited = 1;
    exit(saw_selected && saw_host && root_seen ? 0 : 1);
}

profile:::tick-1sec
/timestamp - started > 90 * 1000000000/
{
    timed_out = 1;
    exit(4);
}

dtrace:::END
{
    printf("HVPATCH4BULK|summary|status=%s|target_exited=%d|root_seen=%d|timed_out=%d|saw_selected=%d|saw_args=%d|saw_host=%d|saw_nested=%d|saw_orphan=%d|saw_mismatch=%d|errors=%d\n",
        root_seen && !timed_out && saw_selected && saw_args && saw_host && !saw_nested &&
            !saw_orphan && !saw_mismatch && !errors ? "ok" : "error",
        target_exited, root_seen, timed_out, saw_selected, saw_args, saw_host,
        saw_nested, saw_orphan, saw_mismatch, errors);
    printa("HVPATCH4BULK|begin|nested=%d|nr=%llu|count=%@d\n", @begin_state);
    printa("HVPATCH4BULK|end|active=%d|identity_match=%d|nr=%llu|count=%@d\n",
        @end_state);
    printa("HVPATCH4BULK|clear|active=%d|identity_match=%d|nr=%llu|count=%@d\n",
        @clear_state);
    printa("HVPATCH4BULK|args|active=%d|identity_match=%d|nr=%llu|count=%@d\n",
        @args_state);
    printa("HVPATCH4BULK|duration-ns|nr=%llu|value=%@d\n", @duration_ns);
    printa("HVPATCH4BULK|transition|from=%llu|to=%llu|count=%@d\n",
        @transition);
    printa("HVPATCH4BULK|newfstatat-after-getdents|value=%d|count=%@d\n",
        @newfstatat_after_getdents);
    printa("HVPATCH4BULK|newfstatat-service=%d|same-enumerated-dirfd=%d|count=%@d\n",
        @newfstatat_after_same_dirfd);
    printf("HVPATCH4BULK|section=host-syscalls\n");
    printa("HVPATCH4BULK|host|nr=%llu|operation=%s|count=%@d\n",
        @host_syscall);
    printf("HVPATCH4BULK|section=outcomes\n");
    printa("HVPATCH4BULK|outcome|nr=%llu|operation=%s|errno=%d|count=%@d\n",
        @selected_outcome);
    printf("HVPATCH4BULK|section=tasks\n");
    trunc(@task_service, 256);
    trunc(@task_host, 256);
    trunc(@guest_dirfd, 256);
    printa("HVPATCH4BULK|guest_pid=%d|guest_tid=%d|asid=%u|nr=%llu|services=%@d\n",
        @task_service);
    printa("HVPATCH4BULK|guest_pid=%d|guest_tid=%d|asid=%u|nr=%llu|host=%s|count=%@d\n",
        @task_host);
    printa("HVPATCH4BULK|guest_pid=%d|guest_tid=%d|asid=%u|nr=%llu|guest_dirfd=%d|count=%@d\n",
        @guest_dirfd);
}
