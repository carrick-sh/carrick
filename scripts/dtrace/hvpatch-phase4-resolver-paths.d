#!/usr/sbin/dtrace -qs
/*
 * Classify the path and flag/command populations of Darwin resolver work
 * induced inside Linux openat (56) and newfstatat (79) services in the
 * one-VM hvpatch backend.
 *
 * WHAT IT MEASURES
 * ----------------
 * The typed hvpatch service begin/completion/clear probes join each host
 * operation to Linux guest PID, TID, ASID, and syscall number. While a selected
 * service is active, this consumer records:
 * - Darwin openat path + flags;
 * - Darwin fstatat64 path + flags;
 * - Darwin fcntl command;
 * - exact per-task operation populations.
 *
 * This answers whether amplification is repeated work on one leaf, separate
 * parent/leaf validation, or semantically-required fallback paths. Aggregate
 * paths are evidence; no path bytes are emitted as a live event stream.
 *
 * PROVIDER ABI QUALIFICATION
 * --------------------------
 * Qualified live on macOS 27.0 arm64 on 2026-08-09 with `dtrace -lvn`:
 * - syscall::openat:entry is
 *   (int dirfd, user_addr_t path, int flags, int mode);
 * - syscall::fstatat64:entry is
 *   (int dirfd, user_addr_t path, user_addr_t statbuf, int flags);
 * - syscall::fcntl:entry is (int fd, int cmd, long arg);
 * - openat/fstatat64 return probes expose `(int result, int error)`, and the
 *   built-in `errno` is the authoritative error. Path bytes are copied at
 *   return, after the kernel has faulted them in, never at entry. EFAULT (14)
 *   is counted but deliberately not dereferenced;
 * - hvpatch-syscall-service-begin is
 *   (int32_t guest_pid, int32_t guest_tid, uint32_t ASID, uint64_t nr);
 * - hvpatch-syscall-service is the same identity plus uint64_t duration_ns;
 * - hvpatch-syscall-service-clear repeats the four identity fields and is the
 *   only retirement boundary.
 *
 * Linux PID/TID/ASID are multiplexed identities. DTrace pid/tid remain Darwin
 * host identities and only bind the host work to the active service window.
 * A nested, orphaned, mismatched, empty, timed-out, or DTrace-error capture
 * fails closed.
 *
 * PERTURBATION
 * ------------
 * VERY HIGH. copyinstr and aggregate-key construction happen on every selected
 * host openat/fstatat64. Only same-instrument populations and ranks are citable;
 * elapsed time is not. Retain behavior changes only with untraced ABBA.
 */

#pragma D option quiet
#pragma D option bufsize=32m
#pragma D option aggsize=256m
#pragma D option dynvarsize=128m
#pragma D option strsize=4k

dtrace:::BEGIN
{
    started = timestamp;
    target_exited = 0;
    root_seen = 0;
    timed_out = 0;
    saw_selected = 0;
    saw_path = 0;
    saw_nested = 0;
    saw_orphan = 0;
    saw_mismatch = 0;
    errors = 0;
    self->service_active = (int32_t)0;
    self->guest_pid = (int32_t)0;
    self->guest_tid = (int32_t)0;
    self->asid = (uint32_t)0;
    self->nr = (uint64_t)0;
    self->open_path_ptr = (uintptr_t)0;
    self->open_flags = (int32_t)0;
    self->fstatat_path_ptr = (uintptr_t)0;
    self->fstatat_flags = (int32_t)0;
}

carrick*:::hvpatch-syscall-service-begin
/(pid == $target || progenyof($target)) &&
 ((uint64_t)arg3 == 56 || (uint64_t)arg3 == 79)/
{
    this->nested = self->service_active != 0;
    saw_nested = saw_nested || this->nested;
    @begin_state[this->nested, (uint64_t)arg3] = count();
    self->service_active = 1;
    self->guest_pid = (int32_t)arg0;
    self->guest_tid = (int32_t)arg1;
    self->asid = (uint32_t)arg2;
    self->nr = (uint64_t)arg3;
    saw_selected = 1;
}

syscall::openat:entry
/(pid == $target || progenyof($target)) && self->service_active/
{
    saw_path = 1;
    @operation[self->nr, "openat"] = count();
    @task_operation[
        self->guest_pid, self->guest_tid, self->asid, self->nr, "openat"] = count();
    self->open_path_ptr = (uintptr_t)arg1;
    self->open_flags = (int32_t)arg2;
}

syscall::openat:return
/(pid == $target || progenyof($target)) && self->service_active &&
 self->open_path_ptr != 0 && errno != 14/
{
    @open_path[self->nr, self->open_flags, errno,
        copyinstr(self->open_path_ptr, 1024)] = count();
    @open_outcome[self->nr, self->open_flags, errno] = count();
}

syscall::openat:return
/(pid == $target || progenyof($target)) && self->open_path_ptr != 0/
{
    @open_errno[self->nr, errno] = count();
    self->open_path_ptr = (uintptr_t)0;
    self->open_flags = 0;
}

syscall::fstatat64:entry
/(pid == $target || progenyof($target)) && self->service_active/
{
    saw_path = 1;
    @operation[self->nr, "fstatat64"] = count();
    @task_operation[
        self->guest_pid, self->guest_tid, self->asid, self->nr, "fstatat64"] = count();
    self->fstatat_path_ptr = (uintptr_t)arg1;
    self->fstatat_flags = (int32_t)arg3;
}

syscall::fstatat64:return
/(pid == $target || progenyof($target)) && self->service_active &&
 self->fstatat_path_ptr != 0 && errno != 14/
{
    @fstatat_path[self->nr, self->fstatat_flags, errno,
        copyinstr(self->fstatat_path_ptr, 1024)] = count();
    @fstatat_outcome[self->nr, self->fstatat_flags, errno] = count();
}

syscall::fstatat64:return
/(pid == $target || progenyof($target)) && self->fstatat_path_ptr != 0/
{
    @fstatat_errno[self->nr, errno] = count();
    self->fstatat_path_ptr = (uintptr_t)0;
    self->fstatat_flags = 0;
}

syscall::fcntl:entry
/(pid == $target || progenyof($target)) && self->service_active/
{
    @operation[self->nr, "fcntl"] = count();
    @fcntl_command[self->nr, (int32_t)arg1] = count();
    @task_operation[
        self->guest_pid, self->guest_tid, self->asid, self->nr, "fcntl"] = count();
}

carrick*:::hvpatch-syscall-service
/(pid == $target || progenyof($target)) &&
 ((uint64_t)arg3 == 56 || (uint64_t)arg3 == 79)/
{
    this->active = self->service_active != 0;
    this->identity_match = self->guest_pid == (int32_t)arg0 &&
        self->guest_tid == (int32_t)arg1 && self->asid == (uint32_t)arg2 &&
        self->nr == (uint64_t)arg3;
    saw_orphan = saw_orphan || !this->active;
    saw_mismatch = saw_mismatch || (this->active && !this->identity_match);
    @end_state[this->active, this->identity_match, (uint64_t)arg3] = count();
}

carrick*:::hvpatch-syscall-service-clear
/(pid == $target || progenyof($target)) &&
 ((uint64_t)arg3 == 56 || (uint64_t)arg3 == 79)/
{
    this->active = self->service_active != 0;
    this->identity_match = self->guest_pid == (int32_t)arg0 &&
        self->guest_tid == (int32_t)arg1 && self->asid == (uint32_t)arg2 &&
        self->nr == (uint64_t)arg3;
    saw_orphan = saw_orphan || !this->active;
    saw_mismatch = saw_mismatch || (this->active && !this->identity_match);
    @clear_state[this->active, this->identity_match, (uint64_t)arg3] = count();
    self->service_active = 0;
    self->guest_pid = 0;
    self->guest_tid = 0;
    self->asid = 0;
    self->nr = 0;
}

carrick*:::hvpatch-guest-lifecycle
/(pid == $target || progenyof($target)) && arg0 == 0/
{
    root_seen = 1;
}

proc:::lwp-exit
/(pid == $target || progenyof($target)) && self->service_active/
{
    printf("HVPATCH4PATH|error=thread-exit-active|host_pid=%d|host_tid=%d|guest_pid=%d|guest_tid=%d|asid=%u|nr=%llu\n",
        pid, tid, self->guest_pid, self->guest_tid, self->asid, self->nr);
    exit(2);
}

dtrace:::ERROR
{
    errors++;
    printf("HVPATCH4PATH|error=dtrace|epid=%d|action=%d|offset=%d|fault=%d|value=%#x\n",
        arg1, arg2, arg3, arg4, arg5);
    exit(3);
}

proc:::exit
/pid == $target/
{
    target_exited = 1;
    exit(saw_selected && saw_path && root_seen ? 0 : 1);
}

profile:::tick-1sec
/timestamp - started > 90 * 1000000000/
{
    timed_out = 1;
    exit(4);
}

dtrace:::END
{
    printf("HVPATCH4PATH|summary|status=%s|target_exited=%d|root_seen=%d|timed_out=%d|saw_selected=%d|saw_path=%d|saw_nested=%d|saw_orphan=%d|saw_mismatch=%d|errors=%d\n",
        root_seen && !timed_out && saw_selected && saw_path && !saw_nested &&
            !saw_orphan && !saw_mismatch && !errors ? "ok" : "error",
        target_exited, root_seen, timed_out, saw_selected, saw_path, saw_nested,
        saw_orphan, saw_mismatch, errors);
    printa("HVPATCH4PATH|begin|nested=%d|nr=%llu|count=%@d\n", @begin_state);
    printa("HVPATCH4PATH|end|active=%d|identity_match=%d|nr=%llu|count=%@d\n",
        @end_state);
    printa("HVPATCH4PATH|clear|active=%d|identity_match=%d|nr=%llu|count=%@d\n",
        @clear_state);
    printf("HVPATCH4PATH|section=operations\n");
    printa("HVPATCH4PATH|operation|nr=%llu|host=%s|count=%@d\n", @operation);
    printf("HVPATCH4PATH|section=fcntl-commands\n");
    printa("HVPATCH4PATH|fcntl|nr=%llu|cmd=%d|count=%@d\n", @fcntl_command);
    printf("HVPATCH4PATH|section=path-outcomes\n");
    printa("HVPATCH4PATH|openat-outcome|nr=%llu|flags=%#x|errno=%d|count=%@d\n",
        @open_outcome);
    printa("HVPATCH4PATH|openat-errno|nr=%llu|errno=%d|count=%@d\n", @open_errno);
    printa("HVPATCH4PATH|fstatat64-outcome|nr=%llu|flags=%#x|errno=%d|count=%@d\n",
        @fstatat_outcome);
    printa("HVPATCH4PATH|fstatat64-errno|nr=%llu|errno=%d|count=%@d\n",
        @fstatat_errno);
    printf("HVPATCH4PATH|section=openat-paths\n");
    trunc(@open_path, 768);
    printa("HVPATCH4PATH|openat|nr=%llu|flags=%#x|errno=%d|path=%s|count=%@d\n",
        @open_path);
    printf("HVPATCH4PATH|section=fstatat64-paths\n");
    trunc(@fstatat_path, 768);
    printa("HVPATCH4PATH|fstatat64|nr=%llu|flags=%#x|errno=%d|path=%s|count=%@d\n",
        @fstatat_path);
    printf("HVPATCH4PATH|section=tasks\n");
    trunc(@task_operation, 256);
    printa("HVPATCH4PATH|guest_pid=%d|guest_tid=%d|asid=%u|nr=%llu|host=%s|count=%@d\n",
        @task_operation);
}
