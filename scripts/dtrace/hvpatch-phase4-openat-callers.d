#!/usr/sbin/dtrace -qs
/*
 * Attribute Darwin openat amplification inside Linux openat (56) and
 * newfstatat (79) hvpatch service windows to exact Carrick user stacks.
 *
 * Provider ABI qualified on macOS 27.0 arm64 on 2026-08-09:
 * - hvpatch-syscall-service-begin(guest_pid, guest_tid, ASID, nr) arms a
 *   host-thread window for Linux 56/79;
 * - hvpatch-syscall-service(guest_pid, guest_tid, ASID, nr, duration_ns)
 *   validates completion without mutating join state;
 * - hvpatch-syscall-service-clear(guest_pid, guest_tid, ASID, nr) is the
 *   distinct retirement boundary;
 * - syscall::openat:entry runs on Carrick's restored host stack, so ustack(48)
 *   is authoritative for the user caller. Linux identities are carried in
 *   separate aggregates; DTrace pid/tid remain Darwin identities.
 * - host-image-base(host_pid, runtime_TEXT_base, slide, binary_path) publishes
 *   the exact Mach-O identity before hvpatch loads the guest. The runtime base
 *   is part of every stack key so offline atos resolution cannot guess a slide
 *   or silently use a rebuilt binary.
 *
 * Perturbation: VERY HIGH. This takes a 48-frame stack on every induced host
 * openat. Only caller shares/ranks are citable, never elapsed time. A capture
 * fails on zero stacks, nested/orphan/mismatched windows, timeout, or D error.
 */

#pragma D option quiet
#pragma D option bufsize=32m
#pragma D option aggsize=128m
#pragma D option dynvarsize=64m
#pragma D option ustackframes=48
#pragma D option strsize=16k

dtrace:::BEGIN
{
    started = timestamp;
    target_exited = 0;
    root_seen = 0;
    timed_out = 0;
    saw_window = 0;
    saw_stack = 0;
    saw_nested = 0;
    saw_orphan = 0;
    saw_mismatch = 0;
    image_base_seen = 0;
    image_base = (uint64_t)0;
    errors = 0;
    self->service_active = (int32_t)0;
    self->guest_pid = (int32_t)0;
    self->guest_tid = (int32_t)0;
    self->asid = (uint32_t)0;
    self->nr = (uint64_t)0;
}

carrick*:::host-image-base
/(pid == $target || progenyof($target))/
{
    image_base_seen = 1;
    image_base = (uint64_t)arg1;
    printf("HVPATCH4OPENSTACK|host-image|pid=%d|base=%#llx|slide=%lld|path=%s\n",
        (int32_t)arg0, (uint64_t)arg1, (int64_t)arg2, copyinstr(arg3));
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
    saw_window = 1;
}

syscall::openat:entry
/(pid == $target || progenyof($target)) && self->service_active/
{
    saw_stack = 1;
    @open_count[self->nr] = count();
    @open_task[self->guest_pid, self->guest_tid, self->asid, self->nr] = count();
    @open_stack[self->nr, image_base, ustack(48)] = count();
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

dtrace:::ERROR
{
    errors++;
    printf("HVPATCH4OPENSTACK|error=dtrace|epid=%d|action=%d|offset=%d|fault=%d|value=%#x\n",
        arg1, arg2, arg3, arg4, arg5);
    exit(3);
}

proc:::exit
/pid == $target/
{
    target_exited = 1;
    exit(saw_window && saw_stack && root_seen && image_base_seen && image_base != 0 ? 0 : 1);
}

profile:::tick-1sec
/timestamp - started > 90 * 1000000000/
{
    timed_out = 1;
    exit(4);
}

dtrace:::END
{
    printf("HVPATCH4OPENSTACK|summary|status=%s|target_exited=%d|root_seen=%d|timed_out=%d|image_base_seen=%d|image_base=%#llx|saw_window=%d|saw_stack=%d|saw_nested=%d|saw_orphan=%d|saw_mismatch=%d|errors=%d\n",
        root_seen && !timed_out && image_base_seen && image_base != 0 &&
            saw_window && saw_stack && !saw_nested &&
            !saw_orphan && !saw_mismatch && !errors ? "ok" : "error",
        target_exited, root_seen, timed_out, image_base_seen, image_base,
        saw_window, saw_stack, saw_nested, saw_orphan, saw_mismatch, errors);
    printa("HVPATCH4OPENSTACK|begin|nested=%d|nr=%llu|count=%@d\n", @begin_state);
    printa("HVPATCH4OPENSTACK|end|active=%d|identity_match=%d|nr=%llu|count=%@d\n",
        @end_state);
    printa("HVPATCH4OPENSTACK|clear|active=%d|identity_match=%d|nr=%llu|count=%@d\n",
        @clear_state);
    printa("HVPATCH4OPENSTACK|host-openat|nr=%llu|count=%@d\n", @open_count);
    printf("HVPATCH4OPENSTACK|section=tasks\n");
    trunc(@open_task, 160);
    printa("HVPATCH4OPENSTACK|guest_pid=%d|guest_tid=%d|asid=%u|nr=%llu|count=%@d\n",
        @open_task);
    printf("HVPATCH4OPENSTACK|section=caller-stacks\n");
    trunc(@open_stack, 128);
    printa("HVPATCH4OPENSTACK|stack-begin|nr=%llu|base=%#llx|count=%@d\n%kHVPATCH4OPENSTACK|stack-end\n",
        @open_stack);
}
