/*
 * hvpatch-idle-entry-kick-exit.d — which kick ends an idle-entry vCPU at
 * EL0 and kills its executor?
 *
 * WHAT: an executor waiting in the guest (EL1 idle entry) can run a
 * native-owned zone record at EL0. A kick that surfaces there as
 * `Aarch64Exit::Kicked` without a published native service makes
 * `wait_in_guest` fail the executor ("a vCPU waiting in the guest left at
 * EL0 (Kicked)"), and the dying executor then trips the refused zone-slot
 * leave fatal (#885). This script prints every vCPU kick with its caller
 * stack, every CANCELED exit that stopped a vCPU at EL0, every re-armed kick
 * IRQ taken at EL0, and the executor failure, so the failing executor's
 * host thread and vCPU id name the kick that reached it.
 *
 * ABI (carrick-observability, qualified live on cloudmac 2026-10-26):
 * vcpu-kick(u64 vcpu, i32 valid, i32 rc); vcpu-canceled(u64 vcpu, u64 pc,
 * u32 el, i32 resumed); vcpu-irq-kick(u64 elr); vcpu-run-enter(u64 vcpu);
 * hvpatch-executor-failure(u32 executor, C string error);
 * trace-witness-exit(raw wait status).
 *
 * PERTURBATION: one line plus a 14-frame user stack per kick (tens to a
 * few hundred per fork-COW run), one line per EL0 cancel and IRQ kick.
 * Enough to shift the race; a run without a failure row is not evidence
 * that the failure cannot happen. Bounded at 150 seconds.
 */
#pragma D option quiet
#pragma D option strsize=2048
#pragma D option bufsize=16m

inline int BOUND_SECONDS = 150;

BEGIN
{
    printf("IKX1|header|version=1|bound_s=%d\n", BOUND_SECONDS);
    secs = 0;
    kicks = 0;
    cancels = 0;
    failures = 0;
    errors = 0;
}

carrick*:::vcpu-run-enter
/pid == $target || progenyof($target)/
{
    self->vcpu = (uint64_t)arg0;
}

carrick*:::vcpu-kick
/(pid == $target || progenyof($target)) && arg1 != 0/
{
    kicks++;
    printf("IKX1|kick|ts=%llu|tid=%d|vcpu=%llu|rc=%d\n", timestamp, tid, (uint64_t)arg0, (int)arg2);
    ustack(14);
}

carrick*:::vcpu-canceled
/(pid == $target || progenyof($target)) && arg2 == 0/
{
    cancels++;
    printf("IKX1|cancel-el0|ts=%llu|tid=%d|vcpu=%llu|pc=0x%llx|resumed=%d\n",
        timestamp, tid, (uint64_t)arg0, (uint64_t)arg1, (int)arg3);
}

carrick*:::vcpu-irq-kick
/pid == $target || progenyof($target)/
{
    printf("IKX1|irq-kick|ts=%llu|tid=%d|vcpu=%llu|elr=0x%llx\n",
        timestamp, tid, (uint64_t)self->vcpu, (uint64_t)arg0);
}

carrick*:::hvpatch-executor-failure
/pid == $target || progenyof($target)/
{
    failures++;
    printf("IKX1|executor-failure|ts=%llu|tid=%d|vcpu=%llu|executor=%d|error=%s\n",
        timestamp, tid, (uint64_t)self->vcpu, (int)arg0, copyinstr(arg1));
    ustack(16);
}

dtrace:::ERROR { errors++; }

profile:::tick-1sec
/++secs >= BOUND_SECONDS/
{
    printf("IKX1|end|reason=bound|kicks=%d|cancels=%d|failures=%d|errors=%d\n",
        kicks, cancels, failures, errors);
    exit(0);
}

carrick*:::trace-witness-exit
/pid == $target/
{
    printf("IKX1|end|reason=exit|status=%d|kicks=%d|cancels=%d|failures=%d|errors=%d\n",
        (int)arg0, kicks, cancels, failures, errors);
    exit(0);
}
