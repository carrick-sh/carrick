/*
 * Attribute signal-frame setup refusal without per-syscall or executor traffic.
 * ABI: signal-deliver (tid, signum) and signal-inject (signum, saved PC,
 * frame SP, handler) qualified live on macOS ARM64 2026-09-20. The new
 * guest-internal-write-fault ABI is base VA, length, phase, error string;
 * phase 0 translation, 1 backing/COW, 2 copy, 3 no-access, 4 backend
 * validation, 5 write protection, 6 missing mapping, 7 permission.
 * Qualified 2026-09-20 by setid-error-only/trace-5.raw: phase 4,
 * VA 0x600108bc60, length 5024.
 * DTrace exposes arguments as signed int64_t; cast unsigned printf operands.
 * PERTURBATION: only refusal events and process exit; successful signal
 * delivery and injection do not fire this consumer.
 * Lower event volume than hvpatch-go-signal-resume.d, but still diagnostic:
 * no traced elapsed time is a performance or liveness acceptance receipt.
 */
#pragma D option quiet

dtrace:::BEGIN
{
    printf("SIGFRAMEFAULT1|header|version=1\n");
}

carrick*:::guest-internal-write-fault
/(pid == $target || progenyof($target))/
{
    printf("SIGFRAMEFAULT1|internal_write_fault|ts=%llu|host_pid=%d|host_tid=%d|address=0x%llx|length=%llu|phase=%u|error=%s\n",
        timestamp, pid, tid, (uint64_t)arg0, (uint64_t)arg1, (uint32_t)arg2, copyinstr(arg3));
}

proc:::exit
/pid == $target/
{
    printf("SIGFRAMEFAULT1|target_exit|ts=%llu|host_pid=%d\n", timestamp, pid);
    exit(0);
}
