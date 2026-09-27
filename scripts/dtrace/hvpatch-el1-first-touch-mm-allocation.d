#!/usr/sbin/dtrace -Zqs
/*
 * hvpatch-el1-first-touch-mm-allocation.d — attribute allocation failure
 * after authenticated EL1 anonymous first-touch publication.
 *
 * WHAT IT MEASURES
 *   Prints the Linux pid/tid, first four arguments and return for brk (214),
 *   munmap (215), mremap (216), mmap (222), mprotect (226) and madvise (233),
 *   plus logical process lifecycle. This distinguishes a guest allocator
 *   refusal from data corruption or a carrier resource failure.
 *
 * PROVIDER ABI
 *   Qualified from carrick-observability on macOS/arm64:
 *     hvpatch-syscall-service-begin(pid, tid, asid, nr)
 *     hvpatch-syscall-args(nr, a0, a1, a2, a3)
 *     hvpatch-guest-lifecycle(phase, pid, ppid, tid, asid)
 *   `syscall-return` does not fire on the HVPatch completion path exercised by
 *   this workload. The pid-provider entry probe for the external Rust symbol
 *   `HvfAarch64Vcpu::complete_syscall_return(&mut self, i64)` supplies the
 *   signed Linux return in arg1 on macOS/arm64. macOS truncates that Rust
 *   function name to `complete_syscall_ret` in the pid provider, so the probe
 *   pattern deliberately ends there. The service begin/args and VMM completion
 *   run on the same host executor thread, so the self-local logical identity is
 *   authoritative for one service window.
 *   The pid-provider also exposes the AArch64 GuestMemory `unmap_range`,
 *   `PageTableManager::unmap_aliased`, stage-1 maintenance and
 *   `HvfAarch64Vmm::on_unmap` entries used below to bracket an ENOMEM without
 *   inserting logging into the transaction. Its `invalidate`, `apply`,
 *   `split_block`, and `alloc_table` entries distinguish a missing walk from
 *   table allocation pressure.
 *
 * PERTURBATION
 *   Diagnostic only. It prints each selected memory-management syscall and
 *   is not timing evidence. Target exit ends the capture; a 20 s bound fails
 *   a wedged run instead of leaving the consumer alive.
 */

#pragma D option quiet
#pragma D option strsize=128
#pragma D option bufsize=16m

dtrace:::BEGIN
{
    live = 1;
    seconds = 0;
    selected = 0;
    completions = 0;
    usdt_returns = 0;
    errors = 0;
    printf("EL1MMALLOC1|start|target=%d|ns=%llu\n", $target, timestamp);
}

carrick*:::hvpatch-syscall-service-begin
/(pid == $target || progenyof($target))/
{
    self->lpid = (int32_t)arg0;
    self->ltid = (int32_t)arg1;
    self->nr = (uint64_t)arg3;
}

carrick*:::hvpatch-syscall-args
/(pid == $target || progenyof($target)) &&
 (uint64_t)arg0 == self->nr &&
 (self->nr == 214 || self->nr == 215 || self->nr == 216 ||
  self->nr == 222 || self->nr == 226 || self->nr == 233)/
{
    selected++;
    printf("EL1MMALLOC1|entry|ts=%llu|lpid=%d|ltid=%d|nr=%llu|a0=0x%llx|a1=0x%llx|a2=0x%llx|a3=0x%llx\n",
        timestamp, self->lpid, self->ltid, self->nr,
        (uint64_t)arg1, (uint64_t)arg2, (uint64_t)arg3, (uint64_t)arg4);
}

carrick*:::syscall-return
/(pid == $target || progenyof($target)) &&
 ((uint64_t)arg0 == 214 || (uint64_t)arg0 == 215 ||
  (uint64_t)arg0 == 216 || (uint64_t)arg0 == 222 ||
  (uint64_t)arg0 == 226 || (uint64_t)arg0 == 233)/
{
    usdt_returns++;
    printf("EL1MMALLOC1|usdt-return|ts=%llu|lpid=%d|ltid=%d|nr=%llu|name=%s|ret=%lld|errno=%d\n",
        timestamp, self->lpid, self->ltid, (uint64_t)arg0,
        copyinstr(arg1), (int64_t)arg2, (int32_t)arg3);
}

pid$target::*complete_syscall_ret*:entry
/(self->nr == 214 || self->nr == 215 || self->nr == 216 ||
  self->nr == 222 || self->nr == 226 || self->nr == 233)/
{
    completions++;
    printf("EL1MMALLOC1|vmm-return|ts=%llu|lpid=%d|ltid=%d|nr=%llu|ret=%lld\n",
        timestamp, self->lpid, self->ltid, self->nr, (int64_t)arg1);
}

pid$target::*GuestMemory*unmap_range*:entry
/self->nr == 215/
{
    printf("EL1MMALLOC1|path|ts=%llu|lpid=%d|ltid=%d|nr=%llu|phase=guest-memory-unmap-range\n",
        timestamp, self->lpid, self->ltid, self->nr);
}

pid$target::*PageTableManager*unmap_aliased*:entry
/self->nr == 215/
{
    printf("EL1MMALLOC1|path|ts=%llu|lpid=%d|ltid=%d|nr=%llu|phase=page-table-unmap-aliased\n",
        timestamp, self->lpid, self->ltid, self->nr);
}

pid$target::*PageTableManager*invalidate*:entry
/self->nr == 215/
{
    printf("EL1MMALLOC1|path|ts=%llu|lpid=%d|ltid=%d|nr=%llu|phase=page-table-invalidate\n",
        timestamp, self->lpid, self->ltid, self->nr);
}

pid$target::*PageTableManager*apply*:entry
/self->nr == 215/
{
    printf("EL1MMALLOC1|path|ts=%llu|lpid=%d|ltid=%d|nr=%llu|phase=page-table-apply\n",
        timestamp, self->lpid, self->ltid, self->nr);
}

pid$target::*PageTableManager*split_block*:entry
/self->nr == 215/
{
    printf("EL1MMALLOC1|path|ts=%llu|lpid=%d|ltid=%d|nr=%llu|phase=page-table-split-block\n",
        timestamp, self->lpid, self->ltid, self->nr);
}

pid$target::*PageTableManager*alloc_table*:entry
/self->nr == 215/
{
    printf("EL1MMALLOC1|path|ts=%llu|lpid=%d|ltid=%d|nr=%llu|phase=page-table-alloc-table\n",
        timestamp, self->lpid, self->ltid, self->nr);
}

pid$target::*run_stage1_maintenance*:entry
/self->nr == 215/
{
    printf("EL1MMALLOC1|path|ts=%llu|lpid=%d|ltid=%d|nr=%llu|phase=stage1-maintenance\n",
        timestamp, self->lpid, self->ltid, self->nr);
}

pid$target::*Aarch64Vmm*on_unmap*:entry
/self->nr == 215/
{
    printf("EL1MMALLOC1|path|ts=%llu|lpid=%d|ltid=%d|nr=%llu|phase=backend-on-unmap\n",
        timestamp, self->lpid, self->ltid, self->nr);
}

carrick*:::hvpatch-guest-lifecycle
/(pid == $target || progenyof($target))/
{
    printf("EL1MMALLOC1|life|ts=%llu|phase=%d|lpid=%d|lppid=%d|ltid=%d|asid=%u\n",
        timestamp, (int32_t)arg0, (int32_t)arg1, (int32_t)arg2,
        (int32_t)arg3, (uint32_t)arg4);
}

proc:::exit
/pid == $target/
{
    live = 0;
}

tick-100ms
/live == 0/
{
    exit(selected == 0 || completions == 0 || errors != 0 ? 5 : 0);
}

tick-1s
{
    seconds++;
}

tick-1s
/seconds >= 20/
{
    printf("EL1MMALLOC1|TRUNCATED|seconds=%d\n", seconds);
    exit(4);
}

dtrace:::ERROR
{
    errors++;
}

dtrace:::END
{
    printf("EL1MMALLOC1|summary|selected=%d|completions=%d|usdt_returns=%d|errors=%d\n",
        selected, completions, usdt_returns, errors);
}
