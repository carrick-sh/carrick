/*
 * tier-d-mach-buffer-unmap.d — test whether Tier-D exec teardown unmaps a
 * live mach_msg_server request/reply buffer.
 *
 * WHAT IT MEASURES
 * ----------------
 * The libsystem mach_msg_server implementation vm_allocates one reply buffer
 * and one request buffer before receiving from Carrick's exception port set.
 * This script records those allocations on the server thread, observes the
 * guest execve boundary, and reports any later host munmap whose range covers
 * either live buffer. Such an overlap proves an ownership bug: an outgoing
 * DirectImage still claims a guest-punched hole that the Darwin VM allocator
 * has since reused for process-private host state.
 *
 * PROVIDER ABI QUALIFICATION
 * --------------------------
 * Qualified on Darwin/arm64 on 2026-08-08. The pid provider exposes
 * mach_msg_server(demux, max_size, rcv_name, options) and
 * vm_allocate(task, address_pointer, size, flags) from
 * libsystem_kernel.dylib. vm_allocate writes a 64-bit address through arg1;
 * its pid-provider return arg1 is the kern_return_t. Carrick syscall-entry
 * arg0 is the canonical Linux number (execve=221). syscall::munmap:entry
 * exposes address and length as arg0/arg1.
 *
 * PERTURBATION
 * ------------
 * LOW but fasttrap-based: two library functions on the exception-server
 * thread plus low-frequency Carrick USDT and munmap events. Launch with -c so
 * DTrace owns the target. If the target hangs, kill the CARRICK_RUN_ID first
 * and let DTrace exit after its target dies; do not abort the consumer while
 * the tracee continues.
 *
 * Usage:
 *   sudo dtrace -Zq -s scripts/dtrace/tier-d-mach-buffer-unmap.d -c \
 *     'env CARRICK_RUN_ID=... target/release/carrick run ...'
 */

#pragma D option quiet
#pragma D option strsize=256

dtrace:::BEGIN
{
    printf("TDMACHBUF1|event=begin|target=%d|time=%Y\n", $target,
        walltimestamp);
}

pid$target:*libsystem_kernel*:mach_msg_server:entry
{
    self->mach_server = 1;
    self->mach_alloc_index = 0;
    printf("TDMACHBUF1|event=server-enter|pid=%d|tid=%d|max-size=%d|port-set=%#x\n",
        pid, tid, arg1, arg2);
}

pid$target:*libsystem_kernel*:vm_allocate:entry
/self->mach_server/
{
    self->vm_address_pointer = arg1;
    self->vm_size = arg2;
}

pid$target:*libsystem_kernel*:vm_allocate:return
/self->mach_server && self->vm_address_pointer != 0/
{
    this->address = *(uintptr_t *)copyin(self->vm_address_pointer,
        sizeof(uintptr_t));
    self->mach_alloc_index++;
    printf("TDMACHBUF1|event=server-buffer|pid=%d|tid=%d|index=%d|address=%#x|length=%#x|status=%d\n",
        pid, tid, self->mach_alloc_index, this->address, self->vm_size, arg1);
    self->mach_alloc_index == 1 ? reply_buffer[pid] = this->address : 0;
    self->mach_alloc_index == 1 ? reply_length[pid] = self->vm_size : 0;
    self->mach_alloc_index == 2 ? request_buffer[pid] = this->address : 0;
    self->mach_alloc_index == 2 ? request_length[pid] = self->vm_size : 0;
    self->vm_address_pointer = 0;
    self->vm_size = 0;
}

pid$target:*libsystem_kernel*:mach_msg_server:return
/self->mach_server/
{
    printf("TDMACHBUF1|event=server-return|pid=%d|tid=%d|status=%#x\n",
        pid, tid, arg1);
    self->mach_server = 0;
    self->mach_alloc_index = 0;
}

carrick*:::syscall-entry
/(pid == $target || progenyof($target)) && arg0 == 221/
{
    execing[pid] = 1;
    printf("TDMACHBUF1|event=guest-exec|pid=%d|tid=%d|reply=%#x|request=%#x\n",
        pid, tid, reply_buffer[pid], request_buffer[pid]);
}

syscall::munmap:entry
/execing[pid]/
{
    this->end = arg0 + arg1;
    this->reply_end = reply_buffer[pid] + reply_length[pid];
    this->request_end = request_buffer[pid] + request_length[pid];
    this->reply_overlap = reply_buffer[pid] != 0 &&
        arg0 < this->reply_end && reply_buffer[pid] < this->end;
    this->request_overlap = request_buffer[pid] != 0 &&
        arg0 < this->request_end && request_buffer[pid] < this->end;
}

syscall::munmap:entry
/execing[pid] && (this->reply_overlap || this->request_overlap)/
{
    overlaps++;
    printf("TDMACHBUF1|event=OVERLAP|pid=%d|tid=%d|unmap=%#x|length=%#x|reply=%#x|reply-length=%#x|request=%#x|request-length=%#x\n",
        pid, tid, arg0, arg1, reply_buffer[pid], reply_length[pid],
        request_buffer[pid], request_length[pid]);
}

proc:::exit
/pid == $target/
{
    target_exited = 1;
}

dtrace:::ERROR
{
    errors++;
}

dtrace:::END
{
    printf("TDMACHBUF1|event=end|overlaps=%d|target-exited=%d|errors=%d|time=%Y\n",
        overlaps, target_exited, errors, walltimestamp);
}
