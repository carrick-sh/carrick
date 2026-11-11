/* x86_64 Linux oracle + CPL0 KVM witness for #1897:
 * poll(2) and ppoll(2) must publish only each entry's 2-byte `revents` field.
 *
 * Modes:
 * - `-DREADONLY_INPUT_PAGE`: places one `struct pollfd` across a page boundary
 *   (`fd` + `events` at `page0 + 4090..4096` with `PROT_READ`, `revents` at
 *   `page1 + 0..2` with `PROT_READ | PROT_WRITE`) and calls `poll` and `ppoll`
 *   with zero timeout. Writing `fd` or `events` faults (`-EFAULT`).
 * - default: spawns a `CLONE_THREAD` sibling sharing the `mm`. While the root
 *   thread is blocked in `poll(&pfd, 1, 80)` (`HostReadinessCrossing`), the
 *   sibling mutates `pfd.fd` (`-1 -> 17`) and `pfd.events` (`POLLIN -> POLLOUT`).
 *   Completion must clear `revents` to `0` while preserving `fd == 17` and
 *   `events == POLLOUT`.
 */
.global _start
.text
_start:
#ifdef READONLY_INPUT_PAGE
    /* mmap(NULL, 8192, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0) */
    xor %edi, %edi
    mov $8192, %esi
    mov $3, %edx
    mov $0x22, %r10d
    mov $-1, %r8d
    xor %r9d, %r9d
    mov $9, %eax
    syscall
    test %rax, %rax
    js fail_10
    mov %rax, %r12

    movl $-1, 4090(%r12)
    movw $1, 4094(%r12)
    movw $0x5555, 4096(%r12)

    /* mprotect(page0, 4096, PROT_READ) */
    mov %r12, %rdi
    mov $4096, %esi
    mov $1, %edx
    mov $10, %eax
    syscall
    test %rax, %rax
    jnz fail_11

    /* poll(page0 + 4090, 1, 0) */
    lea 4090(%r12), %rdi
    mov $1, %esi
    xor %edx, %edx
    mov $7, %eax
    syscall
    test %rax, %rax
    jnz fail_12
    cmpl $-1, 4090(%r12)
    jne fail_13
    cmpw $1, 4094(%r12)
    jne fail_14
    cmpw $0, 4096(%r12)
    jne fail_15

    /* Reset revents on writable page1 and check ppoll(page0 + 4090, 1, &zero_ts, NULL, 8) */
    movw $0x6666, 4096(%r12)
    lea 4090(%r12), %rdi
    mov $1, %esi
    lea zero_ts(%rip), %rdx
    xor %r10d, %r10d
    mov $8, %r8d
    mov $271, %eax
    syscall
    test %rax, %rax
    jnz fail_16
    cmpl $-1, 4090(%r12)
    jne fail_17
    cmpw $1, 4094(%r12)
    jne fail_18
    cmpw $0, 4096(%r12)
    jne fail_19

    xor %edi, %edi
    jmp exit_group

fail_10: mov $10, %edi; jmp exit_group
fail_11: mov $11, %edi; jmp exit_group
fail_12: mov $12, %edi; jmp exit_group
fail_13: mov $13, %edi; jmp exit_group
fail_14: mov $14, %edi; jmp exit_group
fail_15: mov $15, %edi; jmp exit_group
fail_16: mov $16, %edi; jmp exit_group
fail_17: mov $17, %edi; jmp exit_group
fail_18: mov $18, %edi; jmp exit_group
fail_19: mov $19, %edi; jmp exit_group

#else
    movl $-1, pfd(%rip)
    movw $1, pfd+4(%rip)
    movw $0x5555, pfd+6(%rip)
    movl $0, phase(%rip)

    /* clone(CLONE_VM|CLONE_FS|CLONE_FILES|CLONE_SIGHAND|CLONE_THREAD|CLONE_SYSVSEM, stack_top, 0, 0, 0) */
    mov $0x00050f00, %edi
    lea thread_stack_top(%rip), %rsi
    xor %edx, %edx
    xor %r10d, %r10d
    xor %r8d, %r8d
    mov $56, %eax
    syscall
    test %rax, %rax
    jz sibling_thread
    js fail_20

    /* Announce readiness to enter poll(&pfd, 1, 80). */
    movl $1, phase(%rip)
    lea pfd(%rip), %rdi
    mov $1, %esi
    mov $80, %edx
    mov $7, %eax
    syscall
    test %rax, %rax
    jnz fail_21

    /* Bounded wait for sibling mutation if host scheduling delayed CPU 1. */
    mov $60, %r13d
wait_sibling_done:
    movl phase(%rip), %eax
    cmp $2, %eax
    je check_mutated
    dec %r13d
    jz fail_22
    lea short_ts(%rip), %rdi
    xor %esi, %esi
    mov $35, %eax
    syscall
    jmp wait_sibling_done

check_mutated:
    cmpl $17, pfd(%rip)
    jne fail_23
    cmpw $4, pfd+4(%rip)
    jne fail_24
    cmpw $0, pfd+6(%rip)
    jne fail_25

    xor %edi, %edi
    jmp exit_group

sibling_thread:
    mov $60, %r13d
wait_root_ready:
    movl phase(%rip), %eax
    cmp $1, %eax
    je sleep_into_poll
    dec %r13d
    jz thread_exit
    lea short_ts(%rip), %rdi
    xor %esi, %esi
    mov $35, %eax
    syscall
    jmp wait_root_ready

sleep_into_poll:
    /* Sleep 20 ms so the root thread is parked inside HostReadinessCrossing. */
    lea mutate_delay_ts(%rip), %rdi
    xor %esi, %esi
    mov $35, %eax
    syscall

    movl $17, pfd(%rip)
    movw $4, pfd+4(%rip)
    movl $2, phase(%rip)

thread_exit:
    xor %edi, %edi
    mov $60, %eax
    syscall
    ud2

fail_20: mov $20, %edi; jmp exit_group
fail_21: mov $21, %edi; jmp exit_group
fail_22: mov $22, %edi; jmp exit_group
fail_23: mov $23, %edi; jmp exit_group
fail_24: mov $24, %edi; jmp exit_group
fail_25: mov $25, %edi; jmp exit_group
#endif

exit_group:
    mov $231, %eax
    syscall
    ud2

.section .rodata
.balign 8
zero_ts:
    .quad 0, 0
short_ts:
    .quad 0, 5000000
mutate_delay_ts:
    .quad 0, 20000000

.bss
.balign 16
pfd:
    .space 8
phase:
    .space 4
.balign 16
thread_stack:
    .space 16384
thread_stack_top:
