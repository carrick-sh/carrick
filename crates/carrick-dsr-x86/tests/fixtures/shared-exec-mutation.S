/*
 * Mutable MAP_SHARED executable translation regression.
 *
 * One unnamed host-backed file is mapped through separate RW and RX views.
 * The RX view contains `mov $imm32, %eax; ret`. After warming its translation,
 * the guest changes the immediate through (1) the second RW view, (2) pwrite,
 * and (3) a synchronized fork child. Every later call must observe the new
 * value: shared executable translations, edges, and return sites must remain
 * permanently ephemeral even though the RX VMA itself is read-only.
 */
.global _start
.type _start,@function
_start:
    /* openat(AT_FDCWD, "/tmp", O_TMPFILE|O_DIRECTORY|O_RDWR, 0600) */
    mov $257, %eax
    mov $-100, %edi
    lea tmp_dir(%rip), %rsi
    mov $0x410002, %edx
    mov $0600, %r10d
    syscall
    test %rax, %rax
    js fail_open
    mov %eax, %r12d

    /* ftruncate(fd, 4096) */
    mov $77, %eax
    mov %r12d, %edi
    mov $4096, %esi
    syscall
    test %rax, %rax
    js fail_truncate

    /* rw = mmap(NULL, 4096, PROT_READ|PROT_WRITE, MAP_SHARED, fd, 0) */
    mov $9, %eax
    xor %edi, %edi
    mov $4096, %esi
    mov $3, %edx
    mov $1, %r10d
    mov %r12d, %r8d
    xor %r9d, %r9d
    syscall
    test %rax, %rax
    js fail_rw_map
    mov %rax, %r14

    /* Six-byte function: b8 01 00 00 00 c3 = mov $1,%eax; ret. */
    movb $0xb8, 0(%r14)
    movl $1, 1(%r14)
    movb $0xc3, 5(%r14)

    /* rx = mmap(NULL, 4096, PROT_READ|PROT_EXEC, MAP_SHARED, fd, 0) */
    mov $9, %eax
    xor %edi, %edi
    mov $4096, %esi
    mov $5, %edx
    mov $1, %r10d
    mov %r12d, %r8d
    xor %r9d, %r9d
    syscall
    test %rax, %rax
    js fail_rx_map
    mov %rax, %r13

    call *%r13
    cmp $1, %eax
    jne fail_initial

    /* Mutate through a distinct RW mapping of the same backing object. */
    movl $2, 1(%r14)
    call *%r13
    cmp $2, %eax
    jne fail_rw_view

    /* Mutate without touching either VMA: pwrite(fd, &3, 4, 1). */
    mov $18, %eax
    mov %r12d, %edi
    lea value_three(%rip), %rsi
    mov $4, %edx
    mov $1, %r10d
    syscall
    cmp $4, %rax
    jne fail_pwrite
    call *%r13
    cmp $3, %eax
    jne fail_pwrite_observation

    /* Create a synchronization pipe before fork. */
    mov $22, %eax
    lea pipe_fds(%rip), %rdi
    syscall
    test %rax, %rax
    js fail_pipe

    mov $57, %eax
    syscall
    test %rax, %rax
    js fail_fork
    jz fork_child
    mov %eax, %r15d

    /* Parent waits until the child has changed the shared backing. */
    mov $0, %eax
    mov pipe_fds(%rip), %edi
    lea sync_byte(%rip), %rsi
    mov $1, %edx
    syscall
    cmp $1, %rax
    jne fail_sync

    call *%r13
    cmp $4, %eax
    jne fail_fork_observation

    mov $61, %eax
    mov %r15d, %edi
    lea wait_status(%rip), %rsi
    xor %edx, %edx
    xor %r10d, %r10d
    syscall
    cmp %r15, %rax
    jne fail_wait
    cmpl $0, wait_status(%rip)
    jne fail_wait

    xor %edi, %edi
    jmp exit_group

fork_child:
    /* The fork snapshot must retain MAP_SHARED backing identity. */
    movl $4, 1(%r14)
    mov $1, %eax
    mov pipe_fds+4(%rip), %edi
    lea child_ready(%rip), %rsi
    mov $1, %edx
    syscall
    cmp $1, %rax
    jne child_fail
    xor %edi, %edi
    jmp exit_group

child_fail:
    mov $31, %edi
    jmp exit_group
fail_open:
    mov $10, %edi
    jmp exit_group
fail_truncate:
    mov $11, %edi
    jmp exit_group
fail_rw_map:
    mov $12, %edi
    jmp exit_group
fail_rx_map:
    mov $13, %edi
    jmp exit_group
fail_pipe:
    mov $14, %edi
    jmp exit_group
fail_fork:
    mov $15, %edi
    jmp exit_group
fail_sync:
    mov $16, %edi
    jmp exit_group
fail_wait:
    mov $17, %edi
    jmp exit_group
fail_initial:
    mov $21, %edi
    jmp exit_group
fail_rw_view:
    mov $22, %edi
    jmp exit_group
fail_pwrite:
    mov $23, %edi
    jmp exit_group
fail_pwrite_observation:
    mov $24, %edi
    jmp exit_group
fail_fork_observation:
    mov $25, %edi
exit_group:
    mov $231, %eax
    syscall
    ud2
.size _start, .-_start

.section .rodata
tmp_dir:
    .asciz "/tmp"
.align 4
value_three:
    .long 3
child_ready:
    .byte 1

.section .bss
.align 8
pipe_fds:
    .long 0, 0
wait_status:
    .long 0
sync_byte:
    .byte 0

.section .note.GNU-stack,"",@progbits
