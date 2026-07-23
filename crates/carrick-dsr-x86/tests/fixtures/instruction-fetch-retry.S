/*
 * Native x86 translation-time instruction-fetch fault fixture.
 *
 * A two-byte `data16 ret` straddles a page boundary. Phase one denies execute
 * permission on the continuation page and requires SIGSEGV/SEGV_ACCERR at the
 * continuation byte while RIP remains the instruction start. The handler adds
 * PROT_EXEC and normal rt_sigreturn retries the exact instruction.
 *
 * Phase two unmaps the continuation page and requires SIGSEGV/SEGV_MAPERR at
 * the same exact boundary. The handler remaps, populates, and mprotects the
 * page before retry. Phase three puts the instruction in an RX MAP_SHARED file
 * mapping, then truncates the second page. FreeBSD's past-EOF SIGBUS must be
 * contained and delivered as Linux SIGBUS/BUS_ADRERR at the continuation byte.
 * The handler regrows and repopulates the backing before the exact retry.
 */
.global _start
.type _start,@function
_start:
    /* Install one SA_SIGINFO|SA_RESTORER action for SIGSEGV and SIGBUS. */
    lea handler(%rip), %rax
    mov %rax, action(%rip)
    movq $0x04000004, action+8(%rip)
    lea restorer(%rip), %rax
    mov %rax, action+16(%rip)
    movq $0, action+24(%rip)

    mov $13, %eax                    /* rt_sigaction(SIGSEGV) */
    mov $11, %edi
    lea action(%rip), %rsi
    xor %edx, %edx
    mov $8, %r10d
    syscall
    test %rax, %rax
    jne setup_sigaction_failed

    mov $13, %eax                    /* rt_sigaction(SIGBUS) */
    mov $7, %edi
    lea action(%rip), %rsi
    xor %edx, %edx
    mov $8, %r10d
    syscall
    test %rax, %rax
    jne setup_sigbus_action_failed

    /* Anonymous execute-permission boundary. */
    xor %edi, %edi
    mov $8192, %esi
    mov $3, %edx                     /* PROT_READ|PROT_WRITE */
    mov $0x22, %r10d                /* MAP_PRIVATE|MAP_ANONYMOUS */
    mov $-1, %r8
    xor %r9d, %r9d
    mov $9, %eax                     /* mmap */
    syscall
    test %rax, %rax
    js setup_mmap_failed
    mov %rax, anon_mapping(%rip)
    movb $0x66, 4095(%rax)           /* data16 prefix */
    movb $0xc3, 4096(%rax)           /* ret */

    mov %rax, %rdi
    mov $4096, %esi
    mov $5, %edx                     /* PROT_READ|PROT_EXEC */
    mov $10, %eax                    /* mprotect first page */
    syscall
    test %rax, %rax
    jne setup_mprotect_failed
    mov anon_mapping(%rip), %rdi
    add $4096, %rdi
    mov $4096, %esi
    mov $1, %edx                     /* PROT_READ, deliberately !EXEC */
    mov $10, %eax
    syscall
    test %rax, %rax
    jne setup_mprotect_failed

    incq accerr_site_entries(%rip)
    mov anon_mapping(%rip), %rax
    lea 4095(%rax), %rax
    mov %rax, accerr_instruction(%rip)
    lea -8(%rsp), %rcx               /* CALL's interrupted guest RSP */
    mov %rcx, expected_rsp(%rip)
    call *%rax
    cmpq $1, accerr_site_entries(%rip)
    jne bad_site_count
    cmpq $1, handler_entries(%rip)
    jne bad_handler_count

    /* Anonymous unmapped continuation boundary. */
    xor %edi, %edi
    mov $8192, %esi
    mov $3, %edx                     /* PROT_READ|PROT_WRITE */
    mov $0x22, %r10d                 /* MAP_PRIVATE|MAP_ANONYMOUS */
    mov $-1, %r8
    xor %r9d, %r9d
    mov $9, %eax                     /* mmap */
    syscall
    test %rax, %rax
    js setup_mmap_failed
    mov %rax, maperr_mapping(%rip)
    movb $0x66, 4095(%rax)
    movb $0xc3, 4096(%rax)

    mov %rax, %rdi
    mov $4096, %esi
    mov $5, %edx                     /* PROT_READ|PROT_EXEC */
    mov $10, %eax
    syscall
    test %rax, %rax
    jne setup_mprotect_failed
    mov maperr_mapping(%rip), %rdi
    add $4096, %rdi
    mov $4096, %esi
    mov $11, %eax                    /* munmap continuation */
    syscall
    test %rax, %rax
    jne setup_unmap_failed

    incq maperr_site_entries(%rip)
    mov maperr_mapping(%rip), %rax
    lea 4095(%rax), %rax
    mov %rax, maperr_instruction(%rip)
    lea -8(%rsp), %rcx
    mov %rcx, expected_rsp(%rip)
    call *%rax
    cmpq $1, maperr_site_entries(%rip)
    jne bad_site_count
    cmpq $2, handler_entries(%rip)
    jne bad_handler_count

    /* File-backed executable boundary with a truncated continuation page. */
    mov $-100, %edi                  /* AT_FDCWD */
    lea tmp_directory(%rip), %rsi
    mov $0x480002, %edx              /* O_TMPFILE|O_CLOEXEC|O_RDWR */
    mov $0600, %r10d
    mov $257, %eax                   /* openat */
    syscall
    test %rax, %rax
    js setup_tmpfile_failed
    mov %eax, bus_file_fd(%rip)

    mov %eax, %edi
    mov $8192, %esi
    mov $77, %eax                    /* ftruncate */
    syscall
    test %rax, %rax
    jne setup_file_failed

    xor %edi, %edi
    mov $8192, %esi
    mov $3, %edx                     /* PROT_READ|PROT_WRITE */
    mov $1, %r10d                    /* MAP_SHARED */
    mov bus_file_fd(%rip), %r8d
    xor %r9d, %r9d
    mov $9, %eax                     /* mmap */
    syscall
    test %rax, %rax
    js setup_file_mmap_failed
    mov %rax, bus_mapping(%rip)
    movb $0x66, 4095(%rax)
    movb $0xc3, 4096(%rax)

    mov %rax, %rdi
    mov $8192, %esi
    mov $5, %edx                     /* PROT_READ|PROT_EXEC */
    mov $10, %eax
    syscall
    test %rax, %rax
    jne setup_mprotect_failed

    mov bus_file_fd(%rip), %edi
    mov $4096, %esi
    mov $77, %eax                    /* truncate mapped continuation past EOF */
    syscall
    test %rax, %rax
    jne setup_file_failed

    incq bus_site_entries(%rip)
    mov bus_mapping(%rip), %rax
    lea 4095(%rax), %rax
    mov %rax, bus_instruction(%rip)
    lea -8(%rsp), %rcx
    mov %rcx, expected_rsp(%rip)
    call *%rax
    cmpq $1, bus_site_entries(%rip)
    jne bad_site_count
    cmpq $3, handler_entries(%rip)
    jne bad_handler_count

    mov $1, %eax                     /* write */
    mov $1, %edi
    lea success(%rip), %rsi
    mov $success_end-success, %edx
    syscall
    cmp $success_end-success, %rax
    jne bad_write
    xor %edi, %edi
    jmp exit_group
.size _start, .-_start

.type handler,@function
handler:
    mov 160(%rdx), %rax              /* uc_mcontext.rsp */
    cmp expected_rsp(%rip), %rax
    jne bad_rsp
    mov 168(%rdx), %rax              /* uc_mcontext.rip */
    cmp accerr_instruction(%rip), %rax
    je handle_accerr
    cmp maperr_instruction(%rip), %rax
    je handle_maperr
    cmp bus_instruction(%rip), %rax
    je handle_bus
    jmp bad_rip

handle_accerr:
    cmp $11, %edi                    /* SIGSEGV */
    jne bad_signal
    cmpl $2, 8(%rsi)                 /* SEGV_ACCERR */
    jne bad_code
    mov anon_mapping(%rip), %rcx
    add $4096, %rcx
    cmp 16(%rsi), %rcx               /* first denied continuation byte */
    jne bad_address
    incq handler_entries(%rip)
    cmpq $1, handler_entries(%rip)
    jne bad_repeat
    mov %rcx, %rdi
    mov $4096, %esi
    mov $5, %edx                     /* PROT_READ|PROT_EXEC */
    mov $10, %eax
    syscall
    test %rax, %rax
    jne bad_repair
    ret

handle_maperr:
    cmp $11, %edi                    /* SIGSEGV */
    jne bad_signal
    cmpl $1, 8(%rsi)                 /* SEGV_MAPERR */
    jne bad_code
    mov maperr_mapping(%rip), %rcx
    add $4096, %rcx
    cmp 16(%rsi), %rcx               /* first unmapped continuation byte */
    jne bad_address
    incq handler_entries(%rip)
    cmpq $2, handler_entries(%rip)
    jne bad_repeat
    mov %rcx, %rdi
    mov $4096, %esi
    mov $3, %edx                     /* first remap writable */
    mov $0x32, %r10d                 /* MAP_PRIVATE|MAP_ANON|MAP_FIXED */
    mov $-1, %r8
    xor %r9d, %r9d
    mov $9, %eax
    syscall
    cmp %rdi, %rax
    jne bad_repair
    movb $0xc3, (%rax)
    mov %rax, %rdi
    mov $4096, %esi
    mov $5, %edx                     /* finish as RX */
    mov $10, %eax
    syscall
    test %rax, %rax
    jne bad_repair
    ret

handle_bus:
    cmp $7, %edi                     /* SIGBUS */
    jne bad_signal
    cmpl $2, 8(%rsi)                 /* BUS_ADRERR */
    jne bad_code
    mov bus_mapping(%rip), %rcx
    add $4096, %rcx
    cmp 16(%rsi), %rcx               /* first unavailable backing byte */
    jne bad_address
    incq handler_entries(%rip)
    cmpq $3, handler_entries(%rip)
    jne bad_repeat
    mov bus_file_fd(%rip), %edi
    mov $8192, %esi
    mov $77, %eax                    /* regrow backing */
    syscall
    test %rax, %rax
    jne bad_repair
    mov bus_file_fd(%rip), %edi
    lea ret_byte(%rip), %rsi
    mov $1, %edx
    mov $4096, %r10d
    mov $18, %eax                    /* pwrite64 */
    syscall
    cmp $1, %rax
    jne bad_repair
    ret
.size handler, .-handler

.type restorer,@function
restorer:
    mov $15, %eax                    /* rt_sigreturn */
    syscall
.size restorer, .-restorer

setup_sigaction_failed:      mov $80, %edi; jmp exit_group
setup_sigbus_action_failed:  mov $81, %edi; jmp exit_group
setup_mmap_failed:           mov $82, %edi; jmp exit_group
setup_mprotect_failed:       mov $83, %edi; jmp exit_group
setup_unmap_failed:          mov $84, %edi; jmp exit_group
setup_tmpfile_failed:        mov $85, %edi; jmp exit_group
setup_file_failed:           mov $86, %edi; jmp exit_group
setup_file_mmap_failed:      mov $87, %edi; jmp exit_group
bad_signal:                  mov $90, %edi; jmp exit_group
bad_code:                    mov $91, %edi; jmp exit_group
bad_address:                 mov $92, %edi; jmp exit_group
bad_rip:                     mov $93, %edi; jmp exit_group
bad_rsp:                     mov $94, %edi; jmp exit_group
bad_repeat:                  mov $95, %edi; jmp exit_group
bad_repair:                  mov $96, %edi; jmp exit_group
bad_site_count:              mov $97, %edi; jmp exit_group
bad_handler_count:           mov $98, %edi; jmp exit_group
bad_write:                   mov $99, %edi

exit_group:
    mov $231, %eax
    syscall
    ud2

.section .rodata
success:
    .ascii "instruction-fetch retry ok\n"
success_end:
tmp_directory:
    .asciz "/tmp"
ret_byte:
    .byte 0xc3

.section .bss
.align 8
action:                 .skip 32
anon_mapping:           .quad 0
maperr_mapping:         .quad 0
bus_mapping:            .quad 0
accerr_instruction:     .quad 0
maperr_instruction:     .quad 0
bus_instruction:        .quad 0
expected_rsp:           .quad 0
handler_entries:        .quad 0
accerr_site_entries:    .quad 0
maperr_site_entries:    .quad 0
bus_site_entries:       .quad 0
bus_file_fd:            .long 0
