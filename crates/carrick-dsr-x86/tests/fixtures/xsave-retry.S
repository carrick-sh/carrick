/*
 * Mandatory checked-writer XSAVEC64 fault/retry fixture.
 *
 * A SA_SIGINFO alternate-stack handler repairs one real destination MAPERR,
 * one read-only ACCERR, and one writable MAP_SHARED page whose file backing was
 * truncated (SIGBUS/BUS_ADRERR).  A fourth phase repairs a misaligned operand
 * reported as SI_KERNEL/address zero.  Every normal return retries the exact
 * save instruction; each continuation validates the written compacted header
 * and x87 payload.  Virtual PKRU stays nonzero and hostile request bit 9 never
 * reaches the host image.
 */

.global _start
.type _start,@function
_start:
    /* Reserve adjacent destinations so the ACCERR mmap cannot reuse the page
     * removed for the real MAPERR phase. */
    xor %edi, %edi
    mov $8192, %esi
    mov $3, %edx
    mov $0x22, %r10d
    mov $-1, %r8
    xor %r9d, %r9d
    mov $9, %eax                    /* mmap */
    syscall
    test %rax, %rax
    js setup_maperr_mmap_failed
    mov %rax, maperr_page(%rip)
    add $4096, %rax
    mov %rax, accerr_page(%rip)
    mov %rax, %rdi
    mov $4096, %esi
    mov $1, %edx                    /* PROT_READ */
    mov $10, %eax                   /* mprotect */
    syscall
    test %rax, %rax
    jne setup_accerr_mprotect_failed
    mov maperr_page(%rip), %rdi
    mov $4096, %esi
    mov $11, %eax                   /* munmap */
    syscall
    test %rax, %rax
    jne setup_maperr_munmap_failed

    lea alternate_stack(%rip), %rax
    mov %rax, altstack_desc(%rip)
    movl $0, altstack_desc+8(%rip)
    movq $65536, altstack_desc+16(%rip)
    lea altstack_desc(%rip), %rdi
    xor %esi, %esi
    mov $131, %eax                  /* sigaltstack */
    syscall
    test %rax, %rax
    jne setup_altstack_failed

    lea handler(%rip), %rax
    mov %rax, action(%rip)
    movq $0x0c000004, action+8(%rip) /* SA_SIGINFO|SA_RESTORER|SA_ONSTACK */
    lea restorer(%rip), %rax
    mov %rax, action+16(%rip)
    movq $0, action+24(%rip)
    mov $13, %eax                   /* rt_sigaction(SIGSEGV) */
    mov $11, %edi
    lea action(%rip), %rsi
    xor %edx, %edx
    mov $8, %r10d
    syscall
    test %rax, %rax
    jne setup_sigsegv_action_failed
    mov $13, %eax                   /* rt_sigaction(SIGBUS) */
    mov $7, %edi
    lea action(%rip), %rsi
    xor %edx, %edx
    mov $8, %r10d
    syscall
    test %rax, %rax
    jne setup_sigbus_action_failed

    /* Create a genuinely writable MAP_SHARED page, then remove its complete
     * backing page without changing the VMA. */
    mov $-100, %edi                 /* AT_FDCWD */
    lea tmp_directory(%rip), %rsi
    mov $0x480002, %edx             /* O_TMPFILE|O_CLOEXEC|O_RDWR */
    mov $0600, %r10d
    mov $257, %eax                  /* openat */
    syscall
    test %rax, %rax
    js setup_tmpfile_failed
    mov %eax, bus_file_fd(%rip)
    mov %eax, %edi
    mov $8192, %esi
    mov $77, %eax                   /* ftruncate */
    syscall
    test %rax, %rax
    jne setup_file_grow_failed
    xor %edi, %edi
    mov $8192, %esi
    mov $3, %edx                    /* PROT_READ|PROT_WRITE */
    mov $1, %r10d                   /* MAP_SHARED */
    mov bus_file_fd(%rip), %r8d
    xor %r9d, %r9d
    mov $9, %eax
    syscall
    test %rax, %rax
    js setup_file_mmap_failed
    add $4096, %rax
    mov %rax, bus_page(%rip)
    mov bus_file_fd(%rip), %edi
    mov $4096, %esi
    mov $77, %eax
    syscall
    test %rax, %rax
    jne setup_file_truncate_failed

    mov %rsp, original_rsp(%rip)
    mov $3, %eax
    xor %ecx, %ecx
    xor %edx, %edx
    wrpkru

    /* The counters precede the restart RIP.  One handler entry followed by one
     * continuation therefore proves one failed attempt plus one exact retry. */
    call seed_x87
    incq maperr_site_entries(%rip)
    mov maperr_page(%rip), %r12
    mov $0x201, %eax                /* x87 plus hostile PKRU request */
    xor %edx, %edx
maperr_xsavec64:
    xsavec64 (%r12)
after_maperr_retry:
    cmpq $1, maperr_site_entries(%rip)
    jne bad_site_count
    cmpq $1, handler_entries(%rip)
    jne bad_handler_count
    call verify_saved_image

    call seed_x87
    incq accerr_site_entries(%rip)
    mov accerr_page(%rip), %r12
    mov $0x201, %eax
    xor %edx, %edx
accerr_xsavec64:
    xsavec64 (%r12)
after_accerr_retry:
    cmpq $1, accerr_site_entries(%rip)
    jne bad_site_count
    cmpq $2, handler_entries(%rip)
    jne bad_handler_count
    call verify_saved_image

    call seed_x87
    incq bus_site_entries(%rip)
    mov bus_page(%rip), %r12
    mov $0x201, %eax
    xor %edx, %edx
bus_xsavec64:
    xsavec64 (%r12)
after_bus_retry:
    cmpq $1, bus_site_entries(%rip)
    jne bad_site_count
    cmpq $3, handler_entries(%rip)
    jne bad_handler_count
    call verify_saved_image

    /* Decode-time #GP remains useful as a fourth exact-retry receipt and costs
     * no repair syscall: the handler replaces saved R12 with the aligned page. */
    call seed_x87
    incq misaligned_site_entries(%rip)
    mov maperr_page(%rip), %r12
    add $8, %r12
    mov $0x201, %eax
    xor %edx, %edx
misaligned_xsavec64:
    xsavec64 (%r12)
after_misaligned_retry:
    cmpq $1, misaligned_site_entries(%rip)
    jne bad_site_count
    cmpq $4, handler_entries(%rip)
    jne bad_handler_count
    call verify_saved_image

    xor %ecx, %ecx
    rdpkru
    cmp $3, %eax
    jne bad_pkru
    test %edx, %edx
    jne bad_pkru
    xor %edi, %edi
    jmp reset_and_exit

.type seed_x87,@function
seed_x87:
    fninit
    fldcw live_control_word(%rip)
    fld1
    ret

.type verify_saved_image,@function
verify_saved_image:
    cmpw $0x027f, 0(%r12)
    jne bad_payload
    movabs $0x8000000000000000, %rax
    cmp %rax, 32(%r12)
    jne bad_payload
    cmpw $0x3fff, 40(%r12)
    jne bad_payload
    cmpq $1, 512(%r12)              /* only x87 is present */
    jne bad_header
    movabs $0x8000000000000001, %rax /* compacted | effective request */
    cmp %rax, 520(%r12)
    jne bad_header
    ret

.type handler,@function
handler:
    cmp $11, %edi
    je handler_context
    cmp $7, %edi
    jne bad_signal
handler_context:
    mov 160(%rdx), %rax             /* uc_mcontext.rsp */
    cmp original_rsp(%rip), %rax
    jne bad_rsp
    mov 168(%rdx), %rax             /* uc_mcontext.rip */
    lea maperr_xsavec64(%rip), %rcx
    cmp %rcx, %rax
    je handle_maperr
    lea accerr_xsavec64(%rip), %rcx
    cmp %rcx, %rax
    je handle_accerr
    lea bus_xsavec64(%rip), %rcx
    cmp %rcx, %rax
    je handle_bus
    lea misaligned_xsavec64(%rip), %rcx
    cmp %rcx, %rax
    je handle_misaligned
    jmp bad_rip

handle_maperr:
    cmp $11, %edi
    jne bad_signal
    cmpl $1, 8(%rsi)                /* SEGV_MAPERR */
    jne bad_code
    mov maperr_page(%rip), %rcx
    cmp 16(%rsi), %rcx
    jne bad_address
    incq handler_entries(%rip)
    cmpq $1, handler_entries(%rip)
    jne bad_repeat
    mov maperr_page(%rip), %rdi
    mov $4096, %esi
    mov $3, %edx
    mov $0x32, %r10d                /* PRIVATE|FIXED|ANONYMOUS */
    mov $-1, %r8
    xor %r9d, %r9d
    mov $9, %eax
    syscall
    cmp maperr_page(%rip), %rax
    jne bad_mmap_repair
    ret

handle_accerr:
    cmp $11, %edi
    jne bad_signal
    cmpl $2, 8(%rsi)                /* SEGV_ACCERR */
    jne bad_code
    mov accerr_page(%rip), %rcx
    cmp 16(%rsi), %rcx
    jne bad_address
    incq handler_entries(%rip)
    cmpq $2, handler_entries(%rip)
    jne bad_repeat
    mov accerr_page(%rip), %rdi
    mov $4096, %esi
    mov $3, %edx
    mov $10, %eax                   /* mprotect */
    syscall
    test %rax, %rax
    jne bad_mprotect
    ret

handle_bus:
    cmp $7, %edi
    jne bad_signal
    cmpl $2, 8(%rsi)                /* BUS_ADRERR */
    jne bad_code
    mov bus_page(%rip), %rcx
    cmp 16(%rsi), %rcx
    jne bad_address
    incq handler_entries(%rip)
    cmpq $3, handler_entries(%rip)
    jne bad_repeat
    mov bus_file_fd(%rip), %edi
    mov $8192, %esi
    mov $77, %eax                   /* regrow backing for exact retry */
    syscall
    test %rax, %rax
    jne bad_file_repair
    ret

handle_misaligned:
    cmp $11, %edi
    jne bad_signal
    cmpl $128, 8(%rsi)              /* SI_KERNEL */
    jne bad_code
    cmpq $0, 16(%rsi)               /* si_addr = 0 */
    jne bad_address
    incq handler_entries(%rip)
    cmpq $4, handler_entries(%rip)
    jne bad_repeat
    mov maperr_page(%rip), %rax
    mov %rax, 72(%rdx)              /* uc_mcontext.r12 */
    ret
.size handler, .-handler

.type restorer,@function
restorer:
    mov $15, %eax                   /* rt_sigreturn */
    syscall
.size restorer, .-restorer

setup_maperr_mmap_failed:
    mov $90, %edi
    jmp exit_group
setup_maperr_munmap_failed:
    mov $91, %edi
    jmp exit_group
setup_accerr_mprotect_failed:
    mov $92, %edi
    jmp exit_group
setup_altstack_failed:
    mov $93, %edi
    jmp exit_group
setup_sigsegv_action_failed:
    mov $94, %edi
    jmp exit_group
setup_sigbus_action_failed:
    mov $95, %edi
    jmp exit_group
setup_tmpfile_failed:
    mov $96, %edi
    jmp exit_group
setup_file_grow_failed:
    mov $97, %edi
    jmp exit_group
setup_file_mmap_failed:
    mov $98, %edi
    jmp exit_group
setup_file_truncate_failed:
    mov $99, %edi
    jmp exit_group
bad_signal:
    mov $100, %edi
    jmp reset_and_exit
bad_code:
    mov $101, %edi
    jmp reset_and_exit
bad_address:
    mov $102, %edi
    jmp reset_and_exit
bad_rip:
    mov $103, %edi
    jmp reset_and_exit
bad_rsp:
    mov $104, %edi
    jmp reset_and_exit
bad_repeat:
    mov $105, %edi
    jmp reset_and_exit
bad_mmap_repair:
    mov $106, %edi
    jmp reset_and_exit
bad_mprotect:
    mov $107, %edi
    jmp reset_and_exit
bad_file_repair:
    mov $108, %edi
    jmp reset_and_exit
bad_site_count:
    mov $109, %edi
    jmp reset_and_exit
bad_handler_count:
    mov $110, %edi
    jmp reset_and_exit
bad_payload:
    mov $111, %edi
    jmp reset_and_exit
bad_header:
    mov $112, %edi
    jmp reset_and_exit
bad_pkru:
    mov $113, %edi
reset_and_exit:
    push %rdi
    xor %eax, %eax
    xor %ecx, %ecx
    xor %edx, %edx
    wrpkru
    pop %rdi
exit_group:
    mov $231, %eax
    syscall

.section .rodata
live_control_word:
    .word 0x027f
tmp_directory:
    .asciz "/tmp"

.section .data
.balign 8
maperr_page:              .quad 0
accerr_page:              .quad 0
bus_page:                 .quad 0
original_rsp:             .quad 0
action:                   .quad 0, 0, 0, 0
altstack_desc:
    .quad 0
    .long 0, 0
    .quad 0
maperr_site_entries:      .quad 0
accerr_site_entries:      .quad 0
bus_site_entries:         .quad 0
misaligned_site_entries:  .quad 0
handler_entries:          .quad 0
bus_file_fd:              .long -1

.section .bss
.balign 16
alternate_stack:
    .skip 65536

.section .note.GNU-stack,"",@progbits
