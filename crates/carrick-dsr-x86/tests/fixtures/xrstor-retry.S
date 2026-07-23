/*
 * Checked native-x86 XRSTOR synchronous-fault retry fixture.
 *
 * A SA_SIGINFO alternate-stack handler verifies the original RIP/RSP and:
 *  - repairs a PROT_NONE XSAVE header read (SEGV_ACCERR, exact first byte),
 *  - repairs an unmapped header with MAP_FIXED anonymous memory (SEGV_MAPERR),
 *  - grows a truncated MAP_SHARED file after SIGBUS/BUS_ADRERR at the exact
 *    XSAVE header byte, then populates x87 source bytes for the retry,
 *  - repairs an unsafe PKRU XSTATE_BV header (SI_KERNEL, address zero),
 *  - repairs a misaligned operand in saved R12 (SI_KERNEL, address zero).
 * Each phase observes exactly one handler fault, returns without advancing RIP,
 * and reaches its continuation after the normal rt_sigreturn retry succeeds.
 */
.global _start
.type _start,@function
_start:
    xor %edi, %edi
    mov $4096, %esi
    mov $3, %edx
    mov $0x22, %r10d
    mov $-1, %r8
    xor %r9d, %r9d
    mov $9, %eax                    /* mmap */
    syscall
    test %rax, %rax
    js setup_mmap_failed
    mov %rax, image_page(%rip)
    mov %rax, %r12
    movq $0, 512(%r12)
    movq $0, 520(%r12)

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
    jne setup_sigaction_failed

    mov $13, %eax                   /* rt_sigaction(SIGBUS) */
    mov $7, %edi
    lea action(%rip), %rsi
    xor %edx, %edx
    mov $8, %r10d
    syscall
    test %rax, %rax
    jne setup_sigbus_action_failed

    mov %rsp, original_rsp(%rip)
    mov image_page(%rip), %rdi
    mov $4096, %esi
    xor %edx, %edx                  /* PROT_NONE */
    mov $10, %eax                   /* mprotect */
    syscall
    test %rax, %rax
    jne setup_mprotect_failed

    /* Keep a nonzero virtual PKRU throughout every fault/retry. The request
     * includes bit 9, which Carrick must mask instead of importing host PKRU. */
    mov $3, %eax
    xor %ecx, %ecx
    xor %edx, %edx
    wrpkru

    /* These counters sit before the restart RIP, so they count entry into each
     * test site, not instruction attempts. One handler entry plus reaching the
     * continuation proves one failed attempt and one successful retry. */
    incq accerr_site_entries(%rip)
    mov image_page(%rip), %r12
    mov $0x200, %eax
    xor %edx, %edx
accerr_fault:
    xrstor (%r12)
after_accerr_retry:
    cmpq $1, accerr_site_entries(%rip)
    jne bad_site_count
    cmpq $1, handler_entries(%rip)
    jne bad_handler_count

    /* Remove the source entirely. The handler must replace it at the exact
     * address and populate a valid empty standard-format header. */
    mov image_page(%rip), %rdi
    mov $4096, %esi
    mov $11, %eax                   /* munmap */
    syscall
    test %rax, %rax
    jne setup_munmap_failed

    incq maperr_site_entries(%rip)
    mov image_page(%rip), %r12
    mov $0x200, %eax
    xor %edx, %edx
maperr_fault:
    xrstor (%r12)
after_maperr_retry:
    cmpq $1, maperr_site_entries(%rip)
    jne bad_site_count
    cmpq $2, handler_entries(%rip)
    jne bad_handler_count

    /* Install a real anonymous file at two pages, map it MAP_SHARED and
     * readable, then truncate it to one page without changing the VMA. The
     * header read in the second page must become guest SIGBUS, never a host
     * crash. The handler grows the same backing and fills both the x87 payload
     * and header, so retry proves exact target-byte restoration. */
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
    mov $77, %eax                    /* ftruncate: fully back mapping first */
    syscall
    test %rax, %rax
    jne setup_file_grow_failed

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
    add $4096, %rax
    mov %rax, bus_image_page(%rip)

    mov bus_file_fd(%rip), %edi
    mov $4096, %esi
    mov $77, %eax                    /* truncate second mapped page past EOF */
    syscall
    test %rax, %rax
    jne setup_file_truncate_failed

    movw $0x027f, control_word(%rip)
    fldcw control_word(%rip)
    incq bus_site_entries(%rip)
    mov bus_image_page(%rip), %r12
    mov $1, %eax                     /* request x87 */
    xor %edx, %edx
bus_fault:
    xrstor (%r12)
after_bus_retry:
    cmpq $1, bus_site_entries(%rip)
    jne bad_site_count
    cmpq $3, handler_entries(%rip)
    jne bad_handler_count
    fnstcw observed_control_word(%rip)
    cmpw $0x037f, observed_control_word(%rip)
    jne bad_control_word

    /* Unsafe source component 9 must be rejected before any payload read. */
    mov image_page(%rip), %r12
    movq $0x200, 512(%r12)
    incq malformed_site_entries(%rip)
    mov $0x200, %eax
    xor %edx, %edx
malformed_fault:
    xrstor (%r12)
after_malformed_retry:
    cmpq $1, malformed_site_entries(%rip)
    jne bad_site_count
    cmpq $4, handler_entries(%rip)
    jne bad_handler_count

    /* Decode-time #GP for a non-64-byte-aligned effective address. The handler
     * repairs saved R12 but leaves saved RIP/RSP at the fault boundary. */
    mov image_page(%rip), %r12
    add $8, %r12
    incq misaligned_site_entries(%rip)
    mov $0x200, %eax
    xor %edx, %edx
misaligned_fault:
    xrstor (%r12)
after_misaligned_retry:
    cmpq $1, misaligned_site_entries(%rip)
    jne bad_site_count
    cmpq $5, handler_entries(%rip)
    jne bad_handler_count

    xor %ecx, %ecx
    rdpkru
    cmp $3, %eax
    jne bad_pkru
    test %edx, %edx
    jne bad_pkru
    xor %eax, %eax
    xor %ecx, %ecx
    xor %edx, %edx
    wrpkru
    xor %edi, %edi
    jmp exit_group

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
    lea accerr_fault(%rip), %rcx
    cmp %rcx, %rax
    je handle_accerr
    lea maperr_fault(%rip), %rcx
    cmp %rcx, %rax
    je handle_maperr
    lea bus_fault(%rip), %rcx
    cmp %rcx, %rax
    je handle_bus
    lea malformed_fault(%rip), %rcx
    cmp %rcx, %rax
    je handle_malformed
    lea misaligned_fault(%rip), %rcx
    cmp %rcx, %rax
    je handle_misaligned
    jmp bad_rip

handle_accerr:
    cmp $11, %edi
    jne bad_signal
    cmpl $2, 8(%rsi)                /* SEGV_ACCERR */
    jne bad_code
    mov image_page(%rip), %rcx
    add $512, %rcx
    cmp 16(%rsi), %rcx              /* first inaccessible header byte */
    jne bad_address
    incq handler_entries(%rip)
    cmpq $1, handler_entries(%rip)
    jne bad_repeat
    mov image_page(%rip), %rdi
    mov $4096, %esi
    mov $3, %edx                    /* PROT_READ|PROT_WRITE */
    mov $10, %eax                   /* mprotect */
    syscall
    test %rax, %rax
    jne bad_mprotect
    ret

handle_maperr:
    cmp $11, %edi
    jne bad_signal
    cmpl $1, 8(%rsi)                /* SEGV_MAPERR */
    jne bad_code
    mov image_page(%rip), %rcx
    add $512, %rcx
    cmp 16(%rsi), %rcx              /* first unmapped header byte */
    jne bad_address
    incq handler_entries(%rip)
    cmpq $2, handler_entries(%rip)
    jne bad_repeat
    mov image_page(%rip), %rdi
    mov $4096, %esi
    mov $3, %edx                    /* PROT_READ|PROT_WRITE */
    mov $0x32, %r10d                /* MAP_PRIVATE|MAP_FIXED|MAP_ANONYMOUS */
    mov $-1, %r8
    xor %r9d, %r9d
    mov $9, %eax                    /* mmap */
    syscall
    cmp image_page(%rip), %rax
    jne bad_mmap_repair
    movq $0, 512(%rax)              /* populate XSTATE_BV */
    movq $0, 520(%rax)              /* populate standard-format XCOMP_BV */
    ret

handle_bus:
    cmp $7, %edi
    jne bad_signal
    cmpl $2, 8(%rsi)                /* BUS_ADRERR */
    jne bad_code
    mov bus_image_page(%rip), %rcx
    add $512, %rcx
    cmp 16(%rsi), %rcx              /* exact first requested source byte */
    jne bad_address
    incq handler_entries(%rip)
    cmpq $3, handler_entries(%rip)
    jne bad_repeat
    mov bus_file_fd(%rip), %edi
    mov $8192, %esi
    mov $77, %eax                    /* regrow the mapped file backing */
    syscall
    test %rax, %rax
    jne bad_file_repair
    mov bus_image_page(%rip), %rcx
    movw $0x037f, 0(%rcx)           /* distinct x87 control word */
    movq $1, 512(%rcx)              /* XSTATE_BV: x87 source is present */
    movq $0, 520(%rcx)              /* standard-format XCOMP_BV */
    ret

handle_malformed:
    cmp $11, %edi
    jne bad_signal
    cmpl $128, 8(%rsi)              /* SI_KERNEL */
    jne bad_code
    cmpq $0, 16(%rsi)               /* si_addr = 0 */
    jne bad_address
    incq handler_entries(%rip)
    cmpq $4, handler_entries(%rip)
    jne bad_repeat
    mov image_page(%rip), %rax
    movq $0, 512(%rax)              /* repair unsafe XSTATE_BV */
    ret

handle_misaligned:
    cmp $11, %edi
    jne bad_signal
    cmpl $128, 8(%rsi)              /* SI_KERNEL */
    jne bad_code
    cmpq $0, 16(%rsi)
    jne bad_address
    incq handler_entries(%rip)
    cmpq $5, handler_entries(%rip)
    jne bad_repeat
    mov image_page(%rip), %rax
    mov %rax, 72(%rdx)              /* uc_mcontext.r12 */
    ret
.size handler, .-handler

.type restorer,@function
restorer:
    mov $15, %eax                   /* rt_sigreturn */
    syscall
.size restorer, .-restorer

setup_mmap_failed:
    mov $90, %edi
    jmp exit_group
setup_altstack_failed:
    mov $91, %edi
    jmp exit_group
setup_sigaction_failed:
    mov $92, %edi
    jmp exit_group
setup_sigbus_action_failed:
    mov $95, %edi
    jmp exit_group
setup_tmpfile_failed:
    mov $96, %edi
    jmp reset_and_exit
setup_file_grow_failed:
    mov $97, %edi
    jmp reset_and_exit
setup_file_mmap_failed:
    mov $98, %edi
    jmp reset_and_exit
setup_file_truncate_failed:
    mov $99, %edi
    jmp reset_and_exit
setup_mprotect_failed:
    mov $93, %edi
    jmp exit_group
setup_munmap_failed:
    mov $94, %edi
    jmp reset_and_exit
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
bad_mprotect:
    mov $106, %edi
    jmp reset_and_exit
bad_site_count:
    mov $107, %edi
    jmp reset_and_exit
bad_handler_count:
    mov $108, %edi
    jmp reset_and_exit
bad_pkru:
    mov $109, %edi
    jmp reset_and_exit
bad_mmap_repair:
    mov $110, %edi
    jmp reset_and_exit
bad_control_word:
    mov $111, %edi
    jmp reset_and_exit
bad_file_repair:
    mov $112, %edi
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

.section .data
.balign 8
image_page:
    .quad 0
bus_image_page:
    .quad 0
original_rsp:
    .quad 0
action:
    .quad 0, 0, 0, 0
altstack_desc:
    .quad 0
    .long 0, 0
    .quad 0
accerr_site_entries:
    .quad 0
maperr_site_entries:
    .quad 0
bus_site_entries:
    .quad 0
malformed_site_entries:
    .quad 0
misaligned_site_entries:
    .quad 0
handler_entries:
    .quad 0
bus_file_fd:
    .long -1
control_word:
    .word 0
observed_control_word:
    .word 0
tmp_directory:
    .asciz "/tmp"

.section .bss
.balign 16
alternate_stack:
    .skip 65536

.section .note.GNU-stack,"",@progbits
