/*
 * Retry direct CALLs after their return-address pushes fault first on a
 * read-only anonymous page and then on a writable MAP_SHARED page whose file
 * backing was truncated. Alternate-stack SIGSEGV/SIGBUS handlers verify the
 * exact original RIP/RSP and fault address, repair each backing, and return
 * without advancing the CALL. Correct native cflow retry exits 0 after exactly
 * one handler and one target entry for each phase.
 */
.global _start
.type _start,@function
_start:
    /* guard_page = mmap(NULL, 4096, PROT_READ, MAP_PRIVATE|MAP_ANON, -1, 0) */
    xor %edi, %edi
    mov $4096, %esi
    mov $1, %edx
    mov $0x22, %r10d
    mov $-1, %r8
    xor %r9d, %r9d
    mov $9, %eax
    syscall
    test %rax, %rax
    js setup_mmap_failed
    mov %rax, guard_page(%rip)

    lea alternate_stack(%rip), %rax
    mov %rax, altstack_desc(%rip)
    movl $0, altstack_desc+8(%rip)
    movq $65536, altstack_desc+16(%rip)
    lea altstack_desc(%rip), %rdi
    xor %esi, %esi
    mov $131, %eax                   /* sigaltstack */
    syscall
    test %rax, %rax
    jne setup_altstack_failed

    lea handler(%rip), %rax
    mov %rax, action(%rip)
    movq $0x0c000004, action+8(%rip) /* SA_SIGINFO|SA_RESTORER|SA_ONSTACK */
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

    mov guard_page(%rip), %rsp
    add $8, %rsp
    incq site_entries(%rip)
call_fault:
    call target

    cmpq $1, site_entries(%rip)
    jne bad_site_count
    cmpq $1, handler_entries(%rip)
    jne bad_handler_count
    cmpq $1, target_entries(%rip)
    jne bad_target_count

    /* Fully back a two-page shared file mapping, then truncate away page two
     * while leaving its writable VMA installed. The CALL push at page two's
     * first byte must become guest SIGBUS/BUS_ADRERR, never host SIGBUS. */
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
    mov $77, %eax                    /* ftruncate: initially back both pages */
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
    mov %rax, bus_stack_page(%rip)

    mov bus_file_fd(%rip), %edi
    mov $4096, %esi
    mov $77, %eax                    /* truncate the mapped second page */
    syscall
    test %rax, %rax
    jne setup_file_truncate_failed

    mov bus_stack_page(%rip), %rsp
    add $8, %rsp
    incq bus_site_entries(%rip)
bus_call_fault:
    call bus_target

    cmpq $1, bus_site_entries(%rip)
    jne bad_bus_site_count
    cmpq $2, handler_entries(%rip)
    jne bad_bus_handler_count
    cmpq $1, bus_target_entries(%rip)
    jne bad_bus_target_count
    xor %edi, %edi
    jmp exit_group

.type target,@function
target:
    incq target_entries(%rip)
    ret
.size target, .-target

.type bus_target,@function
bus_target:
    incq bus_target_entries(%rip)
    ret
.size bus_target, .-bus_target

.type handler,@function
handler:
    cmp $11, %edi
    je handle_segv
    cmp $7, %edi
    je handle_bus
    jmp bad_signal

handle_segv:
    cmpl $2, 8(%rsi)                 /* SEGV_ACCERR */
    jne bad_code
    mov 16(%rsi), %rax               /* si_addr */
    cmp guard_page(%rip), %rax
    jne bad_address
    mov 168(%rdx), %rax              /* uc_mcontext.rip */
    lea call_fault(%rip), %rcx
    cmp %rcx, %rax
    jne bad_rip
    mov 160(%rdx), %rax              /* uc_mcontext.rsp */
    mov guard_page(%rip), %rcx
    add $8, %rcx
    cmp %rcx, %rax
    jne bad_rsp
    incq handler_entries(%rip)
    cmpq $1, handler_entries(%rip)
    jne bad_repeat

    mov guard_page(%rip), %rdi
    mov $4096, %esi
    mov $3, %edx                     /* PROT_READ|PROT_WRITE */
    mov $10, %eax                    /* mprotect */
    syscall
    test %rax, %rax
    jne bad_mprotect
    ret

handle_bus:
    cmpl $2, 8(%rsi)                 /* BUS_ADRERR */
    jne bad_code
    mov 16(%rsi), %rax               /* si_addr */
    cmp bus_stack_page(%rip), %rax
    jne bad_address
    mov 168(%rdx), %rax              /* uc_mcontext.rip */
    lea bus_call_fault(%rip), %rcx
    cmp %rcx, %rax
    jne bad_rip
    mov 160(%rdx), %rax              /* uc_mcontext.rsp */
    mov bus_stack_page(%rip), %rcx
    add $8, %rcx
    cmp %rcx, %rax
    jne bad_rsp
    incq handler_entries(%rip)
    cmpq $2, handler_entries(%rip)
    jne bad_repeat

    mov bus_file_fd(%rip), %edi
    mov $8192, %esi
    mov $77, %eax                    /* regrow mapped file backing */
    syscall
    test %rax, %rax
    jne bad_file_repair
    ret
.size handler, .-handler

.type restorer,@function
restorer:
    mov $15, %eax                    /* rt_sigreturn */
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
    mov $93, %edi
    jmp exit_group
setup_tmpfile_failed:
    mov $94, %edi
    jmp exit_group
setup_file_grow_failed:
    mov $95, %edi
    jmp exit_group
setup_file_mmap_failed:
    mov $96, %edi
    jmp exit_group
setup_file_truncate_failed:
    mov $97, %edi
    jmp exit_group
bad_signal:
    mov $100, %edi
    jmp exit_group
bad_code:
    mov $101, %edi
    jmp exit_group
bad_address:
    mov $102, %edi
    jmp exit_group
bad_rip:
    mov $103, %edi
    jmp exit_group
bad_rsp:
    mov $104, %edi
    jmp exit_group
bad_repeat:
    mov $105, %edi
    jmp exit_group
bad_mprotect:
    mov $106, %edi
    jmp exit_group
bad_site_count:
    mov $107, %edi
    jmp exit_group
bad_handler_count:
    mov $108, %edi
    jmp exit_group
bad_target_count:
    mov $109, %edi
    jmp exit_group
bad_file_repair:
    mov $110, %edi
    jmp exit_group
bad_bus_site_count:
    mov $111, %edi
    jmp exit_group
bad_bus_handler_count:
    mov $112, %edi
    jmp exit_group
bad_bus_target_count:
    mov $113, %edi
exit_group:
    mov $231, %eax
    syscall

.section .data
.balign 8
guard_page:
    .quad 0
action:
    .quad 0, 0, 0, 0
altstack_desc:
    .quad 0
    .long 0, 0
    .quad 0
site_entries:
    .quad 0
handler_entries:
    .quad 0
target_entries:
    .quad 0
bus_file_fd:
    .long -1
    .long 0
bus_stack_page:
    .quad 0
bus_site_entries:
    .quad 0
bus_target_entries:
    .quad 0
tmp_directory:
    .asciz "/tmp"

.section .bss
.balign 16
alternate_stack:
    .skip 65536

.section .note.GNU-stack,"",@progbits
