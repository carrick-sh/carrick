/*
 * Retry an indirect-memory CALL and a RET after their target loads fault on an
 * unmapped page.
 *
 * The SIGSEGV handler runs on an alternate stack, verifies each exact fault
 * frame, remaps one target slot, and returns without changing RIP/RSP. Correct
 * native cflow retry exits 0 after one retry of each instruction.
 */
.global _start
.type _start,@function
_start:
    /* table_page = mmap(NULL, 4096, PROT_READ|PROT_WRITE, ...). */
    xor %edi, %edi
    mov $4096, %esi
    mov $3, %edx
    mov $0x22, %r10d
    mov $-1, %r8
    xor %r9d, %r9d
    mov $9, %eax
    syscall
    test %rax, %rax
    js setup_mmap_failed
    mov %rax, table_page(%rip)
    mov %rax, %r12

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

    mov %rsp, original_rsp(%rip)
    mov %r12, %rdi
    mov $4096, %esi
    mov $11, %eax                    /* munmap */
    syscall
    test %rax, %rax
    jne setup_munmap_failed

    incq indirect_site_entries(%rip)
indirect_fault:
    call *(%r12)
after_indirect_call:
    cmpq $1, indirect_site_entries(%rip)
    jne bad_indirect_site_count
    cmpq $1, handler_entries(%rip)
    jne bad_first_handler_count
    cmpq $1, indirect_target_entries(%rip)
    jne bad_indirect_target_count

    /* Reuse the target page as an invalid stack. The next RET must fault
     * before changing RSP, then retry from the exact RET boundary. */
    mov %r12, %rdi
    mov $4096, %esi
    mov $11, %eax                    /* munmap */
    syscall
    test %rax, %rax
    jne setup_second_munmap_failed
    mov %r12, %rsp
    incq ret_site_entries(%rip)
ret_fault:
    ret

.type indirect_target,@function
indirect_target:
    incq indirect_target_entries(%rip)
    ret
.size indirect_target, .-indirect_target

.type ret_target,@function
ret_target:
    incq ret_target_entries(%rip)
    cmpq $1, indirect_site_entries(%rip)
    jne bad_indirect_site_count
    cmpq $1, ret_site_entries(%rip)
    jne bad_ret_site_count
    cmpq $2, handler_entries(%rip)
    jne bad_second_handler_count
    cmpq $1, indirect_target_entries(%rip)
    jne bad_indirect_target_count
    cmpq $1, ret_target_entries(%rip)
    jne bad_ret_target_count
    xor %edi, %edi
    jmp exit_group
.size ret_target, .-ret_target

.type handler,@function
handler:
    cmp $11, %edi
    jne bad_signal
    cmpl $1, 8(%rsi)                 /* SEGV_MAPERR */
    jne bad_code
    mov 16(%rsi), %rax               /* si_addr */
    cmp table_page(%rip), %rax
    jne bad_address

    mov 168(%rdx), %rax              /* uc_mcontext.rip */
    lea indirect_fault(%rip), %rcx
    cmp %rcx, %rax
    je handle_indirect_fault
    lea ret_fault(%rip), %rcx
    cmp %rcx, %rax
    je handle_ret_fault
    jmp bad_rip

handle_indirect_fault:
    mov 160(%rdx), %rax              /* failed target read cannot push */
    cmp original_rsp(%rip), %rax
    jne bad_rsp
    incq handler_entries(%rip)
    cmpq $1, handler_entries(%rip)
    jne bad_repeat
    lea indirect_target(%rip), %r13
    jmp repair_target_page

handle_ret_fault:
    mov 160(%rdx), %rax              /* failed RET cannot pop */
    cmp table_page(%rip), %rax
    jne bad_rsp
    incq handler_entries(%rip)
    cmpq $2, handler_entries(%rip)
    jne bad_repeat
    lea ret_target(%rip), %r13

repair_target_page:
    mov table_page(%rip), %rdi
    mov $4096, %esi
    mov $3, %edx
    mov $0x32, %r10d                 /* MAP_FIXED|MAP_PRIVATE|MAP_ANON */
    mov $-1, %r8
    xor %r9d, %r9d
    mov $9, %eax                     /* mmap */
    syscall
    cmp table_page(%rip), %rax
    jne bad_fixed_mmap

    mov %r13, (%rax)                 /* write target; never read it here */
    mov %rax, %rdi
    mov $4096, %esi
    mov $1, %edx                     /* PROT_READ */
    mov $10, %eax                    /* mprotect */
    syscall
    test %rax, %rax
    jne bad_mprotect
    ret
.size handler, .-handler

.type restorer,@function
restorer:
    mov $15, %eax                    /* rt_sigreturn */
    syscall
.size restorer, .-restorer

setup_mmap_failed:
    mov $110, %edi
    jmp exit_group
setup_altstack_failed:
    mov $111, %edi
    jmp exit_group
setup_sigaction_failed:
    mov $112, %edi
    jmp exit_group
setup_munmap_failed:
    mov $113, %edi
    jmp exit_group
setup_second_munmap_failed:
    mov $114, %edi
    jmp exit_group
bad_signal:
    mov $120, %edi
    jmp exit_group
bad_code:
    mov $121, %edi
    jmp exit_group
bad_address:
    mov $122, %edi
    jmp exit_group
bad_rip:
    mov $123, %edi
    jmp exit_group
bad_rsp:
    mov $124, %edi
    jmp exit_group
bad_repeat:
    mov $125, %edi
    jmp exit_group
bad_fixed_mmap:
    mov $126, %edi
    jmp exit_group
bad_mprotect:
    mov $127, %edi
    jmp exit_group
bad_indirect_site_count:
    mov $128, %edi
    jmp exit_group
bad_first_handler_count:
    mov $129, %edi
    jmp exit_group
bad_indirect_target_count:
    mov $130, %edi
    jmp exit_group
bad_ret_site_count:
    mov $131, %edi
    jmp exit_group
bad_second_handler_count:
    mov $132, %edi
    jmp exit_group
bad_ret_target_count:
    mov $133, %edi
exit_group:
    mov $231, %eax
    syscall

.section .data
.balign 8
table_page:
    .quad 0
original_rsp:
    .quad 0
action:
    .quad 0, 0, 0, 0
altstack_desc:
    .quad 0
    .long 0, 0
    .quad 0
indirect_site_entries:
    .quad 0
ret_site_entries:
    .quad 0
handler_entries:
    .quad 0
indirect_target_entries:
    .quad 0
ret_target_entries:
    .quad 0

.section .bss
.balign 16
alternate_stack:
    .skip 65536

.section .note.GNU-stack,"",@progbits
