/* Checked FXSAVE/FXRSTOR fault and exact-retry fixture. */
.global _start
.type _start,@function
_start:
    /* Adjacent anonymous pages: first becomes MAPERR, second ACCERR. */
    xor %edi, %edi
    mov $8192, %esi
    mov $3, %edx
    mov $0x22, %r10d
    mov $-1, %r8
    xor %r9d, %r9d
    mov $9, %eax
    syscall
    test %rax, %rax
    js setup_failed
    mov %rax, map_page(%rip)
    add $4096, %rax
    mov %rax, acc_page(%rip)
    mov %rax, %rdi
    mov $4096, %esi
    mov $1, %edx
    mov $10, %eax
    syscall
    test %rax, %rax
    jne setup_failed
    mov map_page(%rip), %rdi
    mov $4096, %esi
    mov $11, %eax
    syscall
    test %rax, %rax
    jne setup_failed

    lea handler(%rip), %rax
    mov %rax, action(%rip)
    movq $0x04000004, action+8(%rip) /* SA_SIGINFO|SA_RESTORER */
    lea restorer(%rip), %rax
    mov %rax, action+16(%rip)
    movq $0, action+24(%rip)
    mov $13, %eax
    mov $11, %edi
    lea action(%rip), %rsi
    xor %edx, %edx
    mov $8, %r10d
    syscall
    test %rax, %rax
    jne setup_failed
    mov $13, %eax
    mov $7, %edi
    lea action(%rip), %rsi
    xor %edx, %edx
    mov $8, %r10d
    syscall
    test %rax, %rax
    jne setup_failed

    /* Writable MAP_SHARED page with backing removed after mapping. */
    mov $-100, %edi
    lea tmp_directory(%rip), %rsi
    mov $0x480002, %edx
    mov $0600, %r10d
    mov $257, %eax
    syscall
    test %rax, %rax
    js setup_failed
    mov %eax, bus_fd(%rip)
    mov %eax, %edi
    mov $8192, %esi
    mov $77, %eax
    syscall
    test %rax, %rax
    jne setup_failed
    xor %edi, %edi
    mov $8192, %esi
    mov $3, %edx
    mov $1, %r10d
    mov bus_fd(%rip), %r8d
    xor %r9d, %r9d
    mov $9, %eax
    syscall
    test %rax, %rax
    js setup_failed
    add $4096, %rax
    mov %rax, bus_page(%rip)
    mov bus_fd(%rip), %edi
    mov $4096, %esi
    mov $77, %eax
    syscall
    test %rax, %rax
    jne setup_failed

    fninit
    fld1
    mov map_page(%rip), %r12
map_fxsave:
    fxsave64 (%r12)
    cmpq $1, handler_entries(%rip)
    jne bad_count
    cmpw $0x037f, (%r12)
    jne bad_payload

    mov acc_page(%rip), %r12
acc_fxsave:
    fxsave64 (%r12)
    cmpq $2, handler_entries(%rip)
    jne bad_count
    cmpw $0x037f, (%r12)
    jne bad_payload

    mov bus_page(%rip), %r12
bus_fxsave:
    fxsave64 (%r12)
    cmpq $3, handler_entries(%rip)
    jne bad_count
    cmpw $0x037f, (%r12)
    jne bad_payload

    /* Invalid MXCSR is #GP before snapshot mutation. Handler repairs memory;
     * rt_sigreturn retries the exact FXRSTOR64 and then continues once. */
    movw $0x027f, restore_image(%rip)
    movl $0x80001f80, restore_image+24(%rip)
    lea restore_image(%rip), %r12
invalid_fxrstor:
    fxrstor64 (%r12)
    cmpq $4, handler_entries(%rip)
    jne bad_count
    fnstcw observed_control(%rip)
    cmpw $0x027f, observed_control(%rip)
    jne bad_restore

    mov $1, %eax
    mov $1, %edi
    lea success(%rip), %rsi
    mov $success_end-success, %edx
    syscall
    xor %edi, %edi
    jmp exit_group

.type handler,@function
handler:
    mov 168(%rdx), %rax             /* uc_mcontext.rip */
    lea map_fxsave(%rip), %rcx
    cmp %rcx, %rax
    je repair_map
    lea acc_fxsave(%rip), %rcx
    cmp %rcx, %rax
    je repair_acc
    lea bus_fxsave(%rip), %rcx
    cmp %rcx, %rax
    je repair_bus
    lea invalid_fxrstor(%rip), %rcx
    cmp %rcx, %rax
    je repair_mxcsr
    movq $99, handler_entries(%rip)
    ret
repair_map:
    cmp $11, %edi
    jne handler_bad
    cmpl $1, 8(%rsi)
    jne handler_bad
    mov map_page(%rip), %rcx
    cmp %rcx, 16(%rsi)
    jne handler_bad
    incq handler_entries(%rip)
    mov %rcx, %rdi
    mov $4096, %esi
    mov $3, %edx
    mov $0x32, %r10d
    mov $-1, %r8
    xor %r9d, %r9d
    mov $9, %eax
    syscall
    cmp map_page(%rip), %rax
    jne handler_bad
    ret
repair_acc:
    cmp $11, %edi
    jne handler_bad
    cmpl $2, 8(%rsi)
    jne handler_bad
    mov acc_page(%rip), %rcx
    cmp %rcx, 16(%rsi)
    jne handler_bad
    incq handler_entries(%rip)
    mov %rcx, %rdi
    mov $4096, %esi
    mov $3, %edx
    mov $10, %eax
    syscall
    test %rax, %rax
    jne handler_bad
    ret
repair_bus:
    cmp $7, %edi
    jne handler_bad
    cmpl $2, 8(%rsi)
    jne handler_bad
    mov bus_page(%rip), %rcx
    cmp %rcx, 16(%rsi)
    jne handler_bad
    incq handler_entries(%rip)
    mov bus_fd(%rip), %edi
    mov $8192, %esi
    mov $77, %eax
    syscall
    test %rax, %rax
    jne handler_bad
    ret
repair_mxcsr:
    cmp $11, %edi
    jne handler_bad
    cmpl $128, 8(%rsi)
    jne handler_bad
    cmpq $0, 16(%rsi)
    jne handler_bad
    incq handler_entries(%rip)
    movl $0x1f80, restore_image+24(%rip)
    ret
handler_bad:
    movq $98, handler_entries(%rip)
    ret
.size handler, .-handler

.type restorer,@function
restorer:
    mov $15, %eax
    syscall
.size restorer, .-restorer

setup_failed: mov $80, %edi; jmp exit_group
bad_count:    mov $81, %edi; jmp exit_group
bad_payload:  mov $82, %edi; jmp exit_group
bad_restore:  mov $83, %edi
exit_group:
    mov $231, %eax
    syscall
    ud2

.section .rodata
tmp_directory: .asciz "/tmp"
success: .ascii "fxstate-retry ok\n"
success_end:
.section .data
.balign 8
map_page: .quad 0
acc_page: .quad 0
bus_page: .quad 0
handler_entries: .quad 0
action: .quad 0,0,0,0
bus_fd: .long -1
observed_control: .word 0
.section .bss
.balign 16
restore_image: .skip 512
.section .note.GNU-stack,"",@progbits
