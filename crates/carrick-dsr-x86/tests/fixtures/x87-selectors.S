/*
 * Exact virtual non-REX x87 FCS/FDS integration fixture.
 *
 * Plain XRSTOR imports 16-bit selectors while ignoring reserved halves. Plain
 * XSAVE writes the selectors without changing those halves. XRSTOR64 replaces
 * full 64-bit pointers but preserves selector state. Requested-absent x87
 * restores Carrick's initial Linux selectors, and a signal round trip preserves
 * custom selectors through the versioned xstate trailer.
 */
.global _start
.type _start,@function
_start:
    /* Import custom selectors through non-REX XRSTOR. */
    movw $0x037f, input_image(%rip)
    movl $0x89abcdef, input_image+8(%rip)
    movw $0x1357, input_image+12(%rip)
    movw $0xdead, input_image+14(%rip)   /* ignored reserved half */
    movl $0x76543210, input_image+16(%rip)
    movw $0x2468, input_image+20(%rip)
    movw $0xbeef, input_image+22(%rip)   /* ignored reserved half */
    movq $1, input_image+512(%rip)
    movq $0, input_image+520(%rip)
    cmpq $1, input_image+512(%rip)
    jne bad_source_setup
    cmpw $0x1357, input_image+12(%rip)
    jne bad_source_setup
    lea input_image(%rip), %rbx
    mov $1, %eax
    xor %edx, %edx
    xrstor (%rbx)

    call save_and_check_custom

    /* REX.W XRSTOR imports complete pointers but must not touch selectors. */
    movabs $0x1122334455667788, %rax
    mov %rax, input64_image+8(%rip)
    movabs $0x8877665544332211, %rax
    mov %rax, input64_image+16(%rip)
    movw $0x037f, input64_image(%rip)
    movq $1, input64_image+512(%rip)
    movq $0, input64_image+520(%rip)
    lea input64_image(%rip), %rbx
    mov $1, %eax
    xor %edx, %edx
    xrstor64 (%rbx)

    call prepare_output
    lea output_image(%rip), %rbx
    mov $1, %eax
    xor %edx, %edx
    xsave (%rbx)
    cmpw $0x1357, output_image+12(%rip)
    jne bad_selector
    cmpw $0x2468, output_image+20(%rip)
    jne bad_selector
    cmpl $0x55667788, output_image+8(%rip)
    jne bad_pointer
    cmpl $0x44332211, output_image+16(%rip)
    jne bad_pointer
    call check_reserved

    /* Requested-absent x87 returns the virtual selectors to guest ABI init. */
    movq $0, absent_image+512(%rip)
    movq $0, absent_image+520(%rip)
    lea absent_image(%rip), %rbx
    mov $1, %eax
    xor %edx, %edx
    xrstor (%rbx)
    call prepare_output
    lea output_image(%rip), %rbx
    mov $1, %eax
    xor %edx, %edx
    xsave (%rbx)
    cmpw $0x23, output_image+12(%rip)
    jne bad_initial_selector
    cmpw $0x1b, output_image+20(%rip)
    jne bad_initial_selector
    call check_reserved

    /* Restore custom selectors and virtual PKRU, then prove a Linux-compatible
     * handler can relocate exactly extended_size without losing either. */
    lea input_image(%rip), %rbx
    mov $1, %eax
    xor %edx, %edx
    xrstor (%rbx)
    xor %ecx, %ecx
    xor %edx, %edx
    mov $3, %eax
    wrpkru
    lea handler(%rip), %rax
    mov %rax, action(%rip)
    movq $0x04000004, action+8(%rip)    /* SA_SIGINFO|SA_RESTORER */
    lea restorer(%rip), %rax
    mov %rax, action+16(%rip)
    movq $0, action+24(%rip)
    mov $13, %eax                       /* rt_sigaction(SIGUSR1) */
    mov $10, %edi
    lea action(%rip), %rsi
    xor %edx, %edx
    mov $8, %r10d
    syscall
    test %rax, %rax
    jne setup_signal_failed
    mov $39, %eax                       /* getpid */
    syscall
    mov %eax, %edi
    mov $186, %eax                      /* gettid */
    syscall
    mov %eax, %esi
    mov $10, %edx
    mov $234, %eax                      /* tgkill */
    syscall
    test %rax, %rax
    jne setup_signal_failed
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
    cmpq $1, handler_entries(%rip)
    jne bad_handler_count
    call save_and_check_custom

    mov $1, %eax
    mov $1, %edi
    lea success(%rip), %rsi
    mov $success_end-success, %edx
    syscall
    cmp $success_end-success, %rax
    jne bad_write
    xor %edi, %edi
    jmp exit_group
.size _start, .-_start

.type prepare_output,@function
prepare_output:
    movq $0, output_image+512(%rip)
    movq $0, output_image+520(%rip)
    movw $0xa55a, output_image+14(%rip)
    movw $0x5aa5, output_image+22(%rip)
    ret
.size prepare_output, .-prepare_output

.type check_reserved,@function
check_reserved:
    cmpw $0xa55a, output_image+14(%rip)
    jne bad_reserved
    cmpw $0x5aa5, output_image+22(%rip)
    jne bad_reserved
    ret
.size check_reserved, .-check_reserved

.type save_and_check_custom,@function
save_and_check_custom:
    call prepare_output
    lea output_image(%rip), %rbx
    mov $1, %eax
    xor %edx, %edx
    xsave (%rbx)
    cmpw $0x1357, output_image+12(%rip)
    jne bad_selector
    cmpw $0x2468, output_image+20(%rip)
    jne bad_selector
    cmpl $0x89abcdef, output_image+8(%rip)
    jne bad_pointer
    cmpl $0x76543210, output_image+16(%rip)
    jne bad_pointer
    call check_reserved
    ret
.size save_and_check_custom, .-save_and_check_custom

.type handler,@function
handler:
    cmp $10, %edi
    jne handler_bad
    mov 224(%rdx), %rsi             /* uc_mcontext.fpstate */
    mov 468(%rsi), %ecx             /* Linux fpx_sw_bytes.extended_size */
    cmp $32768, %ecx
    ja handler_bad
    lea relocated_fpstate(%rip), %rdi
    mov %rdi, 224(%rdx)
    cld
    rep movsb                       /* copy exactly the advertised extent */
    incq handler_entries(%rip)
    ret
handler_bad:
    movq $99, handler_entries(%rip)
    ret
.size handler, .-handler

.type restorer,@function
restorer:
    mov $15, %eax
    syscall
.size restorer, .-restorer

setup_signal_failed:  mov $80, %edi; jmp exit_group
bad_source_setup:     mov $81, %edi; jmp exit_group
bad_selector:
    mov $1, %eax
    mov $2, %edi
    lea output_image+8(%rip), %rsi
    mov $16, %edx
    syscall
    mov $90, %edi
    jmp exit_group
bad_initial_selector: mov $91, %edi; jmp exit_group
bad_pointer:          mov $92, %edi; jmp exit_group
bad_reserved:         mov $93, %edi; jmp exit_group
bad_handler_count:    mov $94, %edi; jmp exit_group
bad_pkru:             mov $95, %edi; jmp exit_group
bad_write:            mov $96, %edi
exit_group:
    mov $231, %eax
    syscall
    ud2

.section .rodata
success:
    .ascii "x87-selectors ok\n"
success_end:

.section .bss
.align 64
input_image:      .skip 1024
.align 64
input64_image:    .skip 1024
.align 64
absent_image:     .skip 1024
.align 64
output_image:     .skip 1024
.align 64
relocated_fpstate: .skip 32768
.align 8
action:           .skip 32
handler_entries:  .quad 0
