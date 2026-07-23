/* Checked legacy x87/FXSAVE transfer fixture. Every state-transfer memory
 * opcode is a sensitive exit; scalar x87 observations verify side effects. */
.global _start
.type _start,@function
_start:
    /* Import distinctive virtual selectors through plain FXRSTOR. */
    movw $0x0340, fx_input(%rip)
    movl $0x89abcdef, fx_input+8(%rip)
    movw $0x1357, fx_input+12(%rip)
    movl $0x76543210, fx_input+16(%rip)
    movw $0x2468, fx_input+20(%rip)
    movl $0x1f80, fx_input+24(%rip)
    movb $0, fx_input+4(%rip)
    lea fx_input(%rip), %r12
    fxrstor (%r12)

    /* Plain FXSAVE writes selectors and preserves both reserved halves/tail. */
    lea fx_plain(%rip), %rdi
    mov $0xa5, %al
    mov $512, %ecx
    rep stosb
    lea fx_plain(%rip), %r12
    fxsave (%r12)
    cmpw $0x1357, fx_plain+12(%rip)
    jne bad_plain_selector
    cmpw $0x2468, fx_plain+20(%rip)
    jne bad_plain_selector
    cmpw $0xa5a5, fx_plain+14(%rip)
    jne bad_reserved
    cmpw $0xa5a5, fx_plain+22(%rip)
    jne bad_reserved
    cmpb $0xa5, fx_plain+416(%rip)
    jne bad_reserved

    /* FXSAVE64 stores full pointers and no host selectors. */
    lea fx_rex(%rip), %rdi
    mov $0x5a, %al
    mov $512, %ecx
    rep stosb
    lea fx_rex(%rip), %r12
    fxsave64 (%r12)
    cmpl $0, fx_rex+8(%rip)
    je bad_rex_pointer_zero
    cmpl $0x89abcdef, fx_rex+8(%rip)
    jne bad_rex_pointer
    cmpl $0x76543210, fx_rex+16(%rip)
    jne bad_rex_data_pointer

    /* FNSTENV stores the pre-mask control word, then masks exceptions. */
    fldcw live_control(%rip)
    lea env28(%rip), %r12
    fnstenv (%r12)
    cmpw $0x0340, env28(%rip)
    jne bad_env_control
    fnstcw observed_control(%rip)
    cmpw $0x037f, observed_control(%rip)
    jne bad_mask_side_effect
    cmpw $0xffff, env28+2(%rip)
    jne bad_env_reserved
    cmpw $0x1357, env28+16(%rip)
    jne bad_env_selector
    cmpw $0x2468, env28+24(%rip)
    jne bad_env_selector

    /* Operand-size override selects the packed 14-byte environment. */
    fldcw live_control(%rip)
    lea env14(%rip), %r12
    .byte 0x66
    fnstenv (%r12)
    cmpw $0x0340, env14(%rip)
    jne bad_env_control
    cmpw $0x1357, env14+8(%rip)
    jne bad_env_selector
    cmpw $0x2468, env14+12(%rip)
    jne bad_env_selector

    /* Waiting spelling decodes as WAIT + FNSTENV and has the same successful
     * memory/side-effect result when no exception is pending. */
    fldcw live_control(%rip)
    lea wait_env28(%rip), %r12
    fstenv (%r12)
    cmpw $0x0340, wait_env28(%rip)
    jne bad_wait_form
    fnstcw observed_control(%rip)
    cmpw $0x037f, observed_control(%rip)
    jne bad_wait_form

    /* FLDENV imports pointers/selectors/control atomically. */
    movw $0x027f, restore_env28(%rip)
    movw $0xffff, restore_env28+2(%rip)
    movw $0, restore_env28+4(%rip)
    movw $0xffff, restore_env28+6(%rip)
    movw $0xffff, restore_env28+8(%rip)
    movw $0xffff, restore_env28+10(%rip)
    movl $0x11223344, restore_env28+12(%rip)
    movw $0x3456, restore_env28+16(%rip)
    movw $0x321, restore_env28+18(%rip)
    movl $0x55667788, restore_env28+20(%rip)
    movw $0x4567, restore_env28+24(%rip)
    movw $0xffff, restore_env28+26(%rip)
    lea restore_env28(%rip), %r12
    fldenv (%r12)
    lea restored_fx(%rip), %r12
    fxsave (%r12)
    cmpw $0x027f, restored_fx(%rip)
    jne bad_env_restore
    cmpw $0x3456, restored_fx+12(%rip)
    jne bad_env_restore
    cmpw $0x4567, restored_fx+20(%rip)
    jne bad_env_restore
    cmpl $0x11223344, restored_fx+8(%rip)
    jne bad_env_restore
    cmpl $0x55667788, restored_fx+16(%rip)
    jne bad_env_restore

    /* 108-byte full save is ordered env+8x10 and initializes only x87 after
     * complete success. FRSTOR recovers the saved logical ST0 payload. */
    fninit
    fldt seed_value(%rip)
    lea save108(%rip), %r12
    fnsave (%r12)
    /* FSAVE/FNSAVE's implicit FINIT empties the stack and resets the
     * environment, but the physical 80-bit payload bytes remain observable. */
    lea after_save_fx(%rip), %r12
    fxsave (%r12)
    cmpb $0, after_save_fx+4(%rip)
    jne bad_save_init
    lea seed_value(%rip), %rsi
    lea after_save_fx+32(%rip), %rdi
    mov $10, %ecx
    repe cmpsb
    jne bad_save_payload
    fnstcw observed_control(%rip)
    cmpw $0x037f, observed_control(%rip)
    jne bad_save_init
    fnstsw observed_status(%rip)
    cmpw $0, observed_status(%rip)
    jne bad_save_init
    lea save108(%rip), %r12
    frstor (%r12)
    fstpt observed_value(%rip)
    lea seed_value(%rip), %rsi
    lea observed_value(%rip), %rdi
    mov $10, %ecx
    repe cmpsb
    jne bad_full_payload

    /* 94-byte operand-size full-state form. */
    fninit
    fldt seed_value(%rip)
    lea save94(%rip), %r12
    .byte 0x66
    fnsave (%r12)
    cmpw $0x037f, observed_control(%rip) /* previous init receipt remains */
    jne bad_save_init
    lea save94(%rip), %r12
    .byte 0x66
    frstor (%r12)
    fstpt observed_value(%rip)
    lea seed_value(%rip), %rsi
    lea observed_value(%rip), %rdi
    mov $10, %ecx
    repe cmpsb
    jne bad_full_payload

    mov $1, %eax
    mov $1, %edi
    lea success(%rip), %rsi
    mov $success_end-success, %edx
    syscall
    xor %edi, %edi
    jmp exit_group

bad_plain_selector:  mov $80, %edi; jmp exit_group
bad_reserved:        mov $81, %edi; jmp exit_group
bad_rex_pointer:     mov $82, %edi; jmp exit_group
bad_rex_data_pointer:mov $95, %edi; jmp exit_group
bad_rex_pointer_zero:mov $96, %edi; jmp exit_group
bad_env_control:     mov $83, %edi; jmp exit_group
bad_mask_side_effect:mov $84, %edi; jmp exit_group
bad_env_reserved:    mov $85, %edi; jmp exit_group
bad_env_selector:    mov $86, %edi; jmp exit_group
bad_wait_form:       mov $87, %edi; jmp exit_group
bad_env_restore:     mov $88, %edi; jmp exit_group
bad_save_init:       mov $89, %edi; jmp exit_group
bad_full_payload:    mov $90, %edi; jmp exit_group
bad_save_payload:    mov $93, %edi
exit_group:
    mov $231, %eax
    syscall
    ud2

.section .rodata
live_control: .word 0x0340
seed_value: .quad 0xc000000000000000; .word 0x3fff
success: .ascii "legacy-x87-state ok\n"
success_end:

.section .data
observed_control: .word 0
observed_status: .word 0

.section .bss
.balign 64
fx_input: .skip 512
.balign 64
fx_plain: .skip 512
.balign 64
fx_rex: .skip 512
.balign 64
restored_fx: .skip 512
.balign 64
after_save_fx: .skip 512
.balign 16
env28: .skip 28
env14: .skip 14
wait_env28: .skip 28
restore_env28: .skip 28
save108: .skip 108
save94: .skip 94
observed_value: .skip 16
.section .note.GNU-stack,"",@progbits
