/*
 * Gateway-safety regression for virtual Linux PKRU. Value 3 disables read and
 * write access for protection key 0. Executing it physically in Carrick would
 * make the user-mode gateway fault while saving its context; the native lane
 * must sensitive-emulate WRPKRU/RDPKRU instead.
 */
.global _start
.type _start,@function
_start:
    xor %ecx, %ecx
    xor %edx, %edx
    mov $3, %eax
    wrpkru

    rdpkru
    cmp $3, %eax
    jne .Lfail
    test %edx, %edx
    jne .Lfail

    xor %eax, %eax
    xor %edx, %edx
    wrpkru
    mov $37, %edi
    mov $231, %eax                 /* exit_group */
    syscall

.Lfail:
    mov $1, %edi
    mov $231, %eax
    syscall
.size _start, .-_start

.section .note.GNU-stack,"",@progbits
