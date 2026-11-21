/* #2142: a root exec successor's descriptors. fd 30 was close-on-exec and
 * must be gone (F_GETFD is EBADF); fd 31 survives without FD_CLOEXEC. Then
 * stdout, which also survived, carries the marker. Exit 3: fd 30 survived;
 * exit 4: fd 31 is gone or close-on-exec; exit 91: the marker write failed.
 */
#define F_GETFD 1
#define EBADF 9
.global _start
.text
_start:
    mov $30, %edi
    mov $F_GETFD, %esi
    mov $72, %eax           /* fcntl */
    syscall
    cmp $-EBADF, %rax
    je closed
    mov $3, %edi
    jmp exit
closed:
    mov $31, %edi
    mov $F_GETFD, %esi
    mov $72, %eax
    syscall
    test %rax, %rax
    je kept
    mov $4, %edi
    jmp exit
kept:
    mov $1, %eax
    mov $1, %edi
    lea marker(%rip), %rsi
    mov $marker_end-marker, %edx
    syscall
    cmp $marker_end-marker, %rax
    jne failure
    xor %edi, %edi
    jmp exit
failure:
    mov $91, %edi
exit:
    mov $231, %eax
    syscall
    ud2
.section .rodata
marker: .ascii "root-exec-fds-ok\n"
marker_end:
