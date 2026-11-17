/* #2420: a root an executor death must end. PARK_FOREVER parks the root in
   a futex wait nothing wakes, so only the death verdict can end the run;
   otherwise the root exits the group with status 7. */
.global _start
.text
_start:
#ifdef PARK_FOREVER
park:
    lea word(%rip), %rdi
    mov $128, %esi
    xor %edx, %edx
    xor %r10d, %r10d
    mov $202, %eax
    syscall
    jmp park
#else
    mov $7, %edi
    mov $231, %eax
    syscall
    hlt
#endif

.data
.balign 8
word: .space 8
