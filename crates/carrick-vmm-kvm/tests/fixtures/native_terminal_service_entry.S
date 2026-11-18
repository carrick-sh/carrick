/* #2532: hold a live sibling at its production mmap service boundary while
 * the leader closes the thread group.  Host writes are deterministic
 * rendezvous points only; clone, mmap and exit_group all run in CPL0.
 */
.global _start
.text
_start:
    mov $0x013d0f00, %edi
    lea thread_stack_top(%rip), %rsi
    lea sibling_tid(%rip), %rdx
    lea sibling_tid(%rip), %r10
    lea tls(%rip), %r8
    mov $56, %eax
    syscall
    test %rax, %rax
    jz sibling
    js failure
    mov %rax, %r12

    movb $1, marker(%rip)
    call write_marker
    mov $7, %edi
    mov $231, %eax
    syscall
    ud2

sibling:
    /* Retain a real host service on the sibling. The deterministic shared
     * harness supplies the newer mmap/IRQ frame after this same owner wakes.
     */
    lea entropy(%rip), %rdi
    mov $8, %esi
    xor %edx, %edx
    mov $318, %eax
    syscall
    /* Closing is authoritative; this member must never return to EL0. */
    mov $92, %edi
    mov $231, %eax
    syscall
    ud2

failure:
    mov $91, %edi
    mov $231, %eax
    syscall
    ud2

write_marker:
    mov $1, %edi
    lea marker(%rip), %rsi
    mov $1, %edx
    mov $1, %eax
    syscall
    ret

.bss
.balign 4096
marker: .space 8
sibling_tid: .space 8
entropy: .space 8
tls: .space 256
.balign 16
thread_stack: .space 16384
thread_stack_top:
