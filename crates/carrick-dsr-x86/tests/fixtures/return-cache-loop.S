/*
 * Monomorphic return-cache regression. Every iteration crosses one direct
 * call gateway; after warm-up the leaf `ret` must hit its gateway-owned cache
 * and resume the caller without a second Rust round trip.
 */
.global _start
.type _start,@function
_start:
    mov $10000, %r12d
.Lcall:
    call .Lleaf
    decl %r12d
    jne .Lcall

    mov $231, %eax                 /* exit_group */
    mov $37, %edi
    syscall

.Lleaf:
    ret
.size _start, .-_start

.section .note.GNU-stack,"",@progbits
