// MIT OR Apache-2.0. Bounded native gateway. Host SP and x18 stay host-owned.
// State offsets are compile-time asserted in native.rs. Guest x28 is virtual.
.text
.p2align 2
.globl _slice_enter
_slice_enter:
sub sp, sp, #256
stp x19, x20, [sp, #0]
stp x21, x22, [sp, #16]
stp x23, x24, [sp, #32]
stp x25, x26, [sp, #48]
stp x27, x28, [sp, #64]
stp x29, x30, [sp, #80]
stp q8, q9, [sp, #96]
stp q10, q11, [sp, #128]
stp q12, q13, [sp, #160]
stp q14, q15, [sp, #192]
mrs x9, fpsr
str x9, [sp, #224]
mrs x9, fpcr
str x9, [sp, #232]
mrs x9, nzcv
str x9, [sp, #240]
mov x28, x0
str x1, [x28, #840]
b Lslice_restore
.globl _slice_gateway
_slice_gateway:
str x0, [x28, #0]
str x1, [x28, #8]
str x2, [x28, #16]
str x3, [x28, #24]
str x4, [x28, #32]
str x5, [x28, #40]
str x6, [x28, #48]
str x7, [x28, #56]
str x8, [x28, #64]
str x9, [x28, #72]
str x10, [x28, #80]
str x11, [x28, #88]
str x12, [x28, #96]
str x13, [x28, #104]
str x14, [x28, #112]
str x15, [x28, #120]
str x16, [x28, #128]
str x19, [x28, #152]
str x20, [x28, #160]
str x21, [x28, #168]
str x22, [x28, #176]
str x23, [x28, #184]
str x24, [x28, #192]
str x25, [x28, #200]
str x26, [x28, #208]
str x27, [x28, #216]
str x29, [x28, #232]
str x30, [x28, #240]
mrs x9, nzcv
str x9, [x28, #256]
mrs x9, fpsr
str x9, [x28, #264]
mrs x9, fpcr
str x9, [x28, #272]
stp q0, q1, [x28, #304]
stp q2, q3, [x28, #336]
stp q4, q5, [x28, #368]
stp q6, q7, [x28, #400]
stp q8, q9, [x28, #432]
stp q10, q11, [x28, #464]
stp q12, q13, [x28, #496]
stp q14, q15, [x28, #528]
stp q16, q17, [x28, #560]
stp q18, q19, [x28, #592]
stp q20, q21, [x28, #624]
stp q22, q23, [x28, #656]
stp q24, q25, [x28, #688]
stp q26, q27, [x28, #720]
stp q28, q29, [x28, #752]
stp q30, q31, [x28, #784]
mov x0, x28
ldr x1, [x28, #816]
ldr x16, [x28, #824]
blr x16
str x0, [x28, #840]
cbz x0, Lslice_exit
Lslice_restore:
ldp q0, q1, [x28, #304]
ldp q2, q3, [x28, #336]
ldp q4, q5, [x28, #368]
ldp q6, q7, [x28, #400]
ldp q8, q9, [x28, #432]
ldp q10, q11, [x28, #464]
ldp q12, q13, [x28, #496]
ldp q14, q15, [x28, #528]
ldp q16, q17, [x28, #560]
ldp q18, q19, [x28, #592]
ldp q20, q21, [x28, #624]
ldp q22, q23, [x28, #656]
ldp q24, q25, [x28, #688]
ldp q26, q27, [x28, #720]
ldp q28, q29, [x28, #752]
ldp q30, q31, [x28, #784]
ldr x9, [x28, #256]
msr nzcv, x9
ldr x9, [x28, #264]
msr fpsr, x9
ldr x9, [x28, #272]
msr fpcr, x9
ldr x0, [x28, #0]
ldr x1, [x28, #8]
ldr x2, [x28, #16]
ldr x3, [x28, #24]
ldr x4, [x28, #32]
ldr x5, [x28, #40]
ldr x6, [x28, #48]
ldr x7, [x28, #56]
ldr x8, [x28, #64]
ldr x9, [x28, #72]
ldr x10, [x28, #80]
ldr x11, [x28, #88]
ldr x12, [x28, #96]
ldr x13, [x28, #104]
ldr x14, [x28, #112]
ldr x15, [x28, #120]
ldr x16, [x28, #128]
ldr x19, [x28, #152]
ldr x20, [x28, #160]
ldr x21, [x28, #168]
ldr x22, [x28, #176]
ldr x23, [x28, #184]
ldr x24, [x28, #192]
ldr x25, [x28, #200]
ldr x26, [x28, #208]
ldr x27, [x28, #216]
ldr x29, [x28, #232]
ldr x30, [x28, #240]
ldr x17, [x28, #840]
br x17
Lslice_exit:
ldp q8, q9, [sp, #96]
ldp q10, q11, [sp, #128]
ldp q12, q13, [sp, #160]
ldp q14, q15, [sp, #192]
ldr x9, [sp, #224]
msr fpsr, x9
ldr x9, [sp, #232]
msr fpcr, x9
ldr x9, [sp, #240]
msr nzcv, x9
ldp x19, x20, [sp, #0]
ldp x21, x22, [sp, #16]
ldp x23, x24, [sp, #32]
ldp x25, x26, [sp, #48]
ldp x27, x28, [sp, #64]
ldp x29, x30, [sp, #80]
add sp, sp, #256
ret
