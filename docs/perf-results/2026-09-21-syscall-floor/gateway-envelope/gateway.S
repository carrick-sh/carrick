// Experimental native ABI envelope. x18 is preserved and never repurposed.
// Frame: x0..x30 at 0..240, NZCV/FPSR/FPCR at 248/256/264, q0..q31 at 288..799.
.text
.p2align 2
.globl _floor_gateway
_floor_gateway:
sub sp, sp, #800
stp x0, x1, [sp, #0]
stp x2, x3, [sp, #16]
stp x4, x5, [sp, #32]
stp x6, x7, [sp, #48]
stp x8, x9, [sp, #64]
stp x10, x11, [sp, #80]
stp x12, x13, [sp, #96]
stp x14, x15, [sp, #112]
stp x16, x17, [sp, #128]
stp x18, x19, [sp, #144]
stp x20, x21, [sp, #160]
stp x22, x23, [sp, #176]
stp x24, x25, [sp, #192]
stp x26, x27, [sp, #208]
stp x28, x29, [sp, #224]
str x30, [sp, #240]
mrs x9, nzcv
str x9, [sp, #248]
mrs x9, fpsr
str x9, [sp, #256]
mrs x9, fpcr
str x9, [sp, #264]
stp q0, q1, [sp, #288]
stp q2, q3, [sp, #320]
stp q4, q5, [sp, #352]
stp q6, q7, [sp, #384]
stp q8, q9, [sp, #416]
stp q10, q11, [sp, #448]
stp q12, q13, [sp, #480]
stp q14, q15, [sp, #512]
stp q16, q17, [sp, #544]
stp q18, q19, [sp, #576]
stp q20, q21, [sp, #608]
stp q22, q23, [sp, #640]
stp q24, q25, [sp, #672]
stp q26, q27, [sp, #704]
stp q28, q29, [sp, #736]
stp q30, q31, [sp, #768]
mov x19, sp
mov sp, x2
blr x1
mov sp, x19
str x0, [sp]
ldp q0, q1, [sp, #288]
ldp q2, q3, [sp, #320]
ldp q4, q5, [sp, #352]
ldp q6, q7, [sp, #384]
ldp q8, q9, [sp, #416]
ldp q10, q11, [sp, #448]
ldp q12, q13, [sp, #480]
ldp q14, q15, [sp, #512]
ldp q16, q17, [sp, #544]
ldp q18, q19, [sp, #576]
ldp q20, q21, [sp, #608]
ldp q22, q23, [sp, #640]
ldp q24, q25, [sp, #672]
ldp q26, q27, [sp, #704]
ldp q28, q29, [sp, #736]
ldp q30, q31, [sp, #768]
ldr x9, [sp, #248]
msr nzcv, x9
ldr x9, [sp, #256]
msr fpsr, x9
ldr x9, [sp, #264]
msr fpcr, x9
ldp x0, x1, [sp, #0]
ldp x2, x3, [sp, #16]
ldp x4, x5, [sp, #32]
ldp x6, x7, [sp, #48]
ldp x8, x9, [sp, #64]
ldp x10, x11, [sp, #80]
ldp x12, x13, [sp, #96]
ldp x14, x15, [sp, #112]
ldp x16, x17, [sp, #128]
ldp x18, x19, [sp, #144]
ldp x20, x21, [sp, #160]
ldp x22, x23, [sp, #176]
ldp x24, x25, [sp, #192]
ldp x26, x27, [sp, #208]
ldp x28, x29, [sp, #224]
ldr x30, [sp, #240]
add sp, sp, #800
ret
.globl _floor_gateway_oracle
_floor_gateway_oracle:
sub sp, sp, #800
stp x0, x1, [sp, #0]
stp x2, x3, [sp, #16]
stp x4, x5, [sp, #32]
stp x6, x7, [sp, #48]
stp x8, x9, [sp, #64]
stp x10, x11, [sp, #80]
stp x12, x13, [sp, #96]
stp x14, x15, [sp, #112]
stp x16, x17, [sp, #128]
stp x18, x19, [sp, #144]
stp x20, x21, [sp, #160]
stp x22, x23, [sp, #176]
stp x24, x25, [sp, #192]
stp x26, x27, [sp, #208]
stp x28, x29, [sp, #224]
str x30, [sp, #240]
mrs x9, nzcv
str x9, [sp, #248]
mrs x9, fpsr
str x9, [sp, #256]
mrs x9, fpcr
str x9, [sp, #264]
stp q0, q1, [sp, #288]
stp q2, q3, [sp, #320]
stp q4, q5, [sp, #352]
stp q6, q7, [sp, #384]
stp q8, q9, [sp, #416]
stp q10, q11, [sp, #448]
stp q12, q13, [sp, #480]
stp q14, q15, [sp, #512]
stp q16, q17, [sp, #544]
stp q18, q19, [sp, #576]
stp q20, q21, [sp, #608]
stp q22, q23, [sp, #640]
stp q24, q25, [sp, #672]
stp q26, q27, [sp, #704]
stp q28, q29, [sp, #736]
stp q30, q31, [sp, #768]
mov x4, #260
mov x5, #261
mov x6, #262
mov x7, #263
mov x8, #264
mov x9, #265
mov x10, #266
mov x11, #267
mov x12, #268
mov x13, #269
mov x14, #270
mov x15, #271
mov x16, #272
mov x17, #273
mov x19, #275
mov x20, #276
mov x21, #277
mov x22, #278
mov x23, #279
mov x24, #280
mov x25, #281
mov x26, #282
mov x27, #283
mov x28, #284
movi v0.16b, #1
movi v1.16b, #2
movi v2.16b, #3
movi v3.16b, #4
movi v4.16b, #5
movi v5.16b, #6
movi v6.16b, #7
movi v7.16b, #8
movi v8.16b, #9
movi v9.16b, #10
movi v10.16b, #11
movi v11.16b, #12
movi v12.16b, #13
movi v13.16b, #14
movi v14.16b, #15
movi v15.16b, #16
movi v16.16b, #17
movi v17.16b, #18
movi v18.16b, #19
movi v19.16b, #20
movi v20.16b, #21
movi v21.16b, #22
movi v22.16b, #23
movi v23.16b, #24
movi v24.16b, #25
movi v25.16b, #26
movi v26.16b, #27
movi v27.16b, #28
movi v28.16b, #29
movi v29.16b, #30
movi v30.16b, #31
movi v31.16b, #32
mov x16, #0xa0000000
msr nzcv, x16
mov x16, #0
msr fpsr, x16
msr fpcr, x16
mov x16, #272
stp x0, x1, [x3, #0]
stp x2, x3, [x3, #16]
stp x4, x5, [x3, #32]
stp x6, x7, [x3, #48]
stp x8, x9, [x3, #64]
stp x10, x11, [x3, #80]
stp x12, x13, [x3, #96]
stp x14, x15, [x3, #112]
stp x16, x17, [x3, #128]
stp x18, x19, [x3, #144]
stp x20, x21, [x3, #160]
stp x22, x23, [x3, #176]
stp x24, x25, [x3, #192]
stp x26, x27, [x3, #208]
stp x28, x29, [x3, #224]
str x30, [x3, #240]
add x16, x3, #288
stp q0, q1, [x16, #0]
stp q2, q3, [x16, #32]
stp q4, q5, [x16, #64]
stp q6, q7, [x16, #96]
stp q8, q9, [x16, #128]
stp q10, q11, [x16, #160]
stp q12, q13, [x16, #192]
stp q14, q15, [x16, #224]
stp q16, q17, [x16, #256]
stp q18, q19, [x16, #288]
stp q20, q21, [x16, #320]
stp q22, q23, [x16, #352]
stp q24, q25, [x16, #384]
stp q26, q27, [x16, #416]
stp q28, q29, [x16, #448]
stp q30, q31, [x16, #480]
mrs x16, nzcv
str x16, [x3, #248]
mrs x16, fpsr
str x16, [x3, #256]
mrs x16, fpcr
str x16, [x3, #264]
mov x16, sp
str x16, [x3, #272]
mov x16, #272
bl _floor_gateway
add x3, x3, #800
stp x0, x1, [x3, #0]
stp x2, x3, [x3, #16]
stp x4, x5, [x3, #32]
stp x6, x7, [x3, #48]
stp x8, x9, [x3, #64]
stp x10, x11, [x3, #80]
stp x12, x13, [x3, #96]
stp x14, x15, [x3, #112]
stp x16, x17, [x3, #128]
stp x18, x19, [x3, #144]
stp x20, x21, [x3, #160]
stp x22, x23, [x3, #176]
stp x24, x25, [x3, #192]
stp x26, x27, [x3, #208]
stp x28, x29, [x3, #224]
str x30, [x3, #240]
add x16, x3, #288
stp q0, q1, [x16, #0]
stp q2, q3, [x16, #32]
stp q4, q5, [x16, #64]
stp q6, q7, [x16, #96]
stp q8, q9, [x16, #128]
stp q10, q11, [x16, #160]
stp q12, q13, [x16, #192]
stp q14, q15, [x16, #224]
stp q16, q17, [x16, #256]
stp q18, q19, [x16, #288]
stp q20, q21, [x16, #320]
stp q22, q23, [x16, #352]
stp q24, q25, [x16, #384]
stp q26, q27, [x16, #416]
stp q28, q29, [x16, #448]
stp q30, q31, [x16, #480]
mrs x16, nzcv
str x16, [x3, #248]
mrs x16, fpsr
str x16, [x3, #256]
mrs x16, fpcr
str x16, [x3, #264]
mov x16, sp
str x16, [x3, #272]
mov x16, #272
ldp q0, q1, [sp, #288]
ldp q2, q3, [sp, #320]
ldp q4, q5, [sp, #352]
ldp q6, q7, [sp, #384]
ldp q8, q9, [sp, #416]
ldp q10, q11, [sp, #448]
ldp q12, q13, [sp, #480]
ldp q14, q15, [sp, #512]
ldp q16, q17, [sp, #544]
ldp q18, q19, [sp, #576]
ldp q20, q21, [sp, #608]
ldp q22, q23, [sp, #640]
ldp q24, q25, [sp, #672]
ldp q26, q27, [sp, #704]
ldp q28, q29, [sp, #736]
ldp q30, q31, [sp, #768]
ldr x9, [sp, #248]
msr nzcv, x9
ldr x9, [sp, #256]
msr fpsr, x9
ldr x9, [sp, #264]
msr fpcr, x9
ldp x0, x1, [sp, #0]
ldp x2, x3, [sp, #16]
ldp x4, x5, [sp, #32]
ldp x6, x7, [sp, #48]
ldp x8, x9, [sp, #64]
ldp x10, x11, [sp, #80]
ldp x12, x13, [sp, #96]
ldp x14, x15, [sp, #112]
ldp x16, x17, [sp, #128]
ldp x18, x19, [sp, #144]
ldp x20, x21, [sp, #160]
ldp x22, x23, [sp, #176]
ldp x24, x25, [sp, #192]
ldp x26, x27, [sp, #208]
ldp x28, x29, [sp, #224]
ldr x30, [sp, #240]
add sp, sp, #800
ret
.globl _floor_clobber
_floor_clobber:
mov x4, #0
mov x5, #0
mov x6, #0
mov x7, #0
mov x8, #0
mov x9, #0
mov x10, #0
mov x11, #0
mov x12, #0
mov x13, #0
mov x14, #0
mov x15, #0
mov x16, #0
mov x17, #0
movi v0.16b, #0
movi v1.16b, #0
movi v2.16b, #0
movi v3.16b, #0
movi v4.16b, #0
movi v5.16b, #0
movi v6.16b, #0
movi v7.16b, #0
movi v16.16b, #0
movi v17.16b, #0
movi v18.16b, #0
movi v19.16b, #0
movi v20.16b, #0
movi v21.16b, #0
movi v22.16b, #0
movi v23.16b, #0
movi v24.16b, #0
movi v25.16b, #0
movi v26.16b, #0
movi v27.16b, #0
movi v28.16b, #0
movi v29.16b, #0
movi v30.16b, #0
movi v31.16b, #0
mov x9, #0
ins v8.d[1], x9
ins v9.d[1], x9
ins v10.d[1], x9
ins v11.d[1], x9
ins v12.d[1], x9
ins v13.d[1], x9
ins v14.d[1], x9
ins v15.d[1], x9
msr nzcv, x9
mov x9, #1
msr fpsr, x9
mov x9, #0x400000
msr fpcr, x9
mov x0, #77
ret
