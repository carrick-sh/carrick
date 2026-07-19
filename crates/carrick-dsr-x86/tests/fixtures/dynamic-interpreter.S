.global _start
.type _start,@function
_start:
  mov (%rsp), %rcx
  lea 16(%rsp,%rcx,8), %rbx
1:
  cmpq $0, (%rbx)
  je 2f
  add $8, %rbx
  jmp 1b
2:
  add $8, %rbx
  xor %r12d, %r12d
3:
  mov (%rbx), %rax
  mov 8(%rbx), %rdx
  test %rax, %rax
  jz 8f
  test %rdx, %rdx
  jz 7f
  cmp $3, %rax
  jne 4f
  or $1, %r12d
4:
  cmp $5, %rax
  jne 5f
  or $2, %r12d
5:
  cmp $7, %rax
  jne 6f
  or $4, %r12d
6:
  cmp $9, %rax
  jne 7f
  or $8, %r12d
7:
  add $16, %rbx
  jmp 3b
8:
  cmp $15, %r12d
  jne 9f
  mov $1, %eax
  mov $1, %edi
  lea message(%rip), %rsi
  mov $15, %edx
  syscall
  mov $60, %eax
  mov $23, %edi
  syscall
9:
  mov $60, %eax
  mov $99, %edi
  syscall
message:
  .ascii "dynamic-elf ok\n"
