#!/usr/bin/env python3
"""Debug: verify STACK_RIP_DELTA with process actually in the editor."""
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

# Enter the editor via option 2
r.recvuntil(b'> ')
r.sendline(b'2')
r.recvuntil(b':\n')
r.sendline(b'10')
r.recvuntil(b':\n')
r.sendline(b'AAAAAAAAAA')
r.recvuntil(b'?')
r.sendline(b'y')
r.recvuntil(b'> ')  # now in editor

pid = r.pid
maps = open(f'/proc/{pid}/maps').read()
libc_base = binary_base = None
for l in maps.split('\n'):
    p = l.strip().split()
    if len(p) < 5: continue
    if 'funkynator' in p[-1] and p[1] == 'r--p' and p[2] == '00000000':
        binary_base = int(p[0].split('-')[0], 16)
    if 'libc.so.6' in p[-1] and p[1] == 'r--p' and p[2] == '00000000':
        libc_base = int(p[0].split('-')[0], 16)

ENVIRON = 0x1eee28
TARGET_RET = binary_base + 0x1a72

with open(f'/proc/{pid}/mem', 'rb') as f:
    f.seek(libc_base + ENVIRON)
    env_val = struct.unpack('<Q', f.read(8))[0]

log.info(f"binary_base @ {hex(binary_base)}")
log.info(f"libc_base   @ {hex(libc_base)}")
log.info(f"environ val = {hex(env_val)}")

search_start = env_val & ~0xfff
found_addr = None
for off in range(0, 0x400000, 0x1000):
    addr = search_start - off
    try:
        with open(f'/proc/{pid}/mem', 'rb') as f:
            f.seek(addr)
            data = f.read(4096)
        for i in range(0, 4096 - 7, 8):
            val = struct.unpack('<Q', data[i:i+8])[0]
            if val == TARGET_RET:
                found_addr = addr + i
                log.info(f"Found TARGET_RET at {hex(found_addr)}")
                break
        if found_addr:
            break
    except:
        break

if found_addr:
    delta = env_val - found_addr
    log.info(f"environ - saved_rip = {hex(delta)} ({delta})")
    log.info(f"STACK_RIP_DELTA should be {hex(delta)}")
else:
    log.warning("saved_rip not found on stack!")

r.close()
