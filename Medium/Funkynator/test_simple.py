#!/usr/bin/env python3
"""Minimal test - overwrite msg2[0] to verify overwrite works."""
from pwn import *
import struct, time
from pathlib import Path

context.arch = 'amd64'
context.log_level = 'debug'

CHALLENGE_DIR = Path(__file__).parent / 'challenge' / 'challenge'
BINARY = str(CHALLENGE_DIR.resolve() / 'funkynator')

env = {'LD_LIBRARY_PATH': str(CHALLENGE_DIR.resolve() / 'glibc')}

r = process(BINARY, env=env, cwd=str(CHALLENGE_DIR))

# Helper to skip output
def wait_for(prompt, timeout=3):
    return r.recvuntil(prompt, timeout=timeout)

wait_for(b'name?')
r.sendline(b'TEST')
wait_for(b'> ')

# Create msg2 only (need something to edit)
r.sendline(b'2')
wait_for(b'length\n')
r.sendline(b'5')
wait_for(b'message:\n')
r.sendline(b'HELLO')
wait_for(b'?\n')
r.sendline(b'n')
wait_for(b'?\n')
r.sendline(b'y')
wait_for(b'location')
r.recvline()
wait_for(b'> ')
log.info("Message created in slot 1")

# Now let's view it first
r.sendline(b'3')
wait_for(b'id')
r.recvline()
r.sendline(b'1')
wait_for(b'> ')
log.info("Viewed slot 1")

# Enter editor for slot 1
r.sendline(b'5')
wait_for(b'id')
r.recvline()
r.sendline(b'1')
wait_for(b'> ')
log.info("In editor")

# Try option 2 (examine) to see what the message looks like
r.sendline(b'2')
resp = wait_for(b'> ')
log.info(f"Examine output: {resp}")

# Now try overwrite byte 0 with 'X'
r.sendline(b'3')
wait_for(b'offset\n')
r.sendline(b'0')
wait_for(b'value?\n')
r.send(b'X\n')
wait_for(b'> ')
log.info("Overwrote byte 0")

# Examine again to verify
r.sendline(b'2')
resp = wait_for(b'> ')
log.info(f"Examine after overwrite: {resp}")

# Stop
r.sendline(b'1')
wait_for(b'?\n')
r.sendline(b'y')
wait_for(b'location')
r.recvline()
wait_for(b'> ')
log.info("Back to main menu")

# View slot 1 to verify
r.sendline(b'3')
wait_for(b'id')
r.recvline()
r.sendline(b'1')
resp = wait_for(b'> ')
log.info(f"View slot 1: {resp}")

r.close()
