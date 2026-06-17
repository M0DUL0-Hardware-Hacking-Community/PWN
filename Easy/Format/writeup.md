---
title: "Format"
ctf: "HackTheBox"
date: 2026-06-13
category: pwn
difficulty: easy
flag_format: "HTB{...}"
---

# Format

## Summary

Format string vulnerability in `echo()` infinite loop (Full RELRO, PIE, canary). Exploit overwrites printf's return address on the stack with a one_gadget via `%hhn` byte-writes.

## Solution

### Step 1: Leak addresses

- `%39$p.%40$p.%41$p.` → canary, saved rbp, return address → calculate PIE base (`ret_addr - 0x12b3`)
- `%11$s.` + GOT address (`printf@GOT = pie + 0x3fc0`) → leak libc printf → calculate libc base

### Step 2: Overwrite printf return address with one_gadget

`echo()` loops forever (never returns), so we overwrite printf's **return address** on the stack instead.

Stack layout:
- `echo_rbp = saved_rbp - 0x20`  (main `sub rsp,0x10` + `call echo` + `push rbp` in echo)
- `printf_ret_loc = echo_rbp - 0x110 - 8 = saved_rbp - 0x138`
- Position 39 = canary at `echo_rbp - 8`
- Position 6 = buffer at `echo_rbp - 0x110`

Format string constructs 6 `%hhn` writes to overwrite bytes 0-5 of `printf_ret_loc` with the one_gadget address (`libc + 0x4f2c5`). The `%c` width specifiers track cumulative output count to produce correct byte values. Addresses appended after format specifiers (null bytes at end avoid truncating format string).

### Step 3: Shell

When printf returns, it goes to the one_gadget: `execve("/bin/sh", rsp+0x40, environ)` → shell.

### Remote libc

Identified via libc.rip: `libc6_2.27-3ubuntu1_amd64` (`printf=0x64e80`, `system=0x4f440`, `str_bin_sh=0x1b3e9a`, `__libc_start_main=0x21ab0`). One-gadgets: `0x4f2be`, `0x4f2c5`, `0x4f322`, `0x10a38c`.

## Flag

```
HTB{mall0c_h00k_f0r_th3_w1n!}
```
