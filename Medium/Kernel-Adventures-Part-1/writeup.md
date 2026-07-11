---
title: "Kernel Adventures Part 1"
ctf: "HTB Business CTF 2024"
date: 2026-06-16
category: pwn
difficulty: medium
points: N/A
flag_format: "HTB{...}"
author: "gluppler"
---

# Kernel Adventures Part 1

## Summary

A QEMU-based kernel challenge with a custom LKM (`mysu.ko`) that implements a TOCTOU-raceable privilege escalation device. The exploit reverses the 50-char password preimage, then races a kernel-space `dev_write` handler using clone+shared memory to overwrite the uid between three reads of a user buffer.

## Solution

### Step 1: Recover module behavior

The LKM exports `/dev/mysu` which accepts `write(fd, buf, count)` where:
- `buf[0..3]` = requested uid (uint32)
- `buf[4..]` = password string (null-terminated)

The internal hash function:
```
uint32_t hash(const uint8_t *s) {
    uint32_t r = 0;
    while (*s) {
        int sc = (int8_t)*s;
        r += sc; r *= 1025; r ^= r >> 6; r ^= (uint32_t)sc;
        s++;
    }
    return r;
}
```

The module stores `users[] = {uid0, hash0, uid1, hash1}` read via `read(fd)`.

### Step 2: Recover remote users/hashes

On the remote: `users = {1000, 53583733, 1001, 716661863}`.

### Step 3: Find password preimage

Built a construct_long brute-forcer that finds the preimage of `users[3] = 716661863` — a 50-byte non-null string that hashes to the target.

### Step 4: Exploit the TOCTOU race

`dev_write` reads `buf[0]` three times:
1. **First read** (0x10b): path selection — `buf[0] == users[0]` (1000) → Path A; `buf[0] == users[2]` (1001) → Path B
2. **Second read** (0x13e): only on Path A hash failure — checks if `buf[0]` now matches `users[2]` for fallthrough to Path B
3. **Third read** (0x15a): the uid to `commit_creds()` — if `buf[0] = 0`, we get root

Attack: Main thread sets `buf[0] = 1001` (Path B), writes the password (preimage of `users[3]`), then a clone'd racer thread toggles `buf[0]` between 1001 and 0 (biased 3:1 toward 0). During the hash computation, the racer's toggles land `buf[0] = 0` at the third read → `uid = 0` = root.

### Step 5: Capture flag

```python
# upload.py — compressed exploit via QEMU serial console
# Full exploit.c in challenge directory
```

Flag:

```
HTB{C0ngr4ts_y0u_3xpl0it3d_A_D0uBlE-FeTcH}
```
