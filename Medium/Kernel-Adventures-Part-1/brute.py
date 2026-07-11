"""Simple brute-force: find string hashing to target."""
import sys

def hash_round(r, c):
    c = c & 0xff
    r = (r + c) & 0xffffffff
    r = (r * 1025) & 0xffffffff
    r ^= (r >> 6)
    r ^= c
    return r

target = 716789863
saw = set()
count = 0

# 1 char
for a in range(1, 256):
    r = hash_round(0, a)
    if r == target:
        print(f"Found 1-char: {bytes([a])!r}")
        sys.exit(0)

# 2 chars
for a in range(1, 256):
    r1 = hash_round(0, a)
    for b in range(1, 256):
        r2 = hash_round(r1, b)
        if r2 == target:
            print(f"Found 2-char: {bytes([a,b])!r}")
            sys.exit(0)

# 3 chars
for a in range(1, 256):
    r1 = hash_round(0, a)
    for b in range(1, 256):
        r2 = hash_round(r1, b)
        for c in range(1, 256):
            r3 = hash_round(r2, c)
            if r3 == target:
                print(f"Found 3-char: {bytes([a,b,c])!r}")
                sys.exit(0)

print("Not found in 1-3 char range")
