"""Construct a password that hashes to a target value.
Using the property that hash_round is a bijection for each character."""

import sys

def inv_xor_shift_6(y):
    x = y & 0xfc000000
    for i in range(25, -1, -1):
        x |= (((y >> i) ^ (x >> (i + 6))) & 1) << i
    return x & 0xffffffff

INV_1025 = pow(1025, -1, 2**32)

def hash_round(r, c):
    c = c & 0xff
    r = (r + c) & 0xffffffff
    r = (r * 1025) & 0xffffffff
    r ^= (r >> 6)
    r ^= c
    return r

def hash_str(s):
    r = 0
    for ch in s:
        r = hash_round(r, ch)
    return r

def construct_password(target, length):
    """Build a password of given length that hashes to target."""
    # Go backwards from target for length-1 steps with arbitrary chars
    # Then find the final char that connects r=0 to the intermediate value
    
    r = target
    chars = []
    
    # length-1 arbitrary backwards steps
    for step in range(length - 1):
        c = (step % 94) + 33
        r_temp = r ^ c
        r2 = inv_xor_shift_6(r_temp)
        r1 = (r2 * INV_1025) & 0xffffffff
        r_in = (r1 - c) & 0xffffffff
        verify = hash_round(r_in, c)
        if verify != r:
            raise ValueError(f"Step {step}: verification failed")
        chars.append(c)
        r = r_in
    
    # Now r = r_1, the value after first forward character
    # Find c such that hash_round(0, c) = r_1
    last_char = None
    for c in range(1, 256):
        if hash_round(0, c) == r:
            last_char = c
            break
    
    if last_char is None:
        raise ValueError(f"Cannot find final char for r=0 -> 0x{r:08x}, try different length")
    
    # Password = [last_char] + reverse(chars)
    password = bytes([last_char] + list(reversed(chars)))
    
    # Verify
    r_test = 0
    for ch in password:
        r_test = hash_round(r_test, ch)
    assert r_test == target, f"Forward check: {r_test} != {target}"
    
    return password

if __name__ == '__main__':
    targets = [
        ("users[1]", 53623157),
        ("users[3]", 716789863),
    ]
    for name, target in targets:
        print(f"\n=== {name}: {target} (0x{target:08x}) ===")
        for length in [1, 2, 3, 5, 10, 16]:
            try:
                pwd = construct_password(target, length)
                v = hash_str(pwd)
                ok = "OK" if v == target else "FAIL"
                print(f"  len={length}: {pwd!r} verify={v} {ok}")
            except ValueError as e:
                print(f"  len={length}: {e}")
