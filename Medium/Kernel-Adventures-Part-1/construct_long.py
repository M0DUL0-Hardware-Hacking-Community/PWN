"""Construct a long password that hashes to target.
Strategy: start from r=0, pick a random prefix, then construct suffix backwards."""
import sys

INV_1025 = pow(1025, -1, 2**32)

def inv_xor_shift_6(y):
    x = y & 0xfc000000
    for i in range(25, -1, -1):
        x |= (((y >> i) ^ (x >> (i + 6))) & 1) << i
    return x & 0xffffffff

def hash_round(r, c):
    c = c & 0xff
    r = (r + c) & 0xffffffff
    r = (r * 1025) & 0xffffffff
    r ^= (r >> 6)
    r ^= c
    return r

def inv_hash_round(r_out, c):
    r_temp = r_out ^ c
    x = inv_xor_shift_6(r_temp)
    r1 = (x * INV_1025) & 0xffffffff
    r_in = (r1 - c) & 0xffffffff
    return r_in

def hash_str(s):
    r = 0
    for ch in s:
        r = hash_round(r, ch)
    return r

def find_password(target, total_len):
    """Build a password of total_len that hashes to target.
    Uses prefix (forward) + suffix (backward) approach."""
    
    # Try many random prefixes until one works
    import random
    
    suffix_len = total_len // 2
    prefix_len = total_len - suffix_len
    
    for attempt in range(1000000):
        # Generate random prefix
        prefix = bytes([random.randint(1, 255) for _ in range(prefix_len)])
        r_mid = 0
        for ch in prefix:
            r_mid = hash_round(r_mid, ch)
        
        # Build suffix backwards from target
        r = target
        suffix_chars = []
        ok = True
        for i in range(suffix_len):
            c = random.randint(1, 255)
            r_prev = inv_hash_round(r, c)
            if hash_round(r_prev, c) != r:
                ok = False
                break
            suffix_chars.append(c)
            r = r_prev
        
        if not ok:
            continue
        
        # r should now be r_mid (the hash after prefix)
        if r == r_mid:
            password = prefix + bytes(reversed(suffix_chars))
            v = hash_str(password)
            if v == target:
                return password
        
        # Otherwise, the backward chain ended at r (not r_mid)
        # We need to adjust the prefix to match r
        # Try all 1-char prefixes that map 0 -> r
        for c in range(1, 256):
            if hash_round(0, c) == r:
                password = bytes([c]) + bytes(reversed(suffix_chars))
                v = hash_str(password)
                if v == target:
                    return password
    
    return None

def construct_direct(target, length):
    """Start from target, go backwards length-1 steps, then find connecting char."""
    import random
    
    # Go backwards length-1 steps with random chars
    for attempt in range(100000):
        r = target
        chars = []
        for step in range(length - 1):
            c = random.randint(1, 255)
            r = inv_hash_round(r, c)
            chars.append(c)
        
        # Now try all possible final chars
        for c in range(1, 256):
            if hash_round(0, c) == r:
                password = bytes([c] + list(reversed(chars)))
                v = hash_str(password)
                if v == target:
                    return password
    return None

if __name__ == '__main__':
    target = int(sys.argv[1]) if len(sys.argv) > 1 else 716661863
    length = int(sys.argv[2]) if len(sys.argv) > 2 else 50
    
    print(f"Finding {length}-char password for target {target} (0x{target:08x})...")
    
    # Try direct construction first (works better for longer passwords)
    pwd = construct_direct(target, length)
    
    if pwd:
        v = hash_str(pwd)
        print(f"Found! len={len(pwd)}, hex={pwd.hex()}")
        print(f"Verify: hash={v} (expected {target})")
        print(f"Printable: {pwd.decode('latin-1')}")
    else:
        print("Not found with direct approach, trying prefix+suffix...")
        pwd = find_password(target, length)
        if pwd:
            v = hash_str(pwd)
            print(f"Found! len={len(pwd)}, hex={pwd.hex()}")
            print(f"Verify: hash={v} (expected {target})")
