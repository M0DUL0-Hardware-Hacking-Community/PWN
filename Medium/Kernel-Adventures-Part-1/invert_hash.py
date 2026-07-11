"""Invert the hash function: given target, find string that hashes to it."""

# hash: r = ((r + c) * 1025) ^ (((r + c) * 1025) >> 6) ^ c
# where r is 32-bit, c is char (sign-extended to 32-bit)

def hash_round(r, c):
    r = (r + c) & 0xffffffff
    r = (r * 1025) & 0xffffffff
    r = r ^ (r >> 6)
    r = r ^ (c & 0xffffffff)
    return r & 0xffffffff

def hash_str(s):
    r = 0
    for ch in s:
        c = ch if isinstance(ch, int) else ord(ch)
        c = c & 0xff
        r = hash_round(r, c)
    return r

# Modular inverse of 1025 mod 2^32
inv_1025 = pow(1025, -1, 2**32)
print(f"inv_1025 = {inv_1025} (0x{inv_1025:08x})")
print(f"verify: {(1025 * inv_1025) & 0xffffffff} == 1")

def inverse_xor_shift_6(y):
    """Find x such that x ^ (x >> 6) = y."""
    x = y & 0xffffffc0  # top 26 bits (bits 6-31) might be modified
    # bits 0-5 of x = bits 0-5 of y (direct)
    # bit 6 of x = bit 6 of y ^ bit 0 of x
    # bit 7 of x = bit 7 of y ^ bit 1 of x
    # ...
    x = y  # start with y as approximation
    for i in range(6, 32):
        x_bit_i = (y >> i) & 1
        x_bit_im6 = (x >> (i - 6)) & 1
        x_new_bit = x_bit_i ^ x_bit_im6
        x = (x & ~(1 << i)) | (x_new_bit << i)
    return x & 0xffffffff

def hash_inverse_round(r_out, c):
    """Find r_in such that hash_round(r_in, c) = r_out.
    Returns None if no solution exists."""
    c = c & 0xff
    r_temp = r_out ^ c
    x = inverse_xor_shift_6(r_temp)
    # x = (r_in + c) * 1025 mod 2^32
    # r_in + c = x * inv_1025 mod 2^32
    sum_rc = (x * inv_1025) & 0xffffffff
    r_in = (sum_rc - c) & 0xffffffff
    # Verify
    if hash_round(r_in, c) == r_out:
        return r_in
    return None

def find_string(target):
    """Find a string that hashes to target, starting from shortest possible."""
    # Try single char
    for c in range(1, 256):
        r = hash_round(0, c)
        if r == target:
            return bytes([c])
    
    # Try with backtracking - start from end and work backwards
    # We want r_n = target, find r_{n-1} such that hash_round(r_{n-1}, c_n) = target
    # Then continue...
    
    for length in range(1, 6):
        print(f"  Trying length {length}...")
        result = find_string_of_length(target, length)
        if result is not None:
            return result
    return None

def find_string_of_length(target, length):
    """Try to find a string of exact length that hashes to target."""
    chars = []
    
    # We need to find r_0 (0) -> r_1 -> ... -> r_n = target
    # Working backwards from target:
    # Given r_i and c_i, compute r_{i-1}
    
    if length == 0:
        return b"" if target == 0 else None
    
    if length == 1:
        for c in range(1, 256):
            if hash_round(0, c) == target:
                return bytes([c])
        return None
    
    # For longer strings: work backwards
    # We need to find any valid sequence
    return find_preimage_backwards(target, length, 0)

def find_preimage_backwards(target, remaining, current_r):
    """DFS to find a preimage."""
    if remaining == 0:
        return b"" if target == current_r else None
    
    # Find r_child and c such that hash_round(r_child, c) = target
    for c in range(1, 256):
        r_child = hash_inverse_round(target, c)
        if r_child is not None:
            sub = find_preimage_backwards(r_child, remaining - 1, None)
            if sub is not None:
                return sub + bytes([c])
    return None

# But this search is still exponential. Instead, let's use a different approach.
# Start from r = 0 and iterate forwards.
# For a string of unknown length, we can set intermediate r to anything.
# Better approach: use meet-in-the-middle for 4-char strings.

def find_preimage_forward(target):
    """Iterate forward: explore strings up to 4 chars by BFS with dedup."""
    from collections import deque
    
    # BFS but track (r, string) pairs
    visited = {}  # r -> string
    q = deque()
    q.append((0, b""))  # (hash_value, string_so_far)
    visited[0] = b""
    
    while q:
        r, s = q.popleft()
        if r == target and len(s) > 0:
            return s
        
        if len(s) >= 5:
            continue
        
        for c in range(1, 256):
            r_new = hash_round(r, c)
            s_new = s + bytes([c])
            if r_new not in visited or len(s_new) < len(visited[r_new]):
                visited[r_new] = s_new
                q.append((r_new, s_new))
    
    return None

# Actually, the simplest approach: just iterate and check, it's fast enough
# in C or even in Python with optimization

# Let me first try the BFS approach for <= 3 chars
target = 716789863
print(f"\nTarget: {target} ({target:08x})")

# Test inverse
print("\nTesting hash inverse...")
# Sanity check
for r_in in range(0, 100, 7):
    for c in range(1, 256, 31):
        r_out = hash_round(r_in, c)
        r_in2 = hash_inverse_round(r_out, c)
        if r_in2 is None:
            print(f"  FAIL: r_in={r_in}, c={c}, r_out={r_out}")
        elif r_in2 != r_in:
            print(f"  MISMATCH: r_in={r_in}, c={c}, got r_in2={r_in2}")
print("  Inverse check done")

# Test that XOR >> 6 is invertible
print("\nTesting XOR>>6 inverse...")
for x in range(0, 100000, 7):
    y = x ^ (x >> 6)
    x2 = inverse_xor_shift_6(y)
    if x2 != x:
        print(f"  FAIL: x={x}, y={y}, x2={x2}")
        break
else:
    print("  All OK for tested range")

# Try to find preimage with BFS (limited)
result = find_preimage_forward(target)
if result:
    print(f"\nFound: {result.hex()} (len={len(result)})")
    print(f"  hash('{result}') = {hash_str(result)}")
else:
    print("\nNot found with BFS up to 5 chars")
