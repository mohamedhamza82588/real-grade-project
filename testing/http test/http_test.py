import socket

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(('0.0.0.0', 80))
s.listen(5)
print('✓ HTTP server listening on port 80 (VULNERABLE!)')
print('✓ Your scanner should detect unencrypted HTTP')
print('Press Ctrl+C to stop\n')

while True:
    try:
        conn, addr = s.accept()
        print(f'[+] Connection from {addr}')
        conn.send(b'HTTP/1.1 200 OK\r\n\r\nVulnerable HTTP Server')
        conn.close()
    except KeyboardInterrupt:
        print('\n[!] Shutting down...')
        s.close()
        break

