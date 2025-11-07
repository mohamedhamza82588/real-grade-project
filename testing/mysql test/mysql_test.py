import socket

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(('0.0.0.0', 3306))
s.listen(5)
print('✓ MySQL server listening on port 3306 (VULNERABLE!)')
print('✓ Your scanner should detect exposed database')
print('Press Ctrl+C to stop\n')

while True:
    try:
        conn, addr = s.accept()
        print(f'[+] Connection from {addr}')
        conn.send(b'\x0a5.7.0\x00')
        conn.close()
    except KeyboardInterrupt:
        print('\n[!] Shutting down...')
        s.close()
        break