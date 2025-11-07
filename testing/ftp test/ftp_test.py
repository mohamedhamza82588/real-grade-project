import socket

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(('0.0.0.0', 21))
s.listen(5)
print('✓ FTP server listening on port 21 (VULNERABLE!)')
print('✓ Your scanner should detect this as HIGH vulnerability')
print('Press Ctrl+C to stop\n')

while True:
    try:
        conn, addr = s.accept()
        print(f'[+] Connection from {addr}')
        conn.send(b'220 FTP Server Ready\r\n')
        conn.close()
    except KeyboardInterrupt:
        print('\n[!] Shutting down...')
        s.close()
        break