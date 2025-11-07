import socket
import threading

def start_server(port, name, banner):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(('0.0.0.0', port))
    s.listen(5)
    print(f'✓ {name} listening on port {port}')
    
    while True:
        try:
            conn, addr = s.accept()
            print(f'[+] {name} connection from {addr}')
            conn.send(banner.encode())
            conn.close()
        except:
            break

ports = [
    (21, 'FTP (HIGH)', '220 FTP Server Ready\r\n'),
    (23, 'Telnet (CRITICAL)', 'Welcome to Telnet\r\n'),
    (80, 'HTTP (MEDIUM)', 'HTTP/1.1 200 OK\r\n\r\n'),
    (3306, 'MySQL (MEDIUM)', 'MySQL Server\r\n')
]

print('🔴 Starting vulnerable servers...\n')
threads = []
for port, name, banner in ports:
    t = threading.Thread(target=start_server, args=(port, name, banner))
    t.daemon = True
    t.start()
    threads.append(t)

print('\n✅ All vulnerable ports open!')
print('✅ Run your scanner now: python scanner.py\n')
print('Press Ctrl+C to stop all servers\n')

try:
    while True:
        pass
except KeyboardInterrupt:
    print('\n[!] Shutting down all servers...')