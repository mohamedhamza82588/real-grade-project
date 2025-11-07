import socket

s = socket.socket()
s.bind(('0.0.0.0', 23))
s.listen(1)
print('Listening on port 23...')
conn, addr = s.accept()
print(f'Connection from {addr}')
conn.send(b'Welcome to the test port 23!\\n')
conn.close()