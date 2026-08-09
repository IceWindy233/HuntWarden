#!/usr/bin/env python3
import socket

server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
server.bind(("127.0.0.1", 46666))
server.listen(8)
while True:
    connection, _ = server.accept()
    connection.recv(64)
    connection.sendall(b"huntwarden-lab-ok")
    connection.close()
