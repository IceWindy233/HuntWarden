#!/usr/bin/env python3
import socket
import time

server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
server.bind(("127.0.0.1", 18771))
server.listen(8)

while True:
    connection, _ = server.accept()
    connection.recv(64)
    connection.sendall(b"ok")
    while True:
        time.sleep(60)
