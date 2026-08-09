#!/usr/bin/env python3
import socket
import time

server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
server.bind(("127.0.0.1", 46666))
server.listen(8)
while True:
    connection, _ = server.accept()
    connection.recv(64)
    connection.sendall(b"huntwarden-lab-ok")
    # This harmless fixture intentionally keeps one connection open so the
    # process-to-socket correlation is deterministic during Docker tests.
    while True:
        time.sleep(60)
