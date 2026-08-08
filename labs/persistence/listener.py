#!/usr/bin/env python3
"""Harmless loopback-only listener used to validate persistence/process correlation."""
import socket

server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
server.bind(("127.0.0.1", 45555))
server.listen(5)
while True:
    connection, _ = server.accept()
    connection.sendall(b"HuntWarden harmless persistence lab\n")
    connection.close()
