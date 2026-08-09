#!/usr/bin/env python3
import socket
import time

while True:
    try:
        with socket.create_connection(("127.0.0.1", 46666), timeout=2) as connection:
            connection.sendall(b"huntwarden-lab-beacon")
            connection.recv(64)
    except OSError:
        pass
    time.sleep(15)
