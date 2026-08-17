#!/usr/bin/env python3
import socket
import time

while True:
    try:
        with socket.create_connection(("127.0.0.1", 18771), timeout=2) as connection:
            connection.sendall(b"inventory-heartbeat")
            connection.recv(64)
            while True:
                time.sleep(60)
    except OSError:
        time.sleep(2)
