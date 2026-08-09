#!/usr/bin/env python3
import socket
import time

while True:
    try:
        with socket.create_connection(("127.0.0.1", 46666), timeout=2) as connection:
            connection.sendall(b"huntwarden-lab-beacon")
            connection.recv(64)
            # Keep one deterministic ESTABLISHED socket available while the
            # investigator walks the stable process reference chain.
            while True:
                time.sleep(60)
    except OSError:
        pass
    time.sleep(15)
