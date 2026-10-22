"""Dev helper: a TCP listener that goes down on a schedule, to test loss detection.

Listens for UP seconds, closes the socket (connections are refused) for DOWN seconds,
and repeats. Every state change is appended to LOG as "<unix ts> up|down", so a chart
can be checked against ground truth.

    python3 tools/flaky_server.py 127.0.0.1 9099 40 20 flaky.log
"""

from __future__ import annotations

import socket
import sys
import time


def serve(host: str, port: int, up: float, down: float, log: str) -> None:
    def note(state: str) -> None:
        with open(log, "a") as fh:
            fh.write(f"{time.time():.3f} {state}\n")

    while True:
        srv = socket.socket()
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind((host, port))
        srv.listen(64)
        srv.settimeout(0.2)
        note("up")
        end = time.time() + up
        while time.time() < end:
            try:
                conn, _ = srv.accept()
                conn.close()
            except socket.timeout:
                pass
        srv.close()
        note("down")
        time.sleep(down)


if __name__ == "__main__":
    h, p, u, d, lg = sys.argv[1:6]
    serve(h, int(p), float(u), float(d), lg)
