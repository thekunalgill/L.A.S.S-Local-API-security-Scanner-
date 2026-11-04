from __future__ import annotations

import socket
import threading
import time

import uvicorn
import webview

from lass.main import app


def available_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
        listener.bind(("127.0.0.1", 0))
        return listener.getsockname()[1]


def run_app() -> None:
    port = available_port()
    config = uvicorn.Config(
        app,
        host="127.0.0.1",
        port=port,
        log_level="error",
        access_log=False,
    )
    server = uvicorn.Server(config)
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()

    for _ in range(100):
        if server.started:
            break
        if not thread.is_alive():
            raise RuntimeError("The local L.A.S.S. service failed to start.")
        time.sleep(0.05)
    else:
        server.should_exit = True
        raise RuntimeError("Timed out while starting the local L.A.S.S. service.")

    try:
        webview.create_window(
            "L.A.S.S. — Local API Security Scanner",
            f"http://127.0.0.1:{port}",
            width=1160,
            height=860,
            min_size=(760, 620),
        )
        webview.start()
    finally:
        server.should_exit = True
        thread.join(timeout=5)


if __name__ == "__main__":
    run_app()
