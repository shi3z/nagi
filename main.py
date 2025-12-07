#!/usr/bin/env python3
"""Nagi - Web-based terminal for iOS/iPad with touch-friendly controls."""

import asyncio
import fcntl
import json
import os
import pty
import secrets
import socket
import struct
import subprocess
import sys
import termios
from pathlib import Path

from fastapi import FastAPI, WebSocket, WebSocketDisconnect, Query, status
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles

# Base directory for resolving paths (PyInstaller compatible)
if getattr(sys, 'frozen', False):
    BASE_DIR = Path(sys._MEIPASS)
else:
    BASE_DIR = Path(__file__).parent.resolve()

# Load config
CONFIG_PATH = BASE_DIR / "config.json"
DEFAULT_CONFIG = {
    "startup_command": "tmux a || tmux new",
    "shell": "/bin/bash",
    "port": 8765
}

def load_config():
    """Load configuration from config.json."""
    if CONFIG_PATH.exists():
        try:
            with open(CONFIG_PATH) as f:
                config = json.load(f)
                return {**DEFAULT_CONFIG, **config}
        except Exception:
            pass
    return DEFAULT_CONFIG

config = load_config()

# Generate or load authentication token
AUTH_TOKEN = os.environ.get("NAGI_TOKEN") or config.get("token") or secrets.token_urlsafe(24)

app = FastAPI(title="Nagi")

# Serve static files
static_dir = BASE_DIR / "static"
static_dir.mkdir(exist_ok=True)
app.mount("/static", StaticFiles(directory=str(static_dir)), name="static")


def set_winsize(fd: int, rows: int, cols: int) -> None:
    """Set terminal window size."""
    winsize = struct.pack("HHHH", rows, cols, 0, 0)
    fcntl.ioctl(fd, termios.TIOCSWINSZ, winsize)


@app.get("/")
async def index(token: str = Query(None)):
    """Serve the main terminal page with token validation."""
    if token != AUTH_TOKEN:
        return HTMLResponse(
            content="""<!DOCTYPE html>
<html><head><title>Nagi - Unauthorized</title>
<style>body{font-family:sans-serif;display:flex;justify-content:center;align-items:center;height:100vh;margin:0;background:#1a1a2e;color:#eee;}
.box{text-align:center;padding:40px;background:#16213e;border-radius:10px;}
h1{color:#e94560;}</style></head>
<body><div class="box"><h1>Unauthorized</h1><p>Invalid or missing token.<br>Please use the URL displayed in the terminal.</p></div></body></html>""",
            status_code=401
        )
    html_path = BASE_DIR / "templates" / "index.html"
    html_content = html_path.read_text()
    # Inject token into HTML for WebSocket authentication
    html_content = html_content.replace("</head>", f'<script>window.NAGI_TOKEN="{AUTH_TOKEN}";</script></head>')
    return HTMLResponse(content=html_content)


@app.websocket("/ws")
async def websocket_terminal(websocket: WebSocket, token: str = Query(None)):
    """WebSocket endpoint for terminal communication."""
    if token != AUTH_TOKEN:
        await websocket.close(code=status.WS_1008_POLICY_VIOLATION)
        return
    await websocket.accept()

    # Create pseudo-terminal
    master_fd, slave_fd = pty.openpty()

    # Set initial terminal size
    set_winsize(master_fd, 24, 80)

    # Set environment variables
    env = os.environ.copy()
    env["TERM"] = "xterm-256color"
    env["LANG"] = "ja_JP.UTF-8"
    env["LC_ALL"] = "ja_JP.UTF-8"

    # Get shell from config
    shell = config.get("shell", os.environ.get("SHELL", "/bin/bash"))

    # Start shell process
    process = subprocess.Popen(
        [shell, "-l"],
        stdin=slave_fd,
        stdout=slave_fd,
        stderr=slave_fd,
        env=env,
        preexec_fn=os.setsid,
    )

    os.close(slave_fd)

    # Set master to non-blocking
    flags = fcntl.fcntl(master_fd, fcntl.F_GETFL)
    fcntl.fcntl(master_fd, fcntl.F_SETFL, flags | os.O_NONBLOCK)

    running = True
    startup_sent = False

    async def read_from_pty():
        """Read data from PTY and send to WebSocket."""
        nonlocal startup_sent
        while running:
            try:
                await asyncio.sleep(0.02)
                try:
                    data = os.read(master_fd, 4096)
                    if data:
                        await websocket.send_bytes(data)
                        # Send startup command after first output (shell is ready)
                        if not startup_sent:
                            startup_sent = True
                            startup_cmd = config.get("startup_command", "")
                            if startup_cmd:
                                await asyncio.sleep(0.1)
                                os.write(master_fd, (startup_cmd + "\n").encode())
                except BlockingIOError:
                    pass
                except OSError:
                    break
            except Exception:
                break

    # Start reading from PTY
    read_task = asyncio.create_task(read_from_pty())

    try:
        while True:
            message = await websocket.receive()

            if message["type"] == "websocket.disconnect":
                break

            if "bytes" in message:
                data = message["bytes"]
            elif "text" in message:
                text = message["text"]
                # Handle resize command
                if text.startswith("resize:"):
                    _, size = text.split(":", 1)
                    cols, rows = map(int, size.split(","))
                    set_winsize(master_fd, rows, cols)
                    continue
                data = text.encode("utf-8")
            else:
                continue

            # Write to PTY
            try:
                os.write(master_fd, data)
            except OSError:
                break

    except WebSocketDisconnect:
        pass
    finally:
        running = False
        read_task.cancel()
        try:
            os.close(master_fd)
        except Exception:
            pass
        try:
            process.terminate()
            process.wait(timeout=1)
        except Exception:
            try:
                process.kill()
            except Exception:
                pass


def get_local_ip():
    """Get local IP address."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "localhost"


if __name__ == "__main__":
    import uvicorn
    port = config.get("port", 8765)
    local_ip = get_local_ip()

    print("\n" + "=" * 50)
    print("  Nagi - Touch-friendly Web Terminal")
    print("=" * 50)
    print(f"\n  Access URL (copy this to your browser):\n")
    print(f"    http://{local_ip}:{port}/?token={AUTH_TOKEN}")
    print(f"\n  Local: http://localhost:{port}/?token={AUTH_TOKEN}")
    print("\n" + "=" * 50 + "\n")

    uvicorn.run(app, host="0.0.0.0", port=port, log_level="warning")
