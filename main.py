#!/usr/bin/env python3
"""Nagi - Web-based terminal for iOS/iPad with touch-friendly controls."""

import asyncio
import fcntl
import json
import logging
import os
import pty
import secrets
import socket
import struct
import subprocess
import sys
import termios
from pathlib import Path
from typing import Optional

import qrcode

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S"
)
logger = logging.getLogger("nagi")

from fastapi import FastAPI, WebSocket, WebSocketDisconnect, Query, Request, status
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

# Authentication configuration
auth_config = config.get("auth", {})
AUTH_MODE = auth_config.get("mode", "token")  # "tailscale" or "token"
ALLOWED_USERS = auth_config.get("allowed_users", [])

# Generate or load authentication token (for token mode)
AUTH_TOKEN = os.environ.get("NAGI_TOKEN") or config.get("token") or secrets.token_urlsafe(24)

# Session management for Tailscale mode
SESSION_SECRET = secrets.token_urlsafe(32)
active_sessions: dict[str, dict] = {}  # session_token -> user_info


def get_tailscale_user(client_ip: str) -> Optional[dict]:
    """Get Tailscale user info from client IP using tailscale whois."""
    try:
        result = subprocess.run(
            ["tailscale", "whois", "--json", client_ip],
            capture_output=True,
            text=True,
            timeout=5
        )
        if result.returncode == 0:
            data = json.loads(result.stdout)
            user_profile = data.get("UserProfile", {})
            return {
                "login": user_profile.get("LoginName", ""),
                "display_name": user_profile.get("DisplayName", ""),
                "profile_pic": user_profile.get("ProfilePicURL", ""),
                "node": data.get("Node", {}).get("Name", ""),
            }
    except (subprocess.TimeoutExpired, json.JSONDecodeError, FileNotFoundError):
        pass
    return None


def create_session(user_info: dict) -> str:
    """Create a new session and return the session token."""
    session_token = secrets.token_urlsafe(32)
    active_sessions[session_token] = user_info
    return session_token


def verify_session(session_token: str) -> Optional[dict]:
    """Verify a session token and return user info if valid."""
    return active_sessions.get(session_token)


def is_user_allowed(user_info: dict) -> bool:
    """Check if user is in the allowed users list."""
    if not ALLOWED_USERS:
        return True  # Empty list = allow all Tailnet users
    login = user_info.get("login", "")
    return login in ALLOWED_USERS

app = FastAPI(title="Nagi")

# Serve static files
static_dir = BASE_DIR / "static"
static_dir.mkdir(exist_ok=True)
app.mount("/static", StaticFiles(directory=str(static_dir)), name="static")


def set_winsize(fd: int, rows: int, cols: int) -> None:
    """Set terminal window size."""
    winsize = struct.pack("HHHH", rows, cols, 0, 0)
    fcntl.ioctl(fd, termios.TIOCSWINSZ, winsize)


def get_unauthorized_html(message: str = "Unauthorized") -> str:
    """Return HTML for unauthorized access."""
    return f"""<!DOCTYPE html>
<html><head><title>Nagi - {message}</title>
<style>body{{font-family:sans-serif;display:flex;justify-content:center;align-items:center;height:100vh;margin:0;background:#1a1a2e;color:#eee;}}
.box{{text-align:center;padding:40px;background:#16213e;border-radius:10px;}}
h1{{color:#e94560;}}</style></head>
<body><div class="box"><h1>{message}</h1><p>Access denied.</p></div></body></html>"""


@app.get("/")
async def index(request: Request, token: str = Query(None)):
    """Serve the main terminal page with authentication."""
    session_token = None
    user_info = None

    client_ip = request.client.host if request.client else "unknown"

    if AUTH_MODE == "tailscale":
        # Tailscale authentication mode
        if not client_ip or client_ip == "unknown":
            logger.warning(f"Connection rejected: No client IP")
            return HTMLResponse(content=get_unauthorized_html("No Client IP"), status_code=401)

        user_info = get_tailscale_user(client_ip)
        if not user_info:
            logger.warning(f"Connection rejected: {client_ip} - Not a Tailscale connection")
            return HTMLResponse(
                content=get_unauthorized_html("Not a Tailscale connection"),
                status_code=401
            )

        if not is_user_allowed(user_info):
            logger.warning(f"Connection rejected: {client_ip} - User '{user_info.get('login')}' not allowed")
            return HTMLResponse(
                content=get_unauthorized_html("User not allowed"),
                status_code=403
            )

        # Create session for WebSocket authentication
        session_token = create_session(user_info)
        logger.info(f"Access granted: {client_ip} - {user_info.get('display_name')} ({user_info.get('login')}) from {user_info.get('node')}")
    else:
        # Token authentication mode (legacy)
        if token != AUTH_TOKEN:
            logger.warning(f"Connection rejected: {client_ip} - Invalid token")
            return HTMLResponse(
                content=get_unauthorized_html("Invalid or missing token"),
                status_code=401
            )
        session_token = AUTH_TOKEN
        logger.info(f"Access granted: {client_ip} - Token auth")

    html_path = BASE_DIR / "templates" / "index.html"
    html_content = html_path.read_text()
    # Inject token, hostname and IP into HTML
    hostname = get_hostname()
    ip_addr = get_ip_address()
    user_display = user_info.get("display_name", "") if user_info else ""
    inject_script = f'<script>window.NAGI_TOKEN="{session_token}";window.NAGI_HOST="{hostname}";window.NAGI_IP="{ip_addr}";window.NAGI_USER="{user_display}";</script></head>'
    html_content = html_content.replace("</head>", inject_script)
    return HTMLResponse(content=html_content)


@app.websocket("/ws")
async def websocket_terminal(websocket: WebSocket, token: str = Query(None)):
    """WebSocket endpoint for terminal communication."""
    client_ip = websocket.client.host if websocket.client else "unknown"

    # Verify authentication
    if AUTH_MODE == "tailscale":
        user_info = verify_session(token) if token else None
        if not user_info:
            logger.warning(f"WebSocket rejected: {client_ip} - Invalid session")
            await websocket.close(code=status.WS_1008_POLICY_VIOLATION)
            return
        logger.info(f"WebSocket connected: {client_ip} - {user_info.get('display_name', 'unknown')}")
    else:
        if token != AUTH_TOKEN:
            logger.warning(f"WebSocket rejected: {client_ip} - Invalid token")
            await websocket.close(code=status.WS_1008_POLICY_VIOLATION)
            return
        logger.info(f"WebSocket connected: {client_ip}")
        user_info = None

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
        if AUTH_MODE == "tailscale" and user_info:
            logger.info(f"WebSocket disconnected: {client_ip} - {user_info.get('display_name', 'unknown')}")
        else:
            logger.info(f"WebSocket disconnected: {client_ip}")


def get_hostname():
    """Get hostname for URL."""
    if AUTH_MODE == "tailscale":
        # Use Tailscale node name for Tailnet access
        try:
            result = subprocess.run(
                ["tailscale", "status", "--self", "--json"],
                capture_output=True,
                text=True,
                timeout=5
            )
            if result.returncode == 0:
                data = json.loads(result.stdout)
                # Get short hostname (without domain suffix)
                hostname = data.get("Self", {}).get("HostName", "")
                if hostname:
                    return hostname
        except (subprocess.TimeoutExpired, json.JSONDecodeError, FileNotFoundError):
            pass
    return socket.gethostname()


def get_ip_address():
    """Get local IP address."""
    try:
        # Create a socket to determine the outgoing IP
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "127.0.0.1"


def print_qr_code(url: str):
    """Print QR code to terminal."""
    qr = qrcode.QRCode(border=1)
    qr.add_data(url)
    qr.make(fit=True)
    matrix = qr.get_matrix()
    for row in matrix:
        print("  " + "".join("██" if cell else "  " for cell in row))


if __name__ == "__main__":
    import uvicorn
    port = config.get("port", 8765)
    hostname = get_hostname()

    print("\n" + "=" * 50)
    print("  Nagi - Touch-friendly Web Terminal")
    print("=" * 50)

    if AUTH_MODE == "tailscale":
        access_url = f"http://{hostname}:{port}/"
        print(f"\n  Auth Mode: Tailscale")
        if ALLOWED_USERS:
            print(f"  Allowed Users: {', '.join(ALLOWED_USERS)}")
        else:
            print(f"  Allowed Users: All Tailnet users")
        print(f"\n  Access URL:\n")
        print(f"    {access_url}")
        print(f"\n  (Access via Tailscale network only)")
    else:
        access_url = f"http://{hostname}:{port}/?token={AUTH_TOKEN}"
        print(f"\n  Auth Mode: Token")
        print(f"\n  Access URL:\n")
        print(f"    {access_url}")
        print(f"\n  Scan QR code to connect:\n")
        print_qr_code(access_url)

    print("\n" + "=" * 50 + "\n")

    uvicorn.run(app, host="0.0.0.0", port=port, log_level="warning")
