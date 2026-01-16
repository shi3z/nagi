#!/usr/bin/env python3
"""Nagi - Web-based terminal for iOS/iPad with touch-friendly controls."""

import asyncio
import fcntl
import json
import logging
import mimetypes
import os
import pty
import re
import secrets
import socket
import struct
import subprocess
import sys
import termios
from datetime import datetime
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
from fastapi.responses import HTMLResponse, RedirectResponse, JSONResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles

# Base directory for resolving paths (PyInstaller compatible)
if getattr(sys, 'frozen', False):
    BASE_DIR = Path(sys._MEIPASS)
else:
    BASE_DIR = Path(__file__).parent.resolve()

# Load config
USER_CONFIG_PATH = Path.home() / ".nagi" / "config.json"
LOCAL_CONFIG_PATH = BASE_DIR / "config.json"
DEFAULT_CONFIG = {
    "startup_command": "tmux a || tmux new",
    "shell": "/bin/bash",
    "port": 8765
}

def load_config():
    """Load configuration from config.json. ~/.nagi/config.json takes priority."""
    # Check ~/.nagi/config.json first
    for config_path in [USER_CONFIG_PATH, LOCAL_CONFIG_PATH]:
        if config_path.exists():
            try:
                with open(config_path) as f:
                    config = json.load(f)
                    return {**DEFAULT_CONFIG, **config}
            except Exception:
                pass
    return DEFAULT_CONFIG

config = load_config()

# Color schemes (16 variations)
COLOR_SCHEMES = [
    {"name": "crimson",   "bg": "#1a1a2e", "panel": "#16213e", "accent": "#e94560", "cursor": "#e94560"},
    {"name": "emerald",   "bg": "#1a2e1a", "panel": "#163e16", "accent": "#45e960", "cursor": "#45e960"},
    {"name": "azure",     "bg": "#1a1a2e", "panel": "#162e3e", "accent": "#4560e9", "cursor": "#4560e9"},
    {"name": "amber",     "bg": "#2e2a1a", "panel": "#3e3616", "accent": "#e9c545", "cursor": "#e9c545"},
    {"name": "violet",    "bg": "#2a1a2e", "panel": "#36163e", "accent": "#c545e9", "cursor": "#c545e9"},
    {"name": "cyan",      "bg": "#1a2e2e", "panel": "#163e3e", "accent": "#45e9e9", "cursor": "#45e9e9"},
    {"name": "coral",     "bg": "#2e1a1a", "panel": "#3e1616", "accent": "#e96045", "cursor": "#e96045"},
    {"name": "lime",      "bg": "#262e1a", "panel": "#2e3e16", "accent": "#c5e945", "cursor": "#c5e945"},
    {"name": "pink",      "bg": "#2e1a26", "panel": "#3e162e", "accent": "#e945c5", "cursor": "#e945c5"},
    {"name": "sky",       "bg": "#1a262e", "panel": "#162e3e", "accent": "#45c5e9", "cursor": "#45c5e9"},
    {"name": "orange",    "bg": "#2e261a", "panel": "#3e2e16", "accent": "#e98945", "cursor": "#e98945"},
    {"name": "mint",      "bg": "#1a2e26", "panel": "#163e2e", "accent": "#45e9c5", "cursor": "#45e9c5"},
    {"name": "rose",      "bg": "#2e1a22", "panel": "#3e1628", "accent": "#e94589", "cursor": "#e94589"},
    {"name": "teal",      "bg": "#1a2e2a", "panel": "#163e36", "accent": "#45e9a5", "cursor": "#45e9a5"},
    {"name": "gold",      "bg": "#2e2e1a", "panel": "#3e3e16", "accent": "#e9e945", "cursor": "#e9e945"},
    {"name": "lavender",  "bg": "#261a2e", "panel": "#2e163e", "accent": "#a545e9", "cursor": "#a545e9"},
]

def get_color_scheme(scheme_id=None):
    """Get color scheme by ID (0-15) or name. Auto-selects based on port if not specified."""
    if scheme_id is None:
        scheme_id = config.get("color_scheme", None)

    if scheme_id is None:
        # Auto-select based on port number
        port = config.get("port", 8765)
        scheme_id = port % 16
    elif isinstance(scheme_id, str):
        # Find by name
        for i, scheme in enumerate(COLOR_SCHEMES):
            if scheme["name"] == scheme_id.lower():
                scheme_id = i
                break
        else:
            scheme_id = 0

    return COLOR_SCHEMES[scheme_id % 16]

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

# File browser configuration
TEXT_EXTENSIONS = {
    '.py', '.js', '.ts', '.jsx', '.tsx', '.html', '.css', '.scss',
    '.json', '.xml', '.yaml', '.yml', '.md', '.txt', '.sh', '.bash',
    '.c', '.cpp', '.h', '.hpp', '.java', '.go', '.rs', '.rb', '.php',
    '.sql', '.env', '.conf', '.ini', '.toml', '.gitignore', '.dockerfile',
    '.vue', '.svelte', '.astro', '.lock', '.csv', '.log'
}
VIDEO_EXTENSIONS = {'.mp4', '.webm', '.mov', '.avi', '.mkv', '.m4v'}
IMAGE_EXTENSIONS = {'.png', '.jpg', '.jpeg', '.gif', '.svg', '.webp', '.bmp', '.ico'}
MAX_FILE_SIZE = 2 * 1024 * 1024  # 2MB for text files


def verify_auth_with_request(token: str, request: Request) -> tuple[bool, Optional[dict]]:
    """Verify authentication token or Tailscale IP. Returns (is_valid, user_info)."""
    if AUTH_MODE == "tailscale":
        # First try session token
        user_info = verify_session(token) if token else None
        if user_info:
            return (True, user_info)
        # Fall back to Tailscale IP verification
        client_ip = request.client.host if request.client else None
        if client_ip:
            user_info = get_tailscale_user(client_ip)
            if user_info and is_user_allowed(user_info):
                return (True, user_info)
        return (False, None)
    else:
        return (token == AUTH_TOKEN, None)


@app.get("/api/files")
async def list_files(
    request: Request,
    token: str = Query(None),
    path: str = Query(None),
    show_hidden: bool = Query(False)
):
    """List files in a directory."""
    is_valid, _ = verify_auth_with_request(token, request)
    if not is_valid:
        return JSONResponse(status_code=401, content={"error": "Unauthorized"})

    # Default to home directory
    target_path = Path(path) if path else Path.home()

    # Security: resolve and validate path
    try:
        target_path = target_path.resolve()
    except Exception:
        return JSONResponse(status_code=400, content={"error": "Invalid path"})

    if not target_path.exists() or not target_path.is_dir():
        return JSONResponse(status_code=404, content={"error": "Directory not found"})

    items = []
    try:
        for item in sorted(target_path.iterdir(), key=lambda x: (not x.is_dir(), x.name.lower())):
            if not show_hidden and item.name.startswith('.'):
                continue

            try:
                stat = item.stat()
                items.append({
                    "name": item.name,
                    "type": "directory" if item.is_dir() else "file",
                    "size": stat.st_size if item.is_file() else None,
                    "modified": datetime.fromtimestamp(stat.st_mtime).isoformat(),
                    "extension": item.suffix.lower() if item.is_file() else None
                })
            except (PermissionError, OSError):
                # Skip files we can't access
                continue
    except PermissionError:
        return JSONResponse(status_code=403, content={"error": "Permission denied"})

    return {
        "path": str(target_path),
        "parent": str(target_path.parent) if target_path != target_path.parent else None,
        "items": items
    }


@app.get("/api/file")
async def get_file_content(
    request: Request,
    token: str = Query(None),
    path: str = Query(...)
):
    """Get content of a text file."""
    is_valid, _ = verify_auth_with_request(token, request)
    if not is_valid:
        return JSONResponse(status_code=401, content={"error": "Unauthorized"})

    try:
        file_path = Path(path).resolve()
    except Exception:
        return JSONResponse(status_code=400, content={"error": "Invalid path"})

    if not file_path.exists() or not file_path.is_file():
        return JSONResponse(status_code=404, content={"error": "File not found"})

    if file_path.stat().st_size > MAX_FILE_SIZE:
        return JSONResponse(status_code=413, content={"error": "File too large (max 1MB)"})

    # MIME type detection
    mime_type, _ = mimetypes.guess_type(str(file_path))

    # Check if text file
    is_text = (
        file_path.suffix.lower() in TEXT_EXTENSIONS or
        (mime_type and mime_type.startswith('text/'))
    )

    if not is_text:
        return JSONResponse(status_code=415, content={"error": "Not a text file"})

    try:
        content = file_path.read_text(encoding='utf-8')
    except UnicodeDecodeError:
        try:
            content = file_path.read_text(encoding='latin-1')
        except Exception:
            return JSONResponse(status_code=415, content={"error": "Cannot decode file"})

    return {
        "path": str(file_path),
        "name": file_path.name,
        "extension": file_path.suffix.lower(),
        "content": content,
        "size": file_path.stat().st_size,
        "mime_type": mime_type
    }


@app.get("/api/video")
async def stream_video(
    request: Request,
    token: str = Query(None),
    path: str = Query(...)
):
    """Stream a video file with Range request support."""
    is_valid, _ = verify_auth_with_request(token, request)
    if not is_valid:
        return JSONResponse(status_code=401, content={"error": "Unauthorized"})

    try:
        file_path = Path(path).resolve()
    except Exception:
        return JSONResponse(status_code=400, content={"error": "Invalid path"})

    if not file_path.exists() or not file_path.is_file():
        return JSONResponse(status_code=404, content={"error": "File not found"})

    if file_path.suffix.lower() not in VIDEO_EXTENSIONS:
        return JSONResponse(status_code=415, content={"error": "Not a video file"})

    file_size = file_path.stat().st_size
    mime_type, _ = mimetypes.guess_type(str(file_path))
    mime_type = mime_type or 'video/mp4'

    # Handle Range header
    range_header = request.headers.get('range')

    if range_header:
        range_match = re.match(r'bytes=(\d+)-(\d*)', range_header)
        if range_match:
            start = int(range_match.group(1))
            end = int(range_match.group(2)) if range_match.group(2) else file_size - 1
            end = min(end, file_size - 1)

            def iter_file():
                with open(file_path, 'rb') as f:
                    f.seek(start)
                    remaining = end - start + 1
                    while remaining > 0:
                        chunk_size = min(8192, remaining)
                        data = f.read(chunk_size)
                        if not data:
                            break
                        remaining -= len(data)
                        yield data

            return StreamingResponse(
                iter_file(),
                status_code=206,
                media_type=mime_type,
                headers={
                    'Content-Range': f'bytes {start}-{end}/{file_size}',
                    'Accept-Ranges': 'bytes',
                    'Content-Length': str(end - start + 1)
                }
            )

    # No Range header - return full file
    def iter_full_file():
        with open(file_path, 'rb') as f:
            while chunk := f.read(8192):
                yield chunk

    return StreamingResponse(
        iter_full_file(),
        media_type=mime_type,
        headers={
            'Accept-Ranges': 'bytes',
            'Content-Length': str(file_size)
        }
    )


@app.get("/api/image")
async def get_image(
    request: Request,
    token: str = Query(None),
    path: str = Query(...)
):
    """Serve an image file."""
    is_valid, _ = verify_auth_with_request(token, request)
    if not is_valid:
        return JSONResponse(status_code=401, content={"error": "Unauthorized"})

    try:
        file_path = Path(path).resolve()
    except Exception:
        return JSONResponse(status_code=400, content={"error": "Invalid path"})

    if not file_path.exists() or not file_path.is_file():
        return JSONResponse(status_code=404, content={"error": "File not found"})

    if file_path.suffix.lower() not in IMAGE_EXTENSIONS:
        return JSONResponse(status_code=415, content={"error": "Not an image file"})

    mime_type, _ = mimetypes.guess_type(str(file_path))
    mime_type = mime_type or 'image/png'

    def iter_file():
        with open(file_path, 'rb') as f:
            while chunk := f.read(8192):
                yield chunk

    return StreamingResponse(
        iter_file(),
        media_type=mime_type,
        headers={
            'Content-Length': str(file_path.stat().st_size),
            'Cache-Control': 'max-age=3600'
        }
    )


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

    # Get color scheme
    scheme = get_color_scheme()
    color_css = f'''<style>:root{{--nagi-bg:{scheme["bg"]};--nagi-panel:{scheme["panel"]};--nagi-accent:{scheme["accent"]};--nagi-cursor:{scheme["cursor"]};}}</style>'''

    inject_script = f'{color_css}<script>window.NAGI_TOKEN="{session_token}";window.NAGI_HOST="{hostname}";window.NAGI_IP="{ip_addr}";window.NAGI_USER="{user_display}";window.NAGI_SCHEME={json.dumps(scheme)};</script></head>'
    html_content = html_content.replace("</head>", inject_script)

    # Load custom buttons from ~/.nagi/buttons.html
    custom_buttons_path = Path.home() / ".nagi" / "buttons.html"
    default_buttons = '''<div class="button-row">
    <button class="btn" data-cmd="yes">yes</button>
    <button class="btn" data-cmd="git add -A && git commit -m 'update' && git push">commit &amp; push</button>
</div>'''
    if custom_buttons_path.exists():
        try:
            custom_buttons = custom_buttons_path.read_text()
            html_content = html_content.replace("<!-- CUSTOM_BUTTONS -->", custom_buttons)
        except Exception:
            html_content = html_content.replace("<!-- CUSTOM_BUTTONS -->", default_buttons)
    else:
        html_content = html_content.replace("<!-- CUSTOM_BUTTONS -->", default_buttons)

    return HTMLResponse(
        content=html_content,
        headers={"Cache-Control": "no-cache, no-store, must-revalidate"}
    )


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
    import argparse
    import uvicorn

    # Parse command line arguments
    parser = argparse.ArgumentParser(description="Nagi - Touch-friendly Web Terminal")
    parser.add_argument("-p", "--port", type=int, default=0, help="Port to listen on")
    parser.add_argument("-c", "--config", type=str, help="Path to config file")
    args = parser.parse_args()

    # Priority: CLI args > environment variable > config file > default
    port = args.port or int(os.environ.get("NAGI_PORT", 0)) or config.get("port", 8765)
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
