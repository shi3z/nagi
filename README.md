# Nagi

Touch-friendly web-based terminal optimized for vibe coding. Access your terminal from iPad/iPhone without a hardware keyboard and enjoy coding from anywhere - your couch, bed, or cafe.

Supports fullscreen applications like tmux and Claude Code.

> **Security**: Token-based authentication is enabled by default. A random access token is generated on startup and displayed with a QR code for easy mobile access.

**[日本語版 README](README.ja.md)**

<img src="images/mainvisual.png" width="600">

## Features

- **Touch-optimized**: Fully usable without a hardware keyboard
- **Special keys**: Ctrl, Alt, Esc, Tab, Enter, Arrow keys, etc.
- **tmux support**: Quick button panel for tmux operations
- **Text input**: Modal for pasting long text or CJK characters
- **Auto-execute**: Run commands automatically on connection
- **Token auth**: Secure access with auto-generated token
- **QR code**: Scan to connect from your phone instantly
- **xterm.js**: Full-featured terminal emulation

## Installation

### npm (Recommended)

```bash
npm install -g nagi-terminal
```

### Manual Installation

```bash
git clone https://github.com/shi3z/nagi.git
cd nagi
uv sync
```

## Usage

### npm

```bash
nagi
nagi -p 8080  # Custom port
nagi -c /path/to/config.json  # Custom config file
```

### Manual

```bash
uv run python main.py
```

On startup, the access URL with token and QR code will be displayed. Scan the QR code with your phone to connect instantly.

## Configuration

Edit `config.json`:

```json
{
    "startup_command": "tmux a || tmux new",
    "shell": "/bin/bash",
    "port": 8765
}
```

| Option | Description | Default |
|--------|-------------|---------|
| `startup_command` | Command to run on connection | `tmux a \|\| tmux new` |
| `shell` | Shell to use | `/bin/bash` |
| `port` | Listen port | `8765` |
| `token` | Fixed access token (optional) | Random on startup |

You can also set `NAGI_TOKEN` environment variable to use a fixed token.

## Control Panel

### Basic Keys
- **Ctrl** / **Alt**: Modifier keys (toggle)
- **Esc** / **Tab** / **Enter**: Special keys
- **Arrow keys**: Cursor movement
- **Home** / **End** / **PgUp** / **PgDn**: Navigation

### Shortcuts
- **^C**: Interrupt (Ctrl+C)
- **^D**: EOF (Ctrl+D)
- **^Z**: Suspend (Ctrl+Z)

### tmux Panel
Expand with the `tmux` button:
- **c**: New window
- **n** / **p**: Next/Previous window
- **d**: Detach
- **%** / **"**: Split vertical/horizontal
- **o**: Switch pane
- **z**: Zoom
- **[**: Copy mode

### Text Input
Click the `Text` button to open a modal for pasting long text or CJK characters.

## Requirements

- Python 3.10+
- FastAPI
- uvicorn
- websockets

## License

MIT
