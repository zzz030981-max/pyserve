# pyserve

One-command local file sharing server with QR code.

## Install

```bash
pip install pyserve
```

Or run directly:

```bash
python pyserve.py [directory] [options]
```

## Usage

```bash
# Serve current directory
pyserve

# Serve specific directory
pyserve ~/Downloads

# Custom port
pyserve -p 9000

# Enable file upload
pyserve --upload

# Require auth token
pyserve --auth my-secret-token
```

## Features

- One command to start sharing files on local network
- Auto-generate QR code for mobile access
- Clean web UI with file browsing
- File upload support (optional)
- Auth token protection (optional)
- No external dependencies (except qrcode for QR)

## Options

| Option | Description |
|--------|-------------|
| `-p, --port` | Port (default: 8000) |
| `--host` | Host (default: 0.0.0.0) |
| `--upload` | Enable file upload |
| `--auth TOKEN` | Require auth token |

## QR Code

Visit `http://localhost:8000/_qr` to see QR code for mobile access.

## License

MIT
