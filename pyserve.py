#!/usr/bin/env python3
"""pyserve - One-command local file sharing server with QR code."""

import argparse
import base64
import io
import json
import os
import secrets
import socket
import sys
import urllib.parse

from http.server import HTTPServer, SimpleHTTPRequestHandler

try:
    import qrcode
    HAS_QR = True
except ImportError:
    HAS_QR = False

VERSION = "1.0.2"

MAX_UPLOAD_SIZE = 100 * 1024 * 1024  # 100MB

STYLE = """<style>
*{margin:0;padding:0;box-sizing:border-box}
body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;background:#f5f5f5;color:#333}
.container{max-width:800px;margin:0 auto;padding:20px}
.header{background:#2563eb;color:#fff;padding:24px;border-radius:12px;margin-bottom:20px}
.header h1{font-size:24px;margin-bottom:4px}
.header p{opacity:.85;font-size:14px}
.card{background:#fff;border-radius:10px;padding:16px;margin-bottom:12px;box-shadow:0 1px 3px rgba(0,0,0,.08)}
.file-list{list-style:none}
.file-item{display:flex;align-items:center;padding:10px 0;border-bottom:1px solid #f0f0f0}
.file-item:last-child{border-bottom:none}
.file-icon{width:32px;height:32px;border-radius:6px;display:flex;align-items:center;justify-content:center;margin-right:12px;font-size:16px}
.file-icon.folder{background:#dbeafe}
.file-icon.file{background:#f3f4f6}
.file-name{flex:1}
.file-name a{color:#2563eb;text-decoration:none;font-weight:500}
.file-name a:hover{text-decoration:underline}
.file-meta{color:#9ca3af;font-size:13px}
.upload-zone{border:2px dashed #d1d5db;border-radius:10px;padding:30px;text-align:center;cursor:pointer;transition:all .2s}
.upload-zone:hover{border-color:#2563eb;background:#eff6ff}
.upload-zone.dragover{border-color:#2563eb;background:#eff6ff}
.upload-btn{background:#2563eb;color:#fff;border:none;padding:10px 24px;border-radius:8px;cursor:pointer;font-size:14px;margin-top:12px}
.upload-btn:hover{background:#1d4ed8}
.breadcrumb{display:flex;align-items:center;gap:8px;margin-bottom:16px;font-size:14px}
.breadcrumb a{color:#2563eb;text-decoration:none}
.qr-section{text-align:center;padding:20px}
.qr-section img{border-radius:8px}
.status{padding:8px 16px;border-radius:8px;font-size:13px;margin-bottom:12px}
.status.success{background:#d1fae5;color:#065f46}
.status.error{background:#fee2e2;color:#991b1b}
</style>"""


def get_local_ip():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "127.0.0.1"


def format_size(size):
    for unit in ["B", "KB", "MB", "GB"]:
        if size < 1024:
            return f"{size:.1f} {unit}"
        size /= 1024
    return f"{size:.1f} TB"


def escape_html(text):
    return text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace('"', "&quot;").replace("'", "&#39;")


def safe_path(base_dir, user_path):
    """Resolve user_path and ensure it stays within base_dir."""
    resolved = os.path.normpath(os.path.join(base_dir, user_path))
    resolved = os.path.realpath(resolved)
    base_real = os.path.realpath(base_dir)
    if not resolved.startswith(base_real + os.sep) and resolved != base_real:
        return None
    return resolved


def generate_qr_base64(url):
    if not HAS_QR:
        return ""
    qr = qrcode.QRCode(version=1, box_size=8, border=2)
    qr.add_data(url)
    qr.make(fit=True)
    img = qr.make_image(fill_color="#2563eb", back_color="white")
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    return "data:image/png;base64," + base64.b64encode(buf.getvalue()).decode()


def parse_multipart(content_type, body):
    """Simple multipart parser for file uploads."""
    boundary = None
    for part in content_type.split(";"):
        part = part.strip()
        if part.startswith("boundary="):
            boundary = part[9:].strip('"')
            break

    if not boundary:
        return None, None, None

    boundary_bytes = boundary.encode()
    parts = body.split(b"--" + boundary_bytes)

    filename = None
    file_data = None
    upload_path = "/"

    for part in parts:
        if b"Content-Disposition" not in part:
            continue

        header_end = part.find(b"\r\n\r\n")
        if header_end == -1:
            continue

        header = part[:header_end].decode("utf-8", errors="replace")
        content = part[header_end + 4:]
        if content.endswith(b"\r\n"):
            content = content[:-2]

        if 'name="file"' in header:
            for h in header.split(";"):
                h = h.strip()
                if h.startswith("filename="):
                    filename = h[10:].strip('"')
            file_data = content
        elif 'name="path"' in header:
            upload_path = content.decode("utf-8", errors="replace")

    return filename, file_data, upload_path


class PyServeHandler(SimpleHTTPRequestHandler):

    def __init__(self, *args, upload_enabled=False, auth_token=None, **kwargs):
        self.upload_enabled = upload_enabled
        self.auth_token = auth_token
        super().__init__(*args, **kwargs)

    def do_GET(self):
        if self.auth_token:
            token = self.headers.get("X-Auth-Token")
            if not token or not secrets.compare_digest(token, self.auth_token):
                self.send_error(401, "Unauthorized")
                return

        if self.path == "/_qr":
            self._serve_qr()
            return

        # Check path traversal for file access
        path = self.translate_path(self.path)
        base_real = os.path.realpath(os.getcwd())
        real_path = os.path.realpath(path)
        if not real_path.startswith(base_real + os.sep) and real_path != base_real:
            self.send_error(403, "Forbidden")
            return

        if os.path.isdir(path):
            self._serve_directory(path)
        else:
            super().do_GET()

    def do_POST(self):
        if self.auth_token:
            token = self.headers.get("X-Auth-Token")
            if not token or not secrets.compare_digest(token, self.auth_token):
                self.send_error(401, "Unauthorized")
                return

        if self.path == "/_upload" and self.upload_enabled:
            self._handle_upload()
        else:
            self.send_error(405, "Method Not Allowed")

    def _serve_qr(self):
        ip = get_local_ip()
        port = self.server.server_port
        url = f"http://{ip}:{port}"
        qr_data = generate_qr_base64(url)
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.end_headers()
        html_out = f"""<!DOCTYPE html><html><head><meta charset="utf-8"><title>QR</title>{STYLE}</head>
<body><div class="container"><div class="card qr-section">
<h2>Scan to Connect</h2><p style="margin:12px 0;color:#6b7280">{escape_html(url)}</p>
<img src="{qr_data}" alt="QR" width="200">
</div></div></body></html>"""
        self.wfile.write(html_out.encode())

    def _serve_directory(self, dir_path):
        url_path = urllib.parse.unquote(self.path)
        if not url_path.endswith("/"):
            url_path += "/"

        try:
            entries = os.listdir(dir_path)
        except PermissionError:
            self.send_error(403)
            return

        entries.sort(key=lambda x: (not os.path.isdir(os.path.join(dir_path, x)), x.lower()))

        parts = url_path.strip("/").split("/")
        breadcrumb = '<a href="/">Home</a>'
        current = ""
        for part in parts:
            if part:
                current += f"/{part}"
                breadcrumb += f' / <a href="{escape_html(current)}/">{escape_html(part)}</a>'

        file_items = ""
        for entry in entries:
            if entry.startswith("."):
                continue
            full_path = os.path.join(dir_path, entry)
            is_dir = os.path.isdir(full_path)
            icon = "DIR" if is_dir else "FILE"
            icon_class = "folder" if is_dir else "file"
            name = escape_html(entry)
            link = urllib.parse.quote(entry) + ("/" if is_dir else "")
            meta = "" if is_dir else format_size(os.path.getsize(full_path))

            file_items += f"""<li class="file-item">
<div class="file-icon {icon_class}">{icon}</div>
<div class="file-name"><a href="{link}">{name}</a></div>
<div class="file-meta">{meta}</div></li>"""

        upload_html = ""
        if self.upload_enabled:
            upload_html = """<div class="card">
<h3 style="margin-bottom:12px">Upload File</h3>
<div class="upload-zone" id="dropZone" onclick="document.getElementById('fileInput').click()">
<p>Drag files here or click to select</p>
<input type="file" id="fileInput" multiple style="display:none" onchange="uploadFiles(this.files)">
<button class="upload-btn">Select Files</button></div>
<div id="uploadStatus"></div></div>
<script>
const dz=document.getElementById('dropZone');
['dragenter','dragover'].forEach(e=>dz.addEventListener(e,ev=>{ev.preventDefault();dz.classList.add('dragover')}));
['dragleave','drop'].forEach(e=>dz.addEventListener(e,ev=>{ev.preventDefault();dz.classList.remove('dragover')}));
dz.addEventListener('drop',e=>uploadFiles(e.dataTransfer.files));
function esc(s){return s.replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;').replace(/'/g,'&#39;')}
async function uploadFiles(files){
const s=document.getElementById('uploadStatus');
for(const f of files){
const fd=new FormData();fd.append('file',f);fd.append('path',decodeURIComponent(location.pathname));
try{const r=await fetch('/_upload',{method:'POST',body:fd});const d=await r.json();
if(d.ok){s.innerHTML='<div class="status success">Uploaded: '+esc(f.name)+'</div>';setTimeout(()=>location.reload(),500);}
else{s.innerHTML='<div class="status error">'+esc(d.error||'Failed')+'</div>';}}
catch(e){s.innerHTML='<div class="status error">Network error</div>';}}}
</script>"""

        ip = get_local_ip()
        port = self.server.server_port
        url = f"http://{ip}:{port}"

        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.end_headers()

        content = f"""<!DOCTYPE html>
<html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>pyserve - {escape_html(url_path)}</title>{STYLE}</head>
<body><div class="container">
<div class="header"><h1>pyserve</h1><p>{escape_html(url)}</p></div>
<div class="card"><div class="breadcrumb">{breadcrumb}</div>
<ul class="file-list">{file_items or '<li style="padding:20px;text-align:center;color:#9ca3af">Empty</li>'}</ul></div>
{upload_html}</div></body></html>"""
        self.wfile.write(content.encode())

    def _handle_upload(self):
        content_type = self.headers.get("Content-Type", "")
        if "multipart/form-data" not in content_type:
            self._send_error_json(400, "Invalid content type")
            return

        try:
            content_length = int(self.headers.get("Content-Length", 0))
        except (ValueError, TypeError):
            self._send_error_json(400, "Invalid Content-Length")
            return
        if content_length > MAX_UPLOAD_SIZE:
            self._send_error_json(413, f"File too large (max {MAX_UPLOAD_SIZE // 1024 // 1024}MB)")
            return

        body = self.rfile.read(content_length)

        filename, file_data, upload_path = parse_multipart(content_type, body)

        if not filename or not file_data:
            self._send_error_json(400, "No file")
            return

        if len(file_data) > MAX_UPLOAD_SIZE:
            self._send_error_json(413, f"File too large (max {MAX_UPLOAD_SIZE // 1024 // 1024}MB)")
            return

        base_dir = os.getcwd()
        target_dir = safe_path(base_dir, upload_path)
        if not target_dir or not os.path.isdir(target_dir):
            self._send_error_json(400, "Invalid directory")
            return

        filename = os.path.basename(filename)
        if not filename or filename.startswith("."):
            self._send_error_json(400, "Invalid filename")
            return

        # Block dangerous file types
        dangerous_exts = {".exe", ".bat", ".cmd", ".com", ".msi", ".scr", ".ps1", ".vbs", ".js", ".jar", ".sh"}
        ext = os.path.splitext(filename)[1].lower()
        if ext in dangerous_exts:
            self._send_error_json(400, "File type not allowed")
            return

        target_path = os.path.join(target_dir, filename)
        target_real = os.path.realpath(target_path)
        dir_real = os.path.realpath(target_dir)
        if not target_real.startswith(dir_real + os.sep) and target_real != dir_real:
            self._send_error_json(400, "Invalid path")
            return

        try:
            with open(target_path, "wb") as f:
                f.write(file_data)
            self._json_response(True, f"Uploaded: {escape_html(filename)}")
        except Exception:
            self._send_error_json(500, "Upload failed")

    def _json_response(self, ok, message=""):
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(json.dumps({"ok": ok, "error": message if not ok else None}).encode())

    def _send_error_json(self, code, message):
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(json.dumps({"ok": False, "error": message}).encode())

    def log_message(self, format, *args):
        pass


def create_handler(upload_enabled=False, auth_token=None):
    def handler(*args, **kwargs):
        kwargs["upload_enabled"] = upload_enabled
        kwargs["auth_token"] = auth_token
        return PyServeHandler(*args, **kwargs)
    return handler


def main():
    parser = argparse.ArgumentParser(
        prog="pyserve",
        description="One-command local file sharing server with QR code",
    )
    parser.add_argument("directory", nargs="?", default=".", help="Directory to serve")
    parser.add_argument("-p", "--port", type=int, default=8000, help="Port (default: 8000)")
    parser.add_argument("--host", default="0.0.0.0", help="Host (default: 0.0.0.0)")
    parser.add_argument("--upload", action="store_true", help="Enable file upload")
    parser.add_argument("--auth", metavar="TOKEN", help="Require auth token")
    parser.add_argument("--version", action="version", version=f"pyserve {VERSION}")
    args = parser.parse_args()

    directory = os.path.abspath(args.directory)
    if not os.path.isdir(directory):
        print(f"Error: '{directory}' is not a directory", file=sys.stderr)
        sys.exit(1)

    os.chdir(directory)
    handler = create_handler(upload_enabled=args.upload, auth_token=args.auth)
    server = HTTPServer((args.host, args.port), handler)

    ip = get_local_ip()
    url = f"http://{ip}:{args.port}"

    print(f"  pyserve v{VERSION}")
    print(f"  Local:   http://localhost:{args.port}")
    print(f"  Network: {url}")
    print(f"  Dir:     {directory}")
    print(f"  Upload:  {'Enabled' if args.upload else 'Disabled'}")
    print(f"  QR code: http://localhost:{args.port}/_qr")
    print(f"  Press Ctrl+C to stop\n")

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nStopped")
        server.shutdown()


if __name__ == "__main__":
    main()
