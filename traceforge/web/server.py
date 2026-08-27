import email
import http.server
import json
import mimetypes
import os
import socketserver
import urllib.parse
from pathlib import Path
from typing import Optional, Tuple

from traceforge.config import get_workspace_dir
from traceforge.web.router import Request, Response, Router
from traceforge.web.routes import register_all_routes
from traceforge.web.services import case_service


def get_static_dir() -> Path:
    """Returns absolute path to bundled static assets directory."""
    return Path(__file__).resolve().parent / "static"


def create_router() -> Router:
    """Instantiates router and registers all modular web endpoints."""
    router = Router()
    register_all_routes(router)
    return router


GLOBAL_ROUTER = create_router()


class TraceForgeHTTPHandler(http.server.BaseHTTPRequestHandler):
    """
    Lightweight, high-performance standard library HTTP request handler.
    Serves static UI assets and dispatches API requests through the modular router.
    """

    server_version = "TraceForge/1.0"

    def log_message(self, format: str, *args) -> None:
        # Suppress verbose standard library access logging
        pass

    def _send_cors_headers(self) -> None:
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, DELETE, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type, Authorization, X-Requested-With")

    def do_OPTIONS(self) -> None:
        self.send_response(204)
        self._send_cors_headers()
        self.end_headers()

    def _send_response(self, resp: Response) -> None:
        self.send_response(resp.status_code)
        self.send_header("Content-Type", resp.content_type)
        self.send_header("Content-Length", str(len(resp.body)))
        self.send_header("Connection", "close")
        self._send_cors_headers()
        for k, v in resp.headers.items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(resp.body)

    def _serve_static_file(self, rel_path: str) -> None:
        static_dir = get_static_dir().resolve()
        if not rel_path or rel_path == "/":
            rel_path = "index.html"
        else:
            rel_path = rel_path.lstrip("/")

        # Check for traversal attempts
        if ".." in rel_path:
            self.send_response(403)
            self.send_header("Content-Type", "text/plain")
            self.send_header("Connection", "close")
            self.end_headers()
            self.wfile.write(b"Access Denied: Path Traversal Prohibited")
            return

        target_file = (static_dir / rel_path).resolve()
        # Prevent directory climbing outside static directory
        try:
            target_file.relative_to(static_dir)
        except ValueError:
            self.send_response(403)
            self.send_header("Content-Type", "text/plain")
            self.send_header("Connection", "close")
            self.end_headers()
            self.wfile.write(b"Access Denied: Path Traversal Prohibited")
            return

        if not target_file.exists() or target_file.is_dir():
            target_file = static_dir / "index.html"

        if not target_file.exists():
            self.send_response(404)
            self.send_header("Content-Type", "text/plain")
            self.send_header("Connection", "close")
            self.end_headers()
            self.wfile.write(b"Static asset not found")
            return

        mime_type, _ = mimetypes.guess_type(str(target_file))
        if not mime_type:
            mime_type = "application/octet-stream"
        if target_file.suffix == ".js":
            mime_type = "application/javascript; charset=utf-8"
        elif target_file.suffix == ".css":
            mime_type = "text/css; charset=utf-8"
        elif target_file.suffix == ".html":
            mime_type = "text/html; charset=utf-8"

        with open(target_file, "rb") as f:
            content = f.read()

        self.send_response(200)
        self.send_header("Content-Type", mime_type)
        self.send_header("Content-Length", str(len(content)))
        self.send_header("Connection", "close")
        self._send_cors_headers()
        self.end_headers()
        self.wfile.write(content)


    def _handle_multipart_upload(self, case_id: str, content_type: str, body: bytes) -> Response:
        """Parses multipart/form-data upload and saves evidence specimen."""
        try:
            # Construct a message to parse MIME multipart
            msg_data = f"Content-Type: {content_type}\r\n\r\n".encode("utf-8") + body
            msg = email.message_from_bytes(msg_data)
            
            uploaded_record = None
            for part in msg.walk():
                fn = part.get_filename()
                if fn:
                    payload = part.get_payload(decode=True)
                    if payload:
                        rec = case_service.add_evidence(case_id, fn, payload)
                        if rec:
                            uploaded_record = rec

            if uploaded_record:
                return Response.json({"success": True, "evidence": uploaded_record}, status_code=201)
            return Response.error("No valid file payload found in upload", status_code=400)
        except Exception as e:
            return Response.error(f"Upload processing failed: {str(e)}", status_code=500)

    def do_GET(self) -> None:
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path
        query = dict(urllib.parse.parse_qsl(parsed.query))

        if path.startswith("/api/"):
            req = Request(method="GET", path=path, query_params=query, body=b"", headers=dict(self.headers))
            resp = GLOBAL_ROUTER.dispatch(req)
            if resp:
                self._send_response(resp)
            else:
                self._send_response(Response.error(f"API endpoint '{path}' not found", status_code=404))
        else:
            self._serve_static_file(path)

    def do_POST(self) -> None:
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path
        query = dict(urllib.parse.parse_qsl(parsed.query))

        content_len = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(content_len) if content_len > 0 else b""
        content_type = self.headers.get("Content-Type", "")

        # Check for multipart evidence upload: /api/cases/<case_id>/evidence/upload or /api/cases/<case_id>/evidence
        if "multipart/form-data" in content_type:
            parts = path.strip("/").split("/")
            if len(parts) >= 3 and parts[0] == "api" and parts[1] == "cases":
                case_id = parts[2]
                resp = self._handle_multipart_upload(case_id, content_type, body)
                self._send_response(resp)
                return

        req = Request(method="POST", path=path, query_params=query, body=body, headers=dict(self.headers))
        resp = GLOBAL_ROUTER.dispatch(req)
        if resp:
            self._send_response(resp)
        else:
            self._send_response(Response.error(f"API endpoint '{path}' not found", status_code=404))

    def do_DELETE(self) -> None:
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path
        query = dict(urllib.parse.parse_qsl(parsed.query))

        req = Request(method="DELETE", path=path, query_params=query, body=b"", headers=dict(self.headers))
        resp = GLOBAL_ROUTER.dispatch(req)
        if resp:
            self._send_response(resp)
        else:
            self._send_response(Response.error(f"API endpoint '{path}' not found", status_code=404))

    def do_HEAD(self) -> None:
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path
        if path.startswith("/api/"):
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Connection", "close")
            self._send_cors_headers()
            self.end_headers()
        else:
            self._serve_static_file(path)


def run_server(host: str = "127.0.0.1", port: int = 8000) -> None:
    """Runs the TraceForge localhost web server with concurrent request support."""
    server_address = (host, port)
    socketserver.ThreadingTCPServer.allow_reuse_address = True
    with socketserver.ThreadingTCPServer(server_address, TraceForgeHTTPHandler) as httpd:
        print(f"\n[*] TraceForge Web Console active at http://{host}:{port}")
        print(f"[*] Workspace Root: {get_workspace_dir()}")
        print("[*] Press Ctrl+C to terminate the console.\n")
        try:
            httpd.serve_forever()
        except KeyboardInterrupt:
            print("\n[+] TraceForge Web Console terminated.")



# Alias for backward compatibility
run_web_server = run_server
