import threading
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from vibe_pentest.transport import MAX_BODY_BYTES, RequestError, get


@contextmanager
def target(status=200, body=b"{}", headers=None):
    hits = []

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            hits.append((self.path, self.headers.get("Authorization"), self.headers.get("Cookie")))
            self.send_response(status)
            for name, value in (headers or {}).items():
                self.send_header(name, value)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            try:
                self.wfile.write(body)
            except (BrokenPipeError, ConnectionResetError):
                pass

        def log_message(self, *args):
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_port}", hits
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


def test_redirect_never_leaks_bearer_token():
    with target() as (destination, destination_hits):
        with target(302, headers={"Location": destination}) as (url, hits):
            with pytest.raises(RequestError, match="Redirect"):
                get(url, "secret-sentinel", 1)
            assert len(hits) == 1
        assert destination_hits == []


def test_environment_proxy_is_ignored(monkeypatch):
    monkeypatch.setenv("http_proxy", "http://127.0.0.1:1")
    monkeypatch.setenv("HTTP_PROXY", "http://127.0.0.1:1")
    monkeypatch.setenv("NO_PROXY", "")
    with target() as (url, hits):
        assert get(url, "secret", 1).status == 200
        assert hits == [("/", "Bearer secret", None)]


def test_error_response_retains_body_for_evidence():
    with target(403, b'{"private":"leak"}') as (url, _):
        response = get(url, None, 1)
        assert response.status == 403
        assert b"leak" in response.body


def test_response_limit():
    with target(body=b"x" * (MAX_BODY_BYTES + 1)) as (url, _):
        with pytest.raises(RequestError, match="limit"):
            get(url, None, 1)


def test_compressed_body_is_inconclusive():
    with target(headers={"Content-Encoding": "gzip"}) as (url, _):
        with pytest.raises(RequestError, match="Compressed"):
            get(url, None, 1)
