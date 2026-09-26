from __future__ import annotations

import gzip
import http.server
import json
import threading
from pathlib import Path
from typing import cast

import pytest
import requests

from routesentinel import io
from routesentinel.rpki import VrpFileError, load_vrps_json

PAYLOAD = json.dumps(
    {"roas": [{"prefix": "203.0.113.0/24", "asn": "AS64500", "maxLength": 24}]},
    separators=(",", ":"),
).encode()


class _Server(http.server.ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.hits: dict[str, int] = {}


class _Handler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def _state(self) -> _Server:
        return cast(_Server, self.server)

    def log_message(self, format, *args):  # http.server API
        pass

    def _send(self, body: bytes, announced: int | None = None) -> None:
        self.send_response(200)
        self.send_header("Content-Type", "application/octet-stream")
        self.send_header(
            "Content-Length", str(announced if announced is not None else len(body))
        )
        self.end_headers()
        self.wfile.write(body)
        self.wfile.flush()

    def do_GET(self) -> None:  # http.server API
        route = self.path
        state = self._state()
        state.hits[route] = state.hits.get(route, 0) + 1
        if route == "/ok":
            self._send(PAYLOAD)
        elif route == "/short":
            # announces more bytes than it sends, then drops the connection
            self._send(PAYLOAD[:12], announced=len(PAYLOAD) + 64)
            self.close_connection = True
        elif route == "/cut-json":
            # honest Content-Length, but the JSON document never closes
            self._send(PAYLOAD[:20])
        elif route == "/gzipped":
            # CDN behaviour: the body is gzipped, so Content-Length counts compressed bytes
            compressed = gzip.compress(PAYLOAD)
            self.send_response(200)
            self.send_header("Content-Type", "application/octet-stream")
            self.send_header("Content-Encoding", "gzip")
            self.send_header("Content-Length", str(len(compressed)))
            self.end_headers()
            self.wfile.write(compressed)
            self.wfile.flush()
        elif route == "/flaky":
            if state.hits[route] == 1:
                self._send(PAYLOAD[:12], announced=len(PAYLOAD) + 64)
                self.close_connection = True
            else:
                self._send(PAYLOAD)
        else:
            self.send_response(404)
            self.send_header("Content-Length", "0")
            self.end_headers()


@pytest.fixture()
def base_url():
    server = _Server(("127.0.0.1", 0), _Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_address[1]}", server
    finally:
        server.shutdown()
        server.server_close()


@pytest.fixture(autouse=True)
def _no_backoff(monkeypatch):
    monkeypatch.setattr(io, "RETRY_BACKOFF_SECONDS", 0.0)


def test_successful_download_lands_in_target(tmp_path: Path, base_url):
    url, _ = base_url
    target = tmp_path / "vrps.json"

    result = io.download_file(f"{url}/ok", target, retries=1)

    assert result == target
    assert target.read_bytes() == PAYLOAD
    assert not (tmp_path / "vrps.json.part").exists()


def test_short_read_is_retried_and_not_kept(tmp_path: Path, base_url):
    url, server = base_url
    target = tmp_path / "bview.json"

    with pytest.raises((io.DownloadIntegrityError, requests.RequestException)):
        io.download_file(f"{url}/short", target, retries=2)

    assert server.hits["/short"] == 2, "every attempt is a fresh request"
    assert not target.exists(), "a short body must never become the target file"
    assert not (tmp_path / "bview.json.part").exists()


def test_retry_recovers_on_second_attempt(tmp_path: Path, base_url):
    url, server = base_url
    target = tmp_path / "vrps.json"

    io.download_file(f"{url}/flaky", target, retries=3)

    assert server.hits["/flaky"] == 2
    assert target.read_bytes() == PAYLOAD
    assert not (tmp_path / "vrps.json.part").exists()


def test_unterminated_json_is_rejected_even_with_full_body(tmp_path: Path, base_url):
    url, _ = base_url
    target = tmp_path / "vrps.json"

    with pytest.raises(io.DownloadIntegrityError):
        io.download_file(f"{url}/cut-json", target, retries=2)

    assert not target.exists()


def test_client_errors_are_not_retried(tmp_path: Path, base_url):
    url, server = base_url
    target = tmp_path / "vrps.json"

    with pytest.raises(requests.HTTPError):
        io.download_file(f"{url}/missing", target, retries=3)

    assert server.hits["/missing"] == 1


def test_compressed_body_is_not_read_as_a_short_read(tmp_path: Path, base_url):
    """Regression: rpki-client.org serves vrps.json gzipped, so bytes on the wire != decoded size."""

    url, server = base_url
    target = tmp_path / "vrps.json"

    io.download_file(f"{url}/gzipped", target, retries=1)

    assert server.hits["/gzipped"] == 1, "a compressed body is a success, not a retry loop"
    assert target.read_bytes() == PAYLOAD


def test_vrp_loader_explains_truncated_dump(tmp_path: Path):
    broken = tmp_path / "vrps.json"
    broken.write_text(PAYLOAD.decode()[:25])

    with pytest.raises(VrpFileError) as excinfo:
        load_vrps_json(broken)

    assert "not a complete VRP dump" in str(excinfo.value)
