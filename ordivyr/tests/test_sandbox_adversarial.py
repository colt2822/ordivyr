"""Adversarial sandbox tests: ToolBox escape attempts, SSRF guard, permission gates.

These are security tests — an agent under adversarial influence (malicious tool
output, prompt injection in file content) must not be able to escape the
working directory, reach private networks, or exceed its permissions.
"""
import http.server
import json
import socket
import threading

import pytest

from ordivyr.agentloop import ToolBox, fetch_url, ToolError


@pytest.fixture
def box(tmp_path):
    (tmp_path / "data.txt").write_text("secret-in-workdir")
    return ToolBox(tmp_path, write=True, web=False, ask=False)


# ---------------------------------------------------------------- path escapes
def test_absolute_path_rejected(box):
    assert box.call("read_file", {"path": "/etc/passwd"}).startswith("ERROR")


def test_parent_traversal_rejected(box):
    assert box.call("read_file", {"path": "../../etc/passwd"}).startswith("ERROR")
    assert box.call("read_file", {"path": "a/../../.."}).startswith("ERROR")


def test_symlink_escape_rejected(tmp_path, box):
    (tmp_path / "leak").symlink_to("/etc")
    assert box.call("read_file", {"path": "leak/passwd"}).startswith("ERROR")


def test_nul_byte_rejected(box):
    assert box.call("read_file", {"path": "a\0b"}).startswith("ERROR")


def test_write_outside_rejected(box):
    assert box.call("write_file", {"path": "../evil.txt", "content": "x"}).startswith("ERROR")
    assert not (box.root.parent / "evil.txt").exists()


def test_write_dotgit_rejected(box):
    assert box.call("write_file", {"path": ".git/config", "content": "x"}).startswith("ERROR")
    assert box.call("write_file", {"path": "sub/.git/hooks/x", "content": "x"}).startswith("ERROR")


def test_write_oversize_rejected(box):
    r = box.call("write_file", {"path": "big.txt", "content": "x" * 400_001})
    assert "too large" in r


def test_read_inside_ok(box):
    assert "secret-in-workdir" in box.call("read_file", {"path": "data.txt"})


# ---------------------------------------------------------------- permission gates
def test_write_requires_permission(tmp_path):
    ro = ToolBox(tmp_path, write=False, web=False, ask=False)
    assert "no file-write permission" in ro.call("write_file", {"path": "x.txt", "content": "y"})
    assert not (tmp_path / "x.txt").exists()


def test_web_requires_permission(tmp_path):
    nw = ToolBox(tmp_path, write=False, web=False, ask=False)
    assert "no web permission" in nw.call("fetch_url", {"url": "https://example.com"})


def test_unknown_tool(box):
    assert "unknown tool" in box.call("rm_rf_everything", {})


# ---------------------------------------------------------------- SSRF guard
class _FakeConn:
    def __init__(self):
        self.requests = []

    def __getattr__(self, name):
        raise AttributeError(name)


def test_ssrf_blocks_private(monkeypatch):
    import ipaddress
    monkeypatch.setattr(socket, "getaddrinfo", lambda *a, **k: [(socket.AF_INET, None, None, "", ("127.0.0.1", 0))])
    with pytest.raises(ToolError, match="private or local"):
        fetch_url("http://example.com/")
    monkeypatch.setattr(socket, "getaddrinfo", lambda *a, **k: [(socket.AF_INET, None, None, "", ("169.254.169.254", 0))])
    with pytest.raises(ToolError, match="private or local"):
        fetch_url("http://example.com/latest/meta-data/")


def test_ssrf_blocks_metadata_style_dns(monkeypatch):
    # DNS returning multiple IPs where one is private -> blocked (all must be global)
    monkeypatch.setattr(socket, "getaddrinfo", lambda *a, **k: [
        (socket.AF_INET, None, None, "", ("8.8.8.8", 0)), (socket.AF_INET, None, None, "", ("10.0.0.1", 0))])
    with pytest.raises(ToolError, match="private or local"):
        fetch_url("http://rebind.example/")


def test_fetch_rejects_credentials_and_scheme():
    with pytest.raises(ToolError):
        fetch_url("ftp://example.com/x")
    with pytest.raises(ToolError):
        fetch_url("http://user:pass@example.com/")
    with pytest.raises(ToolError):
        fetch_url("file:///etc/passwd")
