import socket

from aegis.plugins.builtin.service.plugin import (
    grab_banner,
)

class FakeSocket:
    def __init__(self, data: bytes):
        self.data = data

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        return False

    def settimeout(self, timeout):
        pass

    def recv(self, max_bytes):
        return self.data[:max_bytes]

def test_grab_banner(monkeypatch):
    fake_socket = FakeSocket(
        b"SSH-2.0-OpenSSH_9.6\r\n"
    )

    monkeypatch.setattr(
        socket,
        "create_connection",
        lambda *args, **kwargs: fake_socket,
    )

    banner = grab_banner(
        "example.com",
        22,
    )

    assert banner == "SSH-2.0-OpenSSH_9.6"

def test_grab_banner_returns_none_when_empty(
    monkeypatch,
):
    fake_socket = FakeSocket(b"")

    monkeypatch.setattr(
        socket,
        "create_connection",
        lambda *args, **kwargs: fake_socket,
    )

    banner = grab_banner(
        "example.com",
        22,
    )

    assert banner is None

def test_grab_banner_limits_bytes(
    monkeypatch,
):
    fake_socket = FakeSocket(
        b"A" * 1000
    )

    monkeypatch.setattr(
        socket,
        "create_connection",
        lambda *args, **kwargs: fake_socket,
    )

    banner = grab_banner(
        "example.com",
        22,
        max_bytes=32,
    )

    assert banner == "A" * 32

def test_grab_banner_handles_connection_error(
    monkeypatch,
):
    def fail(*args, **kwargs):
        raise OSError("connection failed")

    monkeypatch.setattr(
        socket,
        "create_connection",
        fail,
    )

    banner = grab_banner(
        "example.com",
        22,
    )

    assert banner is None