"""Unit tests for ShadowsEye — mocked DNS/socket/network only (no live scans)."""

from __future__ import annotations

import io
import socket
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

import shadowseye as se

FIXTURES = Path(__file__).parent / "fixtures"
TINY_WORDLIST = FIXTURES / "tiny_wordlist.txt"


def test_resolve_host_success():
    fake = [
        (
            socket.AF_INET,
            socket.SOCK_STREAM,
            6,
            "",
            ("93.184.216.34", 0),
        )
    ]
    with patch("socket.getaddrinfo", return_value=fake) as mock_gai:
        assert se.resolve_host("example.com") == "93.184.216.34"
        mock_gai.assert_called_once()
        args, kwargs = mock_gai.call_args
        assert args[0] == "example.com"
        assert kwargs.get("family") == socket.AF_INET or (
            len(args) > 2 and args[2] == socket.AF_INET
        )


def test_resolve_host_failure():
    with patch("socket.getaddrinfo", side_effect=socket.gaierror("nxdomain")):
        assert se.resolve_host("no-such.lab") is None


def test_bruteforce_uses_dns_not_inet_aton():
    """Regression: old code called inet_aton on hostnames and never discovered."""
    resolved = {"www.lab.example": "10.0.0.1", "api.lab.example": "10.0.0.2"}

    def fake_resolve(hostname: str):
        return resolved.get(hostname)

    buf = io.StringIO()
    with patch.object(se, "resolve_host", side_effect=fake_resolve):
        with patch("socket.inet_aton") as mock_aton:
            found = se.bruteforce_subdomains(
                "lab.example", str(TINY_WORDLIST), stream=buf
            )
            mock_aton.assert_not_called()

    assert "www.lab.example" in found
    assert "api.lab.example" in found
    assert "mail.lab.example" not in found
    assert "nonexistent-xyz-lab.lab.example" not in found
    assert len(found) == 2


def test_bruteforce_empty_when_nothing_resolves():
    buf = io.StringIO()
    with patch.object(se, "resolve_host", return_value=None):
        found = se.bruteforce_subdomains(
            "lab.example", str(TINY_WORDLIST), stream=buf
        )
    assert found == []


def test_dns_lookup_prints_success_and_failure():
    buf = io.StringIO()
    with patch.object(se, "resolve_host", return_value="127.0.0.1"):
        assert se.dns_lookup("lab.local", stream=buf) == "127.0.0.1"
    assert "resolves to 127.0.0.1" in buf.getvalue()

    buf2 = io.StringIO()
    with patch.object(se, "resolve_host", return_value=None):
        assert se.dns_lookup("missing.local", stream=buf2) is None
    assert "failed" in buf2.getvalue().lower()


def test_port_scan_reports_open_ports():
    buf = io.StringIO()

    class FakeSock:
        def __init__(self, *a, **k):
            self._port = None

        def settimeout(self, t):
            pass

        def connect_ex(self, addr):
            host, port = addr
            # pretend only 80 is open
            return 0 if port == 80 else 1

        def close(self):
            pass

    with patch("socket.socket", FakeSock):
        open_ports = se.port_scan("127.0.0.1", (79, 81), stream=buf)

    assert open_ports == [80]
    assert "127.0.0.1:80" in buf.getvalue()


def test_parse_port_range():
    assert se.parse_port_range("1-100") == (1, 100)
    with pytest.raises(ValueError):
        se.parse_port_range("80")
    with pytest.raises(ValueError):
        se.parse_port_range("100-1")


def test_banner_authorized_tone():
    text = se.BANNER.lower()
    assert "authorized" in text
    assert "malevolent" not in text
    assert "chaos" not in text
    assert "darkest corners" not in text


def test_cli_help_exits_zero():
    with pytest.raises(SystemExit) as exc:
        se.build_parser().parse_args(["--help"])
    # argparse --help exits 0
    assert exc.value.code == 0


def test_main_dns_only_with_mocks(tmp_path):
    wl = tmp_path / "w.txt"
    wl.write_text("www\n", encoding="utf-8")
    buf = io.StringIO()

    with patch.object(se, "resolve_host", return_value="127.0.0.1"):
        with patch.object(se, "port_scan", return_value=[]):
            with patch.object(se, "authorized_banner"):
                with patch("sys.stdout", buf):
                    code = se.main(
                        [
                            "lab.example",
                            "--wordlist",
                            str(wl),
                            "--ports",
                            "80-80",
                            "--dns-only",
                            "--quiet-banner",
                        ]
                    )
    assert code == 0
