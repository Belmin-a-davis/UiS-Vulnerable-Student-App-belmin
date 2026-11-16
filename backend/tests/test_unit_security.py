"""Pure unit tests (no running app needed):  pytest tests/test_unit_security.py

Run from the repository root; `backend` is put on sys.path so `app.security` imports.
"""
import os
import socket
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "backend"))
from app.security import UnsafeURL, validate_outbound_url, like_pattern  # noqa: E402


def fake_resolver(mapping):
    def _r(host, port, proto=0):
        if host not in mapping:
            raise socket.gaierror("nx")
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (ip, port)) for ip in mapping[host]]
    return _r


OK = fake_resolver({"example.com": ["93.184.216.34"]})


class TestValidateOutboundUrl:

    def test_public_http_and_https_allowed(self):
        assert validate_outbound_url("http://example.com/a", OK)
        assert validate_outbound_url("https://example.com/a", OK)

    @pytest.mark.parametrize("ip", [
        "127.0.0.1", "127.1.2.3", "10.1.2.3", "172.16.5.5", "192.168.0.1",
        "169.254.169.254", "0.0.0.0", "100.64.0.1", "::1", "fe80::1", "fc00::1",
        "::ffff:127.0.0.1", "224.0.0.1",
    ])
    def test_private_and_special_addresses_blocked(self, ip):
        r = fake_resolver({"evil.test": [ip]})
        with pytest.raises(UnsafeURL):
            validate_outbound_url("http://evil.test/", r)

    def test_dns_name_with_mixed_public_and_private_records_blocked(self):
        r = fake_resolver({"mix.test": ["93.184.216.34", "127.0.0.1"]})
        with pytest.raises(UnsafeURL):
            validate_outbound_url("http://mix.test/", r)

    @pytest.mark.parametrize("url", [
        "file:///etc/passwd", "ftp://example.com/", "gopher://example.com/", "javascript:alert(1)",
        "http://", "//example.com", "http://user:pw@example.com/", "http://example.com:22/",
        "http://example.com:99999/", "example.com",
    ])
    def test_bad_scheme_credentials_ports_blocked(self, url):
        with pytest.raises(UnsafeURL):
            validate_outbound_url(url, OK)

    def test_unresolvable_host_blocked(self):
        with pytest.raises(UnsafeURL):
            validate_outbound_url("http://nx.invalid/", OK)

    @pytest.mark.parametrize("url", ["http://2130706433/", "http://0x7f000001/", "http://017700000001/", "http://127.1/"])
    def test_ip_obfuscation_forms_blocked_with_real_resolver(self, url):
        # uses the real getaddrinfo, which normalises these to 127.0.0.1
        with pytest.raises(UnsafeURL):
            validate_outbound_url(url)


def test_like_pattern_escapes_wildcards():
    assert like_pattern("a%b_c\\d") == "%a\\%b\\_c\\\\d%"
    assert like_pattern("") == "%%"
