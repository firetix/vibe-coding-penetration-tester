import socket

from utils.entitlements import extract_client_ip, is_valid_target_for_hosted


def test_extract_client_ip_ignores_forwarded_header_by_default():
    ip = extract_client_ip(
        remote_addr="198.51.100.7",
        x_forwarded_for="203.0.113.9, 198.51.100.4",
        trust_proxy_headers=False,
    )
    assert ip == "198.51.100.7"


def test_extract_client_ip_uses_forwarded_header_when_trusted():
    ip = extract_client_ip(
        remote_addr="198.51.100.7",
        x_forwarded_for="203.0.113.9, 198.51.100.4",
        trust_proxy_headers=True,
    )
    assert ip == "203.0.113.9"


def test_is_valid_target_for_hosted_blocks_hostname_resolving_to_private_ip(monkeypatch):
    def fake_getaddrinfo(*_args, **_kwargs):
        return [
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", 0)),
        ]

    monkeypatch.setattr("utils.entitlements.socket.getaddrinfo", fake_getaddrinfo)
    allowed, reason = is_valid_target_for_hosted("https://example.test")
    assert allowed is False
    assert "private/internal" in (reason or "").lower()


def test_is_valid_target_for_hosted_allows_hostname_when_dns_unavailable(monkeypatch):
    def raise_gaierror(*_args, **_kwargs):
        raise socket.gaierror("dns unavailable")

    monkeypatch.setattr("utils.entitlements.socket.getaddrinfo", raise_gaierror)
    allowed, reason = is_valid_target_for_hosted("https://example.test")
    assert allowed is True
    assert reason is None
