"""
Unit tests for enhanced subdomain discovery module.
"""

from unittest.mock import patch, MagicMock
import socket

from utils.subdomain_discovery import (
    get_domain_from_url,
    fetch_ct_subdomains,
    resolve_dns,
    dns_bruteforce_concurrent,
    generate_permutations,
    check_http_alive,
    enumerate_subdomains_enhanced,
    COMMON_PREFIXES,
)


class TestGetDomainFromUrl:
    """Tests for domain extraction from URLs."""

    def test_simple_domain(self):
        assert get_domain_from_url("example.com") == "example.com"

    def test_with_https(self):
        assert get_domain_from_url("https://example.com") == "example.com"

    def test_with_http(self):
        assert get_domain_from_url("http://example.com") == "example.com"

    def test_with_www(self):
        assert get_domain_from_url("https://www.example.com") == "example.com"

    def test_with_path(self):
        assert get_domain_from_url("https://example.com/path/to/page") == "example.com"

    def test_with_port(self):
        assert get_domain_from_url("https://example.com:8443") == "example.com"

    def test_subdomain_stripped_www(self):
        assert get_domain_from_url("https://www.api.example.com") == "api.example.com"


class TestResolveDns:
    """Tests for DNS resolution."""

    @patch("socket.gethostbyname")
    def test_successful_resolution(self, mock_gethostbyname):
        mock_gethostbyname.return_value = "93.184.216.34"
        assert resolve_dns("example.com") is True
        mock_gethostbyname.assert_called_once_with("example.com")

    @patch("socket.gethostbyname")
    def test_failed_resolution(self, mock_gethostbyname):
        mock_gethostbyname.side_effect = socket.gaierror("DNS lookup failed")
        assert resolve_dns("nonexistent.invalid") is False

    @patch("socket.gethostbyname")
    def test_timeout(self, mock_gethostbyname):
        mock_gethostbyname.side_effect = socket.timeout("Timeout")
        assert resolve_dns("slow.example.com") is False


class TestFetchCtSubdomains:
    """Tests for Certificate Transparency log fetching."""

    @patch("requests.get")
    def test_successful_ct_fetch(self, mock_get):
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = [
            {"common_name": "www.example.com", "name_value": "www.example.com"},
            {
                "common_name": "api.example.com",
                "name_value": "api.example.com\nmail.example.com",
            },
            {"common_name": "*.example.com", "name_value": "*.example.com"},
        ]
        mock_get.return_value = mock_response

        result = fetch_ct_subdomains("example.com")

        assert "www.example.com" in result
        assert "api.example.com" in result
        assert "mail.example.com" in result
        assert "example.com" in result  # From wildcard stripped

    @patch("requests.get")
    def test_ct_fetch_error(self, mock_get):
        mock_get.side_effect = Exception("Network error")

        result = fetch_ct_subdomains("example.com")

        assert result == set()

    @patch("requests.get")
    def test_ct_fetch_non_200(self, mock_get):
        mock_response = MagicMock()
        mock_response.status_code = 404
        mock_get.return_value = mock_response

        result = fetch_ct_subdomains("example.com")

        assert result == set()


class TestDnsBruteforceConcurrent:
    """Tests for concurrent DNS brute-forcing."""

    @patch("utils.subdomain_discovery.resolve_dns")
    def test_finds_valid_subdomains(self, mock_resolve):
        # Only www and api resolve
        def resolve_side_effect(hostname, timeout=2.0):
            return hostname in ["www.example.com", "api.example.com"]

        mock_resolve.side_effect = resolve_side_effect

        result = dns_bruteforce_concurrent(
            "example.com", ["www", "api", "invalid", "test"], max_workers=2
        )

        assert "www.example.com" in result
        assert "api.example.com" in result
        assert "invalid.example.com" not in result
        assert "test.example.com" not in result

    @patch("utils.subdomain_discovery.resolve_dns")
    def test_empty_wordlist(self, mock_resolve):
        result = dns_bruteforce_concurrent("example.com", [], max_workers=2)
        assert result == set()

    @patch("utils.subdomain_discovery.resolve_dns")
    def test_all_fail(self, mock_resolve):
        mock_resolve.return_value = False

        result = dns_bruteforce_concurrent(
            "example.com", ["test1", "test2", "test3"], max_workers=2
        )

        assert result == set()


class TestGeneratePermutations:
    """Tests for permutation-based discovery."""

    def test_generates_prefix_permutations(self):
        known = {"api.example.com", "admin.example.com"}
        result = generate_permutations("example.com", known)

        # Should generate dev-api, api-dev, etc.
        assert "dev-api.example.com" in result
        assert "api-dev.example.com" in result

    def test_generates_suffix_permutations(self):
        known = {"api.example.com"}
        result = generate_permutations("example.com", known)

        # Should generate apidev, apitest, etc.
        assert "apidev.example.com" in result
        assert "apitest.example.com" in result

    def test_skips_compound_subdomains(self):
        # Already has a hyphen, should be skipped
        known = {"api-v2.example.com"}
        result = generate_permutations("example.com", known)

        # Should not create further compounds
        assert "dev-api-v2.example.com" not in result

    def test_empty_known_set(self):
        result = generate_permutations("example.com", set())
        assert result == set()


class TestCheckHttpAlive:
    """Tests for HTTP/HTTPS alive checking."""

    @patch("requests.head")
    def test_https_alive(self, mock_head):
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.headers = {"Server": "nginx"}
        mock_response.url = "https://api.example.com"
        mock_head.return_value = mock_response

        result = check_http_alive("api.example.com")

        assert result is not None
        assert result["protocol"] == "https"
        assert result["status_code"] == 200
        assert result["server"] == "nginx"

    @patch("requests.head")
    def test_http_fallback(self, mock_head):
        def side_effect(url, **kwargs):
            if url.startswith("https://"):
                raise Exception("SSL error")
            mock_response = MagicMock()
            mock_response.status_code = 200
            mock_response.headers = {}
            mock_response.url = url
            return mock_response

        mock_head.side_effect = side_effect

        result = check_http_alive("api.example.com")

        assert result is not None
        assert result["protocol"] == "http"

    @patch("requests.head")
    def test_not_alive(self, mock_head):
        mock_head.side_effect = Exception("Connection refused")

        result = check_http_alive("dead.example.com")

        assert result is None


class TestEnumerateSubdomainsEnhanced:
    """Integration tests for enhanced enumeration."""

    @patch("utils.subdomain_discovery.check_http_alive")
    @patch("utils.subdomain_discovery.dns_bruteforce_concurrent")
    @patch("utils.subdomain_discovery.fetch_ct_subdomains")
    def test_combines_all_techniques(self, mock_ct, mock_dns, mock_alive):
        # Mock CT logs returning some subdomains
        mock_ct.return_value = {"ct.example.com", "api.example.com"}

        # Mock DNS brute-force returning some subdomains
        mock_dns.return_value = {"www.example.com", "api.example.com"}

        # Mock alive check
        mock_alive.return_value = {
            "subdomain": "api.example.com",
            "url": "https://api.example.com",
            "status_code": 200,
            "protocol": "https",
            "server": "nginx",
            "redirect": None,
        }

        result = enumerate_subdomains_enhanced(
            "example.com",
            use_ct_logs=True,
            use_dns_bruteforce=True,
            use_permutations=False,  # Skip for simpler test
            check_alive=True,
        )

        # Should have combined and deduplicated results
        assert "ct.example.com" in result["subdomains"]
        assert "api.example.com" in result["subdomains"]
        assert "www.example.com" in result["subdomains"]

        # Should have source tracking
        assert "ct_logs" in result["sources"]
        assert "dns_bruteforce" in result["sources"]

    @patch("utils.subdomain_discovery.fetch_ct_subdomains")
    def test_ct_only(self, mock_ct):
        mock_ct.return_value = {"api.example.com"}

        result = enumerate_subdomains_enhanced(
            "example.com",
            use_ct_logs=True,
            use_dns_bruteforce=False,
            use_permutations=False,
            check_alive=False,
        )

        assert "api.example.com" in result["subdomains"]
        assert result["sources"]["ct_logs"] == 1


class TestCommonPrefixes:
    """Tests for the common prefixes list."""

    def test_common_prefixes_not_empty(self):
        assert len(COMMON_PREFIXES) > 0

    def test_common_prefixes_contains_basics(self):
        basics = ["www", "api", "mail", "admin", "dev", "staging", "test"]
        for prefix in basics:
            assert prefix in COMMON_PREFIXES, f"Missing common prefix: {prefix}"

    def test_common_prefixes_no_duplicates(self):
        assert len(COMMON_PREFIXES) == len(set(COMMON_PREFIXES))
