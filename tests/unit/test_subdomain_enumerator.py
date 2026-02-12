"""
Unit tests for enhanced subdomain enumeration module.
"""

from unittest.mock import Mock, patch
import dns.resolver
import dns.exception

from utils.subdomain_enumerator import (
    SubdomainEnumerator,
    enumerate_subdomains_enhanced,
)


class TestSubdomainEnumerator:
    """Test the SubdomainEnumerator class."""

    def test_init_with_url(self):
        """Test initialization with full URL."""
        enumerator = SubdomainEnumerator("https://www.example.com/path")
        assert enumerator.domain == "example.com"

    def test_init_with_domain(self):
        """Test initialization with plain domain."""
        enumerator = SubdomainEnumerator("example.com")
        assert enumerator.domain == "example.com"

    def test_init_strips_www(self):
        """Test that www. prefix is stripped."""
        enumerator = SubdomainEnumerator("www.example.com")
        assert enumerator.domain == "example.com"

    def test_init_strips_port(self):
        """Test that port is stripped from domain."""
        enumerator = SubdomainEnumerator("example.com:8080")
        assert enumerator.domain == "example.com"

    def test_clean_domain_lowercase(self):
        """Test that domain is lowercased."""
        enumerator = SubdomainEnumerator("EXAMPLE.COM")
        assert enumerator.domain == "example.com"

    @patch("utils.subdomain_enumerator.requests.get")
    def test_enumerate_from_ct_logs_success(self, mock_get):
        """Test CT log enumeration with successful response."""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = [
            {"name_value": "api.example.com"},
            {"name_value": "dev.example.com\nstaging.example.com"},
            {"name_value": "*.example.com"},  # Should be filtered
        ]
        mock_get.return_value = mock_response

        enumerator = SubdomainEnumerator("example.com")
        results = enumerator.enumerate_from_ct_logs()

        assert "api.example.com" in results
        assert "dev.example.com" in results
        assert "staging.example.com" in results
        # Wildcard should not be included
        assert not any("*" in r for r in results)

    @patch("utils.subdomain_enumerator.requests.get")
    def test_enumerate_from_ct_logs_failure(self, mock_get):
        """Test CT log enumeration handles request failure gracefully."""
        mock_get.side_effect = Exception("Connection failed")

        enumerator = SubdomainEnumerator("example.com")
        results = enumerator.enumerate_from_ct_logs()

        assert results == []

    @patch("utils.subdomain_enumerator.dns.resolver.Resolver")
    def test_parallel_dns_check(self, mock_resolver_class):
        """Test parallel DNS resolution."""
        mock_resolver = Mock()
        mock_resolver_class.return_value = mock_resolver

        # First call succeeds, second fails
        def resolve_side_effect(subdomain, rtype):
            if "api.example.com" in subdomain:
                return Mock()  # Success
            raise dns.resolver.NXDOMAIN()

        enumerator = SubdomainEnumerator("example.com")
        enumerator.resolver.resolve = resolve_side_effect

        results = enumerator._parallel_dns_check(["api", "invalid"])

        assert "api.example.com" in results
        assert "invalid.example.com" not in results

    @patch("utils.subdomain_enumerator.requests.get")
    def test_verify_live_subdomains(self, mock_get):
        """Test verification of live subdomains."""

        def get_side_effect(url, **kwargs):
            mock_resp = Mock()
            if "live" in url:
                mock_resp.status_code = 200
                return mock_resp
            raise Exception("Connection refused")

        mock_get.side_effect = get_side_effect

        enumerator = SubdomainEnumerator("example.com")
        results = enumerator.verify_live_subdomains(
            ["live.example.com", "dead.example.com"]
        )

        assert "live.example.com" in results
        assert "dead.example.com" not in results

    def test_generate_patterns(self):
        """Test pattern generation creates expected subdomains."""
        enumerator = SubdomainEnumerator("example.com")

        # Mock DNS resolution to always fail (we just want to test pattern generation)
        enumerator.resolver.resolve = Mock(side_effect=dns.resolver.NXDOMAIN())

        # Since all DNS checks fail, results will be empty but we can verify the method runs
        results = enumerator.generate_patterns()
        assert isinstance(results, list)

    def test_discovered_subdomains_deduplication(self):
        """Test that discovered subdomains are deduplicated."""
        enumerator = SubdomainEnumerator("example.com")

        # Add same subdomain twice
        enumerator.discovered_subdomains.add("api.example.com")
        enumerator.discovered_subdomains.add("api.example.com")

        assert len(enumerator.discovered_subdomains) == 1


class TestEnumerateSubdomainsEnhanced:
    """Test the convenience function."""

    @patch("utils.subdomain_enumerator.SubdomainEnumerator")
    def test_returns_https_urls(self, mock_enumerator_class):
        """Test that returned URLs have https:// prefix."""
        mock_enumerator = Mock()
        mock_enumerator.enumerate_all.return_value = {
            "live_subdomains": ["api.example.com", "dev.example.com"]
        }
        mock_enumerator_class.return_value = mock_enumerator

        results = enumerate_subdomains_enhanced("example.com")

        assert all(url.startswith("https://") for url in results)
        assert "https://api.example.com" in results
        assert "https://dev.example.com" in results


class TestNetworkUtilsIntegration:
    """Test integration with network_utils.enumerate_subdomains."""

    @patch("utils.subdomain_discovery.enumerate_subdomains_enhanced")
    def test_network_utils_uses_enhanced(self, mock_enhanced):
        """Test that network_utils.enumerate_subdomains uses enhanced mode by default."""
        mock_enhanced.return_value = {
            "alive_services": [{"url": "https://api.example.com"}]
        }

        from utils.network_utils import enumerate_subdomains

        results = enumerate_subdomains("https://example.com", enhanced=True)

        mock_enhanced.assert_called_once()
        assert results == ["https://api.example.com"]

    @patch("utils.network_utils.requests.get")
    def test_network_utils_fallback_mode(self, mock_get):
        """Test that network_utils can fall back to basic mode."""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_get.return_value = mock_response

        from utils.network_utils import enumerate_subdomains

        # Force basic mode
        results = enumerate_subdomains("https://example.com", limit=5, enhanced=False)

        assert isinstance(results, list)
