"""
Enhanced Subdomain Enumeration Module

Provides multiple techniques for comprehensive subdomain discovery:
- Wordlist-based brute force with concurrent DNS resolution
- Certificate Transparency (CT) logs via crt.sh
- DNS zone transfer attempts (AXFR)
- Common subdomain pattern generation

This module addresses the README TODO: "Improve subdomain enumeration techniques"
"""

import socket
import json
import dns.resolver
import dns.zone
import dns.query
from typing import List, Dict, Any, Optional, Set
from urllib.parse import urlparse
from concurrent.futures import ThreadPoolExecutor, as_completed
import requests
import pathlib

from utils.logger import get_logger


class SubdomainEnumerator:
    """Enhanced subdomain enumeration with multiple discovery techniques."""

    # Common DNS resolvers for redundancy
    DNS_RESOLVERS = [
        "8.8.8.8",  # Google
        "8.8.4.4",  # Google
        "1.1.1.1",  # Cloudflare
        "1.0.0.1",  # Cloudflare
        "9.9.9.9",  # Quad9
        "208.67.222.222",  # OpenDNS
    ]

    def __init__(self, domain: str, timeout: float = 3.0, max_workers: int = 20):
        """
        Initialize the subdomain enumerator.

        Args:
            domain: Target domain to enumerate subdomains for
            timeout: Timeout for DNS queries in seconds
            max_workers: Maximum concurrent workers for parallel enumeration
        """
        self.logger = get_logger()
        self.domain = self._clean_domain(domain)
        self.timeout = timeout
        self.max_workers = max_workers
        self.discovered_subdomains: Set[str] = set()

        # Setup DNS resolver with multiple nameservers
        self.resolver = dns.resolver.Resolver()
        self.resolver.nameservers = self.DNS_RESOLVERS[:3]
        self.resolver.timeout = timeout
        self.resolver.lifetime = timeout * 2

    def _clean_domain(self, domain: str) -> str:
        """Extract and clean the root domain from input."""
        # Handle full URLs
        if domain.startswith(("http://", "https://")):
            parsed = urlparse(domain)
            domain = parsed.netloc

        # Remove www. prefix
        if domain.startswith("www."):
            domain = domain[4:]

        # Remove port if present
        if ":" in domain:
            domain = domain.split(":")[0]

        return domain.lower()

    def enumerate_all(
        self,
        wordlist_limit: int = 500,
        use_ct_logs: bool = True,
        use_zone_transfer: bool = True,
        use_patterns: bool = True,
    ) -> Dict[str, Any]:
        """
        Run all enumeration techniques and aggregate results.

        Args:
            wordlist_limit: Maximum subdomains to check from wordlist
            use_ct_logs: Query Certificate Transparency logs
            use_zone_transfer: Attempt DNS zone transfers
            use_patterns: Generate and check common patterns

        Returns:
            Dict with discovered subdomains and metadata
        """
        self.logger.info(
            f"Starting enhanced subdomain enumeration for {self.domain}", color="cyan"
        )

        results = {
            "domain": self.domain,
            "techniques_used": [],
            "subdomains": [],
            "live_subdomains": [],
            "by_technique": {},
            "total_discovered": 0,
            "total_live": 0,
        }

        # 1. Certificate Transparency Logs
        if use_ct_logs:
            self.logger.info("Querying Certificate Transparency logs...", color="cyan")
            ct_results = self.enumerate_from_ct_logs()
            results["by_technique"]["ct_logs"] = ct_results
            results["techniques_used"].append("ct_logs")
            self.logger.info(
                f"CT logs found {len(ct_results)} subdomains", color="green"
            )

        # 2. DNS Zone Transfer
        if use_zone_transfer:
            self.logger.info("Attempting DNS zone transfer...", color="cyan")
            axfr_results = self.attempt_zone_transfer()
            results["by_technique"]["zone_transfer"] = axfr_results
            results["techniques_used"].append("zone_transfer")
            if axfr_results:
                self.logger.success(
                    f"Zone transfer successful! Found {len(axfr_results)} records"
                )

        # 3. Pattern-based generation
        if use_patterns:
            self.logger.info("Generating pattern-based subdomains...", color="cyan")
            pattern_results = self.generate_patterns()
            results["by_technique"]["patterns"] = pattern_results
            results["techniques_used"].append("patterns")

        # 4. Wordlist brute force (always run)
        self.logger.info(
            f"Running wordlist brute force (limit: {wordlist_limit})...", color="cyan"
        )
        wordlist_results = self.enumerate_from_wordlist(limit=wordlist_limit)
        results["by_technique"]["wordlist"] = wordlist_results
        results["techniques_used"].append("wordlist")

        # Aggregate all discovered subdomains
        all_subdomains = list(self.discovered_subdomains)
        results["subdomains"] = sorted(all_subdomains)
        results["total_discovered"] = len(all_subdomains)

        # Verify which subdomains are actually live (respond to HTTP)
        self.logger.info(
            f"Verifying {len(all_subdomains)} discovered subdomains...", color="cyan"
        )
        live_subdomains = self.verify_live_subdomains(all_subdomains)
        results["live_subdomains"] = sorted(live_subdomains)
        results["total_live"] = len(live_subdomains)

        self.logger.success(
            f"Enumeration complete: {results['total_discovered']} discovered, {results['total_live']} live"
        )

        return results

    def enumerate_from_ct_logs(self) -> List[str]:
        """
        Query Certificate Transparency logs via crt.sh for subdomains.

        Returns:
            List of subdomains found in CT logs
        """
        discovered = []
        crtsh_url = f"https://crt.sh/?q=%.{self.domain}&output=json"

        try:
            response = requests.get(crtsh_url, timeout=15)
            if response.status_code == 200:
                data = response.json()

                for entry in data:
                    name_value = entry.get("name_value", "")
                    # Split on newlines (crt.sh can return multiple names per cert)
                    names = name_value.split("\n")
                    for name in names:
                        name = name.strip().lower()
                        # Filter wildcards and validate domain
                        if (
                            name
                            and not name.startswith("*")
                            and name.endswith(self.domain)
                        ):
                            if name not in self.discovered_subdomains:
                                discovered.append(name)
                                self.discovered_subdomains.add(name)

        except Exception as e:
            self.logger.debug(f"CT log query failed: {str(e)}")
        except json.JSONDecodeError:
            self.logger.debug("CT log response was not valid JSON")

        return discovered

    def attempt_zone_transfer(self) -> List[str]:
        """
        Attempt DNS zone transfer (AXFR) from nameservers.

        Returns:
            List of subdomains if zone transfer succeeds
        """
        discovered = []

        try:
            # Get nameservers for the domain
            ns_records = self.resolver.resolve(self.domain, "NS")
            nameservers = [str(ns) for ns in ns_records]

            for ns in nameservers:
                try:
                    # Resolve nameserver to IP
                    ns_ip = socket.gethostbyname(ns.rstrip("."))

                    # Attempt zone transfer
                    zone = dns.zone.from_xfr(
                        dns.query.xfr(ns_ip, self.domain, timeout=self.timeout)
                    )

                    # Extract all names from the zone
                    for name, node in zone.nodes.items():
                        subdomain = str(name)
                        if subdomain != "@":
                            full_subdomain = f"{subdomain}.{self.domain}"
                            if full_subdomain not in self.discovered_subdomains:
                                discovered.append(full_subdomain)
                                self.discovered_subdomains.add(full_subdomain)

                    # If successful, no need to try other nameservers
                    if discovered:
                        self.logger.success(f"Zone transfer successful from {ns}")
                        break

                except Exception as e:
                    self.logger.debug(f"Zone transfer failed from {ns}: {str(e)}")
                    continue

        except dns.resolver.NoAnswer:
            self.logger.debug(f"No NS records found for {self.domain}")
        except dns.resolver.NXDOMAIN:
            self.logger.debug(f"Domain {self.domain} does not exist")
        except Exception as e:
            self.logger.debug(f"NS lookup failed: {str(e)}")

        return discovered

    def generate_patterns(self) -> List[str]:
        """
        Generate common subdomain patterns and check their existence.

        Returns:
            List of pattern-based subdomains that resolve
        """
        patterns = []

        # Environment patterns
        envs = [
            "dev",
            "staging",
            "stage",
            "test",
            "qa",
            "uat",
            "prod",
            "production",
            "demo",
            "sandbox",
            "beta",
            "alpha",
        ]

        # Service patterns
        services = [
            "api",
            "app",
            "web",
            "www",
            "mail",
            "smtp",
            "pop",
            "imap",
            "ftp",
            "sftp",
            "ssh",
            "vpn",
            "remote",
            "admin",
            "portal",
            "dashboard",
            "panel",
            "cms",
            "blog",
            "shop",
            "store",
            "cdn",
            "static",
            "assets",
            "img",
            "images",
            "media",
            "files",
            "download",
            "upload",
            "secure",
            "login",
            "auth",
            "sso",
            "oauth",
            "git",
            "gitlab",
            "github",
            "jenkins",
            "ci",
            "build",
            "deploy",
            "status",
            "monitor",
            "metrics",
            "logs",
            "elk",
            "grafana",
            "kibana",
            "prometheus",
            "docker",
            "k8s",
            "kubernetes",
            "aws",
            "gcp",
            "azure",
        ]

        # Geographic patterns
        geos = [
            "us",
            "eu",
            "uk",
            "de",
            "fr",
            "jp",
            "au",
            "ca",
            "east",
            "west",
            "north",
            "south",
            "central",
            "asia",
            "apac",
            "emea",
            "latam",
        ]

        # Numbered patterns
        for svc in [
            "api",
            "app",
            "web",
            "mail",
            "ns",
            "db",
            "server",
            "node",
            "worker",
        ]:
            for i in range(1, 6):
                patterns.append(f"{svc}{i}")

        # Environment + service combinations
        for env in envs[:5]:  # Limit combinations
            for svc in services[:10]:
                patterns.append(f"{env}-{svc}")
                patterns.append(f"{svc}-{env}")
                patterns.append(f"{env}.{svc}")

        # Add base patterns
        patterns.extend(envs)
        patterns.extend(services)
        patterns.extend([f"{g}-{s}" for g in geos[:5] for s in services[:5]])

        # Remove duplicates
        patterns = list(set(patterns))

        # Check which patterns resolve
        discovered = self._parallel_dns_check(patterns)
        return discovered

    def enumerate_from_wordlist(self, limit: int = 500) -> List[str]:
        """
        Enumerate subdomains using wordlist brute force with parallel DNS resolution.

        Args:
            limit: Maximum number of subdomains to check

        Returns:
            List of valid subdomains
        """
        # Load subdomain wordlist
        subdomains_path = (
            pathlib.Path(__file__).parent.parent / "lists" / "subdomains.txt"
        )

        try:
            with open(subdomains_path, "r") as f:
                wordlist = [line.strip() for line in f if line.strip()]
                self.logger.info(
                    f"Loaded {len(wordlist)} subdomains from wordlist", color="cyan"
                )
        except Exception as e:
            self.logger.warning(f"Could not load wordlist: {str(e)}")
            # Fallback to minimal list
            wordlist = [
                "www",
                "api",
                "dev",
                "test",
                "staging",
                "admin",
                "mail",
                "blog",
                "docs",
                "app",
                "portal",
                "secure",
                "cdn",
                "static",
                "ftp",
                "vpn",
            ]

        # Limit the wordlist
        wordlist = wordlist[:limit]

        # Parallel DNS check
        discovered = self._parallel_dns_check(wordlist)
        return discovered

    def _parallel_dns_check(self, subdomains: List[str]) -> List[str]:
        """
        Check multiple subdomains in parallel using ThreadPoolExecutor.

        Args:
            subdomains: List of subdomain prefixes to check

        Returns:
            List of valid subdomains that resolve
        """
        discovered = []

        def check_subdomain(subdomain: str) -> Optional[str]:
            full_subdomain = f"{subdomain}.{self.domain}"
            try:
                self.resolver.resolve(full_subdomain, "A")
                return full_subdomain
            except (
                dns.resolver.NXDOMAIN,
                dns.resolver.NoAnswer,
                dns.resolver.NoNameservers,
            ):
                return None
            except dns.exception.Timeout:
                # Try alternate resolver on timeout
                try:
                    alt_resolver = dns.resolver.Resolver()
                    alt_resolver.nameservers = [
                        self.DNS_RESOLVERS[3]
                    ]  # Use different resolver
                    alt_resolver.timeout = self.timeout
                    alt_resolver.resolve(full_subdomain, "A")
                    return full_subdomain
                except:
                    return None
            except Exception:
                return None

        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            futures = {executor.submit(check_subdomain, sub): sub for sub in subdomains}

            for future in as_completed(futures):
                result = future.result()
                if result and result not in self.discovered_subdomains:
                    discovered.append(result)
                    self.discovered_subdomains.add(result)
                    self.logger.debug(f"Discovered: {result}")

        return discovered

    def verify_live_subdomains(
        self, subdomains: List[str], check_https: bool = True
    ) -> List[str]:
        """
        Verify which subdomains respond to HTTP/HTTPS requests.

        Args:
            subdomains: List of subdomains to verify
            check_https: Whether to check HTTPS (default: True)

        Returns:
            List of live subdomains
        """
        live = []

        def check_live(subdomain: str) -> Optional[str]:
            protocols = ["https", "http"] if check_https else ["http"]

            for protocol in protocols:
                url = f"{protocol}://{subdomain}"
                try:
                    response = requests.get(
                        url, timeout=self.timeout, verify=False, allow_redirects=True
                    )
                    if response.status_code < 500:  # Accept any non-5xx response
                        return subdomain
                except:
                    continue
            return None

        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            futures = {executor.submit(check_live, sub): sub for sub in subdomains}

            for future in as_completed(futures):
                result = future.result()
                if result:
                    live.append(result)
                    self.logger.success(f"Live: {result}")

        return live

    def get_subdomain_details(self, subdomain: str) -> Dict[str, Any]:
        """
        Get detailed information about a subdomain.

        Args:
            subdomain: The subdomain to analyze

        Returns:
            Dict with IP addresses, CNAMEs, and other DNS records
        """
        details = {
            "subdomain": subdomain,
            "a_records": [],
            "aaaa_records": [],
            "cname_records": [],
            "mx_records": [],
            "txt_records": [],
            "http_status": None,
            "https_status": None,
            "server_header": None,
        }

        # DNS records
        record_types = [
            ("A", "a_records"),
            ("AAAA", "aaaa_records"),
            ("CNAME", "cname_records"),
            ("MX", "mx_records"),
            ("TXT", "txt_records"),
        ]

        for rtype, key in record_types:
            try:
                records = self.resolver.resolve(subdomain, rtype)
                details[key] = [str(r) for r in records]
            except:
                pass

        # HTTP/HTTPS status
        for protocol in ["https", "http"]:
            url = f"{protocol}://{subdomain}"
            try:
                response = requests.get(
                    url, timeout=self.timeout, verify=False, allow_redirects=False
                )
                details[f"{protocol}_status"] = response.status_code
                if "Server" in response.headers:
                    details["server_header"] = response.headers["Server"]
            except:
                pass

        return details


def enumerate_subdomains_enhanced(
    url: str, limit: int = 500, use_ct_logs: bool = True, use_zone_transfer: bool = True
) -> List[str]:
    """
    Enhanced subdomain enumeration function - drop-in replacement for the basic version.

    Args:
        url: Target URL or domain
        limit: Maximum number of wordlist entries to check
        use_ct_logs: Whether to query Certificate Transparency logs
        use_zone_transfer: Whether to attempt DNS zone transfers

    Returns:
        List of live subdomain URLs (with https:// prefix)
    """
    logger = get_logger()
    logger.info(f"Running enhanced subdomain enumeration for {url}", color="cyan")

    enumerator = SubdomainEnumerator(url)
    results = enumerator.enumerate_all(
        wordlist_limit=limit,
        use_ct_logs=use_ct_logs,
        use_zone_transfer=use_zone_transfer,
        use_patterns=True,
    )

    # Return live subdomains as URLs
    return [f"https://{sub}" for sub in results["live_subdomains"]]
