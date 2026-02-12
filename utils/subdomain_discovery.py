"""
Enhanced subdomain discovery module.

Provides multiple techniques for subdomain enumeration:
- Certificate Transparency (CT) log parsing via crt.sh
- DNS brute-forcing with concurrent resolution
- Common subdomain patterns and permutations
- Result deduplication and validation
"""

import socket
import json
from typing import List, Set, Dict, Any, Optional
from urllib.parse import urlparse
from concurrent.futures import ThreadPoolExecutor, as_completed
import requests

from utils.logger import get_logger

# Common subdomain prefixes for permutation-based discovery
COMMON_PREFIXES = [
    "www",
    "mail",
    "ftp",
    "localhost",
    "webmail",
    "smtp",
    "pop",
    "ns1",
    "webdisk",
    "ns2",
    "cpanel",
    "whm",
    "autodiscover",
    "autoconfig",
    "m",
    "imap",
    "test",
    "ns",
    "blog",
    "pop3",
    "dev",
    "www2",
    "admin",
    "forum",
    "news",
    "vpn",
    "ns3",
    "mail2",
    "new",
    "mysql",
    "old",
    "lists",
    "support",
    "mobile",
    "mx",
    "static",
    "docs",
    "beta",
    "shop",
    "sql",
    "secure",
    "demo",
    "cp",
    "calendar",
    "wiki",
    "web",
    "media",
    "email",
    "images",
    "img",
    "www1",
    "intranet",
    "portal",
    "video",
    "sip",
    "dns2",
    "api",
    "cdn",
    "stats",
    "dns1",
    "ns4",
    "www3",
    "dns",
    "search",
    "staging",
    "server",
    "mx1",
    "chat",
    "wap",
    "my",
    "svn",
    "mail1",
    "sites",
    "proxy",
    "ads",
    "host",
    "crm",
    "cms",
    "backup",
    "mx2",
    "lyncdiscover",
    "info",
    "apps",
    "download",
    "remote",
    "db",
    "forums",
    "store",
    "relay",
    "files",
    "newsletter",
    "app",
    "live",
    "owa",
    "en",
    "start",
    "sms",
    "office",
    "exchange",
    "ipv4",
    "mail3",
    "help",
    "blogs",
    "helpdesk",
    "web1",
    "home",
    "library",
    "ftp2",
    "ntp",
    "monitor",
    "login",
    "service",
    "correo",
    "www4",
    "moodle",
    "it",
    "gateway",
    "gw",
    "i",
    "stat",
    "stage",
    "ldap",
    "tv",
    "ssl",
    "web2",
    "ns5",
    "upload",
    "nagios",
    "smtp2",
    "online",
    "ad",
    "survey",
    "data",
    "radio",
    "extranet",
    "test2",
    "mssql",
    "dns3",
    "jobs",
    "services",
    "panel",
    "irc",
    "hosting",
    "cloud",
    "de",
    "gmail",
    "s",
    "bbs",
    "cs",
    "ww",
    "mrtg",
    "git",
    "image",
    "members",
    "poczta",
    "s1",
    "meeting",
    "v2",
    "cache",
    "router",
    "status",
    "tools",
    "alpha",
    "testing",
    "prod",
    "internal",
    "external",
    "preprod",
    "uat",
    "qa",
    "sandbox",
    "preview",
    "edge",
    "origin",
    "assets",
    "content",
    "payments",
    "checkout",
    "billing",
    "account",
    "accounts",
    "auth",
    "oauth",
    "sso",
    "identity",
    "id",
    "users",
    "user",
    "customer",
    "customers",
    "partner",
    "partners",
    "vendor",
    "vendors",
]


def get_domain_from_url(url: str) -> str:
    """Extract the root domain from a URL."""
    parsed = urlparse(
        url if url.startswith(("http://", "https://")) else f"https://{url}"
    )
    hostname = parsed.netloc or parsed.path.split("/")[0]

    # Remove port if present
    hostname = hostname.split(":")[0]

    # Remove www prefix
    if hostname.startswith("www."):
        hostname = hostname[4:]

    return hostname


def fetch_ct_subdomains(domain: str, timeout: int = 30) -> Set[str]:
    """
    Fetch subdomains from Certificate Transparency logs via crt.sh.

    crt.sh provides free access to CT log data, which contains all SSL/TLS
    certificates issued for a domain, including wildcards and subdomains.

    Args:
        domain: Target domain to query
        timeout: Request timeout in seconds

    Returns:
        Set of discovered subdomains
    """
    logger = get_logger()
    subdomains = set()

    try:
        # Query crt.sh for certificates containing the domain
        url = f"https://crt.sh/?q=%.{domain}&output=json"
        logger.debug(f"Querying Certificate Transparency logs: {url}")

        response = requests.get(
            url,
            timeout=timeout,
            headers={"User-Agent": "VibePenTester/1.0 (Security Scanner)"},
        )

        if response.status_code == 200:
            try:
                data = response.json()

                for entry in data:
                    # Extract common_name and name_value fields
                    names = []
                    if "common_name" in entry:
                        names.append(entry["common_name"])
                    if "name_value" in entry:
                        # name_value can contain multiple names separated by newlines
                        names.extend(entry["name_value"].split("\n"))

                    for name in names:
                        name = name.strip().lower()
                        # Skip wildcards but extract the subdomain pattern
                        if name.startswith("*."):
                            name = name[2:]

                        # Validate it's a subdomain of target domain
                        if name.endswith(f".{domain}") or name == domain:
                            subdomains.add(name)

                logger.info(
                    f"CT logs: Found {len(subdomains)} unique subdomains for {domain}",
                    color="cyan",
                )

            except json.JSONDecodeError:
                logger.debug("Failed to parse CT log response as JSON")

        else:
            logger.debug(f"CT log query returned status {response.status_code}")

    except requests.RequestException as e:
        logger.debug(f"CT log query failed: {str(e)}")
    except Exception as e:
        logger.debug(f"Unexpected error in CT log query: {str(e)}")

    return subdomains


def resolve_dns(hostname: str, timeout: float = 2.0) -> bool:
    """
    Check if a hostname resolves via DNS.

    Args:
        hostname: Hostname to resolve
        timeout: Socket timeout in seconds

    Returns:
        True if hostname resolves, False otherwise
    """
    _ = timeout
    try:
        socket.gethostbyname(hostname)
        return True
    except (socket.gaierror, socket.timeout, OSError):
        return False


def dns_bruteforce_concurrent(
    domain: str, wordlist: List[str], max_workers: int = 20, timeout: float = 2.0
) -> Set[str]:
    """
    Perform concurrent DNS brute-forcing using a wordlist.

    Args:
        domain: Target domain
        wordlist: List of subdomain prefixes to try
        max_workers: Maximum concurrent DNS queries
        timeout: DNS resolution timeout per query

    Returns:
        Set of valid subdomains that resolved
    """
    logger = get_logger()
    valid_subdomains = set()

    # Generate full subdomain names
    candidates = [f"{prefix}.{domain}" for prefix in wordlist]

    logger.debug(
        f"DNS brute-force: Testing {len(candidates)} subdomains with {max_workers} workers"
    )

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_to_subdomain = {
            executor.submit(resolve_dns, subdomain, timeout): subdomain
            for subdomain in candidates
        }

        for future in as_completed(future_to_subdomain):
            subdomain = future_to_subdomain[future]
            try:
                if future.result():
                    valid_subdomains.add(subdomain)
                    logger.debug(f"DNS resolved: {subdomain}")
            except Exception as e:
                logger.debug(f"DNS resolution error for {subdomain}: {str(e)}")

    logger.info(
        f"DNS brute-force: Found {len(valid_subdomains)} valid subdomains", color="cyan"
    )
    return valid_subdomains


def generate_permutations(domain: str, known_subdomains: Set[str]) -> Set[str]:
    """
    Generate subdomain permutations based on known subdomains.

    Creates variations like:
    - prefix-subdomain.domain.com
    - subdomain-suffix.domain.com
    - subdomain1subdomain2.domain.com

    Args:
        domain: Target domain
        known_subdomains: Already discovered subdomains

    Returns:
        Set of permutation candidates to test
    """
    permutations = set()
    common_suffixes = [
        "dev",
        "test",
        "staging",
        "prod",
        "api",
        "admin",
        "internal",
        "new",
        "old",
        "v2",
        "backup",
    ]
    common_prefixes = [
        "dev",
        "test",
        "staging",
        "prod",
        "api",
        "admin",
        "internal",
        "new",
        "old",
        "v2",
    ]

    for subdomain in known_subdomains:
        # Extract the subdomain prefix (without the domain part)
        if subdomain.endswith(f".{domain}"):
            prefix = subdomain[: -len(domain) - 1]

            # Skip if already compound or too long
            if "-" in prefix or len(prefix) > 20:
                continue

            # Generate prefix-based permutations
            for p in common_prefixes:
                permutations.add(f"{p}-{prefix}.{domain}")
                permutations.add(f"{prefix}-{p}.{domain}")

            # Generate suffix-based permutations
            for s in common_suffixes:
                permutations.add(f"{prefix}{s}.{domain}")

    return permutations


def check_http_alive(subdomain: str, timeout: int = 5) -> Optional[Dict[str, Any]]:
    """
    Check if a subdomain has an active HTTP/HTTPS service.

    Args:
        subdomain: Subdomain to check
        timeout: Request timeout

    Returns:
        Dict with service info if alive, None otherwise
    """
    for protocol in ["https", "http"]:
        try:
            url = f"{protocol}://{subdomain}"
            response = requests.head(
                url, timeout=timeout, allow_redirects=True, verify=False
            )
            return {
                "subdomain": subdomain,
                "url": url,
                "status_code": response.status_code,
                "protocol": protocol,
                "server": response.headers.get("Server", "Unknown"),
                "redirect": response.url if response.url != url else None,
            }
        except Exception:
            continue
    return None


def enumerate_subdomains_enhanced(
    url: str,
    wordlist: Optional[List[str]] = None,
    use_ct_logs: bool = True,
    use_dns_bruteforce: bool = True,
    use_permutations: bool = True,
    check_alive: bool = True,
    max_workers: int = 20,
    limit: int = 500,
) -> Dict[str, Any]:
    """
    Enhanced subdomain enumeration using multiple techniques.

    Combines:
    1. Certificate Transparency log parsing (crt.sh)
    2. DNS brute-forcing with concurrent resolution
    3. Permutation-based discovery
    4. HTTP/HTTPS alive checking

    Args:
        url: Target URL or domain
        wordlist: Custom wordlist (defaults to COMMON_PREFIXES)
        use_ct_logs: Enable CT log parsing
        use_dns_bruteforce: Enable DNS brute-forcing
        use_permutations: Enable permutation generation
        check_alive: Verify HTTP/HTTPS services
        max_workers: Concurrent workers for DNS/HTTP checks
        limit: Maximum wordlist entries to use

    Returns:
        Dict containing discovered subdomains and metadata
    """
    logger = get_logger()
    domain = get_domain_from_url(url)

    logger.info(f"Starting enhanced subdomain enumeration for {domain}", color="cyan")

    all_subdomains: Set[str] = set()
    sources: Dict[str, int] = {}

    # 1. Certificate Transparency logs
    if use_ct_logs:
        logger.info("Phase 1: Querying Certificate Transparency logs...", color="cyan")
        ct_subdomains = fetch_ct_subdomains(domain)
        sources["ct_logs"] = len(ct_subdomains)
        all_subdomains.update(ct_subdomains)

    # 2. DNS brute-forcing with wordlist
    if use_dns_bruteforce:
        logger.info("Phase 2: DNS brute-forcing with wordlist...", color="cyan")
        word_list = wordlist or COMMON_PREFIXES
        word_list = word_list[:limit]

        dns_subdomains = dns_bruteforce_concurrent(domain, word_list, max_workers)
        sources["dns_bruteforce"] = len(dns_subdomains)
        all_subdomains.update(dns_subdomains)

    # 3. Permutation-based discovery
    if use_permutations and len(all_subdomains) > 0:
        logger.info("Phase 3: Generating and testing permutations...", color="cyan")
        permutations = generate_permutations(domain, all_subdomains)

        # Only test a subset of permutations
        permutation_list = list(permutations)[:200]
        permutation_prefixes = [p.replace(f".{domain}", "") for p in permutation_list]

        perm_subdomains = dns_bruteforce_concurrent(
            domain, permutation_prefixes, max_workers
        )
        sources["permutations"] = len(perm_subdomains)
        all_subdomains.update(perm_subdomains)

    # 4. Check HTTP/HTTPS services
    alive_services = []
    if check_alive and len(all_subdomains) > 0:
        logger.info("Phase 4: Checking HTTP/HTTPS services...", color="cyan")

        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = {
                executor.submit(check_http_alive, sd): sd for sd in all_subdomains
            }

            for future in as_completed(futures):
                result = future.result()
                if result:
                    alive_services.append(result)
                    logger.success(
                        f"HTTP alive: {result['url']} ({result['status_code']})"
                    )

    # Sort results
    sorted_subdomains = sorted(all_subdomains)
    sorted_alive = sorted(alive_services, key=lambda x: x["subdomain"])

    logger.info(
        f"Enhanced enumeration complete: {len(sorted_subdomains)} subdomains, {len(sorted_alive)} alive",
        color="green",
    )

    return {
        "domain": domain,
        "subdomains": sorted_subdomains,
        "alive_services": sorted_alive,
        "total_discovered": len(sorted_subdomains),
        "total_alive": len(sorted_alive),
        "sources": sources,
        "techniques_used": {
            "ct_logs": use_ct_logs,
            "dns_bruteforce": use_dns_bruteforce,
            "permutations": use_permutations,
            "alive_check": check_alive,
        },
    }


# CLI entry point for testing
if __name__ == "__main__":
    import sys

    if len(sys.argv) < 2:
        print("Usage: python subdomain_discovery.py <domain>")
        sys.exit(1)

    target = sys.argv[1]
    results = enumerate_subdomains_enhanced(target)

    print(f"\n=== Subdomain Enumeration Results for {results['domain']} ===")
    print(f"Total discovered: {results['total_discovered']}")
    print(f"Total alive: {results['total_alive']}")
    print(f"\nSources: {results['sources']}")
    print("\nSubdomains:")
    for sd in results["subdomains"][:50]:  # Limit output
        print(f"  - {sd}")
    if len(results["subdomains"]) > 50:
        print(f"  ... and {len(results['subdomains']) - 50} more")
    print("\nAlive services:")
    for svc in results["alive_services"][:20]:
        print(f"  - {svc['url']} ({svc['status_code']}) - Server: {svc['server']}")
