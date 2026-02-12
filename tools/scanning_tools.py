from typing import Dict, List, Any, Optional
import random
from urllib.parse import urlparse, urljoin
from datetime import datetime

from utils.logger import get_logger
from utils.list_helper import load_fuzz_directories, load_subdomains


def get_scanning_tools() -> List[Dict[str, Any]]:
    """Get tool definitions for scanning."""

    # Define scanning tool definitions
    tools = [
        {
            "type": "function",
            "function": {
                "name": "scan_headers",
                "description": "Analyze HTTP headers for security issues",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "target_url": {
                            "type": "string",
                            "description": "URL of the target application",
                        },
                        "check_hsts": {
                            "type": "boolean",
                            "description": "Check for HTTP Strict Transport Security header",
                        },
                        "check_csp": {
                            "type": "boolean",
                            "description": "Check for Content Security Policy header",
                        },
                        "check_xframe": {
                            "type": "boolean",
                            "description": "Check for X-Frame-Options header",
                        },
                    },
                    "required": ["target_url"],
                },
            },
        },
        {
            "type": "function",
            "function": {
                "name": "scan_ssl_tls",
                "description": "Analyze SSL/TLS configuration for security issues",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "target_host": {
                            "type": "string",
                            "description": "Hostname of the target application",
                        },
                        "target_port": {
                            "type": "integer",
                            "description": "Port for SSL/TLS connection",
                        },
                        "check_protocols": {
                            "type": "boolean",
                            "description": "Check for insecure protocols",
                        },
                        "check_ciphers": {
                            "type": "boolean",
                            "description": "Check for weak ciphers",
                        },
                        "check_cert": {
                            "type": "boolean",
                            "description": "Check certificate validity",
                        },
                    },
                    "required": ["target_host"],
                },
            },
        },
        {
            "type": "function",
            "function": {
                "name": "analyze_page_content",
                "description": "Analyze page content for security issues or sensitive information",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "target_url": {
                            "type": "string",
                            "description": "URL of the target application",
                        },
                        "check_comments": {
                            "type": "boolean",
                            "description": "Check for sensitive information in HTML comments",
                        },
                        "check_js": {
                            "type": "boolean",
                            "description": "Check for sensitive information in JavaScript",
                        },
                        "check_forms": {
                            "type": "boolean",
                            "description": "Check forms for security issues",
                        },
                    },
                    "required": ["target_url"],
                },
            },
        },
        {
            "type": "function",
            "function": {
                "name": "check_outdated_software",
                "description": "Check for outdated software or frameworks with known vulnerabilities",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "target_url": {
                            "type": "string",
                            "description": "URL of the target application",
                        },
                        "technologies": {
                            "type": "array",
                            "items": {
                                "type": "object",
                                "properties": {
                                    "name": {
                                        "type": "string",
                                        "description": "Technology name",
                                    },
                                    "version": {
                                        "type": "string",
                                        "description": "Technology version",
                                    },
                                },
                            },
                            "description": "List of detected technologies",
                        },
                    },
                    "required": ["target_url"],
                },
            },
        },
    ]

    return tools


def scan_headers(
    target_url: str,
    check_hsts: bool = True,
    check_csp: bool = True,
    check_xframe: bool = True,
) -> Dict[str, Any]:
    """Analyze HTTP headers for security issues."""
    logger = get_logger()
    logger.info(f"Scanning headers for {target_url}")

    # In a real implementation, this would interact with the scanner to check headers
    # For now, we'll simulate the process

    # Simulate header checks
    import random

    has_hsts = not check_hsts or random.choice([True, False])
    has_csp = not check_csp or random.choice([True, False])
    has_xframe = not check_xframe or random.choice([True, False])

    # Determine if there are security issues
    missing_headers = []
    if not has_hsts and check_hsts:
        missing_headers.append("Strict-Transport-Security")
    if not has_csp and check_csp:
        missing_headers.append("Content-Security-Policy")
    if not has_xframe and check_xframe:
        missing_headers.append("X-Frame-Options")

    has_issues = len(missing_headers) > 0

    if has_issues:
        logger.info(
            f"Security header issues found in {target_url}: {', '.join(missing_headers)}"
        )
        return {
            "security_issue_found": True,
            "issue_type": "Missing Security Headers",
            "target_url": target_url,
            "missing_headers": missing_headers,
            "has_hsts": has_hsts,
            "has_csp": has_csp,
            "has_xframe": has_xframe,
            "severity": "medium",
            "description": f"The application is missing important security headers: {', '.join(missing_headers)}.",
            "impact": "Missing security headers can expose the application to various attacks including clickjacking, XSS, and man-in-the-middle attacks.",
            "remediation": "Implement the missing security headers to enhance the application's security posture. Use proper values for each header according to your security requirements.",
            "references": [
                "https://owasp.org/www-project-secure-headers/",
                "https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html",
            ],
            "timestamp": datetime.now().isoformat(),
        }

    # No vulnerability found
    return {
        "security_issue_found": False,
        "target_url": target_url,
        "has_hsts": has_hsts,
        "has_csp": has_csp,
        "has_xframe": has_xframe,
        "timestamp": datetime.now().isoformat(),
    }


def scan_ssl_tls(
    target_host: str,
    target_port: int = 443,
    check_protocols: bool = True,
    check_ciphers: bool = True,
    check_cert: bool = True,
) -> Dict[str, Any]:
    """Analyze SSL/TLS configuration for security issues."""
    logger = get_logger()
    logger.info(f"Scanning SSL/TLS configuration for {target_host}:{target_port}")

    # In a real implementation, this would interact with the scanner to check SSL/TLS
    # For now, we'll simulate the process

    # Simulate SSL/TLS checks
    import random

    # Simulated protocol support
    supports_ssl2 = random.choice([False, False, False])  # Rare
    supports_ssl3 = random.choice([False, False, True])  # Uncommon
    supports_tls1_0 = random.choice([True, False, True])  # Sometimes
    supports_tls1_1 = random.choice([True, True, False])  # Common
    supports_tls1_2 = True  # Standard
    supports_tls1_3 = random.choice([True, False])  # Modern

    # Simulated weak cipher support
    has_weak_ciphers = random.choice([False, True, False])  # Sometimes

    # Simulated certificate issues
    cert_issues = []
    is_self_signed = random.choice([False, False, True])  # Uncommon
    if is_self_signed:
        cert_issues.append("Self-signed certificate")

    is_expired = random.choice([False, False, False, True])  # Rare
    if is_expired:
        cert_issues.append("Expired certificate")

    weak_key_size = random.choice([False, False, False, True])  # Rare
    if weak_key_size:
        cert_issues.append("Weak key size (less than 2048 bits)")

    # Determine if there are security issues
    protocol_issues = []
    if check_protocols:
        if supports_ssl2:
            protocol_issues.append("SSLv2")
        if supports_ssl3:
            protocol_issues.append("SSLv3")
        if supports_tls1_0:
            protocol_issues.append("TLSv1.0")
        if supports_tls1_1:
            protocol_issues.append("TLSv1.1")

    has_issues = (
        (len(protocol_issues) > 0 and check_protocols)
        or (has_weak_ciphers and check_ciphers)
        or (len(cert_issues) > 0 and check_cert)
    )

    if has_issues:
        issues = []
        if protocol_issues and check_protocols:
            issues.append(f"Insecure protocols: {', '.join(protocol_issues)}")
        if has_weak_ciphers and check_ciphers:
            issues.append("Weak cipher suites")
        if cert_issues and check_cert:
            issues.append(f"Certificate issues: {', '.join(cert_issues)}")

        issue_str = "; ".join(issues)
        logger.info(f"SSL/TLS issues found in {target_host}:{target_port}: {issue_str}")

        return {
            "security_issue_found": True,
            "issue_type": "SSL/TLS Configuration Issues",
            "target_host": target_host,
            "target_port": target_port,
            "protocol_issues": protocol_issues if check_protocols else [],
            "has_weak_ciphers": has_weak_ciphers if check_ciphers else False,
            "cert_issues": cert_issues if check_cert else [],
            "severity": "high",
            "description": f"The server has SSL/TLS configuration issues: {issue_str}.",
            "impact": "Weak SSL/TLS configurations can expose the application to various attacks including BEAST, POODLE, and man-in-the-middle attacks.",
            "remediation": "Disable insecure protocols (SSLv2, SSLv3, TLSv1.0, TLSv1.1). Use only strong cipher suites. Ensure certificates are valid, not expired, and use adequate key sizes (at least 2048 bits for RSA).",
            "references": [
                "https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Protection_Cheat_Sheet.html",
                "https://www.ssllabs.com/ssltest/",
            ],
            "timestamp": datetime.now().isoformat(),
        }

    # No vulnerability found
    return {
        "security_issue_found": False,
        "target_host": target_host,
        "target_port": target_port,
        "supports_tls1_2": supports_tls1_2,
        "supports_tls1_3": supports_tls1_3,
        "timestamp": datetime.now().isoformat(),
    }


def analyze_page_content(
    target_url: str,
    check_comments: bool = True,
    check_js: bool = True,
    check_forms: bool = True,
) -> Dict[str, Any]:
    """Analyze page content for security issues or sensitive information."""
    logger = get_logger()
    logger.info(f"Analyzing page content for {target_url}")

    # In a real implementation, this would interact with the scanner to analyze the page
    # For now, we'll simulate the process

    # Simulate content checks
    import random

    # Simulated sensitive information in comments
    sensitive_comments = []
    if check_comments and random.choice([False, True, False, False]):  # Uncommon
        sensitive_comments = [
            "<!-- TODO: Remove hardcoded credentials -->",
            "<!-- Database connection string: jdbc:mysql://localhost:3306/app_db?user=dbuser&password=dbpass -->",
        ]

    # Simulated sensitive information in JavaScript
    sensitive_js = []
    if check_js and random.choice([False, True, False, False]):  # Uncommon
        sensitive_js = [
            "const apiKey = 'sk_live_abcdef123456';",
            "// AWS access key: AKIAIOSFODNN7EXAMPLE",
        ]

    # Simulated form issues
    form_issues = []
    if check_forms:
        if random.choice([True, False]):
            form_issues.append("Form submission over HTTP")
        if random.choice([True, False]):
            form_issues.append("Password input without autocomplete=off")
        if random.choice([True, False]):
            form_issues.append("Form without CSRF protection")

    # Determine if there are security issues
    has_sensitive_info = len(sensitive_comments) > 0 or len(sensitive_js) > 0
    has_form_issues = len(form_issues) > 0

    has_issues = has_sensitive_info or has_form_issues

    if has_issues:
        issues = []
        if has_sensitive_info:
            issues.append("Sensitive information disclosure")
        if has_form_issues:
            issues.append("Insecure form implementation")

        issue_str = ", ".join(issues)
        logger.info(f"Page content issues found in {target_url}: {issue_str}")

        return {
            "security_issue_found": True,
            "issue_type": "Page Content Security Issues",
            "target_url": target_url,
            "sensitive_comments": sensitive_comments,
            "sensitive_js": sensitive_js,
            "form_issues": form_issues,
            "severity": "medium",
            "description": f"The page contains security issues: {issue_str}.",
            "impact": "Sensitive information disclosure can lead to unauthorized access. Insecure forms can be vulnerable to various attacks including CSRF and credential theft.",
            "remediation": "Remove sensitive information from comments and client-side code. Implement secure form practices including CSRF protection, submission over HTTPS, and proper autocomplete attributes.",
            "references": [
                "https://owasp.org/www-project-top-ten/2017/A3_2017-Sensitive_Data_Exposure",
                "https://cheatsheetseries.owasp.org/cheatsheets/HTML5_Security_Cheat_Sheet.html",
            ],
            "timestamp": datetime.now().isoformat(),
        }

    # No vulnerability found
    return {
        "security_issue_found": False,
        "target_url": target_url,
        "timestamp": datetime.now().isoformat(),
    }


def brute_force_directories(
    base_url: str, wordlist: str = "common", extensions: Optional[List[str]] = None
) -> Dict[str, Any]:
    """Brute force directories and files on a website using wordlists."""
    logger = get_logger()
    logger.info(f"Brute forcing directories on {base_url} using {wordlist} wordlist")

    # Load directories from the wordlist file
    directories = load_fuzz_directories(100)  # Limit to 100 for faster testing

    # Set default extensions if not provided
    if not extensions:
        extensions = ["", ".php", ".html", ".js", ".txt", ".xml", ".json"]

    discovered_urls = []
    tried_paths = []

    for directory in directories:
        for ext in extensions:
            path = f"{directory}{ext}"
            full_url = urljoin(base_url, path)
            tried_paths.append(path)

            # In a real implementation, we would make an actual request
            # For simulation purposes, randomly "discover" some paths
            if random.random() < 0.05:  # 5% chance of finding a valid path
                discovered_urls.append(full_url)
                logger.info(f"Discovered URL: {full_url}")

    return {
        "urls": discovered_urls,
        "base_url": base_url,
        "tried_paths_count": len(tried_paths),
        "discovered_count": len(discovered_urls),
        "timestamp": datetime.now().isoformat(),
    }


def crawl_website(url: str, max_depth: int = 2, max_pages: int = 20) -> Dict[str, Any]:
    """Crawl a website to discover links and content."""
    logger = get_logger()
    logger.info(
        f"Crawling website: {url} (max_depth: {max_depth}, max_pages: {max_pages})"
    )

    # In a real implementation, this would use Playwright to crawl the site
    # For now, we'll simulate the process with random discoveries

    discovered_urls = [url]
    processed_count = 0

    # Simulate discovering additional URLs based on common web paths
    base_url = url.rstrip("/")
    potential_paths = [
        "/login",
        "/admin",
        "/signup",
        "/profile",
        "/settings",
        "/upload",
        "/api",
        "/docs",
        "/help",
        "/about",
        "/contact",
        "/search",
        "/index",
        "/main",
        "/home",
    ]

    # Simulate the crawling process
    for path in potential_paths:
        if processed_count >= max_pages:
            break

        # In a real crawler, we'd check if the URL exists and follow links
        # Here we'll just add some random URLs with a probability
        if random.random() < 0.3:  # 30% chance of "finding" each URL
            new_url = f"{base_url}{path}"
            if new_url not in discovered_urls:
                discovered_urls.append(new_url)
                logger.info(f"Discovered URL: {new_url}")
                processed_count += 1

    return {
        "urls": discovered_urls,
        "crawled_count": processed_count + 1,  # +1 for the initial URL
        "max_depth": max_depth,
        "max_pages": max_pages,
        "base_url": url,
        "timestamp": datetime.now().isoformat(),
    }


def extract_links(url: str) -> Dict[str, Any]:
    """Extract links from a web page."""
    logger = get_logger()
    logger.info(f"Extracting links from: {url}")

    # In a real implementation, this would use Playwright to extract links
    # For now, we'll simulate the process

    # Simulate finding links by generating some dummy URLs
    base_url = url.rstrip("/")
    domain = urlparse(url).netloc

    # Generate some links that might be found
    internal_links = [
        f"{base_url}/page1",
        f"{base_url}/page2",
        f"{base_url}/login",
        f"{base_url}/products",
        f"{base_url}/about",
    ]

    external_links = [
        "https://www.google.com",
        "https://www.example.com",
        "https://www.github.com",
    ]

    # Randomly select a subset of links to "find"
    discovered_internal = random.sample(internal_links, min(3, len(internal_links)))
    discovered_external = random.sample(external_links, min(2, len(external_links)))

    all_discovered = discovered_internal + discovered_external

    return {
        "links": all_discovered,
        "internal_links": discovered_internal,
        "external_links": discovered_external,
        "url": url,
        "count": len(all_discovered),
        "timestamp": datetime.now().isoformat(),
    }


def enumerate_subdomains(
    domain: str, techniques: Optional[List[str]] = None, use_enhanced: bool = True
) -> Dict[str, Any]:
    """
    Enumerate subdomains for a given domain using various techniques.

    When use_enhanced=True (default), uses real discovery techniques:
    - Certificate Transparency log parsing via crt.sh API
    - Concurrent DNS brute-forcing with resolution verification
    - Permutation-based discovery for deeper enumeration
    - HTTP/HTTPS alive checking

    Args:
        domain: Target domain to enumerate
        techniques: List of techniques to use (for compatibility)
        use_enhanced: Use enhanced multi-technique enumeration (default: True)

    Returns:
        Dict with discovered subdomains, alive services, and metadata
    """
    logger = get_logger()
    logger.info(f"Enumerating subdomains for {domain}")

    # Set default techniques if not provided
    if not techniques:
        techniques = ["wordlist", "certificate", "dns", "permutation"]

    # Try enhanced enumeration first
    if use_enhanced:
        try:
            from utils.subdomain_discovery import enumerate_subdomains_enhanced

            logger.info(
                "Using enhanced multi-technique subdomain enumeration", color="cyan"
            )

            results = enumerate_subdomains_enhanced(
                url=domain,
                use_ct_logs="certificate" in techniques,
                use_dns_bruteforce="dns" in techniques or "wordlist" in techniques,
                use_permutations="permutation" in techniques,
                check_alive=True,
                limit=200,
            )

            return {
                "subdomains": results["subdomains"],
                "alive_services": results["alive_services"],
                "domain": results["domain"],
                "techniques": techniques,
                "discovered_count": results["total_discovered"],
                "alive_count": results["total_alive"],
                "sources": results["sources"],
                "timestamp": datetime.now().isoformat(),
            }

        except ImportError as e:
            logger.warning(f"Enhanced enumeration unavailable: {e}. Using fallback.")
        except Exception as e:
            logger.warning(f"Enhanced enumeration failed: {e}. Using fallback.")

    # Fallback to basic/simulated enumeration
    logger.info("Using basic subdomain enumeration (fallback mode)", color="yellow")
    discovered_subdomains = []

    # Load subdomains from the wordlist
    if "wordlist" in techniques:
        subdomain_list = load_subdomains(100)  # Limit to 100 for faster testing

        for subdomain in subdomain_list:
            full_subdomain = f"{subdomain}.{domain}"

            # In fallback mode, randomly "discover" some subdomains for simulation
            if random.random() < 0.05:  # 5% chance of finding a valid subdomain
                discovered_subdomains.append(full_subdomain)
                logger.info(f"Discovered subdomain: {full_subdomain}")

    # Simulate certificate transparency and DNS techniques in fallback mode
    if "certificate" in techniques or "dns" in techniques:
        # Add a few random "discovered" subdomains for simulation
        extra_count = random.randint(1, 5)
        for _ in range(extra_count):
            subdomain_prefix = random.choice(
                ["api", "mail", "dev", "test", "staging", "app", "web", "secure"]
            )
            if subdomain_prefix not in discovered_subdomains:
                full_subdomain = f"{subdomain_prefix}.{domain}"
                discovered_subdomains.append(full_subdomain)
                logger.info(f"Discovered subdomain: {full_subdomain}")

    return {
        "subdomains": discovered_subdomains,
        "alive_services": [],
        "domain": domain,
        "techniques": techniques,
        "discovered_count": len(discovered_subdomains),
        "alive_count": 0,
        "sources": {"fallback": len(discovered_subdomains)},
        "timestamp": datetime.now().isoformat(),
    }


def check_outdated_software(
    target_url: str, technologies: Optional[List[Dict[str, str]]] = None
) -> Dict[str, Any]:
    """Check for outdated software or frameworks with known vulnerabilities."""
    logger = get_logger()
    logger.info(f"Checking for outdated software on {target_url}")

    # In a real implementation, this would interact with the scanner and vuln databases
    # For now, we'll simulate the process

    # Use provided technologies or simulate detection
    if not technologies:
        # Simulate technology detection
        possible_techs = [
            {"name": "jQuery", "version": "1.8.3"},
            {"name": "jQuery", "version": "3.6.0"},
            {"name": "Bootstrap", "version": "3.3.7"},
            {"name": "Bootstrap", "version": "5.1.3"},
            {"name": "WordPress", "version": "4.7.2"},
            {"name": "WordPress", "version": "5.9.3"},
            {"name": "PHP", "version": "5.6.40"},
            {"name": "PHP", "version": "8.1.4"},
            {"name": "Apache", "version": "2.2.34"},
            {"name": "Apache", "version": "2.4.53"},
        ]

        # Randomly select 2-4 technologies
        technologies = random.sample(possible_techs, random.randint(2, 4))

    # Define known vulnerable versions (simplified for simulation)
    vulnerable_versions = {
        "jQuery": [
            "1.8.3",
            "1.9.0",
            "1.10.2",
            "1.11.3",
            "1.12.4",
            "2.0.3",
            "2.1.4",
            "2.2.4",
        ],
        "Bootstrap": ["2.3.2", "3.0.0", "3.1.1", "3.2.0", "3.3.7", "4.0.0"],
        "WordPress": ["4.6.1", "4.7.2", "4.8.3", "4.9.6", "5.0.1"],
        "PHP": ["5.3.29", "5.4.45", "5.5.38", "5.6.40", "7.0.33", "7.1.33"],
        "Apache": ["2.2.34", "2.4.10", "2.4.20"],
    }

    # Check for vulnerabilities
    outdated_techs = []
    for tech in technologies:
        name = tech["name"]
        version = tech["version"]

        if name in vulnerable_versions and version in vulnerable_versions[name]:
            outdated_techs.append(
                {
                    "name": name,
                    "version": version,
                    "latest_version": "latest",  # In a real implementation, this would be the actual latest version
                    "known_vulnerabilities": True,
                }
            )

    # Determine if there are security issues
    has_issues = len(outdated_techs) > 0

    if has_issues:
        formatted_techs = [t["name"] + " " + t["version"] for t in outdated_techs]
        logger.info(
            f"Outdated software found in {target_url}: {', '.join(formatted_techs)}"
        )

        return {
            "security_issue_found": True,
            "issue_type": "Outdated Software with Known Vulnerabilities",
            "target_url": target_url,
            "outdated_technologies": outdated_techs,
            "all_technologies": technologies,
            "severity": "high",
            "description": f"The application uses outdated software with known vulnerabilities: {', '.join(formatted_techs)}.",
            "impact": "Outdated software often contains known vulnerabilities that can be exploited by attackers to compromise the application or server.",
            "remediation": "Update all outdated software to the latest secure versions. Implement a regular update and patch management process.",
            "references": [
                "https://owasp.org/www-project-top-ten/2017/A9_2017-Using_Components_with_Known_Vulnerabilities",
                "https://cve.mitre.org/",
            ],
            "timestamp": datetime.now().isoformat(),
        }

    # No vulnerability found
    return {
        "security_issue_found": False,
        "target_url": target_url,
        "technologies": technologies,
        "timestamp": datetime.now().isoformat(),
    }
