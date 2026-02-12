import os
import requests
import pathlib
import time
import base64
from urllib.parse import urlparse
from typing import List
from playwright.sync_api import Page

from utils.logger import get_logger


def check_hostname(url_start: str, url_to_check: str) -> bool:
    """
    Check if two URLs have the same hostname.

    Args:
        url_start: First URL to compare
        url_to_check: Second URL to compare

    Returns:
        bool: True if hostnames match, False otherwise
    """
    url_start_hostname = urlparse(url_start).netloc
    url_to_check_hostname = urlparse(url_to_check).netloc
    return url_start_hostname == url_to_check_hostname


def enumerate_subdomains(
    url: str, limit: int = 100, enhanced: bool = True
) -> List[str]:
    """
    Find valid subdomains for a given domain by testing common subdomain names.

    When enhanced=True (default), uses multiple discovery techniques:
    - Certificate Transparency log parsing via crt.sh
    - Concurrent DNS brute-forcing
    - Permutation-based discovery

    Args:
        url: Base URL to check subdomains for
        limit: Maximum number of subdomains to check (for wordlist)
        enhanced: Use enhanced multi-technique enumeration (default: True)

    Returns:
        list: List of valid subdomain URLs that returned HTTP 200
    """
    logger = get_logger()
    logger.info(f"Enumerating subdomains for {url}", color="cyan")

    # Extract the root domain from the URL
    parsed = urlparse(url)
    hostname = parsed.netloc
    # Remove any www. prefix if present
    if hostname.startswith("www."):
        hostname = hostname[4:]
    # Split on dots and take last two parts to get root domain
    parts = hostname.split(".")
    if len(parts) > 2:
        hostname = ".".join(parts[-2:])

    # Use enhanced enumeration if enabled
    if enhanced:
        try:
            from utils.subdomain_discovery import enumerate_subdomains_enhanced

            logger.info(
                "Using enhanced subdomain enumeration (CT logs + DNS + permutations)",
                color="cyan",
            )
            results = enumerate_subdomains_enhanced(
                url=url,
                use_ct_logs=True,
                use_dns_bruteforce=True,
                use_permutations=True,
                check_alive=True,
                limit=limit,
            )

            # Return alive service URLs
            valid_domains = [svc["url"] for svc in results["alive_services"]]
            logger.info(
                f"Enhanced enumeration found {len(valid_domains)} alive subdomains",
                color="green",
            )
            return valid_domains

        except ImportError as e:
            logger.warning(
                f"Enhanced enumeration unavailable: {e}. Falling back to basic method."
            )
        except Exception as e:
            logger.warning(
                f"Enhanced enumeration failed: {e}. Falling back to basic method."
            )

    # Basic enumeration (fallback)
    logger.info("Using basic subdomain enumeration (wordlist only)", color="yellow")

    # Load subdomain list
    subdomains_path = pathlib.Path(__file__).parent.parent / "lists" / "subdomains.txt"
    try:
        with open(subdomains_path, "r") as f:
            subdomains = f.read().splitlines()
            logger.info(
                f"Loaded {len(subdomains)} subdomains from {subdomains_path}",
                color="cyan",
            )
    except Exception as e:
        logger.error(f"Error loading subdomain list: {str(e)}")
        # Fallback to a minimal list
        subdomains = [
            "www",
            "api",
            "dev",
            "test",
            "staging",
            "admin",
            "mail",
            "blog",
            "docs",
        ]
        logger.info(
            f"Using fallback list of {len(subdomains)} common subdomains",
            color="yellow",
        )

    # Limit the number of subdomains to check
    subdomains = subdomains[:limit]

    valid_domains = []
    for i, subdomain in enumerate(subdomains):
        subdomain_url = f"https://{subdomain}.{hostname}"
        try:
            logger.debug(
                f"Testing subdomain ({i + 1}/{len(subdomains)}): {subdomain_url}"
            )
            response = requests.get(subdomain_url, timeout=3, verify=False)
            if response.status_code == 200:
                logger.success(f"Found valid subdomain: {subdomain_url}")
                valid_domains.append(subdomain_url)
        except Exception:
            # Skip failed attempts without error message to reduce noise
            pass

    logger.info(f"Found {len(valid_domains)} valid subdomains", color="green")
    return valid_domains


def get_base64_screenshot(page: Page) -> str:
    """
    Take a screenshot of the page and return it as a base64 encoded string.

    Args:
        page: Playwright page object

    Returns:
        str: Base64 encoded screenshot image
    """
    logger = get_logger()
    try:
        # Ensure temp directory exists
        os.makedirs("temp", exist_ok=True)

        screenshot_path = "temp/temp_screenshot.png"
        page.screenshot(path=screenshot_path)
        with open(screenshot_path, "rb") as image_file:
            base64_image = base64.b64encode(image_file.read()).decode("utf-8")

        # Clean up the temporary file
        try:
            os.remove(screenshot_path)
        except:
            pass

        return base64_image
    except Exception as e:
        logger.error(f"Error taking screenshot: {str(e)}")
        return ""


def wait_for_network_idle(page: Page, timeout: int = 10000) -> None:
    """
    Wait for network activity to become idle with improved fallback behavior.

    Args:
        page: Playwright page object
        timeout: Maximum time to wait in milliseconds (default: 10000)
    """
    logger = get_logger()
    try:
        # Try using networkidle first
        page.wait_for_load_state("networkidle", timeout=timeout)
    except Exception as e:
        logger.debug(f"Networkidle timeout ({timeout}ms): {str(e)}")
        try:
            # Try domcontentloaded which is more reliable
            logger.debug("Falling back to domcontentloaded")
            page.wait_for_load_state("domcontentloaded", timeout=int(timeout / 2))
        except Exception as e2:
            logger.debug(f"Domcontentloaded also timed out: {str(e2)}")
            # Ensure a minimum delay
            time.sleep(2)


def normalize_url(url: str) -> str:
    """
    Normalize a URL by ensuring it has a protocol and removing trailing slashes.

    Args:
        url: URL to normalize

    Returns:
        Normalized URL
    """
    # Add protocol if missing
    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    # Remove trailing slash if present
    if url.endswith("/"):
        url = url[:-1]

    return url
