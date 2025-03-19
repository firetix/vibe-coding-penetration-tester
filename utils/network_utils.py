import os
import requests
import pathlib
import time
import base64
from urllib.parse import urlparse
from typing import List, Dict, Any, Optional
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

def enumerate_subdomains(url: str, limit: int = 100) -> List[str]:
    """
    Find valid subdomains for a given domain by testing common subdomain names.
    
    Args:
        url: Base URL to check subdomains for
        limit: Maximum number of subdomains to check
        
    Returns:
        list: List of valid subdomain URLs that returned HTTP 200
    """ 
    logger = get_logger()
    logger.info(f"Enumerating subdomains for {url}", color="cyan")
    
    # Extract the root domain from the URL
    parsed = urlparse(url)
    hostname = parsed.netloc
    # Remove any www. prefix if present
    if hostname.startswith('www.'):
        hostname = hostname[4:]
    # Split on dots and take last two parts to get root domain
    parts = hostname.split('.')
    if len(parts) > 2:
        hostname = '.'.join(parts[-2:])

    # Load subdomain list
    subdomains_path = pathlib.Path(__file__).parent.parent / "lists" / "subdomains.txt"
    try:
        with open(subdomains_path, "r") as f:
            subdomains = f.read().splitlines()
            logger.info(f"Loaded {len(subdomains)} subdomains from {subdomains_path}", color="cyan")
    except Exception as e:
        logger.error(f"Error loading subdomain list: {str(e)}")
        # Fallback to a minimal list
        subdomains = ["www", "api", "dev", "test", "staging", "admin", "mail", "blog", "docs"]
        logger.info(f"Using fallback list of {len(subdomains)} common subdomains", color="yellow")

    # Limit the number of subdomains to check
    subdomains = subdomains[:limit]
    
    valid_domains = []
    for i, subdomain in enumerate(subdomains):
        subdomain_url = f"https://{subdomain}.{hostname}"
        try:
            logger.debug(f"Testing subdomain ({i+1}/{len(subdomains)}): {subdomain_url}")
            response = requests.get(subdomain_url, timeout=3, verify=False)
            if response.status_code == 200:
                logger.success(f"Found valid subdomain: {subdomain_url}")
                valid_domains.append(subdomain_url)
        except Exception as e:
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

def wait_for_network_idle(page: Page, timeout: int = 5000) -> None:
    """
    Wait for network activity to become idle.
    
    Args:
        page: Playwright page object
        timeout: Maximum time to wait in milliseconds (default: 5000)
    """
    try:
        page.wait_for_load_state('networkidle', timeout=timeout)
    except Exception as e:
        # If timeout occurs, give a small delay anyway
        time.sleep(1)  # Fallback delay

def normalize_url(url: str) -> str:
    """
    Normalize a URL by ensuring it has a protocol and removing trailing slashes.
    
    Args:
        url: URL to normalize
        
    Returns:
        Normalized URL
    """
    # Add protocol if missing
    if not url.startswith(('http://', 'https://')):
        url = 'https://' + url
    
    # Remove trailing slash if present
    if url.endswith('/'):
        url = url[:-1]
        
    return url