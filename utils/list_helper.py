import os
import pathlib
from typing import List, Optional

from utils.logger import get_logger

def get_project_root() -> pathlib.Path:
    """Return the project root directory."""
    return pathlib.Path(__file__).parent.parent

def load_common_passwords(limit: Optional[int] = None) -> List[str]:
    """Load common passwords from the list file."""
    logger = get_logger()
    passwords_path = get_project_root() / "lists" / "common_passwords.txt"
    
    try:
        with open(passwords_path, "r") as f:
            passwords = f.read().splitlines()
        
        logger.info(f"Loaded {len(passwords)} common passwords from {passwords_path}")
        return passwords[:limit] if limit else passwords
    except Exception as e:
        logger.error(f"Error loading common passwords: {str(e)}")
        # Return a minimal fallback list
        return ["password", "123456", "admin", "qwerty", "letmein"]

def load_fuzz_directories(limit: Optional[int] = None) -> List[str]:
    """Load directory paths for fuzzing from the list file."""
    logger = get_logger()
    fuzz_path = get_project_root() / "lists" / "fuzz_dirs.txt"
    
    try:
        with open(fuzz_path, "r") as f:
            dirs = f.read().splitlines()
        
        logger.info(f"Loaded {len(dirs)} fuzzing directories from {fuzz_path}")
        return dirs[:limit] if limit else dirs
    except Exception as e:
        logger.error(f"Error loading fuzz directories: {str(e)}")
        # Return a minimal fallback list
        return ["admin", "backup", "config", "db", "temp", "uploads", "test", "dev"]

def load_subdomains(limit: Optional[int] = None) -> List[str]:
    """Load subdomain names from the list file."""
    logger = get_logger()
    subdomains_path = get_project_root() / "lists" / "subdomains.txt"
    
    try:
        with open(subdomains_path, "r") as f:
            subdomains = f.read().splitlines()
        
        logger.info(f"Loaded {len(subdomains)} subdomains from {subdomains_path}")
        return subdomains[:limit] if limit else subdomains
    except Exception as e:
        logger.error(f"Error loading subdomains: {str(e)}")
        # Return a minimal fallback list
        return ["admin", "mail", "www", "test", "dev", "api", "staging", "beta"]