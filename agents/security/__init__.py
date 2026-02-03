# Import all security agents for easier access
from agents.security.specialized_agent import SpecializedSecurityAgent
from agents.security.access_control_agent import AccessControlAgent
from agents.security.data_integrity_agent import DataIntegrityAgent
from agents.security.ssrf_agent import SSRFAgent
from agents.security.crypto_agent import CryptoFailureAgent
from agents.security.insecure_design_agent import InsecureDesignAgent
from agents.security.validator_agent import ValidationAgent
from agents.security.idor_agent import IDORAgent
from agents.security.xss_agent import XSSAgent
from agents.security.sqli_agent import SQLInjectionAgent
from agents.security.csrf_agent import CSRFAgent
from agents.security.auth_agent import AuthenticationAgent
from agents.security.api_security_agent import APISecurityAgent

# Export the classes for easier importing
__all__ = [
    'SpecializedSecurityAgent',
    'AccessControlAgent',
    'DataIntegrityAgent',
    'SSRFAgent',
    'CryptoFailureAgent',
    'InsecureDesignAgent',
    'ValidationAgent',
    'IDORAgent',
    'XSSAgent',
    'SQLInjectionAgent',
    'CSRFAgent',
    'AuthenticationAgent',
    'APISecurityAgent'
]