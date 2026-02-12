import os
import yaml
from typing import Dict, Any

from utils.logger import get_logger

DEFAULT_CONFIG = {
    "scanning": {
        "max_depth": 3,
        "max_pages": 50,
        "max_subdomains": 100,
        "request_delay": 0.5,  # seconds
        "timeout": 30,  # seconds
        "user_agent": "VibePenTester Security Scanner",
    },
    "security_testing": {
        "xss": {"enabled": True, "max_payloads": 20},
        "sqli": {"enabled": True, "max_payloads": 20},
        "csrf": {"enabled": True},
        "auth": {"enabled": True},
    },
    "reporting": {
        "min_severity": "low",  # low, medium, high, critical
        "include_evidence": True,
        "include_remediation": True,
    },
    "llm": {
        "openai": {"temperature": 0.7, "max_tokens": 4000},
        "anthropic": {"temperature": 0.7, "max_tokens": 4000},
    },
}


def load_config(config_path: str = "config/config.yaml") -> Dict[str, Any]:
    """Load configuration from file or use defaults."""
    logger = get_logger()

    if os.path.exists(config_path):
        try:
            with open(config_path, "r") as f:
                config = yaml.safe_load(f)
            logger.info(f"Loaded configuration from {config_path}")

            # Merge with defaults to ensure all required fields exist
            merged_config = DEFAULT_CONFIG.copy()
            _deep_merge(merged_config, config)
            return merged_config
        except Exception as e:
            logger.error(f"Error loading configuration: {str(e)}")
            logger.info("Using default configuration")
            return DEFAULT_CONFIG
    else:
        logger.info(
            f"Configuration file {config_path} not found, using default configuration"
        )

        # Create default config file if it doesn't exist
        try:
            os.makedirs(os.path.dirname(config_path), exist_ok=True)
            with open(config_path, "w") as f:
                yaml.dump(DEFAULT_CONFIG, f, default_flow_style=False)
            logger.info(f"Created default configuration file at {config_path}")
        except Exception as e:
            logger.error(f"Error creating default configuration file: {str(e)}")

        return DEFAULT_CONFIG


def _deep_merge(target: Dict[str, Any], source: Dict[str, Any]) -> Dict[str, Any]:
    """Deep merge two dictionaries, updating target with values from source."""
    for key, value in source.items():
        if key in target and isinstance(target[key], dict) and isinstance(value, dict):
            _deep_merge(target[key], value)
        else:
            target[key] = value
    return target
