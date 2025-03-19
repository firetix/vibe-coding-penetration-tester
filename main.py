#!/usr/bin/env python3

import argparse
import os
import sys
from datetime import datetime

from core.coordinator import SwarmCoordinator
from utils.logger import setup_logger
from utils.config import load_config

def parse_arguments():
    parser = argparse.ArgumentParser(description="VibePenTester - Advanced AI Security Testing Agent")
    parser.add_argument("--url", type=str, required=True, help="Target URL to scan")
    parser.add_argument("--model", type=str, default="gpt-4o", help="LLM model to use")
    parser.add_argument("--provider", type=str, default="openai", choices=["openai", "anthropic"], help="LLM provider")
    parser.add_argument("--scope", type=str, default="url", choices=["url", "domain", "subdomain"], help="Scan scope")
    parser.add_argument("--output", type=str, default="reports", help="Output directory for reports")
    parser.add_argument("--verbose", action="store_true", help="Enable verbose logging")
    return parser.parse_args()

def main():
    args = parse_arguments()
    
    # Configure logging - always use DEBUG for now
    log_level = "DEBUG"  # Force debug logging
    logger = setup_logger(log_level)
    logger.info(f"Starting VibePenTester scan of {args.url}")
    
    # Load configuration
    config = load_config()
    
    # Prepare output directory
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    output_dir = os.path.join(args.output, f"{args.url.replace('://', '_').replace('/', '_')}_{timestamp}")
    os.makedirs(output_dir, exist_ok=True)
    
    # Initialize and run swarm coordinator
    coordinator = SwarmCoordinator(
        url=args.url,
        model=args.model,
        provider=args.provider,
        scope=args.scope,
        output_dir=output_dir,
        config=config
    )
    
    try:
        results = coordinator.run()
        logger.info(f"Scan completed. Results saved to {output_dir}")
        return 0
    except Exception as e:
        logger.error(f"Scan failed: {str(e)}")
        return 1

if __name__ == "__main__":
    sys.exit(main())
