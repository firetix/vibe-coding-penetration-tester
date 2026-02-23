#!/usr/bin/env python3

import argparse
import importlib.util
import os
import sys
from datetime import datetime
from dotenv import load_dotenv  # Import dotenv

from core.coordinator import SwarmCoordinator
from utils.logger import setup_logger
from utils.config import load_config

# Load environment variables from .env file
load_dotenv()

DEFAULT_OPENAI_MODEL = "gpt-5.2"


def parse_arguments():
    available_providers = ["openai", "anthropic", "ollama"]
    if importlib.util.find_spec("google.generativeai") is not None:
        available_providers.append("gemini")

    parser = argparse.ArgumentParser(
        description="VibePenTester - Advanced AI Security Testing Agent"
    )
    parser.add_argument("--url", type=str, required=True, help="Target URL to scan")
    parser.add_argument(
        "--model",
        type=str,
        default=DEFAULT_OPENAI_MODEL,
        help="LLM model to use (e.g., gpt-5.2, gpt-5.2-codex, claude-opus-4-6, ollama/llama3, gemini-2.0-flash)",
    )
    parser.add_argument(
        "--provider",
        type=str,
        default="openai",
        choices=available_providers,
        help=(
            "LLM provider. Available providers depend on installed SDKs "
            "(gemini appears when google-generativeai is installed)."
        ),
    )
    parser.add_argument(
        "--scope",
        type=str,
        default="url",
        choices=["url", "domain", "subdomain"],
        help="Scan scope",
    )
    parser.add_argument(
        "--output", type=str, default="reports", help="Output directory for reports"
    )
    parser.add_argument("--verbose", action="store_true", help="Enable verbose logging")
    parser.add_argument(
        "--ollama-url",
        type=str,
        default="http://localhost:11434",
        help="Ollama server URL (used only with --provider=ollama)",
    )
    parser.add_argument(
        "--openai-api-key", type=str, default=None, help="OpenAI API key override"
    )
    parser.add_argument(
        "--anthropic-api-key", type=str, default=None, help="Anthropic API key override"
    )
    parser.add_argument(
        "--google-api-key", type=str, default=None, help="Google API key override"
    )
    return parser.parse_args()


def main():
    args = parse_arguments()

    # Configure logging - always use DEBUG for now
    log_level = "DEBUG"  # Force debug logging
    logger = setup_logger(log_level)
    logger.info(f"Starting VibePenTester scan of {args.url}")

    # Load configuration
    config = load_config()

    # Set Ollama URL in environment if using Ollama provider
    if args.provider == "ollama":
        os.environ["OLLAMA_BASE_URL"] = args.ollama_url
        logger.info(f"Using Ollama server at {args.ollama_url}")

        # If no specific model is provided, use the default from config
        if (
            args.model == DEFAULT_OPENAI_MODEL
        ):  # This is the default model, so user didn't specify one
            default_ollama_model = (
                config.get("llm", {}).get("ollama", {}).get("default_model", "llama3")
            )
            logger.info(
                f"No specific model provided for Ollama, using default: {default_ollama_model}"
            )
            args.model = default_ollama_model

    # Prepare output directory
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    output_dir = os.path.join(
        args.output, f"{args.url.replace('://', '_').replace('/', '_')}_{timestamp}"
    )
    os.makedirs(output_dir, exist_ok=True)

    # Initialize and run swarm coordinator
    coordinator = SwarmCoordinator(
        url=args.url,
        model=args.model,
        provider=args.provider,
        scope=args.scope,
        output_dir=output_dir,
        config=config,
        openai_api_key=args.openai_api_key,
        anthropic_api_key=args.anthropic_api_key,
        google_api_key=args.google_api_key,
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
