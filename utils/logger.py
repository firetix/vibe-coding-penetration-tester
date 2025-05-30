import logging
import os
import sys
import re
from datetime import datetime
from typing import Optional, Dict, Any, List, Union

# Global logger instance
_logger = None

# ANSI color codes for pretty printing
COLORS = {
    "reset": "\033[0m",
    "black": "\033[30m",
    "red": "\033[31m",
    "green": "\033[32m",
    "yellow": "\033[33m",
    "blue": "\033[34m",
    "magenta": "\033[35m",
    "cyan": "\033[36m",
    "white": "\033[37m",
    "light_black": "\033[90m",
    "light_red": "\033[91m",
    "light_green": "\033[92m",
    "light_yellow": "\033[93m",
    "light_blue": "\033[94m",
    "light_magenta": "\033[95m",
    "light_cyan": "\033[96m",
    "light_white": "\033[97m",
    "bold": "\033[1m",
    "underline": "\033[4m",
    "reverse": "\033[7m"
}

class ColoredFormatter(logging.Formatter):
    """Custom formatter that colorizes log messages based on level."""

    LEVEL_COLORS = {
        logging.DEBUG: COLORS["light_black"],
        logging.INFO: COLORS["green"],
        logging.WARNING: COLORS["yellow"],
        logging.ERROR: COLORS["red"],
        logging.CRITICAL: COLORS["bold"] + COLORS["red"]
    }

    def format(self, record):
        """Format log record with colorized level and message."""
        levelname = record.levelname
        message = super().format(record)

        # Check if we already have ANSI color codes in the message
        if any(color in message for color in COLORS.values()):
            # Return the message as is if it's already colored
            return message

        # Check for embedded color directives in format: [color:text]
        def repl(match):
            color_name = match.group(1).lower()
            text = match.group(2)
            if color_name in COLORS:
                return f"{COLORS[color_name]}{text}{COLORS['reset']}"
            return text

        message = re.sub(r'\[(\w+):([^\]]+)\]', repl, message)

        # Apply color based on log level
        color = self.LEVEL_COLORS.get(record.levelno, COLORS["reset"])
        formatted_level = f"{color}{levelname}{COLORS['reset']}"

        # Replace the original level name with the colored version
        return message.replace(levelname, formatted_level)

class PrettyLogger:
    """Wrapper around logging.Logger with additional pretty printing capabilities."""

    def __init__(self, logger):
        self.logger = logger

    def debug(self, msg, *args, color=None, **kwargs):
        """Log a debug message with optional color."""
        if color:
            msg = f"{COLORS.get(color, '')}{msg}{COLORS['reset']}"
        self.logger.debug(msg, *args, **kwargs)

    def info(self, msg, *args, color=None, **kwargs):
        """Log an info message with optional color."""
        if color:
            msg = f"{COLORS.get(color, '')}{msg}{COLORS['reset']}"
        self.logger.info(msg, *args, **kwargs)

    def warning(self, msg, *args, color=None, **kwargs):
        """Log a warning message with optional color."""
        if color:
            msg = f"{COLORS.get(color, '')}{msg}{COLORS['reset']}"
        self.logger.warning(msg, *args, **kwargs)

    def error(self, msg, *args, color=None, **kwargs):
        """Log an error message with optional color."""
        if color:
            msg = f"{COLORS.get(color, '')}{msg}{COLORS['reset']}"
        self.logger.error(msg, *args, **kwargs)

    def critical(self, msg, *args, color=None, **kwargs):
        """Log a critical message with optional color."""
        if color:
            msg = f"{COLORS.get(color, '')}{msg}{COLORS['reset']}"
        self.logger.critical(msg, *args, **kwargs)

    def success(self, msg, *args, **kwargs):
        """Log a success message (special helper for positive outcomes)."""
        self.info(f"{COLORS['green']}{msg}{COLORS['reset']}", *args, **kwargs)

    def highlight(self, msg, *args, **kwargs):
        """Log a highlighted message (special helper for important info)."""
        self.info(f"{COLORS['bold']}{COLORS['cyan']}{msg}{COLORS['reset']}", *args, **kwargs)

    def security(self, msg, *args, **kwargs):
        """Log a security-related message (special helper for security findings)."""
        self.info(f"{COLORS['bold']}{COLORS['red']}[SECURITY] {msg}{COLORS['reset']}", *args, **kwargs)

    def pretty_dict(self, data: Dict[str, Any], title: str = None, level: str = "info"):
        """Pretty print a dictionary."""
        if title:
            getattr(self, level)(f"{COLORS['bold']}{title}{COLORS['reset']}")

        for key, value in data.items():
            formatted_key = f"{COLORS['cyan']}{key}{COLORS['reset']}"
            if isinstance(value, dict):
                getattr(self, level)(f"  {formatted_key}:")
                for k, v in value.items():
                    formatted_subkey = f"{COLORS['light_cyan']}{k}{COLORS['reset']}"
                    getattr(self, level)(f"    {formatted_subkey}: {v}")
            elif isinstance(value, (list, tuple)):
                getattr(self, level)(f"  {formatted_key}:")
                for item in value:
                    if isinstance(item, dict):
                        for k, v in item.items():
                            formatted_subkey = f"{COLORS['light_cyan']}{k}{COLORS['reset']}"
                            getattr(self, level)(f"    - {formatted_subkey}: {v}")
                    else:
                        getattr(self, level)(f"    - {item}")
            else:
                getattr(self, level)(f"  {formatted_key}: {value}")

    def pretty_table(self, headers: List[str], rows: List[List[Any]], title: str = None, level: str = "info"):
        """Pretty print a table."""
        if not rows:
            return

        if title:
            getattr(self, level)(f"{COLORS['bold']}{title}{COLORS['reset']}")

        # Calculate column widths
        col_widths = [len(h) for h in headers]
        for row in rows:
            for i, cell in enumerate(row):
                cell_str = str(cell)
                # Strip ANSI color codes for width calculation
                clean_str = re.sub(r'\033\[[0-9;]+m', '', cell_str)
                col_widths[i] = max(col_widths[i], len(clean_str))

        # Create header row
        header_str = "  "
        for i, header in enumerate(headers):
            header_str += f"{COLORS['bold']}{header.ljust(col_widths[i])}{COLORS['reset']}  "
        getattr(self, level)(header_str)

        # Create separator row
        separator = "  " + "  ".join("-" * width for width in col_widths)
        getattr(self, level)(separator)

        # Create data rows
        for row in rows:
            row_str = "  "
            for i, cell in enumerate(row):
                cell_str = str(cell)
                # Strip ANSI color codes for width calculation
                clean_str = re.sub(r'\033\[[0-9;]+m', '', cell_str)
                # Add padding based on the clean string length
                row_str += f"{cell_str.ljust(col_widths[i] + (len(cell_str) - len(clean_str)))}  "
            getattr(self, level)(row_str)

    def pretty_print_traffic(self, traffic: List[Dict[str, Any]]):
        """Pretty print HTTP traffic for network monitoring."""
        if not traffic:
            return

        self.info(f"\n{COLORS['bold']}HTTP Traffic Summary:{COLORS['reset']}")

        for entry in traffic:
            method = entry.get("method", "")
            url = entry.get("url", "")
            status = entry.get("status", "")

            # Color method based on type
            if method == "GET":
                method_colored = f"{COLORS['green']}{method}{COLORS['reset']}"
            elif method in ["POST", "PUT", "PATCH"]:
                method_colored = f"{COLORS['yellow']}{method}{COLORS['reset']}"
            elif method == "DELETE":
                method_colored = f"{COLORS['red']}{method}{COLORS['reset']}"
            else:
                method_colored = f"{COLORS['light_blue']}{method}{COLORS['reset']}"

            # Color status based on category
            if str(status).startswith("2"):
                status_colored = f"{COLORS['green']}{status}{COLORS['reset']}"
            elif str(status).startswith("3"):
                status_colored = f"{COLORS['cyan']}{status}{COLORS['reset']}"
            elif str(status).startswith("4"):
                status_colored = f"{COLORS['yellow']}{status}{COLORS['reset']}"
            elif str(status).startswith("5"):
                status_colored = f"{COLORS['red']}{status}{COLORS['reset']}"
            else:
                status_colored = f"{COLORS['white']}{status}{COLORS['reset']}"

            # Format and output the request line
            self.info(f"  {method_colored} {url} {status_colored}")

            # Add headers if present
            if "headers" in entry and entry["headers"]:
                for key, value in entry["headers"].items():
                    self.debug(f"    {COLORS['light_black']}{key}: {value}{COLORS['reset']}")

def setup_logger(log_level: str = "DEBUG", log_file: Optional[str] = None, enable_colors: bool = True) -> Union[logging.Logger, PrettyLogger]:
    """Set up and configure the logger."""
    global _logger

    if _logger is not None:
        return _logger

    # Create logger
    logger = logging.getLogger("vibe_pen_tester")
    logger.setLevel(getattr(logging, log_level))
    logger.propagate = False

    # Clear any existing handlers
    if logger.handlers:
        logger.handlers.clear()

    # Create console handler
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setLevel(getattr(logging, log_level))

    # Create formatter based on color preference
    if enable_colors:
        formatter = ColoredFormatter(
            "%(asctime)s - %(name)s - %(levelname)s - %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S"
        )
    else:
        formatter = logging.Formatter(
            "%(asctime)s - %(name)s - %(levelname)s - %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S"
        )

    # Add formatter to console handler
    console_handler.setFormatter(formatter)

    # Add console handler to logger
    logger.addHandler(console_handler)

    # Add file handler if log_file is specified
    if log_file:
        # Ensure the directory exists
        os.makedirs(os.path.dirname(os.path.abspath(log_file)), exist_ok=True)

        file_handler = logging.FileHandler(log_file)
        file_handler.setLevel(getattr(logging, log_level))
        # Use non-colored formatter for file logging
        file_formatter = logging.Formatter(
            "%(asctime)s - %(name)s - %(levelname)s - %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S"
        )
        file_handler.setFormatter(file_formatter)
        logger.addHandler(file_handler)

    # Wrap the logger with our pretty printing capabilities
    pretty_logger = PrettyLogger(logger)
    _logger = pretty_logger
    return pretty_logger

def get_logger() -> Union[logging.Logger, PrettyLogger]:
    """Get the global logger instance, initializing it if necessary."""
    global _logger

    if _logger is None:
        _logger = setup_logger()

    return _logger
