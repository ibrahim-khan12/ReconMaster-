"""
Logging Utilities
=================
Provides logging configuration and utilities for the reconnaissance tool.

Supports multiple verbosity levels and formatted output.

Usage:
    from utils.logging_utils import setup_logging
    
    logger = setup_logging(verbosity=1)
"""

import logging
import sys
from typing import Optional
from datetime import datetime


class ColoredFormatter(logging.Formatter):
    """Colored formatter for console output."""
    
    # ANSI color codes
    COLORS = {
        'DEBUG': '\033[36m',      # Cyan
        'INFO': '\033[32m',       # Green
        'WARNING': '\033[33m',    # Yellow
        'ERROR': '\033[31m',      # Red
        'CRITICAL': '\033[41m',   # Red background
        'RESET': '\033[0m'        # Reset
    }
    
    def format(self, record):
        if sys.stdout.isatty():
            levelname = record.levelname
            if levelname in self.COLORS:
                record.levelname = f"{self.COLORS[levelname]}{levelname}{self.COLORS['RESET']}"
        return super().format(record)


def setup_logging(name: str = 'ReconMaster',
                  verbosity: int = 0,
                  log_file: Optional[str] = None) -> logging.Logger:
    """
    Configure logging for the reconnaissance tool.
    
    Args:
        name: Logger name
        verbosity: Verbosity level (0=INFO, 1=DEBUG, 2=VERBOSE_DEBUG)
        log_file: Optional log file path
        
    Returns:
        Configured logger instance
    """
    
    # Determine log level
    if verbosity == 0:
        log_level = logging.INFO
        log_format = '[%(asctime)s] %(levelname)-8s - %(message)s'
    elif verbosity == 1:
        log_level = logging.DEBUG
        log_format = '[%(asctime)s] %(levelname)-8s [%(name)s] - %(message)s'
    else:  # verbosity >= 2
        log_level = logging.DEBUG
        log_format = '[%(asctime)s] %(levelname)-8s [%(name)s:%(funcName)s:%(lineno)d] - %(message)s'
    
    # Create logger
    logger = logging.getLogger(name)
    logger.setLevel(log_level)
    
    # Remove existing handlers
    logger.handlers = []
    
    # Console handler
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setLevel(log_level)
    console_formatter = ColoredFormatter(log_format, datefmt='%Y-%m-%d %H:%M:%S')
    console_handler.setFormatter(console_formatter)
    logger.addHandler(console_handler)
    
    # File handler (optional)
    if log_file:
        try:
            file_handler = logging.FileHandler(log_file)
            file_handler.setLevel(log_level)
            file_formatter = logging.Formatter(log_format, datefmt='%Y-%m-%d %H:%M:%S')
            file_handler.setFormatter(file_formatter)
            logger.addHandler(file_handler)
            logger.info(f"Logging to file: {log_file}")
        except Exception as e:
            logger.warning(f"Could not create log file: {e}")
    
    return logger


def log_section(logger: logging.Logger, title: str, level: int = logging.INFO):
    """
    Log a section header.
    
    Args:
        logger: Logger instance
        title: Section title
        level: Log level
    """
    separator = "=" * 60
    logger.log(level, separator)
    logger.log(level, title)
    logger.log(level, separator)


def log_subsection(logger: logging.Logger, title: str, level: int = logging.INFO):
    """
    Log a subsection header.
    
    Args:
        logger: Logger instance
        title: Subsection title
        level: Log level
    """
    logger.log(level, f"\n--- {title} ---")


def log_result(logger: logging.Logger, key: str, value, level: int = logging.INFO):
    """
    Log a key-value result.
    
    Args:
        logger: Logger instance
        key: Result key
        value: Result value
        level: Log level
    """
    logger.log(level, f"{key}: {value}")


def log_list(logger: logging.Logger, title: str, items: list, level: int = logging.INFO):
    """
    Log a list of items.
    
    Args:
        logger: Logger instance
        title: List title
        items: List of items to log
        level: Log level
    """
    logger.log(level, f"{title}:")
    for item in items:
        logger.log(level, f"  • {item}")


if __name__ == "__main__":
    # Example usage
    logger = setup_logging(verbosity=1)
    
    log_section(logger, "RECONNAISSANCE TOOL STARTED")
    log_subsection(logger, "WHOIS Lookup")
    log_result(logger, "Domain", "example.com")
    log_list(logger, "Name Servers", ["ns1.example.com", "ns2.example.com"])
    log_section(logger, "RECONNAISSANCE COMPLETED")
