"""Logging helpers for the honeypot."""

import logging
import os


LOG_DIR = "/app/logs"
LOG_FILE = "honeypot.log"


def create_logger(name="honeypot", level=logging.INFO):
    """
    Create and configure a logger.

    Args:
        name (str): Logger name
        level (int): Logging level (logging.INFO, DEBUG, etc.)

    Returns:
        logging.Logger
    """

    # Create log directory
    os.makedirs(LOG_DIR, exist_ok=True)

    logger = logging.getLogger(name)
    logger.setLevel(level)

    # Log format
    formatter = logging.Formatter(
        "%(asctime)s | %(levelname)s | %(name)s | %(message)s"
    )

    # -------- File Handler --------
    file_handler = logging.FileHandler(os.path.join(LOG_DIR, LOG_FILE))

    file_handler.setFormatter(formatter)
    file_handler.setLevel(level)

    # -------- Console Handler --------
    console_handler = logging.StreamHandler()
    console_handler.setFormatter(formatter)
    console_handler.setLevel(level)

    # Add handlers
    logger.addHandler(file_handler)
    logger.addHandler(console_handler)

    return logger
