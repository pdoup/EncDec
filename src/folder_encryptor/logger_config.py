# src/folder_encryptor/logger_config.py
"""
Logging configuration for the application.
"""
import logging
import time
from pathlib import Path
from typing import Optional

from .constants import (LOG_DATE_FORMAT, LOG_FILE_BASENAME,
                        LOG_FILE_TIMESTAMP_FORMAT, LOG_FORMAT)

current_log_file_path: Optional[Path] = None


def setup_logging() -> Path:
    """Sets up logging configuration and returns the log file path."""
    global current_log_file_path
    timestamp = time.strftime(LOG_FILE_TIMESTAMP_FORMAT)
    log_file = Path(f"{LOG_FILE_BASENAME}_{timestamp}.log").resolve()
    current_log_file_path = log_file

    logging.basicConfig(
        filename=log_file,
        filemode="w",
        level=logging.INFO,
        format=LOG_FORMAT,
        datefmt=LOG_DATE_FORMAT,
    )
    return log_file
