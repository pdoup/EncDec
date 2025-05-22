# src/folder_encryptor/constants.py
"""
Global constants for the folder encryption application.
"""
import os

from lib.secure_magic import get_key_magic  # Relative import

# Cryptographic Constants
KEY_HMAC_LENGTH: int = 32  # SHA-256 output size in bytes
KEY_MAGIC: bytes = get_key_magic()  # Loaded once from lib.secure_magic

# Application Defaults
DEFAULT_MAX_WORKERS: int = (os.cpu_count() or 1) * 2
DEFAULT_KEY_FILENAME: str = "secret.key"

# Logging
LOG_FILE_BASENAME: str = "folder_encryptor"
LOG_FILE_TIMESTAMP_FORMAT: str = "%Y%m%d_%H%M%S"
LOG_FORMAT: str = (
    "%(asctime)s.%(msecs)d - %(levelname)s - %(threadName)s - (%(funcName)s.%(lineno)s): %(message)s"
)
LOG_DATE_FORMAT: str = "%d-%b-%y %H:%M:%S"

# Backup & Mapping
BACKUP_DIR_NAME: str = ".bak"
MAPPING_FILENAME: str = "filenames.map"
BACKUP_MAPPING_FILENAME: str = "filenames_backup.json"  # Used in .bak folder

# Cache
FOLDER_SIZE_CACHE_MAXSIZE: int = 100_000
