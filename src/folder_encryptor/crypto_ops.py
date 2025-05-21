# src/folder_encryptor/crypto_ops.py
"""
Cryptographic operations including key management, Fernet encryption/decryption,
filename hashing, and mapping file handling.
"""
import base64
import hashlib
import hmac
import json
import logging
from pathlib import Path
from typing import Dict, Literal

from cryptography.fernet import Fernet, InvalidToken
from lib.secure_magic import compute_hmac

from .constants import KEY_HMAC_LENGTH, KEY_MAGIC, MAPPING_FILENAME
from .errors import (CryptoOperationError, FileOperationError,
                     KeyManagementError, MappingError)


# --- Key Management ---
def generate_key_file(key_path: Path) -> bytes:
    """Generates and saves a new Fernet key with HMAC."""
    logging.info(f"Attempting to generate key file at: {key_path}")
    try:
        b64_key: bytes = Fernet.generate_key()
        raw_key: bytes = base64.urlsafe_b64decode(b64_key)  # 32 bytes

        # Compute HMAC of the raw key
        hmac_digest: bytes = compute_hmac(raw_key)

        key_path.parent.mkdir(parents=True, exist_ok=True)
        key_path.write_bytes(raw_key + hmac_digest)
        logging.info(f"Generated and saved tamper-resistant key: {key_path.name}")
        return raw_key
    except OSError as e:
        raise KeyManagementError(f"Failed to write key file {key_path}: {e}") from e
    except Exception as e:
        raise KeyManagementError(
            f"Unexpected error generating key file {key_path}: {e}"
        ) from e


def load_key_file(key_path: Path) -> bytes:
    """Loads and verifies a Fernet key from a file."""
    logging.info(f"Attempting to load key file from: {key_path}")
    if not key_path.exists():
        raise KeyManagementError(f"Key file not found: {key_path}")
    try:
        data: bytes = key_path.read_bytes()
    except OSError as e:
        raise KeyManagementError(f"Failed to read key file {key_path}: {e}") from e

    expected_length = 32 + KEY_HMAC_LENGTH
    if len(data) != expected_length:
        raise KeyManagementError(
            f"Invalid key file size: Expected {expected_length} bytes, found {len(data)}. "
            f"File: {key_path.name} may be corrupted or from a different version."
        )

    raw_key, stored_hmac = data[:32], data[32:]
    calc_hmac: bytes = hmac.new(raw_key, KEY_MAGIC, hashlib.sha256).digest()

    if not hmac.compare_digest(stored_hmac, calc_hmac):
        raise KeyManagementError(
            "Key integrity check failed. File may have been tampered with."
        )

    logging.info(f"Key loaded and verified from {key_path.name}")
    return raw_key


# --- Filename Hashing ---
def hash_filename(name: str) -> str:
    """Generates a SHA-256 hex digest for a filename string."""
    return hashlib.sha256(name.encode("utf-8")).hexdigest()


# --- Mapping File Operations ---
def get_map_path(folder: Path) -> Path:
    """Returns the standard path for the filenames.map file within a folder."""
    return folder / MAPPING_FILENAME


def save_mapping(
    mapping_data: Dict[str, Path], folder_path: Path, fernet: Fernet
) -> None:
    """Saves and encrypts the filename mapping to the standard map file."""
    map_file_path = get_map_path(folder_path)
    logging.info(f"Saving encrypted filename mapping to: {map_file_path}")
    serializable_mapping: Dict[str, str] = {
        k: str(v.as_posix()) for k, v in mapping_data.items()
    }
    try:
        plain_data: bytes = json.dumps(serializable_mapping).encode("utf-8")
        encrypted_data: bytes = fernet.encrypt(plain_data)
        map_file_path.write_bytes(encrypted_data)
        logging.info(f"Saved encrypted filename mapping at {map_file_path.name}")
    except json.JSONEncodeError as e:
        raise MappingError(
            f"Failed to serialize mapping data for {map_file_path.name}: {e}"
        ) from e
    except OSError as e:
        raise FileOperationError(
            f"Failed to write mapping file {map_file_path.name}: {e}",
            filepath=str(map_file_path),
        ) from e
    except Exception as e:  # Catch other crypto errors
        raise CryptoOperationError(
            f"Failed to encrypt mapping data for {map_file_path.name}: {e}"
        ) from e


def load_mapping(folder_path: Path, fernet: Fernet) -> Dict[str, Path]:
    """Loads and decrypts the filename mapping from the standard map file."""
    map_file_path = get_map_path(folder_path)
    logging.info(f"Loading encrypted filename mapping from: {map_file_path}")
    if not map_file_path.exists():
        raise MappingError(f"Filename mapping file not found: {map_file_path}")
    try:
        encrypted_data: bytes = map_file_path.read_bytes()
    except OSError as e:
        raise FileOperationError(
            f"Failed to read mapping file {map_file_path.name}: {e}",
            filepath=str(map_file_path),
        ) from e

    try:
        decrypted_data: bytes = fernet.decrypt(encrypted_data)
        deserialized_data: Dict[str, str] = json.loads(decrypted_data.decode("utf-8"))
        return {k: Path(v) for k, v in deserialized_data.items()}
    except InvalidToken:
        raise MappingError(
            f"Failed to decrypt mapping file {map_file_path.name}. Invalid key or corrupted file."
        )
    except json.JSONDecodeError:
        raise MappingError(
            f"Failed to parse mapping file {map_file_path.name}. File is corrupted."
        )
    except Exception as e:  # Catch other errors
        raise MappingError(
            f"Unexpected error loading mapping file {map_file_path.name}: {e}"
        )


# --- Core Encryption/Decryption of File Content ---
def perform_file_crypto_operation(
    filepath: Path,
    fernet: Fernet,
    operation_mode: Literal["encrypt", "decrypt"],
) -> bool:
    """
    Performs encryption or decryption on a single file's content in place.
    Assumes backup, if any, has been handled by the caller.

    Returns:
        True on success.
    Raises:
        FileOperationError for I/O issues.
        CryptoOperationError for encryption/decryption issues.
    """
    logging.debug(f"Performing {operation_mode} on content of: {filepath.name}")
    try:
        data: bytes = filepath.read_bytes()
        processed_data: bytes
        if operation_mode == "encrypt":
            processed_data = fernet.encrypt(data)
        else:  # decrypt
            processed_data = fernet.decrypt(data)  # Can raise InvalidToken

        filepath.write_bytes(processed_data)
        logging.info(f"Content of {filepath.name} {operation_mode}ed successfully.")
        return True
    except InvalidToken as e:
        logging.error(
            f"Decryption failed for {filepath.name}: Invalid token (likely wrong key or corrupted data)."
        )
        raise CryptoOperationError(
            f"Invalid token for {filepath.name}",
        ) from e
    except OSError as e:
        logging.error(
            f"{operation_mode.capitalize()}ion content failed (I/O error): {filepath.name} - {e}"
        )
        raise FileOperationError(
            f"I/O error during {operation_mode} for {filepath.name}: {e}",
            filepath=str(filepath),
        ) from e
    except Exception as e:  # Other cryptography errors
        logging.error(
            f"{operation_mode.capitalize()}ion content failed (unexpected crypto error): {filepath.name} - {e}"
        )
        raise CryptoOperationError(
            f"Unexpected crypto error for {filepath.name} during {operation_mode}: {e}"
        ) from e
