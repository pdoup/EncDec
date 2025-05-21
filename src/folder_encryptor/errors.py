# src/folder_encryptor/errors.py
"""
Custom exception classes for the folder encryption application.
"""


class FolderEncryptorError(Exception):
    """Base class for exceptions in this application."""

    pass


class InitializationError(FolderEncryptorError):
    """Errors during application initialization (e.g., config, permissions)."""

    pass


class KeyManagementError(FolderEncryptorError):
    """Errors related to cryptographic key generation, loading, or validation."""

    pass


class FileOperationError(FolderEncryptorError):
    """Errors during file system operations (read, write, move, etc.)."""

    def __init__(self, message: str, filepath: str = None):
        super().__init__(message)
        self.filepath = filepath

    def __str__(self):
        if self.filepath:
            return f"{super().__str__()} (File: {self.filepath})"
        return super().__str__()


class MappingError(FolderEncryptorError):
    """Errors related to filename mapping operations (save, load, corruption)."""

    pass


class CryptoOperationError(FolderEncryptorError):
    """Errors during encryption or decryption processes."""

    pass


class BackupRestoreError(FolderEncryptorError):
    """Errors during backup or restoration processes."""

    pass


class ConfigurationError(FolderEncryptorError):
    """Errors related to invalid user configuration or arguments."""

    pass
