# src/folder_encryptor/models.py
"""
Dataclasses for the folder encryption application.
"""
from dataclasses import dataclass, field
from pathlib import Path
from typing import Literal, Optional, Union


@dataclass(kw_only=True, slots=True, eq=False)
class ProcessResult:
    """Represents the result of an encryption or decryption process."""

    method: Literal["encrypt", "decrypt"] = field(default="encrypt")
    total_processed: int = field(default=0)
    total_skipped_size_filter: int = field(default=0, repr=False)
    total_skipped_type_filter: int = field(default=0, repr=False)
    total_skipped_permissions: int = field(default=0, repr=False)
    success: bool = field(default=True)
    fatal_error: Optional[str] = field(
        default=None, repr=False
    )  # For process-halting errors
    file_operation_errors: int = field(
        default=0, repr=False
    )  # Count of non-fatal individual file errors

    def __post_init__(self) -> None:
        if self.fatal_error is not None:
            self.fatal_error = (
                f"Process completed with fatal errors: {self.fatal_error}"
            )

        if self.method != "encrypt":
            # For decryption, skipping logic is different
            self.total_skipped_size_filter: Union[int, str] = "N/A"
            self.total_skipped_type_filter: Union[int, str] = "N/A"

    @property
    def total_skipped(self) -> Union[int, str]:
        if self.method != "encrypt":
            return (
                self.total_skipped_permissions
            )  # Only permission skips are directly counted for decrypt within process_folder
        return (
            self.total_skipped_size_filter
            + self.total_skipped_type_filter
            + self.total_skipped_permissions
        )


@dataclass(slots=True)
class WorkerEncryptResult:
    """Result of an encryption attempt by a worker."""

    status: Literal["ok", "skipped_permission", "skipped_filter", "error"]
    original_file_path: Optional[Path] = None
    hashed_name: Optional[str] = None
    relative_path: Optional[Path] = None
    error_details: Optional[str] = None


@dataclass(slots=True)
class WorkerDecryptResult:
    """Result of a decryption attempt by a worker."""

    status: Literal["ok", "skipped_permission", "error", "file_not_found"]
    original_hashed_name: str  # Even on error, we know which hash we were trying
    restored_path: Optional[Path] = None
    error_details: Optional[str] = None
