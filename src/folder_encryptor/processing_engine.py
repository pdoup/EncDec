# src/folder_encryptor/processing_engine.py
"""
Core processing engine for encrypting and decrypting folders.
Includes worker functions for concurrent file operations.
"""
import concurrent.futures
import json
import logging
from pathlib import Path
from typing import Callable, Dict, List, Literal, Set, Tuple

from cryptography.fernet import Fernet

from .constants import BACKUP_MAPPING_FILENAME, DEFAULT_MAX_WORKERS
from .crypto_ops import (get_map_path, hash_filename, load_mapping,
                         perform_file_crypto_operation, save_mapping)
from .errors import (BackupRestoreError, CryptoOperationError,
                     FileOperationError, MappingError)
from .file_ops import (backup_file, clean_backups_and_maps,
                       get_backup_run_root, get_cached_folder_size,
                       restore_file_from_backup)
from .models import ProcessResult, WorkerDecryptResult, WorkerEncryptResult

# --- Worker Functions ---


def _worker_encrypt_file(
    file_to_process: Path,  # Absolute path to the file
    processing_root_folder: Path,  # Absolute path to the main folder being processed (args.folder)
    fernet_instance: Fernet,
    do_create_backup: bool,
    max_file_size_bytes: float,
    console_print_func: Callable = print,
) -> WorkerEncryptResult:
    """Worker to encrypt a single file."""
    try:
        if not file_to_process.exists():
            logging.warning(
                f"File {file_to_process.name} no longer exists at start of worker, skipping."
            )
            return WorkerEncryptResult(
                status="skipped_filter",
                original_file_path=file_to_process,
                error_details="File disappeared",
            )

        if file_to_process.stat().st_size > max_file_size_bytes:
            logging.info(
                f"Skipping large file in worker: {file_to_process.name} ({file_to_process.stat().st_size / 1024**2:.6f}MB)"
            )
            return WorkerEncryptResult(
                status="skipped_filter", original_file_path=file_to_process
            )

        original_relative_path: Path = file_to_process.relative_to(
            processing_root_folder
        )
        hashed_filename_str: str = hash_filename(
            file_to_process.name
        )  # Hash only the filename part

        new_filename = hash_filename(file_to_process.name)
        renamed_path = file_to_process.with_name(new_filename)

        # Backup original file (using its original name and path) before rename & encrypt
        if do_create_backup:
            backup_file(file_to_process, processing_root_folder)  # Raises on error

        # Rename the file
        file_to_process.rename(renamed_path)
        logging.info(f"Renamed '{file_to_process.name}' to '{renamed_path.name}'")

        # Encrypt the renamed file
        perform_file_crypto_operation(
            renamed_path, fernet_instance, "encrypt"
        )  # Raises on error
        console_print_func(f"[+] Encrypted: {original_relative_path}")
        return WorkerEncryptResult(
            status="ok",
            hashed_name=new_filename,  # Store the new filename (hash of original filename)
            relative_path=original_relative_path,  # Store original relative path for mapping
            original_file_path=file_to_process,
        )

    except (FileOperationError, CryptoOperationError, BackupRestoreError) as e:
        logging.error(f"Error processing {file_to_process.name} for encryption: {e}")
        # Attempt to restore from backup if rename occurred and backup was made
        if do_create_backup and "renamed_path" in locals() and renamed_path.exists():
            try:
                if restore_file_from_backup(file_to_process, processing_root_folder):
                    logging.info(
                        f"Successfully restored {file_to_process.name} from backup after error."
                    )
                    if renamed_path.exists() and renamed_path != file_to_process:
                        renamed_path.unlink(missing_ok=True)
                else:  # Restore failed or backup not found
                    logging.warning(
                        f"Could not restore {file_to_process.name} from backup after error."
                    )
                    # If rename happened, try to rename it back to original if possible.
                    if renamed_path.exists() and not file_to_process.exists():
                        try:
                            renamed_path.rename(file_to_process)
                            logging.info(
                                f"Renamed {renamed_path.name} back to {file_to_process.name} after error."
                            )
                        except Exception as rename_back_err:
                            logging.error(
                                f"Could not rename {renamed_path.name} back to {file_to_process.name}: {rename_back_err}"
                            )

            except Exception as restore_err:
                logging.error(
                    f"Error during post-error restoration for {file_to_process.name}: {restore_err}"
                )

        return WorkerEncryptResult(
            status="error", original_file_path=file_to_process, error_details=str(e)
        )

    except (PermissionError, OSError) as e:
        logging.warning(
            f"Permission/OS error during encryption of {file_to_process.name}: {e}"
        )
        return WorkerEncryptResult(
            status="skipped_permission",
            original_file_path=file_to_process,
            error_details=str(e),
        )
    except ValueError as e:
        logging.error(
            f"Error in encryption worker for {file_to_process.name}: {e}",
            exc_info=True,
            extra=dict(type_=e.__class__.__name__),
        )
        return WorkerEncryptResult(
            status="error",
            original_file_path=file_to_process,
            error_details=f"Possible subpath processing error detected: {e}",
        )
    except Exception as e:  # Catch-all for unexpected
        logging.critical(
            f"Unexpected critical error in encryption worker for {file_to_process.name}: {e}",
            exc_info=True,
        )
        return WorkerEncryptResult(
            status="error",
            original_file_path=file_to_process,
            error_details=f"Unexpected: {e}",
        )


def _worker_decrypt_file(
    encrypted_file_path: Path,  # Absolute path to the encrypted file (with hashed name)
    original_relative_path: Path,  # Original relative path (e.g., 'subdir/original_name.txt')
    processing_root_folder: Path,  # Absolute path to args.folder
    fernet_instance: Fernet,
    do_create_backup: bool,
    console_print_func: Callable = print,
) -> WorkerDecryptResult:
    """Worker to decrypt a single file."""
    original_hashed_name = encrypted_file_path.name
    try:
        if not encrypted_file_path.exists():
            logging.warning(
                f"Encrypted file {original_hashed_name} not found at start of worker. Skipping."
            )
            # This indicates an issue with the file list or concurrent modifications.
            return WorkerDecryptResult(
                status="file_not_found",
                original_hashed_name=original_hashed_name,
                error_details="File disappeared",
            )

        # Backup the encrypted file before decryption and rename
        if do_create_backup:
            backup_file(encrypted_file_path, processing_root_folder)  # Raises on error

        # Decrypt content in place
        perform_file_crypto_operation(
            encrypted_file_path, fernet_instance, "decrypt"
        )  # Raises on error

        # Rename to original name and path structure
        final_restored_path: Path = processing_root_folder / original_relative_path
        final_restored_path.parent.mkdir(parents=True, exist_ok=True)

        if encrypted_file_path != final_restored_path:
            encrypted_file_path.rename(final_restored_path)
            logging.info(
                f"Decrypted and renamed '{original_hashed_name}' to '{final_restored_path.relative_to(processing_root_folder)}'"
            )
        else:
            logging.info(
                f"Decrypted '{original_hashed_name}' (already at final path '{final_restored_path.relative_to(processing_root_folder)}')"
            )

        console_print_func(
            f"[+] Decrypted: {original_hashed_name[:10]}...{original_hashed_name[-10:]} -> {original_relative_path}"
        )
        return WorkerDecryptResult(
            status="ok",
            original_hashed_name=original_hashed_name,
            restored_path=final_restored_path,
        )

    except (FileOperationError, CryptoOperationError, BackupRestoreError) as e:
        logging.error(f"Error processing {original_hashed_name} for decryption: {e}")
        return WorkerDecryptResult(
            status="error",
            original_hashed_name=original_hashed_name,
            error_details=str(e),
        )
    except (PermissionError, OSError) as e:
        logging.warning(
            f"Permission/OS error during decryption of {original_hashed_name}: {e}"
        )
        return WorkerDecryptResult(
            status="skipped_permission",
            original_hashed_name=original_hashed_name,
            error_details=str(e),
        )
    except Exception as e:
        logging.critical(
            f"Unexpected critical error in decryption worker for {original_hashed_name}: {e}",
            exc_info=True,
        )
        return WorkerDecryptResult(
            status="error",
            original_hashed_name=original_hashed_name,
            error_details=f"Unexpected: {e}",
        )


# --- Main Processing Function ---
def process_folder(
    folder_to_process: Path,
    fernet: Fernet,
    mode: Literal["encrypt", "decrypt"],
    key_file_path: Path,
    excluded_extensions: Set[str],
    purge_backups_after_decrypt: bool,
    create_backup_files: bool,
    min_folder_size_bytes: int,
    max_file_size_bytes: float,
    num_workers: int = DEFAULT_MAX_WORKERS,
    console_print_func: Callable = print,
) -> ProcessResult:
    """Processes a folder for encryption or decryption using multiple threads."""
    result = ProcessResult(method=mode)
    map_file_path = get_map_path(folder_to_process)

    if not create_backup_files:
        logging.warning("Backups are OFF. This is risky.")
    console_print_func(
        f"[{'+' if create_backup_files else '!'}] Backups are {'ON' if create_backup_files else 'OFF'}"
    )
    console_print_func(f"[*] Using up to {num_workers} worker threads.")

    if mode == "encrypt":
        # --- Encryption ---
        current_filename_map: Dict[str, Path] = (
            {}
        )  # hashed_filename -> original_relative_path
        backup_reference_map: Dict[str, str] = {}

        files_for_processing: List[Path] = []
        # Phase 1: Discover and filter files (sequentially)
        subfolders_to_evaluate: List[Path] = [folder_to_process]
        try:
            if (
                min_folder_size_bytes >= 0
            ):  # Only rglob if needed for subfolder size check
                for f_obj in folder_to_process.rglob("*"):
                    if f_obj.is_dir():
                        subfolders_to_evaluate.append(f_obj)
        except (OSError, PermissionError) as e:
            logging.warning(
                f"Could not fully scan {folder_to_process.name} for subdirectories due to {e}. Some subfolders might be missed."
            )
            result.total_skipped_permissions += 1  # Count this as a permission issue

        discovered_files: Set[Path] = set()
        for subfolder_path in subfolders_to_evaluate:
            if not subfolder_path.is_dir():
                continue

            if min_folder_size_bytes >= 0:
                try:
                    current_subfolder_size = get_cached_folder_size(subfolder_path)
                    if current_subfolder_size < min_folder_size_bytes:
                        logging.info(
                            f"Skipping subfolder '{subfolder_path.relative_to(folder_to_process)}' (size {current_subfolder_size / 1024**2:.2f}MB < min {min_folder_size_bytes / 1024**2:.2f}MB)"
                        )
                        continue
                except Exception as e:
                    logging.warning(
                        f"Could not get size for subfolder {subfolder_path.name}: {e}. Skipping its direct evaluation for min_folder_size."
                    )

            try:
                for item in subfolder_path.iterdir():
                    abs_item_path = item.resolve()
                    if abs_item_path.is_file():
                        if (
                            abs_item_path == key_file_path
                            or abs_item_path == map_file_path
                            or abs_item_path.suffix.lower() in excluded_extensions
                        ):
                            result.total_skipped_type_filter += 1
                            logging.info(
                                f"Skipping '{abs_item_path.name}' due to type/exclusion filter."
                            )
                            continue
                        discovered_files.add(abs_item_path)
            except (PermissionError, OSError) as e:
                logging.warning(
                    f"Cannot access files in '{subfolder_path.name}' due to {e}. Skipping this directory."
                )
                result.total_skipped_permissions += 1

        # Sort files by path for deterministic processing order (simple scheduling)
        files_for_processing = sorted(list(discovered_files), key=lambda p: str(p))

        if not files_for_processing:
            logging.warning("No files found to encrypt after discovery and filtering.")
            console_print_func("[*] No files eligible for encryption.")
            return result

        console_print_func(
            f"[*] Identified {len(files_for_processing)} files for potential encryption."
        )

        # Phase 2: Process files concurrently
        with concurrent.futures.ThreadPoolExecutor(max_workers=num_workers) as executor:
            futures_map: Dict[concurrent.futures.Future[WorkerEncryptResult], Path] = {
                executor.submit(
                    _worker_encrypt_file,
                    fp,
                    folder_to_process,
                    fernet,
                    create_backup_files,
                    max_file_size_bytes,
                    console_print_func,
                ): fp
                for fp in files_for_processing
            }
            for future in concurrent.futures.as_completed(futures_map):
                worker_res = future.result()
                if (
                    worker_res.status == "ok"
                    and worker_res.hashed_name
                    and worker_res.relative_path
                ):
                    result.total_processed += 1
                    current_filename_map[worker_res.hashed_name] = (
                        worker_res.relative_path
                    )
                    backup_reference_map[worker_res.hashed_name] = str(
                        worker_res.relative_path.as_posix()
                    )
                elif worker_res.status == "skipped_permission":
                    result.total_skipped_permissions += 1
                elif worker_res.status == "skipped_filter":
                    result.total_skipped_size_filter += 1
                elif worker_res.status == "error":
                    result.file_operation_errors += 1
                    logging.error(
                        f"Encryption failed for {worker_res.original_file_path.name if worker_res.original_file_path else 'unknown file'}: {worker_res.error_details}"
                    )

        if not current_filename_map and result.total_processed == 0:
            logging.warning("No files were successfully encrypted.")
            console_print_func("[!] No files were encrypted.")
        else:
            try:
                save_mapping(current_filename_map, folder_to_process, fernet)
                if create_backup_files and backup_reference_map:
                    backup_run_root = get_backup_run_root(folder_to_process)
                    backup_run_root.mkdir(parents=True, exist_ok=True)
                    backup_map_path = backup_run_root / BACKUP_MAPPING_FILENAME
                    backup_map_path.write_text(
                        json.dumps(backup_reference_map, indent=2), encoding="utf-8"
                    )
                    logging.info(f"Saved backup reference map to {backup_map_path}")
            except (MappingError, FileOperationError, CryptoOperationError) as e:
                logging.critical(
                    f"CRITICAL: Failed to save mapping or backup reference map: {e}",
                    exc_info=True,
                )
                result.success = False
                result.fatal_error = f"Failed to save map files: {e}"

    elif mode == "decrypt":
        # --- Decryption ---
        try:
            filename_map_to_restore = load_mapping(folder_to_process, fernet)
        except MappingError as e:
            logging.error(f"Cannot decrypt: {e}")
            result.success = False
            result.fatal_error = str(e)
            return result

        if not filename_map_to_restore:
            logging.warning("Filename map is empty. Nothing to decrypt.")
            console_print_func("[*] Filename map is empty. No files to decrypt.")
            return result

        files_for_decryption: List[Tuple[Path, Path]] = (
            []
        )  # (abs_encrypted_path, original_relative_path)
        try:
            for original_relative_path_obj in filename_map_to_restore.values():
                hashed_filename_str = None
                for h_name, o_rel_path in filename_map_to_restore.items():
                    if o_rel_path == original_relative_path_obj:
                        hashed_filename_str = h_name
                        break

                if not hashed_filename_str:
                    continue  # Should not happen if map is consistent

                expected_encrypted_file_path = (
                    folder_to_process
                    / original_relative_path_obj.parent
                    / hashed_filename_str
                ).resolve()

                if expected_encrypted_file_path.is_file():
                    files_for_decryption.append(
                        (expected_encrypted_file_path, original_relative_path_obj)
                    )
                else:
                    logging.warning(
                        f"Mapped file for decryption not found: expected at '{expected_encrypted_file_path}' (original: '{original_relative_path_obj}')"
                    )

        except (OSError, PermissionError) as e:
            logging.error(
                f"Failed to scan folder {folder_to_process.name} for decryption candidates: {e}"
            )
            result.success = False
            result.fatal_error = f"Could not scan folder: {e}"
            return result

        # Sort by encrypted file path for deterministic order
        files_for_decryption.sort(key=lambda x: str(x[0]))

        if not files_for_decryption:
            logging.warning("No files found matching the map for decryption.")
            console_print_func("[*] No encrypted files found matching the map.")
            return result

        console_print_func(
            f"[*] Identified {len(files_for_decryption)} files for decryption based on map."
        )

        with concurrent.futures.ThreadPoolExecutor(max_workers=num_workers) as executor:
            futures_map: Dict[concurrent.futures.Future[WorkerDecryptResult], Path] = {
                executor.submit(
                    _worker_decrypt_file,
                    enc_path,
                    orig_rel_path,
                    folder_to_process,
                    fernet,
                    create_backup_files,
                    console_print_func,
                ): enc_path
                for enc_path, orig_rel_path in files_for_decryption
            }
            for future in concurrent.futures.as_completed(futures_map):
                worker_res = future.result()
                if worker_res.status == "ok":
                    result.total_processed += 1
                elif worker_res.status == "skipped_permission":
                    result.total_skipped_permissions += 1
                elif worker_res.status == "error":
                    result.file_operation_errors += 1
                    logging.error(
                        f"Decryption failed for {worker_res.original_hashed_name}: {worker_res.error_details}"
                    )
                elif worker_res.status == "file_not_found":
                    result.file_operation_errors += 1
                    logging.warning(
                        f"Decryption skipped for {worker_res.original_hashed_name}: File disappeared."
                    )

        if purge_backups_after_decrypt:
            try:
                clean_backups_and_maps(folder_to_process, console_print_func)
            except Exception as e:
                logging.error(f"Error during post-decryption cleanup: {e}")
                console_print_func(f"[!] Error during cleanup: {e}. Check logs.")
        else:
            logging.info("Skipping cleanup of backups and map file as per settings.")

    return result
