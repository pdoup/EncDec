# src/folder_encryptor/file_ops.py
"""
File system operations: backup, restore, cleanup, size calculation, log deletion.
"""
import json
import logging
import shutil
from pathlib import Path
from threading import Lock
from typing import Dict

from cachetools import LRUCache

from .constants import (BACKUP_DIR_NAME, BACKUP_MAPPING_FILENAME,
                        FOLDER_SIZE_CACHE_MAXSIZE, LOG_FILE_BASENAME,
                        MAPPING_FILENAME)
from .errors import BackupRestoreError, FileOperationError

# --- Cache for Folder Sizes ---
folder_size_cache: LRUCache = LRUCache(maxsize=FOLDER_SIZE_CACHE_MAXSIZE)
_cache_lock: Lock = Lock()


def get_cached_folder_size(folder: Path) -> int:
    """Calculates and caches the total size of files in a folder."""
    # Ensure folder is absolute for consistent cache keys
    abs_folder = folder.resolve()
    with _cache_lock:
        if abs_folder in folder_size_cache:
            return folder_size_cache[abs_folder]

    total_size = 0
    try:
        for entry in abs_folder.rglob("*"):
            if entry.is_file():
                try:
                    total_size += entry.stat().st_size
                except (
                    PermissionError,
                    OSError,
                    FileNotFoundError,
                ):  # FileNotFoundError if symlink broken
                    logging.warning(
                        f"Skipping size calculation for {entry.name} (permission/OS/not found)."
                    )
                except Exception as e:  # Catch any other stat error
                    logging.warning(
                        f"Unexpected error getting size of {entry.name}: {e}, skipping."
                    )
    except (PermissionError, OSError) as e:
        logging.warning(f"Cannot access folder {abs_folder} for size calculation: {e}")
        return 0
    except Exception as e:  # Catch any other rglob error
        logging.warning(
            f"Unexpected error iterating {abs_folder} for size calculation: {e}"
        )
        return 0

    with _cache_lock:
        folder_size_cache[abs_folder] = total_size
    return total_size


# --- Backup and Restore Individual Files ---


def _get_backup_path_for_file(file_path: Path, main_processing_folder: Path) -> Path:
    """
    Determines the backup location for a given file.
    Backups are stored relative to `main_processing_folder.parent / .bak / main_processing_folder.name / ...`
    """
    try:
        relative_to_main_folder: Path = file_path.relative_to(main_processing_folder)
    except (
        ValueError
    ):  # If file_path is not under main_processing_folder (e.g. key file outside)
        logging.error(
            f"Cannot determine relative path for backup of {file_path} against {main_processing_folder}"
        )
        raise BackupRestoreError(f"Cannot create relative backup path for {file_path}")

    backup_root_for_this_run: Path = (
        main_processing_folder.parent / BACKUP_DIR_NAME / main_processing_folder.name
    )
    return backup_root_for_this_run / relative_to_main_folder


def backup_file(file_to_backup: Path, main_processing_folder: Path) -> bool:
    """
    Creates a backup of a file.
    main_processing_folder is the root folder passed to the program (e.g. args.folder).
    Returns True if backup successful or not needed, False on error.
    """
    backup_target_path = _get_backup_path_for_file(
        file_to_backup, main_processing_folder
    )
    logging.debug(f"Attempting to backup {file_to_backup.name} to {backup_target_path}")
    try:
        backup_target_path.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(file_to_backup, backup_target_path)  # Preserves metadata
        logging.info(f"Backed up {file_to_backup.name} -> {backup_target_path.name}")
        return True
    except (PermissionError, OSError) as e:
        logging.warning(
            f"Backup failed for {file_to_backup.name} (permission/OS error): {e}"
        )
        raise FileOperationError(
            f"Backup permission/OS error for {file_to_backup.name}: {e}",
            filepath=str(file_to_backup),
        ) from e
    except Exception as e:
        logging.warning(
            f"Backup failed for {file_to_backup.name} (unexpected error): {e}"
        )
        raise BackupRestoreError(
            f"Unexpected backup error for {file_to_backup.name}: {e}"
        ) from e


def restore_file_from_backup(
    file_to_restore_to: Path, main_processing_folder: Path
) -> bool:
    """
    Restores a single file to `file_to_restore_to` from its corresponding backup location.
    Returns True if successful or backup not found, False on error during restore.
    """
    backup_source_path = _get_backup_path_for_file(
        file_to_restore_to, main_processing_folder
    )
    logging.debug(
        f"Attempting to restore {file_to_restore_to.name} from {backup_source_path.name}"
    )

    if not backup_source_path.exists():
        logging.warning(
            f"No backup found for {file_to_restore_to.name} at {backup_source_path}, cannot restore."
        )
        return True  # Not an error if backup doesn't exist, just can't restore

    try:
        file_to_restore_to.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(backup_source_path, file_to_restore_to)
        logging.info(
            f"Restored {file_to_restore_to.name} from backup {backup_source_path.name}"
        )
        return True
    except (PermissionError, OSError) as e:
        logging.error(
            f"Failed to restore {file_to_restore_to.name} from backup (permission/OS error): {e}"
        )
        raise FileOperationError(
            f"Restore permission/OS error for {file_to_restore_to.name}: {e}",
            filepath=str(file_to_restore_to),
        ) from e
    except Exception as e:
        logging.error(
            f"Failed to restore {file_to_restore_to.name} from backup (unexpected error): {e}"
        )
        raise BackupRestoreError(
            f"Unexpected restore error for {file_to_restore_to.name}: {e}"
        ) from e


# --- Full Backup Restoration and Cleanup ---


def get_backup_run_root(target_folder: Path) -> Path:
    """Returns the root directory for backups of a specific run/target_folder."""
    return target_folder.parent / BACKUP_DIR_NAME / target_folder.name


def restore_all_from_run_backup(target_folder: Path, console_print_func=print) -> None:
    """Attempts to restore all files and filenames for a given target_folder from its backup."""
    backup_run_root = get_backup_run_root(target_folder)
    backup_map_json_path = backup_run_root / BACKUP_MAPPING_FILENAME

    total_restored_files = 0

    logging.info(
        f"Attempting full restore for '{target_folder.name}' from backup at '{backup_run_root}'"
    )
    console_print_func(
        f"[*] Attempting full restore for '{target_folder.name}' from backups..."
    )

    if not backup_run_root.exists() or not backup_run_root.is_dir():
        logging.warning(
            f"Backup directory {backup_run_root} not found. Nothing to restore."
        )
        console_print_func(f"[!] Backup directory not found: {backup_run_root}")
        return

    # Step 1: Restore file contents
    for item in backup_run_root.rglob("*"):
        if item.is_file() and item.name != BACKUP_MAPPING_FILENAME:
            try:
                relative_path_from_backup_root = item.relative_to(backup_run_root)
                destination_path = target_folder / relative_path_from_backup_root
                destination_path.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(item, destination_path)
                logging.info(f"Restored content: '{item.name}' to '{destination_path}'")
                total_restored_files += 1
            except Exception as e:
                logging.error(f"Failed to restore content from '{item}': {e}")
                console_print_func(
                    f"[!] Error restoring content from '{item.name}': {e}"
                )

    # Step 2: Restore filenames using the backup mapping JSON
    original_names_map: Dict[str, str] = {}
    if backup_map_json_path.exists():
        try:
            original_names_map = json.loads(backup_map_json_path.read_text("utf-8"))
            logging.info(
                f"Loaded original filenames map from {backup_map_json_path.name}"
            )
        except Exception as e:
            logging.error(
                f"Failed to load or parse {backup_map_json_path.name}: {e}. Filename restoration may be incomplete."
            )
            console_print_func(
                f"[!] Error loading backup map {backup_map_json_path.name}: {e}"
            )

    if original_names_map:
        # Iterate through files currently in the target_folder (potentially with hashed names)
        files_in_target = list(target_folder.rglob("*"))  # Materialize once
        for current_file_path in files_in_target:
            if current_file_path.is_file():
                logging.warning(
                    "Filename restoration in restore_all_from_run_backup currently relies on content restoration only."
                )
                console_print_func(
                    "[*] Content restoration from backup is complete. Filename restoration requires a valid main mapping file for decryption."
                )

    console_print_func(
        f"[+] Restore attempt: {total_restored_files} file contents copied from backup."
    )
    if total_restored_files == 0 and not (
        backup_run_root.exists() and any(backup_run_root.iterdir())
    ):
        console_print_func(f"[!] No backup data found in {backup_run_root} to restore.")


def clean_backups_and_maps(processed_folder: Path, console_print_func=print) -> None:
    """Cleans up the specific backup run directory and the main .map file."""
    backup_run_root = get_backup_run_root(processed_folder)
    main_map_file = processed_folder / MAPPING_FILENAME
    items_deleted = 0
    errors_occurred = 0

    logging.info(f"Cleaning up backups for '{processed_folder.name}' and its map file.")
    console_print_func(f"[*] Cleaning up backups for '{processed_folder.name}'...")

    if backup_run_root.exists() and backup_run_root.is_dir():
        try:
            shutil.rmtree(backup_run_root)
            logging.info(f"Deleted backup directory: {backup_run_root}")
            console_print_func(
                f"  [-] Deleted backup directory: {backup_run_root.name}"
            )
            items_deleted += 1
        except Exception as e:
            logging.warning(f"Failed to delete backup directory {backup_run_root}: {e}")
            console_print_func(
                f"  [!] Error deleting backup directory {backup_run_root.name}: {e}"
            )
            errors_occurred += 1
    else:
        logging.info(
            f"Backup directory {backup_run_root} not found, skipping deletion."
        )

    if main_map_file.exists() and main_map_file.is_file():
        try:
            main_map_file.unlink()
            logging.info(f"Deleted map file: {main_map_file}")
            console_print_func(f"  [-] Deleted map file: {main_map_file.name}")
            items_deleted += 1
        except Exception as e:
            logging.warning(f"Failed to delete map file {main_map_file}: {e}")
            console_print_func(
                f"  [!] Error deleting map file {main_map_file.name}: {e}"
            )
            errors_occurred += 1
    else:
        logging.info(f"Map file {main_map_file} not found, skipping deletion.")

    if items_deleted > 0:
        console_print_func(
            f"[*] Cleanup finished. {items_deleted} item(s) targeted for deletion."
        )
    if errors_occurred > 0:
        console_print_func(
            f"[!] {errors_occurred} error(s) during cleanup. Check logs."
        )


def delete_old_log_files(
    console_print_func=print, current_log_file_path: str | Path = None
) -> None:
    """Deletes old log files from the CWD, keeping the current session's log."""
    cwd = Path.cwd()
    current_log_name = current_log_file_path.name if current_log_file_path else None
    deleted_count = 0
    errors_count = 0

    logging.info(
        f"Checking for old log files (basename: '{LOG_FILE_BASENAME}') in {cwd}"
    )
    if not current_log_name:
        logging.warning("Current log file path not set, cannot safely delete old logs.")
        return

    for entry in cwd.iterdir():
        if (
            entry.is_file()
            and entry.name.startswith(LOG_FILE_BASENAME)
            and entry.name.lower().endswith(".log")
            and entry.name != current_log_name
        ):
            try:
                entry.unlink()
                logging.info(f"Deleted old log file: {entry.name}")
                deleted_count += 1
            except Exception as e:
                logging.error(f"Failed to delete old log file {entry.name}: {e}")
                errors_count += 1

    if deleted_count > 0:
        console_print_func(f"[*] Deleted {deleted_count} old log file(s).")
    if errors_count > 0:
        console_print_func(
            f"[!] Failed to delete {errors_count} old log file(s). Check logs."
        )
