# src/folder_encryptor/main.py
"""
Main command-line interface for the Folder Encryptor application.
"""
import argparse
import base64
import builtins
import logging
import re
from pathlib import Path
from pprint import pformat
from typing import Callable, Set

from cryptography.fernet import Fernet

from . import constants
from .crypto_ops import generate_key_file, load_key_file
from .errors import ConfigurationError, FolderEncryptorError
from .file_ops import delete_old_log_files, restore_all_from_run_backup
from .logger_config import setup_logging
from .models import ProcessResult
from .processing_engine import process_folder

__version__ = "1.0.0"


def parse_size_str(size_str: str) -> int:
    """Parses size strings like '1KB', '10MB' or '1.5GB' into bytes."""
    match = re.match(r"^\s*(\d+(\.\d+)?)\s*(KB|MB|GB)\s*$", size_str, re.IGNORECASE)
    if not match:
        raise argparse.ArgumentTypeError(
            "Invalid size format. Use e.g., '1KB', '10MB', '1.5GB'."
        )

    number_str, _, unit = match.groups()
    size_float = float(number_str)
    multiplier_map = {"KB": 1024, "MB": 1024**2, "GB": 1024**3}
    return int(size_float * multiplier_map[unit.upper()])


def run_main():
    """Main function to parse arguments and orchestrate the encryption/decryption process."""
    parser = argparse.ArgumentParser(
        prog="FolderEncryptor",
        description="Securely encrypts or decrypts a folder's contents.",
        formatter_class=lambda prog: argparse.HelpFormatter(prog, max_help_position=40),
    )
    parser.add_argument(
        "folder", type=Path, help="Target folder for encryption or decryption."
    )
    parser.add_argument("mode", choices=["encrypt", "decrypt"], help="Operation mode.")
    parser.add_argument(
        "--key",
        type=Path,
        default=constants.DEFAULT_KEY_FILENAME,
        help=f"Path to the key file (default: {constants.DEFAULT_KEY_FILENAME}).",
    )
    parser.add_argument(
        "--exclude",
        type=str,
        default="",
        help="Comma-separated file extensions to exclude (e.g., .log,.tmp). Case-insensitive.",
    )
    parser.add_argument(
        "--no-purge-after-decrypt",
        action="store_false",
        dest="purge_after_decrypt",
        default=True,
        help="If set, keeps backup folders and map files after successful decryption.",
    )
    parser.add_argument(
        "--no-backup",
        action="store_false",
        dest="create_backup",
        default=True,
        help="If set, disables creation of backups before modifying files. RISKY.",
    )
    parser.add_argument(
        "--min-folder-size",
        type=parse_size_str,
        default=None,
        dest="min_folder_size_bytes",
        help="Min total size of a subfolder for processing (e.g., 10MB). Encryption only.",
        metavar="SIZE",
    )
    parser.add_argument(
        "--max-file-size",
        type=parse_size_str,
        default=None,
        dest="max_file_size_bytes",
        help="Skip individual files larger than this size (e.g., 100MB). Encryption only.",
        metavar="SIZE",
    )
    parser.add_argument(
        "--workers",
        type=int,
        default=constants.DEFAULT_MAX_WORKERS,
        help=f"Number of worker threads (default: {constants.DEFAULT_MAX_WORKERS}).",
    )
    parser.add_argument(
        "-q",
        "--quiet",
        action="store_true",
        help="Suppress console output (logs are still written to file).",
    )
    parser.add_argument(
        "--restore-from-backup",
        action="store_true",
        dest="restore_mode",
        help="Special mode: attempts to restore the target folder from existing backups.",
    )
    parser.add_argument(
        "-v", "--version", action="version", version=f"%(prog)s {__version__}"
    )

    args = parser.parse_args()

    # --- Setup ---
    log_file_abs_path = setup_logging()

    # Handle quiet mode by replacing builtins.print
    original_print_func: Callable = builtins.print
    console_printer: Callable = original_print_func
    if args.quiet:
        console_printer = lambda *a, **kw: None  # type: ignore
        builtins.print = console_printer

    try:
        delete_old_log_files(console_printer, log_file_abs_path)
    except Exception as e:
        logging.warning(f"Could not complete deletion of old log files: {e}")

    logging.info(f"--- Starting {parser.prog} ---")
    logging.info(f"Version: {__version__}")
    logging.info(f"Arguments: {pformat(vars(args), compact=True)}")
    logging.info(f"Log file for this session: {log_file_abs_path}")

    target_folder: Path = args.folder.resolve()
    key_file: Path = args.key.resolve()

    try:
        if not target_folder.exists() or not target_folder.is_dir():
            raise ConfigurationError(
                f"Target folder not found or is not a directory: {target_folder}"
            )

        if args.restore_mode:
            console_printer(f"[*] Entering restore mode for folder: {target_folder}")
            logging.info(f"Restore mode activated for {target_folder}.")
            restore_all_from_run_backup(target_folder, console_printer)
            console_printer("[*] Restore attempt finished. Check logs for details.")
            logging.info("--- Restore mode finished ---")
            return

        # --- Normal encrypt/decrypt operation ---
        excluded_exts: Set[str] = {
            ext.strip().lower() for ext in args.exclude.split(",") if ext.strip()
        }
        if excluded_exts:
            logging.info(f"Excluding file extensions: {list(excluded_exts)}")

        fernet_key_bytes: bytes
        if args.mode == "encrypt":
            fernet_key_bytes = generate_key_file(key_file)
        else:  # decrypt
            fernet_key_bytes = load_key_file(key_file)

        fernet_instance = Fernet(base64.urlsafe_b64encode(fernet_key_bytes))

        min_f_size = (
            args.min_folder_size_bytes if args.min_folder_size_bytes is not None else 0
        )
        max_f_size = (
            args.max_file_size_bytes
            if args.max_file_size_bytes is not None
            else float("inf")
        )

        operation_result: ProcessResult = process_folder(
            folder_to_process=target_folder,
            fernet=fernet_instance,
            mode=args.mode,  # type: ignore
            key_file_path=key_file,
            excluded_extensions=excluded_exts,
            purge_backups_after_decrypt=args.purge_after_decrypt,
            create_backup_files=args.create_backup,
            min_folder_size_bytes=min_f_size,
            max_file_size_bytes=max_f_size,
            num_workers=args.workers,
            console_print_func=console_printer,
        )

    except FolderEncryptorError as e:
        logging.critical(f"Application error: {e}", exc_info=True)
        operation_result = ProcessResult(
            method=args.mode if "args" in locals() else "unknown",
            success=False,
            fatal_error=str(e),
        )
    except Exception as e:
        logging.critical(f"An unexpected critical error occurred: {e}", exc_info=True)
        operation_result = ProcessResult(
            method=args.mode if "args" in locals() else "unknown",
            success=False,
            fatal_error=f"Unexpected: {e}",
        )

        # Attempt rollback for encryption if backups were on and error is critical
        if "args" in locals() and args.mode == "encrypt" and args.create_backup:
            console_printer(
                "[!] Critical error during encryption. Attempting to restore from backups..."
            )
            logging.warning(
                "Critical error during encryption, attempting restore_all_from_run_backup."
            )
            try:
                restore_all_from_run_backup(target_folder, console_printer)
                console_printer(
                    "[!] Restore attempt finished. Please check the target folder and logs carefully."
                )
            except Exception as restore_ex:
                console_printer(
                    f"[!!!] Restore attempt FAILED: {restore_ex}. Manual check required."
                )
                logging.critical(
                    f"Restore attempt after critical error also FAILED: {restore_ex}",
                    exc_info=True,
                )
        elif "args" in locals() and args.mode == "encrypt" and not args.create_backup:
            console_printer(
                "[!] Critical error during encryption and backups were OFF. Manual recovery may be needed."
            )

    if args.quiet:
        builtins.print = original_print_func
        console_printer = builtins.print
    # --- Final Summary ---
    if operation_result.success:
        summary = (
            f"[+] {operation_result.method.capitalize()}ion complete.\n"
            f"  Total files processed: {operation_result.total_processed}\n"
        )
        if operation_result.method == "encrypt":
            summary += (
                f"  Files skipped (size/type filters): {operation_result.total_skipped_size_filter + operation_result.total_skipped_type_filter}\n"  # type: ignore
                f"  Files skipped (permissions): {operation_result.total_skipped_permissions}\n"
            )
        else:  # Decrypt
            summary += f"  Files skipped (permissions/map issues): {operation_result.total_skipped_permissions}\n"
        if operation_result.file_operation_errors > 0:
            summary += f"  File operations with non-fatal errors: {operation_result.file_operation_errors}\n"
        console_printer(summary)
    else:
        console_printer(f"[!!!] {operation_result.method.capitalize()}ion FAILED.")
        if operation_result.fatal_error:
            console_printer(f"  Fatal Error: {operation_result.fatal_error}")

    console_printer(
        f"[*] Log file: {log_file_abs_path.name if log_file_abs_path else 'N/A'}"
    )
    logging.info(f"--- {parser.prog} finished ---")
