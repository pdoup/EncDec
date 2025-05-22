# Folder Encryptor/Decryptor Tool

A command-line utility for encrypting and decrypting the contents of entire folders.

## :warning: **EXTREME CAUTION ADVISED** :warning:

* **DESTRUCTIVE NATURE**: This tool directly modifies your files and filenames. Incorrect use, bugs, interruptions, or loss of the encryption key **WILL LEAD TO IRREVERSIBLE DATA LOSS.**
* **HANDLE WITH EXTREME CARE**: Especially when dealing with sensitive or important data.
* **ALWAYS BACKUP YOUR DATA**: Before using this tool on any important files, ensure you have a separate, verified backup.
* **KEY MANAGEMENT IS CRITICAL**: Losing your `secret.key` file means your encrypted data will be **PERMANENTLY UNRECOVERABLE**. Secure your key file diligently.
* **TEST THOROUGHLY**: Use on non-critical data first to understand its behavior and ensure it works as expected in your environment.

**USE AT YOUR OWN RISK. THE AUTHORS ARE NOT RESPONSIBLE FOR ANY DATA LOSS.**

## Features

* **Strong Encryption**: Uses Fernet (AES-128 in CBC mode with PKCS7 padding) for file content.
* **Filename Obfuscation**: Encrypted files are renamed to their SHA-256 hashes.
* **Integrity Checks**: HMAC-SHA256 for key file and filename mapping integrity.
* **Concurrency**: Utilizes multithreading for faster processing of multiple files.
* **Backup Option**: Can create backups of files before encryption/decryption.
* **Restore Mode**: Attempt to restore files from backups in case of errors during encryption.
* **Customizable**:
    * Exclude files by extension.
    * Filter files/folders by size.
    * Adjustable number of worker threads.

## Core Operations

1.  **Encryption**:
    * Generates a `secret.key` (if one doesn't exist for encryption).
    * Optionally backs up original files to a `.bak` directory.
    * Renames original files to a hash of their original name.
    * Encrypts the content of these renamed files.
    * Creates an encrypted `filenames.map` to track original names.
2.  **Decryption**:
    * Requires the correct `secret.key`.
    * Reads the encrypted `filenames.map`.
    * Optionally backs up encrypted files.
    * Decrypts file content.
    * Restores original filenames.
    * Optionally cleans up backup files and the map.

## Installation

### Local Build

Inside the root project folder, run:

```bash
python -m build -w
```

The command generates a `.whl` file in the `dist/` directory.

Install the wheel with:
```bash
pip install dist/generated_file.whl # replace with actual .whl filename
```

### Run program without installation

The `folder-encryptor` can also run as a standalone application without building via `run.py` script:
```bash
python run.py target_dir/ encrypt # e.g., to encrypt target_dir
```

## Basic Usage

```bash
# Encrypt a folder
folder-encryptor "/path/to/your/folder" encrypt --key "my_secret.key"

# Decrypt a folder
folder-encryptor "/path/to/your/folder" decrypt --key "my_secret.key"

# View all options
folder-encryptor --help
```
```txt
# Output
usage: FolderEncryptor [-h] [--key KEY] [--exclude EXCLUDE] [--no-purge-after-decrypt] [--no-backup] [--min-folder-size SIZE]
                       [--max-file-size SIZE] [--workers WORKERS] [-q] [--restore-from-backup] [-v]
                       folder {encrypt,decrypt}

Securely encrypts or decrypts a folders contents.

positional arguments:
  folder                    Target folder for encryption or decryption.
  {encrypt,decrypt}         Operation mode.

options:
  -h, --help                show this help message and exit
  --key KEY                 Path to the key file (default: secret.key).
  --exclude EXCLUDE         Comma-separated file extensions to exclude (e.g., .log,.tmp). Case-insensitive.
  --no-purge-after-decrypt  If set, keeps backup folders and map files after successful decryption.
  --no-backup               If set, disables creation of backups before modifying files. RISKY.
  --min-folder-size SIZE    Min total size of a subfolder for processing (e.g., 10MB). Encryption only.
  --max-file-size SIZE      Skip individual files larger than this size (e.g., 100MB). Encryption only.
  --workers WORKERS         Number of worker threads (default: 2).
  -q, --quiet               Suppress console output (logs are still written to file).
  --restore-from-backup     Special mode: attempts to restore the target folder from existing backups.
  -v, --version             show program's version number and exit
```


## Dependencies

```bash
cachetools
cryptography
```

Also, `setuptools`, `wheel` and `build` are required for building the package.

## Disclaimer

This tool is provided "as-is" without any warranty. Always ensure you understand the risks before using it.
