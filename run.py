#!/usr/bin/env python3
# run.py
import sys
from pathlib import Path

project_root = Path(__file__).resolve().parent
src_dir = project_root / "src"
sys.path.insert(0, str(src_dir))

from folder_encryptor.main import run_main

if __name__ == "__main__":
    run_main()
