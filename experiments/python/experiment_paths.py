#!/usr/bin/env python3
"""Shared path helpers for the active experiment scripts."""

from __future__ import annotations

import ctypes
import os
import sys
from pathlib import Path


SRC_DIR = Path(__file__).resolve().parent
EXPERIMENT_DIR = SRC_DIR.parent
REPO_ROOT = EXPERIMENT_DIR.parent
LIBOQS_PYTHON_DIR = REPO_ROOT / "build" / "liboqs-python"
LIBOQS_INSTALL_DIR = REPO_ROOT / "build" / "liboqs-install"
_LOCAL_LIBOQS_HANDLE = None


def add_liboqs_python_to_path() -> None:
    """Load the pinned local liboqs-python/liboqs pair when available."""
    global _LOCAL_LIBOQS_HANDLE
    local_liboqs = LIBOQS_INSTALL_DIR / "lib" / "liboqs.so"
    if local_liboqs.exists():
        os.environ.setdefault("OQS_INSTALL_PATH", str(LIBOQS_INSTALL_DIR))
        if _LOCAL_LIBOQS_HANDLE is None:
            _LOCAL_LIBOQS_HANDLE = ctypes.CDLL(
                str(local_liboqs), mode=ctypes.RTLD_GLOBAL
            )
    path = str(LIBOQS_PYTHON_DIR)
    if path not in sys.path:
        sys.path.insert(0, path)
