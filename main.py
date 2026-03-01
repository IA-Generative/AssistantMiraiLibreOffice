"""Compatibility shim for LibreOffice Python loader.

The real implementation lives in src/mirai/entrypoint.py.
"""

import os
import sys

# Ensure the extension root is importable when loaded by UNO/pythonloader.
_THIS_DIR = os.path.dirname(__file__)
if _THIS_DIR and _THIS_DIR not in sys.path:
    sys.path.insert(0, _THIS_DIR)

from src.mirai.entrypoint import *  # noqa: F401,F403
