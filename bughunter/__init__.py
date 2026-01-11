# BugHunter Arsenal - Main platform module

# Read version from version.txt
from pathlib import Path

_version_file = Path(__file__).parent.parent / "version.txt"
if _version_file.exists():
    with open(_version_file, 'r') as f:
        __version__ = f.read().strip()
else:
    __version__ = "1.0.0"  # Fallback

# Export shared modules
from . import recon
from . import http_client
from . import database

__all__ = ['recon', 'http_client', 'database']