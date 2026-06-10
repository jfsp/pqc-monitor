"""
PQC-Monitor: Version module
Single source of truth for the application version string.
All UI, API, and CLI components import from here.

Version is read from the VERSION file in the project root so it
can be updated in one place without editing Python source.

SPDX-License-Identifier: GPL-3.0-or-later
Copyright (C) 2024 PQC-Monitor Contributors
AI-assisted development: portions generated with Claude (Anthropic)
"""

import os as _os

# Resolve path relative to this file so it works regardless of CWD
_VERSION_FILE = _os.path.join(_os.path.dirname(__file__), "VERSION")

try:
    with open(_VERSION_FILE) as _f:
        __version__: str = _f.read().strip()
except FileNotFoundError:
    __version__ = "0.0.0+unknown"

# Short alias used in templates and log messages
VERSION: str = __version__
