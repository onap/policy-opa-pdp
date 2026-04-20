# utils/config.py
"""
Central configuration values used across the tool.

Nothing here should depend on a particular parsing backend.
"""

from __future__ import annotations

# CSV writing
CSV_DELIMITER: str = ","
CSV_ENCODING: str = "utf-8"

# Logging
DEFAULT_LOG_LEVEL: str = "INFO"

# Object-root wrapper names (used by YANG today; harmless for other parsers)
# You can extend this set during modularization if you decide to treat more
# wrapper containers as non-MOs (e.g., 'config', 'state', 'statistics').
WRAPPER_NAMES: set[str] = {"attributes"}

# File discovery defaults (extensions the pipeline is interested in by default)
# Keep it configurable; XML can pass a different set when it arrives.
DEFAULT_FILE_EXTENSIONS: tuple[str, ...] = (".yang",)
