# utils/config.py
"""
Central configuration values used across the tool.

Nothing here should depend on a particular parsing backend.
"""

from __future__ import annotations
from dataclasses import dataclass
import json

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


@dataclass
class YangParserConfig:
    input: str
    deps: str
    output: str
    no_subdirs: bool = False
    log_level: str = "INFO"


def load_config() -> YangParserConfig:
    """Load configuration from JSON file."""
    with open("config.py", "r") as f:
        data = json.load(f)

    return YangParserConfig(
        input=data["input"],
        deps=data["deps"],
        output=data["output"],
        no_subdirs=data.get("no_subdirs", False),
        log_level=data.get("log_level", "INFO"),
    )
