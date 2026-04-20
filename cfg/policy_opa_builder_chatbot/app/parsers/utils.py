# utils.py
"""Utility functions for logging, strings, paths, and small data models."""
from __future__ import annotations

import glob
# ---------------- logging ----------------
import logging
import os
import re
from dataclasses import dataclass
from typing import Any, Callable, Dict, Hashable, Iterable, List, Optional, Sequence, TypeVar

ProjectLogger = None
try:
    # prefer package under project root: ./var/logs.py
    from libs.logs import Logger as _ProjectLogger
    ProjectLogger = _ProjectLogger
except Exception:
    try:
        # fallback if your environment exposes ./libs/log.py
        from libs.logs import Logger as _ProjectLogger
        ProjectLogger = _ProjectLogger
    except Exception:
        ProjectLogger = None


def init_logging(level: str) -> None:
    """
    Initialize logging for the app.

    - If central Logger is available, propagate the level via LOG_LEVEL env var
      before any logger is acquired.
    - Else, fall back to stdlib basicConfig (previous behavior).
    """
    if ProjectLogger is not None:
        os.environ["LOG_LEVEL"] = str(level).upper()
        # Force-create a logger at module '' (root-ish) so handler is installed once.
        ProjectLogger.get("")  # handler + level set by Logger.get(...)
    else:
        lvl = getattr(logging, str(level).upper(), logging.INFO)
        logging.basicConfig(level=lvl, format="[%(levelname)s] %(message)s")


def get_logger(name: Optional[str] = None) -> Any:
    """get_logger.

    Return a module logger using the central Logger if available.
    otherwise, return stdlib logger.
    """
    if ProjectLogger is not None:
        return ProjectLogger.get(name or "")
    return logging.getLogger(name or "")


def set_log_level(level: str) -> None:
    """
    Set global logging level at runtime.

    - With central Logger: update LOG_LEVEL and re-acquire the root logger.
    - Else: set stdlib root level.
    """
    if ProjectLogger is not None:
        os.environ["LOG_LEVEL"] = str(level).upper()
        ProjectLogger.get("")  # re-evaluate level
    else:
        lvl = getattr(logging, str(level).upper(), logging.INFO)
        logging.getLogger().setLevel(lvl)


# ---------------- strings ----------------
_WS_RE = re.compile(r"\s+")


def normalize_description(text: str) -> str:
    """Normalize whitespace inside a description string."""
    if not text:
        return ""
    return _WS_RE.sub(" ", str(text)).strip()


def safe_filename(name: str, *, allowed: str = "-_.") -> str:
    """Sanitize only the filename part."""
    return "".join(ch for ch in name if ch.isalnum() or ch in allowed) or "out"


def output_xlsx_path(input_path: str, out_dir: str) -> str:
    """Generate the output .xlsx file path for a given input file."""
    base = os.path.basename(input_path)
    base = safe_filename(base)
    filename = f"{base}.xlsx"
    return os.path.join(out_dir, filename)


# ---------------- preserve order ----------------
T = TypeVar("T")


def preserve_order(
        items: Iterable[T],
        key: Callable[[T], Hashable]
) -> List[T]:
    """Preserve order while removing items with duplicate keys."""
    out: List[T] = []
    seen: set[Hashable] = set()
    for it in items:
        k = key(it)
        if k in seen:
            continue
        seen.add(k)
        out.append(it)
    return out


# ---------------- paths ----------------
def expand_colon_list(value: str) -> List[str]:
    """Split a colon-separated string into expanded path components."""
    out: List[str] = []
    if not value:
        return out
    for piece in value.split(":"):
        piece = piece.strip()
        if not piece:
            continue
        out.append(os.path.expanduser(os.path.expandvars(piece)))
    return out


def expand_paths(colon_value: str) -> List[str]:
    """Expand patterns in colon-separated paths into absolute paths."""
    items = expand_colon_list(colon_value)
    expanded: List[str] = []
    for raw in items:
        matches = glob.glob(raw) or [raw]
        expanded.extend(os.path.abspath(m) for m in matches)
    seen: set[str] = set()
    uniq: List[str] = []
    for p in expanded:
        if p not in seen:
            seen.add(p)
            uniq.append(p)
    return uniq


def gather_files(
    paths: Sequence[str],
    *,
    recurse: bool = True,
    extensions: Sequence[str] = (".yang",),
) -> List[str]:
    """Collect files from given paths, optionally recursing into directories."""
    normalized_extensions = normalize_extensions(extensions)
    collected: List[str] = []
    for path in paths:
        collected.extend(collect_from_path(path, recurse, normalized_extensions))
    return unique_absolute_paths(collected)


def normalize_extensions(extensions: Optional[Sequence[str]]) -> tuple[str, ...]:
    """Normalize extensions for matching."""
    return tuple(extensions) if extensions else ()


def matches_extension(name: str, normalized_extensions: tuple[str, ...]) -> bool:
    """Check if filename matches extensions (case-insensitive)."""
    return (not normalized_extensions) or name.lower().endswith(normalized_extensions)


def collect_from_path(
    path: str,
    recurse: bool,
    normalized_extensions: tuple[str, ...],
) -> List[str]:
    """Collect files from a single path."""
    if os.path.isfile(path):
        return [absolute_if_matches(path, normalized_extensions)]
    if os.path.isdir(path):
        return collect_from_directory(path, recurse, normalized_extensions)
    return []


def absolute_if_matches(path: str, normalized_extensions: tuple[str, ...]) -> str:
    """Return absolute path if extension matches; else empty."""
    return os.path.abspath(path) if matches_extension(path, normalized_extensions) else ""


def collect_from_directory(
    directory_path: str,
    recurse: bool,
    normalized_extensions: tuple[str, ...],
) -> List[str]:
    """Collect matching files from a directory."""
    out: List[str] = []
    if recurse:
        iterator = (
            os.path.join(base, filename)
            for base, _, files in os.walk(directory_path)
            for filename in files
        )
    else:
        iterator = (
            os.path.join(directory_path, filename)
            for filename in os.listdir(directory_path)
            if os.path.isfile(os.path.join(directory_path, filename))
        )
    for path in iterator:
        if matches_extension(path, normalized_extensions):
            out.append(path)
    return out


def unique_absolute_paths(paths: Sequence[str]) -> List[str]:
    """Return unique absolute paths, skipping empty entries."""
    seen: set[str] = set()
    uniq: List[str] = []
    for p in paths:
        if not p:
            continue
        ap = os.path.abspath(p)
        if ap not in seen:
            seen.add(ap)
            uniq.append(ap)
    return uniq


def collect_search_dirs(
    input_paths: Sequence[str], dep_paths: Sequence[str]
) -> List[str]:
    """Collect unique directories referenced in input and dependency paths."""
    dirs: List[str] = []
    for p in list(input_paths or []) + list(dep_paths or []):
        if os.path.isdir(p):
            dirs.append(os.path.abspath(p))
        elif os.path.isfile(p):
            dirs.append(os.path.abspath(os.path.dirname(p)))
    seen: set[str] = set()
    uniq: List[str] = []
    for d in dirs:
        if d not in seen:
            seen.add(d)
            uniq.append(d)
    return uniq


# ---------------- models ----------------
@dataclass
class Discovery:
    """Container for discovered input/dep paths, files, search dirs, and flags."""

    input_paths: List[str]
    dep_paths: List[str]
    input_files: List[str]
    dep_files: List[str]
    search_dirs: List[str]
    recurse: bool


@dataclass
class ModulePlan:
    """Plan describing the mapping of module identifiers to files."""

    file_map: Dict[str, str]  # id -> file
    targets: List[str]  # ordered list


@dataclass
class Row:
    """A simple structure for export rows used in YANG CSV output."""

    managed_object: str = ""
    hierarchical_path: str = ""
    param_short: str = ""
    param_long: str = ""
    description: str = ""
    default: str = ""
    units: str = ""
    range_text: str = ""
    type_text: str = ""
    is_key: str = ""
    min_instance_cardinality: str = ""
    max_instance_cardinality: str = ""
