"""Helpers to extract module names and build a module->file map."""

# pyang_integration/yang/modules.py
from __future__ import annotations

from typing import Dict, List, Tuple
from parsers.utils import get_logger

log = get_logger(__name__)

MODULE_PREFIX = "module "


def extract_module_name(yang_file: str) -> str:
    """Return the YANG module name from a top-level 'module <name>' statement.

    Simple and fast; works well with standard YANG headers.
    """
    with open(yang_file, "r", encoding="utf-8") as fh:
        for line in fh:
            s = line.strip()
            if s.startswith(MODULE_PREFIX):
                parts = s.split()
                if len(parts) >= 2:
                    return parts[1].rstrip("{").strip()
    raise RuntimeError(f"Could not find module name in {yang_file}")


def collect_modules(
    input_files: List[str], dep_files: List[str]
) -> Tuple[Dict[str, str], List[str]]:
    """Map module name -> file path using (input_files + dep_files); prefer input_files.

    Returns (file_map, targets_from_inputs) with order preserved.
    """
    file_map: Dict[str, str] = {}
    targets: List[str] = []

    # 1) Targets + precedence from inputs
    for f in input_files:
        try:
            mod = extract_module_name(f)
            file_map[mod] = f
            targets.append(mod)
        except Exception as exc:
            log.warning(
                "Failed to extract module name from input file '%s':  %s", f, exc
            )
            continue

    # 2) Fill from deps only if not already present
    for f in dep_files:
        try:
            mod = extract_module_name(f)
            if mod not in file_map:
                file_map[mod] = f
        except Exception as exc:
            log.warning(
                "Failed to extract module name from input file '%s':  %s", f, exc
            )
            continue

    return file_map, targets
