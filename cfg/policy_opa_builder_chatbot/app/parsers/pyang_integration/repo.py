"""Thin wrapper around pyang repository and context to manage YANG modules."""

# pyang_integration/yang/repo.py
from __future__ import annotations

import os
from typing import Any, Dict, List

from pyang import context, repository

from parsers.utils import get_logger

log = get_logger(__name__)


class YangRepository:
    """
    Thin wrapper around pyang's FileRepository + Context.

    - Keeps search-dir order intact (no sorting).
    - Loads all modules (by file content) before a single validate().
    """

    def __init__(self, search_paths: List[str]) -> None:
        """Initialize the repository and context using provided search paths."""
        joined = os.pathsep.join(os.path.abspath(p) for p in search_paths)
        self.repo = repository.FileRepository(joined)
        self.ctx = context.Context(self.repo)

    def load(self, file_map: Dict[str, str]) -> None:
        """Load module contents into the context from a {module_name: file_path} map."""
        for path in file_map.values():
            with open(path, "r", encoding="utf-8") as fh:
                self.ctx.add_module(os.path.basename(path), fh.read())

    def validate(self) -> None:
        """Validate all loaded modules in the current context."""
        self.ctx.validate()

    def get_module(self, name: str) -> Any:
        """Return the parsed module statement for the given module name, if present."""
        return self.ctx.get_module(name)

    @property
    def errors(self) -> List[Any]:
        """Return pyang context errors, if any, otherwise an empty list."""
        return getattr(self.ctx, "errors", []) or []
