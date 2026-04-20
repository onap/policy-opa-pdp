"""High-level parser orchestration around pyang repo, planning, and walking."""

# pyang_integration/parser.py
from __future__ import annotations

from typing import Dict, List, Set, Tuple, Optional
from typing import Any

from parsers.pyang_integration.modules_parser import collect_modules
from parsers.pyang_integration.repo import YangRepository
from parsers.pyang_integration.find_hpath_for_leaf import (
    walk_local_tree,
    walk_augments_authored,
)
from parsers.utils import (
    Discovery,
    ModulePlan,
    Row,
    collect_search_dirs,
    expand_paths,
    gather_files,
    get_logger,
)
from config.config import DEFAULT_FILE_EXTENSIONS

log = get_logger(__name__)


class YangParser:
    """Concrete parser for YANG modules.

    - Colon-separated inputs/deps (files/dirs/globs).
    - Input precedence when modules duplicate.
    - Single validate() for all modules.
    - Walk augments first, then local.
    - Emit authored-only leaves/leaf-lists.
    - MO via Object-Parent rule (augment fallback to base anchor last segment).
    """

    def __init__(self) -> None:
        """Initialize an empty parser with no repository loaded yet."""
        self.repo: Optional[YangRepository] = None

    # 1) Discover
    def discover(self, args: Any) -> Discovery:
        """Resolve input/dep paths, gather files, and compute pyang search dirs."""
        input_paths = expand_paths(args.input)
        dep_paths = expand_paths(args.deps)
        recurse = not getattr(args, "no_subdirs", False)

        input_files = gather_files(
            input_paths, recurse=recurse, extensions=DEFAULT_FILE_EXTENSIONS
        )
        dep_files = gather_files(
            dep_paths, recurse=recurse, extensions=DEFAULT_FILE_EXTENSIONS
        )
        search_dirs = collect_search_dirs(input_paths, dep_paths)

        return Discovery(
            input_paths=input_paths,
            dep_paths=dep_paths,
            input_files=input_files,
            dep_files=dep_files,
            search_dirs=search_dirs,
            recurse=recurse,
        )

    # 2) Plan
    def plan(self, d: Discovery) -> ModulePlan:
        """Build a module-to-file map and the ordered list of targets."""
        file_map, targets = collect_modules(d.input_files, d.dep_files)
        if not targets:
            raise RuntimeError("No target YANG modules resolved from --input files.")
        return ModulePlan(file_map=file_map, targets=targets)

    # 3) Load
    def load(self, d: Discovery, plan: ModulePlan) -> None:
        """Instantiate the repository and load all modules by content."""
        self.repo = YangRepository(d.search_dirs)
        self.repo.load(plan.file_map)

    # 4) Validate
    def validate(self) -> None:
        """Validate the loaded modules and log any pyang errors."""
        if self.repo is None:
            raise RuntimeError("Repository not initialized")
        self.repo.validate()
        errs = getattr(self.repo, "errors", [])
        if errs:
            # Current policy: log errors. If you want strict fail, raise here.
            for err, pos in errs:
                ref = getattr(pos, "ref", None)
                line = getattr(pos, "line", None)
                col = getattr(pos, "col", None)
                where = ""
                if ref is not None:
                    where += str(ref)
                if line is not None:
                    where += f":{line}"
                if col is not None:
                    where += f":{col}"
                log.error("pyang error: %s %s", where, err)

    # 5) Walk (one module rows)
    def walk_module(self, module_name: str) -> List[Row]:
        """Walk augments then local nodes for one module and return output rows."""
        if self.repo is None:
            raise RuntimeError("Repository not initialized")
        mod_stmt = self.repo.get_module(module_name)
        if mod_stmt is None:
            log.warning(
                "Module '%s' not present after validation; skipping", module_name
            )
            return []

        rows_dicts: List[Dict[str, str]] = []
        emitted_keys: Set[Tuple[str, str, str]] = set()

        # Augments first, then local
        walk_augments_authored(mod_stmt, module_name, rows_dicts, emitted_keys)
        walk_local_tree(mod_stmt, module_name, rows_dicts, emitted_keys)

        # Convert to Row dataclass instances (writer expects these)
        out = [
            Row(
                managed_object=r.get("ManagedObject", ""),
                hierarchical_path=r.get("HierarchicalPath", ""),
                param_short=r.get("ParameterShortName", ""),
                param_long=r.get("ParameterLongName", ""),
                description=r.get("ParameterDescription", ""),
                default=r.get("DefaultValue", ""),
                units=r.get("Units", ""),
                range_text=r.get("Range", ""),
                type_text=r.get("Type", ""),
                is_key=str(r.get("isKey", "false")).lower(),
            )
            for r in rows_dicts
        ]
        return out
