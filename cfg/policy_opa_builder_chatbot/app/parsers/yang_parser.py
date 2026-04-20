"""YANG parser CLI and pipeline to export per-module Excel files."""

# yang_parser.py
from __future__ import annotations

import argparse
import os
from typing import List, Tuple, Dict, Set, Any

from parsers.dataframe_builder import CsvWriter
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
    init_logging,
    output_xlsx_path
)
from config.config import DEFAULT_FILE_EXTENSIONS

log = get_logger("yang_parser")
print(os.getcwd())


# ---------------------------
# CLI
# ---------------------------


def split_paths(value: str) -> list[str]:
    """Split colon-separated paths."""
    return [p.strip() for p in value.split(":") if p.strip()]


def load_args_from_config(input_data: Any, out_dir: Any) -> argparse.Namespace:
    """Build argparse.Namespace from JSON config."""
    return argparse.Namespace(
        input=input_data["input"],
        deps=input_data["deps"],
        output=out_dir,
        no_subdirs="False",
        log_level="INFO",
    )


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    """Define CLI flags (no deprecated flags; Excel-only output)."""
    p = argparse.ArgumentParser(
        prog="yang_parser",
        description=(
            "Export leaves/leaf-lists authored by each YANG module into "
            "per-module Excel file (.xlsx)."
        ),
    )
    p.add_argument(
        "--input",
        required=True,
        help='Target YANGs: colon-separated file/dir/glob list (e.g., "a.yang:dir/:*.yang").',
    )
    p.add_argument(
        "--deps",
        required=True,
        help='Dependency YANGs: colon-separated file/dir/glob list (e.g., "deps/:vendor/*.yang").',
    )
    p.add_argument(
        "--output", required=True, help="Output folder for Excel files (.xlsx)"
    )
    p.add_argument(
        "--no-subdirs",
        action="store_true",
        help="Do NOT include subdirectories (default: recurse)",
    )
    p.add_argument(
        "--log-level",
        choices=["DEBUG", "INFO", "WARN", "ERROR", "CRITICAL", "TRACE"],
        help="Log verbosity (default: INFO if not provided)",
    )
    return p.parse_args(argv)


# ---------------------------
# Pipeline helpers
# ---------------------------


def _discover(args: argparse.Namespace) -> Discovery:
    """Step 1: Expand paths, gather files, identify pyang search directories.

    Pure I/O and path processing only; no pyang operations.
    """
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


def _plan(disc: Discovery) -> ModulePlan:
    """Step 2: Build map (module -> file) with input precedence and ordered targets."""
    file_map, targets = collect_modules(disc.input_files, disc.dep_files)
    return ModulePlan(file_map=file_map, targets=targets)


def _load_repo(disc: Discovery, plan: ModulePlan) -> YangRepository:
    """Step 3: Create repository and load all modules by content (pyang)."""
    repo = YangRepository(disc.search_dirs)
    repo.load(plan.file_map)
    return repo


def _validate_repo(repo: YangRepository) -> None:
    """Step 4: Validate once and log pyang errors; proceed even on failures.

    Non-strict behavior for now; consider adding a --strict flag later.
    """
    try:
        repo.validate()
    except Exception as exc:
        # pyang may throw; errors are also recorded in repo.errors
        log.exception("pyang validation raised as an exception: %s", exc)

    errs = getattr(repo, "errors", []) or []
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


def _walk_and_write(
    repo: YangRepository,
    targets: List[str],
    out_dir: str,
    input_path: str,
) -> tuple[int, str]:
    """Step 5: Walk augments and local trees, collect rows, and write Excel.

    For each target module: gather authored augment and local rows, convert to
    `Row` dataclasses, and write a single `.xlsx` via `CsvWriter`. Returns the
    number of modules exported.
    """
    writer = CsvWriter(out_dir=out_dir)  # Excel-only writer
    all_rows: List[Row] = []

    total = 0
    out_file = output_xlsx_path(input_path, out_dir)
    for mod in targets:
        rows_dicts: List[Dict[str, str]] = []
        emitted_keys: Set[Tuple[str, str, str]] = set()

        mod_stmt = repo.get_module(mod)
        if mod_stmt is None:
            log.warning("Module '%s' not present after validation; skipping", mod)
            continue

        # Augments first, then local (authored-only rule)
        walk_augments_authored(mod_stmt, mod, rows_dicts, emitted_keys)
        walk_local_tree(mod_stmt, mod, rows_dicts, emitted_keys)

        # Marshal to Row dataclasses expected by the writer
        out_rows: List[Row] = [
            Row(
                managed_object=r.managed_object or "",
                hierarchical_path=r.hierarchical_path or "",
                param_short=r.param_short or "",
                param_long=r.param_long or "",
                description=r.description or "",
                default=r.default or "",
                units=r.units or "",
                range_text=r.range_text or "",
                type_text=r.type_text or "",
                is_key=(r.is_key or "false").lower(),
                min_instance_cardinality=r.min_instance_cardinality,
                max_instance_cardinality=r.max_instance_cardinality,
                )
            for r in rows_dicts
        ]
        all_rows.extend(out_rows)
        total += 1
    # WRITE ONLY ONCE

    writer.write(module_name=out_file, rows=all_rows)
    return total, out_file


# ---------------------------
# Orchestrator
# ---------------------------


def export(args: argparse.Namespace) -> Any:
    """End-to-end flow to export per-module Excel files.

    Steps:
      1) discover
      2) plan
      3) load
      4) validate
      5) walk + write Excel files
    """
    init_logging(args.log_level or "INFO")
    log.info(
        "Starting export (MO rule: object-parent; augment-fallback: base-anchor last segment)"
    )

    # 1) Discover
    disc = _discover(args)
    if not disc.input_files:
        log.error("No YANG modules found in --input paths.")
        return 2

    # 2) Plan
    plan = _plan(disc)
    if not plan.targets:
        log.error("No target YANG modules resolved from --input files.")
        return 2

    # 3) Load
    repo = _load_repo(disc, plan)

    # 4) Validate (non-strict)
    _validate_repo(repo)

    # 5) Walk + write
    total, out_file = _walk_and_write(
        repo=repo,
        targets=plan.targets,
        out_dir=args.output,
        input_path=args.input
    )
    log.info("Done. Exported %d module(s).", total)
    return out_file


# ---------------------------
# Script execution
# ---------------------------

if __name__ == "__main__":
    args = parse_args()
    raise SystemExit(export(args))
