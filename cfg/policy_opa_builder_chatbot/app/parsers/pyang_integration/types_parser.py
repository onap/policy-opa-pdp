"""Helpers for extracting description/default and summarizing YANG types."""

# pyang_integration/yang/types.py
from __future__ import annotations

import re

from typing import Dict, List, Tuple

from pyang import statements

from parsers.utils import normalize_description, get_logger

log = get_logger(__name__)


_MOM_MIN_MAX_RE = re.compile(
    r"MOM:min/max-elements:(\d+)/(unbounded|\d+)",
    re.IGNORECASE,
)

def description_value(stmt: statements.Statement) -> str:
    """Return the best-available description text for a statement.

    Checks the statement, its original `i_orig`, and any `must` clauses in order.
    """
    d = stmt.search_one("description")
    if d and d.arg:
        return d.arg or ""
    if hasattr(stmt, "i_orig") and stmt.i_orig is not None:
        d = stmt.i_orig.search_one("description")
        if d and d.arg:
            return d.arg or ""
    for m in stmt.search("must"):
        d = m.search_one("description")
        if d and d.arg:
            return d.arg or ""
    return ""


def default_value(stmt: statements.Statement) -> str:
    """Return the default value for a statement if declared, else empty string.

    Checks the statement first, then its original `i_orig`.
    """
    d = stmt.search_one("default")
    if d and d.arg:
        return str(d.arg)
    if hasattr(stmt, "i_orig") and stmt.i_orig is not None:
        d = stmt.i_orig.search_one("default")
        if d and d.arg:
            return str(d.arg)
    return ""


def unit_value(stmt: statements.Statement) -> str:
    """Return the unit value for a statement if declared, else empty string.

    Checks the statement first, then its original `i_orig`.
    """
    u = stmt.search_one("units")
    if u and u.arg:
        return str(u.arg)
    if hasattr(stmt, "i_orig") and stmt.i_orig is not None:
        u = stmt.i_orig.search_one("units")
        if u and u.arg:
            return str(u.arg)
    return ""


def _collect_type_constraints(
    tstmt: statements.Statement,
    tname: str
) -> Dict[str, List[str] | str]:

    info: Dict[str, List[str] | str] = {
        "type_display": tname,
        "ranges": [],
        "lengths": [],
    }

    spec = getattr(tstmt, "i_type_spec", None)

    if spec is None:
        return info

    base_type = getattr(spec, "name", tname)
    info["type_display"] = base_type

    enums = getattr(spec, "enums", None)
    if enums:
        enum_names = [e[0] for e in enums]
        info["ranges"].append(",".join(enum_names))   # type: ignore[union-attr]
        return info

    ranges = getattr(spec, "ranges", None)
    if ranges:
        for range in ranges:
            if len(range) == 2:
                info["ranges"].append(f"{range[0]}..{range[1]}")  # type: ignore[union-attr]

    lengths = getattr(spec, "lengths", None)
    if lengths:
        for length in lengths:
            if len(length) == 2:
                info["lengths"].append(f"{length[0]}..{length[1]}")  # type: ignore[union-attr]

    return info


def collect_type_info(type_stmt: statements.Statement) -> Dict[str, List[str] | str]:
    """
    Return {'type_display','ranges','lengths'}.

    - union: flatten members
    - leafref: resolve to target's underlying type if possible; else keep 'leafref'
    - typedefs: display typedef names (no flattening)
    """
    tname = type_stmt.arg

    if tname == "union":
        names: List[str] = []
        ranges: List[str] = []
        lengths: List[str] = []
        for m in type_stmt.search("type"):
            sub = collect_type_info(m)
            names.append(str(sub["type_display"]))
            ranges.extend(sub.get("ranges", []))
            lengths.extend(sub.get("lengths", []))
        return {
            "type_display": f"union({', '.join(names)})",
            "ranges": ranges,
            "lengths": lengths,
        }

    if tname == "leafref":
        try:
            spec = getattr(type_stmt, "i_type_spec", None)
            target = getattr(spec, "i_leafref_ptr", None) if spec is not None else None
            if target is not None:
                t2 = target.search_one("type")
                if t2 is not None:
                    return collect_type_info(t2)
        except Exception as exc:
            log.exception("got exception: %s", exc)
        return {"type_display": "leafref", "ranges": [], "lengths": []}

    return _collect_type_constraints(type_stmt, tname)


def emit_type_and_range(stmt: statements.Statement) -> Tuple[str, str]:
    """Return a `(type_display, range_text)` summary for a typed statement."""
    type_stmt = stmt.search_one("type")
    type_display = ""
    range_text = ""
    if type_stmt is not None:
        info = collect_type_info(type_stmt)
        type_display = str(info.get("type_display", ""))
        ranges = info.get("ranges", [])
        lengths = info.get("lengths", [])
        parts: List[str] = []
        if ranges:
            parts.extend(ranges)
        if lengths:
            parts.extend(lengths)
        range_text = "; ".join(parts)
    return type_display, range_text


def normalized_description(stmt: statements.Statement) -> str:
    """Return a whitespace-normalized description derived from the statement."""
    return normalize_description(description_value(stmt))  # type: ignore[no-any-return]


def parse_instance_cardinality(description: str) -> Tuple[str, str]:
    """
    Extract min/max instance cardinality from list description.

    Returns (min, max) or ("", "") if not present.
    """
    if not description:
        return "", ""

    match = _MOM_MIN_MAX_RE.search(description)
    if not match:
        return "", ""

    return match.group(1), match.group(2)
