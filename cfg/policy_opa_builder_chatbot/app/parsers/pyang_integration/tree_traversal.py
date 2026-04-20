"""Helpers for traversing pyang statements and rendering YANG data paths."""

# pyang_integration/yang/pathing.py
from __future__ import annotations

from typing import Dict, List, Optional

from pyang import statements

DATA_NODE_KEYWORDS = ("container", "list", "leaf", "leaf-list", "anydata", "anyxml")


def is_data_node(stmt: statements.Statement) -> bool:
    """Return True if the statement is a YANG data node."""
    return getattr(stmt, "keyword", None) in DATA_NODE_KEYWORDS


def get_module_prefix(mod_stmt: statements.Statement) -> str:
    """Return the module prefix string for the provided module statement."""
    if mod_stmt is None:
        return ""
    pref = mod_stmt.search_one("prefix")
    if pref and pref.arg:
        return str(pref.arg)
    return str(getattr(mod_stmt, "arg", "")) or ""


def strip_prefix(name: str) -> str:
    """Remove the 'prefix:' from a qualified name if present."""
    return name.split(":", 1)[1] if ":" in name else name


def get_data_parent(stmt: statements.Statement) -> Optional[statements.Statement]:
    """Return the nearest data-node ancestor.

    Prefer the `i_parent` chain; if it stops at a non-data wrapper, fall back to the
    syntax `parent` chain.
    """
    ip = getattr(stmt, "i_parent", None)
    cur = ip
    while cur is not None and not is_data_node(cur):
        nxt = getattr(cur, "i_parent", None)
        if nxt is None:
            nxt = getattr(cur, "parent", None)
        cur = nxt
    if cur is not None and is_data_node(cur):
        return cur

    cur = getattr(stmt, "parent", None)
    while cur is not None and not is_data_node(cur):
        cur = getattr(cur, "parent", None)
    return cur if (cur is not None and is_data_node(cur)) else None


def collect_path_segments(stmt: statements.Statement) -> List[Dict[str, str]]:
    """Collect the data-node path from the top-most data ancestor down to `stmt`."""
    segs: List[Dict[str, str]] = []
    cur = stmt
    while cur is not None and is_data_node(cur):
        mod = getattr(cur, "i_module", None)
        segs.append(
            {
                "name": cur.arg,
                "keyword": cur.keyword,
                "prefix": get_module_prefix(mod),
            }
        )
        cur = get_data_parent(cur)
    segs.reverse()
    return segs


def parse_augment_path(path_str: str) -> List[str]:
    """Split an augment path string into non-empty tokens."""
    return [p for p in path_str.strip().split("/") if p]


def render_full_path_prefixless(segments: List[Dict[str, str]]) -> str:
    """Render a full path string without prefixes from path segments."""
    parts = []
    for seg in segments:
        if seg.get("prefix"):
            parts.append(strip_prefix(f"{seg.get('prefix')}:{seg['name']}"))
        else:
            parts.append(seg["name"])
    return "/".join(parts)


def render_tokens_prefixless(tokens: List[str]) -> str:
    """Render a '/'-joined path from tokens with prefixes stripped."""
    return "/".join(strip_prefix(t) for t in tokens if t)
