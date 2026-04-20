"""Helpers to determine Managed Object (MO) roots from hierarchical paths."""

# pyang_integration/yang/mo/local.py
from __future__ import annotations

from pyang import statements
from parsers.pyang_integration.tree_traversal import get_data_parent, is_data_node
from typing import List, Set, Iterable
from config.config import WRAPPER_NAMES

MO_KEYWORDS = ("container", "list")
DATA_NODE_KEYWORDS = ("container", "list", "leaf", "leaf-list", "anydata", "anyxml")


def is_object_root_local(node: statements.Statement, target_module_name: str) -> bool:
    """Determine whether the node is a local object-root.

    Local object-root:
      - node is container/list
      - authored by target module
      - top-level under the module (no data-node parent)
    """
    if getattr(node, "keyword", None) not in MO_KEYWORDS:
        return False
    imod = getattr(node, "i_module", None)
    if getattr(imod, "arg", None) != target_module_name:
        return False
    parent_dn = get_data_parent(node)
    return parent_dn is None


def choose_mo_object_parent_local(
    leaf_stmt: statements.Statement, target_module_name: str
) -> str:
    """Return the nearest ancestor that is a local object-root."""
    cur = get_data_parent(leaf_stmt)  # start at leaf's parent
    while cur is not None and is_data_node(cur):
        if is_object_root_local(cur, target_module_name):
            return str(cur.arg)
        cur = get_data_parent(cur)
    return ""  # rare: leaf at absolute top


def _is_authored_mo_node(node: statements.Statement, target_module_name: str) -> bool:
    name = node.arg if isinstance(node.arg, str) else ""
    return (
        getattr(node, "keyword", None) in MO_KEYWORDS
        and getattr(getattr(node, "i_module", None), "arg", None) == target_module_name
        and name not in WRAPPER_NAMES
    )


def collect_aug_depth1_data_nodes(
    aug_stmt: statements.Statement,
) -> List[statements.Statement]:
    """Return all depth-1 realized data-nodes under this augment block.

    Handles 'uses', 'choice', and 'case' similarly to DFS entry points.
    """
    out: List[statements.Statement] = []
    for node in iter_aug_depth1_nodes(aug_stmt):
        if is_data_node(node):
            out.append(node)
    return out


def iter_aug_depth1_nodes(aug_stmt: statements.Statement) -> Iterable[statements.Statement]:
    """Yield depth-1 realized nodes under an augment, mirroring DFS entry rules."""
    for top in list(getattr(aug_stmt, "substmts", []) or []):
        kw = getattr(top, "keyword", None)
        if kw == "uses":
            for ch in list(getattr(top, "i_children", []) or []):
                # original code only pushed realized children that have a keyword
                if getattr(ch, "keyword", None):
                    yield ch
        elif kw in ("choice", "case"):
            realized = list(getattr(top, "i_children", []) or [])
            if realized:
                for ch in realized:
                    yield ch
            else:
                for ch in list(getattr(top, "substmts", []) or []):
                    yield ch
        elif kw in DATA_NODE_KEYWORDS:
            yield top


def collect_aug_object_roots(
    aug_stmt: statements.Statement,
    target_module_name: str,
) -> Set[int]:
    """Return node IDs for authored container/list roots introduced by this augment.

    Augment object-roots = authored container/list introduced by this augment:

      - include every authored depth-1 container/list
      - recursively include their authored container/list descendants
      - skip wrappers (from WRAPPER_NAMES)
    """
    roots: Set[int] = set()
    stack: List[statements.Statement] = []

    # seed: depth-1 authored containers/lists
    for dn in collect_aug_depth1_data_nodes(aug_stmt):
        if _is_authored_mo_node(dn, target_module_name):
            roots.add(id(dn))
            stack.append(dn)

    # recursively walk authored container/list descendants
    while stack:
        cur = stack.pop()
        children = collect_mo_children_for_walk(cur)

        for ch in children:
            if _is_authored_mo_node(ch, target_module_name):
                ch_id = id(ch)
                if ch_id not in roots:
                    roots.add(ch_id)
                    stack.append(ch)

    return roots


def collect_mo_children_for_walk(
    node: statements.Statement,
) -> List[statements.Statement]:
    """Return children consistent with the original logic.

    Prefer realized children; if none, fall back to authored substatements,
    expanding 'uses' and handling 'choice'/'case' as before.
    """
    children = list(getattr(node, "i_children", []) or [])
    if children:
        return children

    # fall back to authored substatements (handles groupings/uses)
    out: List[statements.Statement] = []
    for ch in list(getattr(node, "substmts", []) or []):
        kw = getattr(ch, "keyword", None)
        if kw == "uses":
            out.extend(list(getattr(ch, "i_children", []) or []))
        elif kw in ("choice", "case"):
            rc = list(getattr(ch, "i_children", []) or [])
            if rc:
                out.extend(rc)
            else:
                out.extend(list(getattr(ch, "substmts", []) or []))
        elif kw in DATA_NODE_KEYWORDS:
            out.append(ch)
    return out
