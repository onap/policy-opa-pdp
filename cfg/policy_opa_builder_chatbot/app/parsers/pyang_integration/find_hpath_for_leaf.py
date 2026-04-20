"""Traverse local and augment trees to emit authored leaf rows for export."""

# pyang_integration/yang/walkers/local_walker.py
from __future__ import annotations

from typing import Dict, List, Set, Tuple, Iterable

from pyang import statements

from parsers.pyang_integration.find_mo_from_hpath import (
    choose_mo_object_parent_local,
    collect_aug_object_roots,
)
from parsers.pyang_integration.tree_traversal import (
    collect_path_segments,
    get_data_parent,
    is_data_node,
    render_full_path_prefixless,
    get_module_prefix,
    parse_augment_path,
    render_tokens_prefixless,
    strip_prefix,
)
from parsers.pyang_integration.types_parser import (
    default_value,
    emit_type_and_range,
    normalized_description,
    unit_value,
    parse_instance_cardinality
)
from parsers.utils import get_logger, Row

log = get_logger(__name__)

ATTRIBUTE_KEYWORDS = ("leaf", "leaf-list")


def _is_attribute(stmt: statements.Statement) -> bool:
    return getattr(stmt, "keyword", None) in ATTRIBUTE_KEYWORDS


def _authored_by(stmt: statements.Statement, module_name: str) -> bool:
    return getattr(getattr(stmt, "i_module", None), "arg", None) == module_name


def _is_list_key_leaf(node: statements.Statement) -> bool:
    """_is_list_key_leaf.

    Return True iff `node` is a `leaf` AND its nearest data-node parent is a `list`.
    that declares a `key` statement containing this leaf's name (prefix-insensitive).
    Note: leaf-list cannot be part of a list's `key`.
    """
    if getattr(node, "keyword", None) != "leaf":
        return False
    parent = get_data_parent(node)
    if parent is None or getattr(parent, "keyword", None) != "list":
        return False
    key_stmt = parent.search_one("key")
    if key_stmt is None or not getattr(key_stmt, "arg", None):
        return False
    # Parse space-separated key identifiers and compare after stripping prefixes
    leaf_name = strip_prefix(str(getattr(node, "arg", "")))
    key_idents = [strip_prefix(tok) for tok in str(key_stmt.arg).split() if tok]
    return leaf_name in key_idents


def _is_local_to_module(node: statements.Statement, module_name: str) -> bool:
    """Determine whether the node is local to the given module.

    Returns True iff all data-node ancestors (including the node itself), up to the
    first non-data ancestor, are authored by the target module. The climb follows
    the data-node chain.
    """
    cur = node
    while cur is not None and is_data_node(cur):
        imod = getattr(cur, "i_module", None)
        if getattr(imod, "arg", None) != module_name:
            return False
        cur = get_data_parent(cur)
    return True


def _emit_local_leaf(
    node: statements.Statement,
    target_module_name: str,
    rows: List[Dict[str, str]],
    emitted_keys: Set[Tuple[str, str, str]],
) -> None:
    full_segments = collect_path_segments(node)
    if not full_segments:
        return
    mo = choose_mo_object_parent_local(node, target_module_name)
    parent_segments = full_segments[:-1]
    # parent_segments = [d for d in parent_segments if d.get("name") != "attributes"]
    path = (
        render_full_path_prefixless(parent_segments)
        if parent_segments
        else ""
    )
    log.debug(
        "LOCAL emit \n module=%s \n rule=object-parent \n mo=%s "
        "\n path=%s \n leaf=%s \n full=%s",
        target_module_name,
        mo,
        path,
        node.arg,
        "/".join([s["name"] for s in full_segments]),
    )

    ekey = (mo, path, node.arg)

    type_display, range_text = emit_type_and_range(node)
    if ekey in emitted_keys:
        print("EKEY", ekey)
        for data in rows:
            if data.hierarchical_path == path and data.param_short == node.arg:
                data.type_text = type_display
                data.range_text = range_text
        return
    else:
        type_display, range_text = emit_type_and_range(node)
        min_ic = ""
        max_ic = ""
        if _is_list_key_leaf(node):
            parent = get_data_parent(node)
            if parent is not None and parent.keyword == "list":
                desc_stmt = parent.search_one("description")
                desc = desc_stmt.arg if desc_stmt and desc_stmt.arg else ""
                min_ic, max_ic = parse_instance_cardinality(desc)
        rows.append(
                Row(
                    managed_object=mo,
                    hierarchical_path=path,
                    param_short=node.arg,
                    param_long=node.arg,
                    description=normalized_description(node),
                    default=default_value(node),
                    units=unit_value(node),
                    range_text=range_text,
                    type_text=type_display,
                    is_key="true" if _is_list_key_leaf(node) else "false",
                    min_instance_cardinality=min_ic,
                    max_instance_cardinality=max_ic,
                    )
                )
        emitted_keys.add(ekey)


def walk_local_tree(
    mod_stmt: statements.Statement,
    target_module_name: str,
    rows: List[Dict[str, str]],
    emitted_keys: Set[Tuple[str, str, str]],
) -> None:
    """Walk locally-authored data nodes and emit leaf rows.

    Traverses data nodes authored by the target module within the same module
    (not augment-based), builds hierarchical paths, and appends unique row dicts
    to `rows`. Deduplication is enforced using `emitted_keys`.
    """

    def walk(node: statements.Statement) -> None:
        if (
            _is_attribute(node)
            and _authored_by(node, target_module_name)
            and _is_local_to_module(node, target_module_name)
        ):
            _emit_local_leaf(node, target_module_name, rows, emitted_keys)
        for ch in getattr(node, "i_children", []) or []:
            walk(ch)

    walk(mod_stmt)


def _dbg_names_only(segs: List[Dict[str, object]]) -> List[str]:
    return [str(s.get("name")) for s in segs]


def _dbg_authors(chain: List[Dict[str, object]]) -> List[str]:
    out: List[str] = []
    for s in chain:
        n = s.get("node", None)
        imod = (
            getattr(getattr(n, "i_module", None), "arg", None)
            if n is not None
            else None
        )
        out.append(imod if imod is not None else "")
    return out


def walk_augments_authored(
    mod_stmt: statements.Statement,
    target_module_name: str,
    rows: List[Dict[str, str]],
    emitted_keys: Set[Tuple[str, str, str]],
) -> None:
    """
    Traverse each augment authored by the module and emit leaves.

    MO (augment): nearest ancestor inside the augment subtree that is an
    "augment object-root". If none, fallback to last base anchor segment.
    """
    for aug in mod_stmt.search("augment"):
        if getattr(getattr(aug, "i_module", None), "arg", None) != target_module_name:
            continue

        base_tokens = parse_augment_path(aug.arg)
        aug_root_ids = collect_aug_object_roots(aug, target_module_name)  # set of node ids

        def dfs(node: statements.Statement, rel_segments: List[Dict[str, object]]) -> None:
            pushed = push_segment_if_data(node, rel_segments)

            if should_emit_attribute(node, target_module_name):
                pre_nodes = compute_pre_nodes(rel_segments)
                mo, picked_from, fallback = choose_mo_in_augment(
                    rel_segments, aug_root_ids, base_tokens
                )
                full_path = build_full_path(base_tokens, rel_segments)

                # Emit (de-dup here; writer will also de-dup)
                emit_row_if_needed(
                    node=node,
                    mo=mo,
                    path=full_path,
                    rows=rows,
                    emitted_keys=emitted_keys,
                    is_key=_is_list_key_leaf(node),
                )

                # Preserve DEBUG logging behavior
                debug_augment_emit(
                    target_module_name=target_module_name,
                    aug=aug,
                    mo=mo,
                    picked_from=picked_from,
                    fallback=fallback,
                    full_path=full_path,
                    node=node,
                    pre_nodes=pre_nodes,
                    rel_segments=rel_segments,
                )

            for child in iterate_children(node):
                dfs(child, rel_segments)

            if pushed:
                rel_segments.pop()

        # Entry points for DFS: each authored item under this augment
        for top in get_aug_entry_points(aug):
            dfs(top, [])


def should_emit_attribute(node: statements.Statement, module_name: str) -> bool:
    """Return True if node is a leaf/leaf-list and authored by the given module."""
    return _is_attribute(node) and _authored_by(node, module_name)


def push_segment_if_data(node: statements.Statement, rel_segments: List[Dict[str, object]]) -> bool:
    """Append a segment dict for data-nodes and return True; otherwise return False."""
    if not is_data_node(node):
        return False
    rel_segments.append({
        "name": node.arg,
        "keyword": node.keyword,
        "prefix": get_module_prefix(getattr(node, "i_module", None)),
        "node": node,
    })
    return True


def compute_pre_nodes(rel_segments: List[Dict[str, object]]) -> List[Dict[str, object]]:
    """Realized data ancestors ABOVE the augment subtree (for logging)."""
    out: List[Dict[str, object]] = []
    if not rel_segments:
        return out
    top_stmt = rel_segments[0]["node"]
    cur = getattr(top_stmt, "i_parent", None)
    while cur is not None and is_data_node(cur):
        out.append({
            "name": cur.arg,
            "keyword": cur.keyword,
            "prefix": get_module_prefix(getattr(cur, "i_module", None)),
            "node": cur,
        })
        cur = getattr(cur, "i_parent", None)
    out.reverse()
    return out


def choose_mo_in_augment(
    rel_segments: List[Dict[str, object]],
    aug_root_ids: Set[int],
    base_tokens: List[str],
) -> Tuple[str, str, str]:
    """
    Return (mo, picked_from, fallback).

      - picked_from: "object-root" when found in rel_segments, else "none"
      - fallback: "base-anchor" if used, "empty" if no base tokens, else "none"
    """
    # 1) Within the augment subtree: walk up to nearest object-root (exclude the leaf itself)
    for seg in reversed(rel_segments[:-1]):
        if id(seg["node"]) in aug_root_ids:
            return str(seg["name"]), "object-root", "none"

    # 2) Fallback to last base anchor segment
    if base_tokens:
        return strip_prefix(base_tokens[-1]), "none", "base-anchor"

    return "", "none", "empty"


def build_full_path(base_tokens: List[str], rel_segments: List[Dict[str, object]]) -> str:
    """Build prefix-less hierarchical path excluding the leaf itself."""
    base_path = render_tokens_prefixless(base_tokens)
    parent_segments = rel_segments[:-1]  # drop the leaf segment
    # parent_segments = [d for d in parent_segments if d.get("name") != "attributes"]
    rel_parent_path = (
        render_full_path_prefixless(
            [
                {
                    "name": s["name"],
                    "keyword": s["keyword"],
                    "prefix": s["prefix"],
                }
                for s in parent_segments
            ]
        )
        if parent_segments else ""
    )
    if base_path and rel_parent_path:
        return f"{base_path}/{rel_parent_path}"
    return rel_parent_path or base_path  # may be ""


def emit_row_if_needed(
    node: statements.Statement,
    mo: str,
    path: str,
    rows: List[Dict[str, str]],
    emitted_keys: Set[Tuple[str, str, str]],
    is_key: bool = False,
) -> None:
    """Emit a row for this node if it has not already been emitted."""
    ekey = (mo, path, node.arg)
    type_display, range_text = emit_type_and_range(node)
    if ekey in emitted_keys:
        for data in rows:
            if data.hierarchical_path == path and data.param_short == node.arg:
                if node.arg == "systemFunctionsId":
                    print("ekey", ekey)
                    print("emiettd_keys", emitted_keys)
                    print("Data.hierarchicalpath", data.hierarchical_path)
                    data.type_text = type_display
                    data.range_text = range_text

        return
    min_ic = ""
    max_ic = ""
    if is_key:
        parent = get_data_parent(node)
        if parent is not None and parent.keyword == "list":
            desc_stmt = parent.search_one("description")
            desc = desc_stmt.arg if desc_stmt and desc_stmt.arg else ""
            min_ic, max_ic = parse_instance_cardinality(desc)
    rows.append(
            Row(
                managed_object=mo,
                hierarchical_path=path,
                param_short=node.arg,
                param_long=node.arg,
                description=normalized_description(node),
                default=default_value(node),
                units=unit_value(node),
                range_text=range_text,
                type_text=type_display,
                is_key="true" if _is_list_key_leaf(node) else "false",
                min_instance_cardinality=min_ic,
                max_instance_cardinality=max_ic,
                )
            )
    emitted_keys.add(ekey)


def iterate_children(node: statements.Statement) -> List[statements.Statement]:
    """
    Prefer realized children; fall back to authored stmts.

    Preserves original traversal rules and filters out children without a keyword.
    """
    realized = list(getattr(node, "i_children", []) or [])
    if realized:
        return [ch for ch in realized if getattr(ch, "keyword", None)]

    result: List[statements.Statement] = []
    for ch in getattr(node, "substmts", []) or []:
        kw = getattr(ch, "keyword", None)
        if kw == "uses":
            result.extend(list(getattr(ch, "i_children", []) or []))
        elif kw in ("choice", "case"):
            rc = list(getattr(ch, "i_children", []) or [])
            result.extend(rc or list(getattr(ch, "substmts", []) or []))
        elif kw in ("container", "list", "leaf", "leaf-list", "anydata", "anyxml"):
            result.append(ch)
    return result


def _yield_children(node: statements.Statement) -> Iterable[statements.Statement]:
    for ch in getattr(node, "substmts", []) or []:
        yield ch


def _yield_i_children(node: statements.Statement) -> Iterable[statements.Statement]:
    for ch in getattr(node, "i_children", []) or []:
        yield ch


def get_aug_entry_points(aug: statements.Statement) -> Iterable[statements.Statement]:
    """Yield entry points for DFS: authored items under the augment."""
    for top in getattr(aug, "substmts", []) or []:
        kw = getattr(top, "keyword", None)
        if kw == "uses":
            yield from _yield_i_children(top)
            continue
        if kw in ("choice", "case"):
            rc = list(getattr(top, "i_children", []) or [])
            if rc:
                yield from rc
            else:
                yield from _yield_children(top)
                continue
        if kw in ("container", "list", "leaf", "leaf-list", "anydata", "anyxml"):
            yield top


def debug_augment_emit(
    target_module_name: str,
    aug: statements.Statement,
    mo: str,
    picked_from: str,
    fallback: str,
    full_path: str,
    node: statements.Statement,
    pre_nodes: List[Dict[str, object]],
    rel_segments: List[Dict[str, object]],
) -> None:
    """Preserve the original DEBUG logging (wrapped in try/except like before)."""
    try:
        log.debug(
            "AUGMENT emit \n module=%s \n rule=object-parent \n base=%s "
            "\n mo=%s \n picked_from=%s \n fallback=%s \n path=%s \n leaf=%s "
            "\n pre=%s \n rel=%s \n authors=%s",
            target_module_name,
            getattr(aug, "arg", ""),
            mo,
            picked_from,
            fallback,
            full_path,
            getattr(node, "arg", ""),
            "/".join(_dbg_names_only(pre_nodes)),
            "/".join(_dbg_names_only(rel_segments)),
            " -> ".join(_dbg_authors(pre_nodes + rel_segments)),
        )
    except Exception as exc:
        log.debug("Debug logging failed for Augment Emit: %s", exc)


def _instance_cardinality_for_leaf(
    node: statements.Statement,
    target_module_name: str,
) -> tuple[str, str]:
    """
    Return (min, max) instance cardinality for key leafs only.
    """
    # only key leafs
    if not _is_list_key_leaf(node):
        return "", ""

    parent = get_data_parent(node)

    # keys only belong to lists
    if parent is None or parent.keyword != "list":
        return "", ""

    desc_stmt = parent.search_one("description")
    desc = desc_stmt.arg if desc_stmt and desc_stmt.arg else ""

    return parse_instance_cardinality(desc)
