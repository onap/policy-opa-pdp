#  -
#    ========================LICENSE_START=================================
#    Copyright (C) 2025-2026: Deutsche Telekom
#
#    Licensed under the Apache License, Version 2.0 (the "License");
#    you may not use this file except in compliance with the License.
#    You may obtain a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS,
#    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#    See the License for the specific language governing permissions and
#    limitations under the License.
#    SPDX-License-Identifier: Apache-2.0
#   ========================LICENSE_END===================================

"""Utility helpers for MO hierarchy, expressions, metrics, and config."""

import json
import os
import re
from constants import (
    COL_MANAGED_OBJECT,
    CONFIG_PATH,
    COL_HIERARCHY_PATH,
    BASE_MO,
)
from typing import Any, Dict, List, Optional, Tuple

import pandas as pd

from libs.logs import Logger

logger = Logger.get(__name__)


def load_mo_dataframe(excel_path: str, vendor: str) -> pd.DataFrame:
    """Load Excel containing ManagedObject + DistinguishName columns.

    Args:
        excel_path: Path to Excel file.
        vendor: Vendor name sheet to load.

    Returns:
        DataFrame with MO data.

    """
    return pd.read_excel(excel_path, sheet_name=vendor)

def create_folder() -> None:
        """Create the FAISS storage folder if it does not already exist."""
        os.makedirs("faiss_store", exist_ok=True)

def get_mo(df: pd.DataFrame, mo_type: str) -> Optional[str]:
    """Fetch the actual ManagedObject (MO) of the user given MO from Excel.

    Args:
        df: DataFrame containing MO data.
        mo_type: Managed object type to search for.

    Returns:
        DN string or None if not found.

    """
    row = df[df[COL_MANAGED_OBJECT].str.lower() == mo_type.lower()]
    if row.empty:
        return None
    logger.info(
        "HierarchicalPath: %s | ManagedObject: %s",
        row.iloc[0][COL_HIERARCHY_PATH],
        row.iloc[0][COL_MANAGED_OBJECT],
    )
    value = row.iloc[0][COL_MANAGED_OBJECT]
    return str(value)


def fetch_mo_from_path(df: pd.DataFrame, hierarchicalpath: str) -> Optional[str]:
    """Fetch the MO (DN) from Excel.

    Args:
        df: DataFrame containing MO data.
        hierarchicalpath: Hierarchical Path type to search for.

    Returns:
        DN string or None if not found.

    """
    row = df[df[COL_HIERARCHY_PATH].str.lower() == hierarchicalpath.lower()]
    if row.empty:
        return None
    logger.info(
        "HierarchicalPath: %s | ManagedObject: %s",
        row.iloc[0][COL_HIERARCHY_PATH],
        row.iloc[0][COL_MANAGED_OBJECT],
    )
    value = row.iloc[0][COL_MANAGED_OBJECT]
    return str(value)


def dn_to_hierarchy(dn: str) -> List[str]:
    """Convert DN (like A/B/C) into a list.

    Args:
        dn: Distinguished name string.

    Returns:
        List of hierarchy components.

    """
    return dn.split("/") if dn else []


def check_if_mo_in_hierarchy(mo: str, dn: str) -> bool:
    """Return True if MO appears inside DN hierarchy.

    Args:
        mo: Managed object name.
        dn: Distinguished name.

    Returns:
        True if MO is in hierarchy.

    """
    hierarchy = dn_to_hierarchy(dn)
    return any(mo.lower() == h.lower() for h in hierarchy)


def find_parent_child(path1: str, path2: str) -> Tuple[Any, Any]:
    """Find parent-child relationship.

    Args:
        path1: First path.
        path2: Second path.

    Returns:
        Tuple of (parent, child) or (None, None).

    """
    p1 = re.split(r"[./]", path1)
    p2 = re.split(r"[./]", path2)
    if p1 == p2[: len(p1)]:
        return normalize(path1), normalize(path2)
    if p2 == p1[: len(p2)]:
        return normalize(path2), normalize(path1)

    return None, None


def strip_parent_from_child(parent_expr: str, child_expr: str) -> str:
    """Remove parent prefix from child expression.

    Args:
        parent_expr: Parent expression.
        child_expr: Child expression.

    Returns:
        Stripped child expression.

    """
    parent_parts = re.split(r"[./]", parent_expr)
    child_parts = re.split(r"[./]", child_expr)
    if child_parts[: len(parent_parts)] == parent_parts:
        return ".".join(child_parts[len(parent_parts):])

    return child_expr


def normalize(path: str) -> List[str]:
    """Normalize path.

    Args:
        path: Path string to normalize.

    Returns:
        Normalized path components.

    """
    path = path.replace(".", "/").strip("/")
    return re.split(r"[./]", path)


def build_expr(parts: List[str]) -> str:
    """
    Build expression from path parts with rules.

      - hyphenated part -> ["part"] (no leading dot)
      - non-hyphen part:
          * in base_mo -> .part
          * not in base_mo -> .part[_]

    """
    expr = []
    for i, part in enumerate(parts):

        if "-" in part:
            segment = f'["{part}"]'
        else:
            segment = f"{part}" if part in BASE_MO else f".{part}[_]"

        expr.append(segment)

    # Join without adding extra dots: segments already include their own prefix/form.
    # Note: The first segment might start with '.' if it's non-hyphen. If you need
    # this to attach to a DN prefix, prefer: DN + build_expr(parts, BASE_MO)
    return "".join(expr)


def build_motype_expression(
    dn: str, prefix: str = ""
) -> Tuple[Any, Any, Any, Any]:
    """Build MOType expression from DN.

    Args:
        dn: Distinguished name.
        prefix: Optional prefix.

    Returns:
        Tuple of (parent_expr, child_expr, parent_obj, child_obj).

    """
    parent_path, child_path = find_parent_child(dn, prefix)
    if parent_path and child_path:
        parent_obj = parent_path[-1]
        child_obj = child_path[-1]
        parent_expr = build_expr(parent_path)
        child_expr = build_expr(child_path)
        stripped_child = strip_parent_from_child(parent_expr, child_expr)
        return parent_expr, stripped_child, parent_obj, child_obj

    return None, None, None, None


def get_attribute_motype_for_category(
    df: pd.DataFrame, target_mo: str
) -> Optional[Tuple[Any, Any, Any, Any]]:
    """Full workflow to build attribute MOType expression.

    Args:
        df: DataFrame with MO data.
        target_mo: Target managed object.

    Returns:
        Tuple of MOType expression components or None.

    """
    dn = get_mo(df, target_mo)
    if not dn:
        return None

    return build_motype_expression(dn)


def calculate_comprehensive_averages(
    ret_metrics: Dict[str, Dict[str, float]]
) -> Dict[str, float]:
    """Calculate comprehensive average metrics.

    Args:
        ret_metrics: Dictionary of metrics per parameter.

    Returns:
        Dictionary of averaged metrics.

    """
    if not ret_metrics:
        return {}

    totals: Dict[str, float] = {}
    count = len(ret_metrics)

    for metrics in ret_metrics.values():
        for metric_name, value in metrics.items():
            totals[metric_name] = totals.get(metric_name, 0.0) + value

    return {metric: total / count for metric, total in totals.items()}


def print_comprehensive_metrics(
    ret_metrics: Dict[str, Dict[str, float]],
    avg_metrics: Dict[str, float],
) -> None:
    """Print comprehensive metrics in a nice format.

    Args:
        ret_metrics: Per-parameter metrics.
        avg_metrics: Average metrics across parameters.

    """
    logger.info("\n" + "=" * 60)
    logger.info("COMPREHENSIVE RAG RETRIEVAL METRICS")
    logger.info("=" * 60)

    logger.info("\nAVERAGE METRICS ACROSS ALL PARAMETERS:")
    logger.info("-" * 40)
    for metric_name, value in avg_metrics.items():
        logger.info(
            f"{metric_name.replace('_', ' ').title()}: {value:.4f}"
        )

    logger.info("\nPER-PARAMETER DETAILED METRICS:")
    logger.info("-" * 40)
    for param_name, metrics in ret_metrics.items():
        logger.info(f"\n{param_name}:")
        for metric_name, value in metrics.items():
            logger.info(
                f"{metric_name.replace('_', ' ').title()}: {value:.4f}"
            )


def print_generative_metrics(
    avg_metrics: Dict[str, float],
    per_param_faith: Dict[str, Any],
    per_param_rel: Dict[str, Any],
    vendor: str,
) -> None:
    """Print comprehensive metrics in a nice format.

    Args:
        avg_metrics: Average metrics.
        per_param_faith: Per-parameter faithfulness metrics.
        per_param_rel: Per-parameter relevancy metrics.
        vendor: Vendor name.

    """
    logger.info("\n" + "=" * 60)
    logger.info("COMPREHENSIVE RAG GENERATIVE METRICS")
    logger.info("=" * 60)

    logger.info("\nAVERAGE METRICS ACROSS ALL PARAMETERS:")
    logger.info("-" * 40)
    for metric_name, value in avg_metrics.items():
        logger.info(
            f"{metric_name.replace('_', ' ').title()}: {value:.4f}"
        )
    logger.info("\nPER-PARAMETER DETAILED METRICS:")
    logger.info("-" * 40)

    # Extract parameter name (excluding 'vendor')
    param_list = [key for key in per_param_faith.keys() if key != "vendor"]
    for param_name in param_list:
        logger.info(
            f"WEIGHTS OF ALL THE FIELDS OF PARAMETER FOR CALCULATING FAITHFULNESS: {param_name}"
        )
        logger.info(
            "-----------------------------------------------------------------------------------"
        )
        if vendor != "Generic":
            logger.info(
                f"Vendor: {vendor}"
            )
        logger.info(f"{param_name}: ")
        logger.info(
            "-----------------------------------------------------------------------------------"
        )
        for key, value in per_param_faith[param_name].items():
            logger.info(f"'{key}': {value},")

    # Extract parameter name (excluding 'vendor')
    param_list = [key for key in per_param_rel.keys() if key != "vendor"]
    for param_name in param_list:
        logger.info(
            f"\nWEIGHTS OF ALL THE FIELDS OF PARAMETER FOR CALCULATING RELEVANCY:  {param_name}"
        )
        logger.info(
            "------------------------------------------------------------------------------------"
        )
        if vendor != "Generic":
            logger.info(
                f"Vendor: {vendor}"
            )
        logger.info(f"{param_name}: ")
        logger.info(
            "------------------------------------------------------------------------------------"
        )
        for metric_name, value in per_param_rel[param_name].items():
            logger.info(
                f"'{metric_name}' : {value},"
            )


def calc_avg_top_k_mrr(
    metrics: Dict[str, Dict[str, float]]
) -> Tuple[float, float]:
    """Calculate average top_k and mrr.

    Args:
        metrics: Dictionary of metrics.

    Returns:
        Tuple of (top_k_avg, mrr_avg).

    """
    top_k_values = [v["top_k"] for v in metrics.values()]
    mrr_values = [v["mrr"] for v in metrics.values()]

    top_k_avg = sum(top_k_values) / len(top_k_values)
    mrr_avg = sum(mrr_values) / len(mrr_values)

    logger.info("Average top_k: %s", top_k_avg)
    logger.info("Average mrr: %s", mrr_avg)

    return top_k_avg, mrr_avg


def context_to_text(context: Dict[str, Any]) -> str:
    """Convert context to text description.

    Args:
        context: Context dictionary.
        vendor: Vendor name.
        parameters: List of parameters.

    Returns:
        Text description of context.

    """
    return (
        f"attribute {context['attr'].split('.')[-1]} "
        f"in path {context['hierarchical_path']}"
    )


def get_next_index(existing_keys: List[str], base_key: str) -> int:
    """Return next available index for numbered keys.

    Args:
        existing_keys: List of existing keys.
        base_key: Base key pattern.

    Returns:
        Next available index number.

    """
    pattern = re.compile(rf"{base_key}(\d+)$")
    numbers = [
        int(m.group(1)) for k in existing_keys if (m := pattern.match(k))
    ]

    return max(numbers) + 1 if numbers else 1


def get_config_value(key: str) -> Any:
    """Load JSON config and return value for given key.

    Args:
        key: Configuration key to retrieve.

    Returns:
        Configuration value.

    """
    with open(CONFIG_PATH, "r", encoding="utf-8") as f:
        config = json.load(f)

    return config.get(key)
