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

"""RAG context builder utilities for constructing context objects."""

from __future__ import annotations
from dataclasses import dataclass
from typing import Any, Dict, List, Optional
import pandas as pd
from libs.utilities import (
    get_mo,
    build_motype_expression
)
from libs.logs import Logger
from constants import (
    COL_HIERARCHY_PATH,
    COL_MANAGED_OBJECT,
    DEFAULT_PACKAGE_NAME,
    OPERATOR_MAP,
    COL_PARAM_SHORT_NAME,
    COL_PARAM_LONG_NAME,
    CTX_AAI,
    BASE_MO,
    CTX_VENDOR,
    CTX_AAI_RELATION,
    CTX_VENDOR_HIERARCHY,
    OUTPUT_HEADER,
    OUTPUT_BLOCK_END,
)
logger = Logger.get(__name__)


# --------------------------
# Context Dataclasses
# --------------------------
@dataclass
class AAIContext:
    """Context container for AAI-based attribute matching."""

    attribute_fullname: str
    fullname: str
    attr: str
    hierarchical_path: str
    motype: str
    operator: str


@dataclass
class VendorContext:
    """Context container for vendor-specific attributes."""

    vendor: str
    fullname: str
    attribute_fullname: str
    attr: str
    hierarchical_path: str
    motype: str
    operator: str


@dataclass
class AAIRelationContext:
    """Context container for AAI relation-based rule construction."""

    attribute_fullname: str
    attr: str
    hierarchical_path: str
    motype: str
    primarymo: str
    relation_key: str
    relationship_fields_for_motype: str
    operator: str


@dataclass
class VendorHierarchyContext:
    """Context container for vendor hierarchy evaluation."""

    attribute_fullname: str
    vendor: str
    attr: str
    motype: str
    fullname: str
    moobjectpath: str
    operator: str
    hierarchical_path: str
    primarymo: str
    parentobj: str
    childobj: str


CONTEXT_SCHEMA: Dict[str, Any] = {
    "aai": AAIContext,
    "vendor": VendorContext,
    "aai_relationship": AAIRelationContext,
    "vendor_hierarchy": VendorHierarchyContext,
}


# --------------------------
# ContextBuilder Class
# --------------------------
class ContextBuilder:
    """Builder for creating context objects for policy generation."""

    def __init__(self) -> None:
        """Initialize the context builder."""
        pass

    def construct_fullname(self, distinguishname: str) -> str:
        """Generate the formatted fullname for a managed object (MO)."""
        parts = distinguishname.split(".")
        print("Parts", parts)
        result_parts = [
            (f'["{part}"]' if "-" in part else part)       # hyphen check first
            if part in BASE_MO
            else (f'["{part}"]' if "-" in part else f"{part}[_]")
            for part in parts
        ]
        return ".".join(result_parts)

    def relationship_fields_for_motype(self, motype: str) -> tuple[str, str, str]:
        """Return the relation name, key name, and object variable for an MO type."""
        relation_field = f"{motype}-name" if motype == "pnf" else f"{motype}-id"
        relation_key = f"{motype}.{relation_field}"
        moObj_name = f"{motype}_{'name' if motype == 'pnf' else 'id'}"
        return relation_field, relation_key, moObj_name

    def operator_to_symbol(self, raw_op: str) -> Any:
        """Map a raw operator string into its symbolic equivalent."""
        return OPERATOR_MAP.get(raw_op.upper(), raw_op)

    def format_DN(self, path: str) -> str:
        """
        Convert a slash-separated path into an expression where.

        - segments containing '-' use ["segment"]
        - all other segments use .segment

        """
        parts = [p for p in path.split(".") if p]  # split and drop empty pieces
        if not parts:
            return ""

        # First segment: no leading dot
        first = parts[0]
        if "-" in first:
            result = f'["{first}"]'
        else:
            result = first

        # Remaining segments
        for seg in parts[1:]:
            if "-" in seg:
                result += f'["{seg}"]'
            else:
                result += f".{seg}"

        return result

    def create_base_fields(
        self,
        row: pd.Series,
        raw_op: str,
        category: str,
        motype: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Create a context dictionary for a given row and category.

        Args:
            row: The row to build context from.
            raw_op: operator string from the rule.
            category: Context category (aai, vendor, etc.).
            motype: Managed object type (optional).

        Returns:
            A dictionary representing the context object.
        """
        operation_symbol = self.operator_to_symbol(raw_op)
        DN = row[COL_MANAGED_OBJECT]
        if not pd.isna(row[COL_HIERARCHY_PATH]):
            DN = row[COL_HIERARCHY_PATH].replace("/", ".")
        formatted_DN = self.format_DN(DN)
        attr_short_name = row[COL_PARAM_SHORT_NAME]
        attr_long_name = row[COL_PARAM_LONG_NAME]
        base_fields: Dict[str, Any] = {
            "attribute_fullname": (
                f'{formatted_DN}["{attr_short_name}"]'
                if "-" in attr_short_name
                else f"{formatted_DN}.{attr_short_name}"
            ),
            "hierarchical_path": DN,
            "attr": attr_long_name,
            "motype": row[COL_MANAGED_OBJECT],
            "operator": operation_symbol,
        }
        return base_fields

    def create_context(
        self,
        df: pd.DataFrame,
        base_fields: Dict[str, Any],
        vendor: str,
        context_type: str,
        motype: Optional[str] = None,
        mopath: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Create a context dictionary for a given row and category.

        Args:
            df: The dataframe containing MO data.
            row: The row to build context from.
            raw_op: operator string from the rule.
            vendor: Vendor name.
            category: Context category (aai, vendor, etc.).
            motype: Managed object type (optional).
            mopath: MO path (optional).

        Returns:
            A dictionary representing the context object.
        """
        print("Base field", base_fields)
        if context_type == CTX_AAI:
            base_fields.update({"fullname": base_fields['hierarchical_path']})
        elif context_type == CTX_VENDOR:
            base_fields.update({"vendor": vendor,
                                "fullname": self.construct_fullname(
                                    base_fields['hierarchical_path']
                                )})
        elif context_type == CTX_AAI_RELATION:
            rel_name_, relation_key, _ = self.relationship_fields_for_motype(motype)  # type: ignore
            base_fields.update({"primarymo": motype,
                                "relation_key": relation_key,
                                "rel_name": rel_name_})
        elif context_type == CTX_VENDOR_HIERARCHY:
            if motype is not None and mopath is not None:
                self.mo = get_mo(df, motype)
                parent_path, child_path, parent_obj, child_obj = build_motype_expression(
                    mopath, base_fields['hierarchical_path']
                )
            logger.info("Parent path, child path: %s, %s", parent_path, child_path)
            base_fields.update({
                "vendor": vendor,
                "primarymo": self.mo,
                "fullname": parent_path,
                "moobjectpath": child_path,
                "parentobj": parent_obj,
                "childobj": child_obj,
            })

        contextclass = CONTEXT_SCHEMA.get(context_type)
        if contextclass is None:
            raise ValueError(f"Unknown context type: {context_type}")

        return dict(contextclass(**base_fields).__dict__)


# --------------------------
# Transform Context Functions
# --------------------------
def transform_context(
    ctx: List[Dict[str, Any]],
    category: str,
    vendor: str,
    package_name: str = DEFAULT_PACKAGE_NAME,
) -> Dict[str, Any]:
    """Transform context."""
    logger.info("Context: %s", ctx)
    output = _init_output(package_name, vendor)

    handlers = {
        CTX_AAI: _handle_aai,
        CTX_AAI_RELATION: _handle_aai_relationship,
        CTX_VENDOR_HIERARCHY: _handle_vendor_hierarchy,
        CTX_VENDOR: _handle_vendor,
    }

    handler = handlers.get(category)
    if handler is None:
        raise ValueError(f"Unsupported category: {category}")

    handler(ctx, output)
    return output


def _init_output(package_name: str, vendor: str) -> Dict[str, Any]:
    """Initilaize."""
    return {OUTPUT_HEADER: [{"package_name": f"{package_name}.{vendor}"}], OUTPUT_BLOCK_END: []}


def _add_block(
    output: Dict[str, Any], block_id: str, entry: Optional[Dict[str, Any]] = None
) -> None:
    if block_id not in output:
        output[block_id] = []
    if entry is not None:
        output[block_id].append(entry)


# --------------------------
# Handler Implementations
# --------------------------
def _handle_aai(ctx: List[Dict[str, Any]], output: Dict[str, Any]) -> None:
    target_motype = ctx[0]["motype"]
    formatted_mo_type = target_motype.replace("-", "_")
    obj_var = f"{formatted_mo_type}_obj"
    _add_block(output, "set_return",
               {"result_set_name": f"{obj_var}_list", "result_item": obj_var})
    _add_block(output, "motype_check", {"mo_type": target_motype})
    _add_block(output, "obj_init", {"obj_var": obj_var,
                                    "data_obj_name": f"data.{formatted_mo_type}[_]"})

    for context in ctx:
        _add_block(output, "condition_check", {
            "lhs": f"input.{context['attribute_fullname']}",
            "op": context["operator"],
            "rhs": f'{obj_var}["{context["attr"]}"]',
        })


def _handle_aai_relationship(ctx: List[Dict[str, Any]], output: Dict[str, Any]) -> None:
    target_motype = ctx[0]["primarymo"]
    attribute_motype = ctx[0]["motype"]
    obj_var = f"{target_motype}_obj"
    _add_block(output, "motype_check", {"mo_type": attribute_motype})
    _add_block(output, "set_return", {"result_set_name": f"{target_motype}_obj_list",
                                      "result_item": obj_var})
    _add_block(output, "obj_init", {"obj_var": obj_var,
                                    "data_obj_name": f"data.{target_motype}[_]"})
    _add_block(output, "obj_init", {"obj_var": f"{attribute_motype}_obj",
                                    "data_obj_name": f"data.{attribute_motype}[_]"})

    for context in ctx:
        _add_block(output, "condition_check", {
            "lhs": f"input.{context['attribute_fullname']}",
            "op": context["operator"],
            "rhs": f'{attribute_motype}_obj["{context["attr"]}"]',
        })

    _add_block(output, "rel_relationship", {
        "obj_var": f"{attribute_motype}_obj",
        "related_type": target_motype,
        "relationship_key": ctx[0]["relation_key"],
        "related_id": f"{target_motype}_list",
    })

    _add_block(output, "some_exist_in_collection", {
        "x": target_motype,
        "collection": f"[{target_motype}_list]",
        "obj": obj_var,
        "rel_name": ctx[0]["rel_name"],
    })


def _handle_vendor_hierarchy(ctx: List[Dict[str, Any]], output: Dict[str, Any]) -> None:
    target_motype = ctx[0]["primarymo"].replace("-", "_")
    _add_block(output, "set_return", {"result_set_name": f"{target_motype}_list",
                                      "result_item": f"{target_motype}_obj"})
    _add_block(output, "vendor_check", {"vendor": ctx[0]["vendor"]})
    parent_var = f"{ctx[0]['parentobj']}_obj"
    child_var = f"{ctx[0]['childobj']}_obj"
    _init_parent(ctx, output, parent_var)
    _init_child(ctx, output, parent_var, child_var, ctx[0]["moobjectpath"])
    attribute_motype = ctx[0]["motype"]
    _add_block(output, "motype_check", {"mo_type": attribute_motype})
    formatted_mo_type = attribute_motype.replace("_", "-")
    for context in ctx:
        _add_block(output, "condition_check", {
            "lhs": f"input.{context['attribute_fullname']}"
                   if not context['attribute_fullname'].startswith('[')
                   else f"input{context['attribute_fullname']}",
            "op": context["operator"],
            "rhs": f'{formatted_mo_type}_obj["attributes"]["{context["attr"]}"]',
        })


def _handle_vendor(ctx: List[Dict[str, Any]], output: Dict[str, Any]) -> None:
    target_motype = ctx[0]["motype"]
    formatted_mo_type = target_motype.replace("-", "_")
    obj_var = f"{formatted_mo_type}_obj"
    _add_block(output, "set_return",
               {"result_set_name": f"{obj_var}_list", "result_item": obj_var})
    _add_block(output, "vendor_check", {"vendor": ctx[0]["vendor"]})
    _add_block(output, "obj_init", {"obj_var": obj_var,
                                    "data_obj_name": f"data.{ctx[0]['fullname']}"
                                    if not ctx[0]['fullname'].startswith('[')
                                    else f"data{ctx[0]['fullname']}"
                                    })
    _add_block(output, "motype_check", {"mo_type": target_motype})
    for context in ctx:
        _add_block(output, "condition_check", {
            "lhs": f"input.{context['attribute_fullname']}"
                   if not context['attribute_fullname'].startswith('[')
                   else f"input{context['attribute_fullname']}",
            "op": context["operator"],
            "rhs": f'{formatted_mo_type}_obj["attributes"]["{context["attr"]}"]',
        })


# --------------------------
# Parent/Child helpers
# --------------------------
def _init_parent(ctx: List[Dict[str, Any]], output: Dict[str, Any], parent_var: str) -> None:
    fullname = ctx[0]["fullname"]
    if "[_]" in fullname:
        print("If", fullname)
        _add_block(output, "enumerate_dataobj", {"obj_var": parent_var,
                                                 "base_obj": "data",
                                                 "enumerate_obj": fullname})
    else:
        print("Else Fullname", fullname)
        _add_block(output, "obj_init", {"obj_var": parent_var,
                                        "data_obj_name": f"data.{fullname}"})


def _init_child(ctx: List[Dict[str, Any]], output: Dict[str, Any],
                parent_var: str, child_var: str, child_path: str) -> None:
    fullname = ctx[0]["moobjectpath"]
    if "[_]" in fullname:
        print("child if", fullname)
        _add_block(output, "enumerate_dataobj", {"obj_var": child_var,
                                                 "base_obj": parent_var,
                                                 "enumerate_obj": child_path})
    else:
        print("Child else", fullname)
        _add_block(output, "obj_init", {"obj_var": child_var,
                                        "data_obj_name": f"data.{fullname}"})
