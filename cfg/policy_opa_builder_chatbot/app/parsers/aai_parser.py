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

"""Parser utilities for processing AAI XML and generating hierarchy mappings."""

from typing import Any, Dict, List, Tuple

import pandas as pd
import xmltodict

AAI_FILE: str = "./dataset/aai_oxm_v30.xml"
TARGET_TYPES: set[str] = {"cell", "pnf"}
XML_ATTR_NAME_KEY: str = "@name"


def extract_description(attr: Dict[str, Any]) -> str:
    """Extract the description field from an XML attribute block."""
    props: Any = attr.get("xml-properties", {}).get("xml-property", [])

    if isinstance(props, dict):
        props = [props]

    for prop in props:
        if prop.get(XML_ATTR_NAME_KEY) == "description":
            return str(prop.get("@value", ""))

    return ""


def parse_xml() -> Tuple[Dict[str, List[Dict[str, str]]], Dict[str, str]]:
    """
    Parse the AAI XML file and extract type and root mappings.

    Returns
    -------
    tuple
        type_map: java_type_name -> list of attributes
        root_elements: java_type_name -> xml_root_name
    """
    with open(AAI_FILE, "r", encoding="utf-8") as f:
        xml_data: Dict[str, Any] = xmltodict.parse(f.read())

    java_types: Any = xml_data["xml-bindings"]["java-types"]["java-type"]

    if isinstance(java_types, dict):
        java_types = [java_types]

    type_map: Dict[str, List[Dict[str, str]]] = {}
    root_elements: Dict[str, str] = {}

    for jt in java_types:
        java_type_name_raw: Any = jt.get(XML_ATTR_NAME_KEY)
        if not java_type_name_raw:
            continue

        java_type_name: str = str(java_type_name_raw)

        # xml root
        xml_root: Any = jt.get("xml-root-element")
        if isinstance(xml_root, dict) and xml_root.get(XML_ATTR_NAME_KEY):
            root_elements[java_type_name] = str(xml_root[XML_ATTR_NAME_KEY])

        # attributes
        attributes: Any = jt.get("java-attributes", {}).get("xml-element", [])
        if isinstance(attributes, dict):
            attributes = [attributes]

        cleaned: List[Dict[str, str]] = []

        for attr in attributes:
            cleaned.append(
                {
                    "short": str(attr.get("@java-attribute", "")),
                    "long": str(attr.get(XML_ATTR_NAME_KEY, "")),
                    "type": str(attr.get("@type", "")),
                    "container": str(attr.get("@container-type", "")),
                    "description": extract_description(attr),
                }
            )

        type_map[java_type_name] = cleaned

    return type_map, root_elements


def build_parent_map(
    type_map: Dict[str, List[Dict[str, str]]],
) -> Dict[str, Dict[str, str]]:
    """Build child_type -> {parent, xml_name} mapping."""
    parent_map: Dict[str, Dict[str, str]] = {}

    for parent_type, attrs in type_map.items():
        for attr in attrs:
            type_value: str = attr.get("type", "")
            child_type: str = type_value.split(".")[-1] if type_value else ""

            if child_type:
                parent_map[child_type] = {
                    "parent": parent_type,
                    "xml_name": attr["long"],
                }

    return parent_map


def build_aai_path(
    type_name: str,
    parent_map: Dict[str, Dict[str, str]],
    root_elements: Dict[str, str],
) -> str:
    """Build DN dynamically by walking up to inventory."""
    path: List[str] = []

    current: str = type_name

    while current in parent_map:
        path.insert(0, parent_map[current]["xml_name"])
        current = parent_map[current]["parent"]

    root: str | None = root_elements.get(current)
    if root:
        path.insert(0, root)

    return "/".join(path)


def build_hierarchy(
    type_name: str,
    root_name: str,
    type_map: Dict[str, List[Dict[str, str]]],
    parent_map: Dict[str, Dict[str, str]],
    root_elements: Dict[str, str],
) -> List[Dict[str, str]]:
    """Build a hierarchical row structure for a given AAI type."""
    dn: str = build_aai_path(type_name, parent_map, root_elements)
    rows: List[Dict[str, str]] = []

    for attr in type_map.get(type_name, []):
        rows.append(
            {
                "ManagedObject": root_name,
                "HierarchicalPath": dn,
                "ParameterShortName": attr["short"],
                "ParameterLongName": attr["long"],
                "ParameterDescription": attr["description"],
                "Range": "",
            }
        )

    return rows


def parse_aai() -> Tuple[pd.DataFrame, str]:
    """Parse the AAI model, build hierarchy, and export it to Excel."""
    type_map, root_elements = parse_xml()
    parent_map: Dict[str, Dict[str, str]] = build_parent_map(type_map)

    all_rows: List[Dict[str, str]] = []

    for java_type, xml_root in root_elements.items():
        if xml_root.lower() in TARGET_TYPES:
            all_rows.extend(
                build_hierarchy(
                    java_type,
                    xml_root,
                    type_map,
                    parent_map,
                    root_elements,
                )
            )

    df: pd.DataFrame = pd.DataFrame(all_rows)
    output: str = "./dataset/AAI_hierarchy.xlsx"

    df.to_excel(output, index=False)

    return df, output
