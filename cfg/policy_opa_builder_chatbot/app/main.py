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

"""Main entry point and high-level orchestration for the OPA chatbot app."""

from contextlib import asynccontextmanager
from fastapi import FastAPI
from rag_pipeline.create_faiss import CreateFAISSIndex
from parsers.aai_parser import (
    build_hierarchy,
    build_parent_map,
    parse_xml,
)
from parsers.yang_parser import export, load_args_from_config
from rag_pipeline.rag_retriever import RAGRetriever
from rag_pipeline.rego_generator import RegoGenerator
from opa_validator.rego_validator import RegoValidator
from chatbot_backend.chatbot import MultiParameterChatbot
from libs.utilities import get_config_value
from api.routes import router
from constants import (
    AAI_TARGET_TYPES,
    AAI_OUTPUT_EXCEL,
)
import pandas as pd
from typing import Any, Tuple, List


def parse_aai() -> Any:
    """Parse an AAI XML file into a structured dictionary."""
    type_map, root_elements = parse_xml()
    parent_map = build_parent_map(type_map)

    all_rows = []

    for java_type, xml_root in root_elements.items():
        if xml_root.lower() in AAI_TARGET_TYPES:
            all_rows.extend(
                build_hierarchy(
                    java_type, xml_root, type_map, parent_map, root_elements
                )
            )

    df = pd.DataFrame(all_rows)
    output = AAI_OUTPUT_EXCEL
    df.to_excel(output, index=False)
    return output


# Initialize FAISS Index and necessary components
def create_faiss_index(vendor_files: List[str], aai_file: str) -> Any:
    """Create a FAISS index from prepared sentences."""
    faiss_obj = CreateFAISSIndex(vendor_files, aai_file)
    return faiss_obj


def initialize_modules(_faiss_obj: Any) -> Tuple[Any, Any, Any]:
    """Initialize FAISS, retriever, and Rego generator modules."""
    rt = RAGRetriever(_faiss_obj.dp)
    rv = RegoValidator()
    rg = RegoGenerator()
    #rv.setup_opa()
    #rv.check_opa_version()
    return rt, rg, rv


def run_yang_export() -> Any:
    """Run YANG export only once (cached)."""
    vendors = get_config_value("vendors")
    arg_file = []
    for vendor in vendors:
        args = load_args_from_config(get_config_value(vendor), get_config_value("out_dir"))
        vendor_file = export(args)
        arg_file.append(vendor_file)
    return arg_file


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Initialize backend"""
    print("🚀 Starting backend initialization...")
    # FAISS
     # Step 1: Prepare input data
    aai_file = parse_aai()
    vendor_files = run_yang_export()

    # Step 2: Build FAISS
    faiss_obj = create_faiss_index(vendor_files, aai_file)

    # Step 3: Initialize modules
    rt, rg, rv = initialize_modules(faiss_obj)

    # Step 4: Create chatbot
    chatbot = MultiParameterChatbot(
        faiss_obj=faiss_obj,
        rt_module=rt,
        dp_module=faiss_obj.dp,
        val_module=rv,
        gen_rego_module=rg,
    )

    # Step 5: Store global singletons
    app.state.chatbot = chatbot
    app.state.faiss = faiss_obj
    app.state.retriever = rt
    app.state.validator = rv
    print("✅ Backend initialization complete")
    yield
    print("Shutting Down Backend")

app = FastAPI(lifespan=lifespan)
app.include_router(router)
