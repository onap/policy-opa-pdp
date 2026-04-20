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
"""Create FAISS indexes for source datasets used by the RAG pipeline."""

from typing import Any, List
import os

from rag_pipeline.rag_docbuilder import RAGDocumentBuilder
from libs.utilities import create_folder


class CreateFAISSIndex:
    """Build FAISS indexes for general and AAI datasets."""

    dp: RAGDocumentBuilder
    excel_data: Any
    aai_data: Any
    vendor_dataset: Any

    def __init__(self, vendor_files: List[str], aai_file: str) -> None:
        """Initialize data sources and ensure the FAISS store folder exists."""
        self.dp = RAGDocumentBuilder()
        self.vendor_dataset = {}
        create_folder()
        # Load the entire Excel data (no vendor filter)
        for files in vendor_files:
            filename = os.path.basename(files)
            vendor = filename.split("_")[0]
            data = self.dp.load_excel_data(files)
            self.vendor_dataset[vendor] = data
            self.create_source_faiss(data, vendor)
        self.aai_data = self.dp.load_excel_data(aai_file)
        self.create_aai_source_faiss()
        self.aai_data = self.dp.load_excel_data(aai_file)
        self.create_aai_source_faiss()

    def create_source_faiss(self, data: Any, vendor: str) -> None:
        """Create a FAISS index from the main dataset."""
        sentences, _ = self.dp.create_sentences(data, "Vendor")
        self.dp.create_faiss_index(
            sentences, f"./faiss_store/faiss_index_{vendor}_dataset"
        )

    def create_aai_source_faiss(self) -> None:
        """Create a FAISS index from the AAI dataset."""
        sentences, _ = self.dp.create_sentences(self.aai_data)
        self.dp.create_faiss_index(
            sentences, "./faiss_store/faiss_index_aai_dataset"
        )
