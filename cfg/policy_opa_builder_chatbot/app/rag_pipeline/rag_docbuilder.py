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

"""Build RAG documents and FAISS indices from Excel/JSON datasets."""

from __future__ import annotations

from typing import Any, Dict, List, Optional, Tuple

import faiss
import pandas as pd
from sentence_transformers import SentenceTransformer
from libs.utilities import get_config_value
from constants import (
    EMBEDDING_MODEL,
    COL_PARAM_SHORT,
    COL_HIERARCHY_PATH,
    INVALID_PARAMETER_VALUES,
    CONFIG_VENDORS_KEY,
)
from libs.logs import Logger

logger = Logger.get(__name__)


class RAGDocumentBuilder:
    """Prepare sentences/embeddings and build FAISS indices for RAG retrieval."""

    def __init__(self) -> None:
        """Initialize the embedding model and internal state."""
        self.embedder: SentenceTransformer = SentenceTransformer(
            EMBEDDING_MODEL
        )
        self.df: Optional[pd.DataFrame] = None
        self.grouped_df: Optional[pd.DataFrame] = None

    def load_excel_data(self, file_path: str) -> Optional[pd.DataFrame]:
        """Load Excel sheets, add 'Vendor' column, preprocess, and return a DataFrame.

        Args:
            file_path: Path to the Excel file.

        Returns:
            Preprocessed pandas DataFrame or None if error occurs.

        """
        try:
            sheets_dict: Dict[str, pd.DataFrame] = pd.read_excel(
                file_path, sheet_name=None
            )

            df_all = pd.concat(sheets_dict.values(), ignore_index=True)
            self.df = self.preprocess_data(df_all)
            return self.df

        except ValueError as e:
            logger.error(f"Error loading data from Excel: {e}")
            return None

    def get_all_vendors(self) -> Any:
        """Return unique vendor names from the DataFrame.

        Args:
            df: DataFrame containing a 'Vendor' column.

        Returns:
            List of unique vendor names.

        """
        return get_config_value(CONFIG_VENDORS_KEY)

    def preprocess_data(self, df: pd.DataFrame) -> pd.DataFrame:
        """Clean column names, drop duplicates, and filter invalid attributes.

        Args:
            df: Raw pandas DataFrame.

        Returns:
            Preprocessed DataFrame.

        Raises:
            ValueError: If 'ParameterShortName' column is missing.

        """
        df.columns = df.columns.str.strip()
        df = df.drop_duplicates()

        if COL_PARAM_SHORT in df.columns:
            df = df[
                ~df[COL_PARAM_SHORT]
                .astype(str)
                .str.lower()
                .isin(INVALID_PARAMETER_VALUES)
            ]
            return df
        else:
            raise ValueError(
                "'ParameterShortName' column not found after reading Excel."
            )

    def create_sentences(
        self, df: pd.DataFrame, vendor: Optional[str] = None
    ) -> Tuple[Optional[List[str]], Optional[pd.DataFrame]]:
        """Create sentence strings from the DataFrame for embeddings.

        Args:
            df: Preprocessed pandas DataFrame.
            Vendor: Optional vendor filter.

        Returns:
            Tuple of list of sentences and the possibly updated DataFrame.

        """
        if df is None:
            logger.debug(
                "----DataFrame is empty. Please load the data first.----"
            )
            return None, None
        if vendor is not None:
            df["sentence"] = df.apply(
                lambda row: (
                    f"Attribute '{row[COL_PARAM_SHORT]}' "
                    f"in HierarchicalPath '{row[COL_HIERARCHY_PATH]}"
                ),
                axis=1,
            )
        else:
            df["sentence"] = df.apply(
                lambda row: f"Attribute '{row[COL_PARAM_SHORT]}'",
                axis=1,
            )

        self.grouped_df = (
            df.groupby(["HierarchicalPath", "ParameterShortName"])[
                "sentence"
            ]
            .apply(lambda x: " ".join(x))
            .reset_index()
        )
        sentences: List[str] = df["sentence"].tolist()
        return sentences, df

    def create_faiss_index(
        self, sentences: Optional[List[str]], index_name: str
    ) -> None:
        """Encode sentences, build a FAISS index, save it, and return index + embeddings.

        Args:
            sentences: List of sentences to encode.
            index_name: Name/path to save the FAISS index.

        Returns:
            None

        """
        if not sentences:
            logger.info(
                "----No sentences provided to create FAISS index.----"
            )

        embeddings = self.embedder.encode(sentences, convert_to_numpy=True)
        index = faiss.IndexFlatL2(embeddings.shape[1])
        index.add(embeddings)

        faiss.write_index(index, f"{index_name}.faiss")
        logger.info(
            f"----FAISS index created and saved as '{index_name}.faiss'----"
        )
