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

"""Retrieve relevant rows using FAISS + hybrid reranking for RAG workflows."""

import json
import pandas as pd
from typing import cast, List, Dict, Any, Optional, Tuple

import faiss
import numpy as np
from sentence_transformers import SentenceTransformer, util
from sklearn.preprocessing import MinMaxScaler
from rank_bm25 import BM25Okapi
from constants import (
    FAISS_VENDOR_INDEX_PATH,
    FAISS_AAI_INDEX_PATH,
    RERANK_ALPHA,
    EXACT_MATCH_BOOST,
    CONFIG_USECASE_INFO,
    OPERATOR_MAP
)
from libs.utilities import get_config_value
from libs.logs import Logger

logger = Logger.get(__name__)


class DataProcessor:
    """Minimal protocol class for type hints for data processors."""

    embedder: SentenceTransformer


class RAGRetriever:
    """Retrieve relevant rows for a query using FAISS and hybrid reranking."""

    def __init__(self, dp: DataProcessor):
        """Initialize the retriever with a data processor embedding model.

        Args:
            dp: A data processor with an embedding model.
        """
        self.embedder: SentenceTransformer = dp.embedder
        self.dp: DataProcessor = dp

    def load_faiss_index(self, index_file: str) -> Optional[faiss.Index]:
        """Load a FAISS index from a file.

        Args:
            index_file: Path to the FAISS index file.

        Returns:
            Loaded FAISS index, or None if loading fails.
        """
        try:
            index = faiss.read_index(index_file)
            logger.info("FAISS index loaded from %s", index_file)
            return index
        except Exception as e:
            logger.error("Error loading FAISS index: %s", e)
            return None

    def retrieve_row(
        self, query: str, vendor: str, grouped_df: "pd.DataFrame", top_k: int = 5
    ) -> Optional["pd.DataFrame"]:
        """Retrieve top-k rows matching a query using FAISS + reranking.

        Args:
            query: User query string.
            vendor: Vendor name.
            grouped_df: DataFrame containing candidate rows.
            top_k: Number of top matches to retrieve.

        Returns:
            DataFrame with top-k matched rows and similarity scores, or None.
        """
        if vendor != "Generic":
            index_file = FAISS_VENDOR_INDEX_PATH.format(vendor=vendor)
        else:
            index_file = FAISS_AAI_INDEX_PATH
        index = self.load_faiss_index(index_file)
        if index is None:
            return None

        query_embedding = self.embedder.encode([query], convert_to_numpy=True)
        if query_embedding.ndim == 1:
            query_embedding = query_embedding.reshape(1, -1)

        if query_embedding.shape[1] != index.d:
            logger.error(
                "Dimension mismatch: query %d vs index %d",
                query_embedding.shape[1],
                index.d,
            )
            return None

        _, indices = index.search(query_embedding, top_k)
        valid_indices = indices[0][indices[0] != -1]
        if len(valid_indices) == 0:
            logger.info("No valid matches found.")
            return None

        matched_rows = grouped_df.iloc[valid_indices]
        return self.reranking(matched_rows, query, query_embedding, top_k)

    def reranking(
        self,
        matched_rows: "pd.DataFrame",
        query: str,
        query_embedding: np.ndarray,
        top_k: int,
    ) -> "pd.DataFrame":
        """Rerank matched rows using BM25 and dense embeddings.

        Args:
            matched_rows: Candidate rows.
            query: User query.
            vendor: Vendor name.
            query_embedding: Embedding of the query.
            top_k: Number of top rows to return.

        Returns:
            DataFrame with top-k rows and similarity scores.
        """
        # Build candidate texts
        candidate_texts = matched_rows.apply(
            lambda row: (
                f"Attribute {row['ParameterShortName']} "
                f"in HierarchicalPath {row['HierarchicalPath']}"
            ),
            axis=1,
        ).tolist()

        # BM25 sparse scores
        tokenized_corpus = [doc.split() for doc in candidate_texts]
        bm25 = BM25Okapi(tokenized_corpus)
        bm25_scores = bm25.get_scores(query.split())

        # Dense embedding similarity
        candidate_embeddings = self.embedder.encode(candidate_texts, convert_to_numpy=True)
        dense_scores = util.cos_sim(query_embedding, candidate_embeddings)[0].numpy()

        # Normalize scores
        scaler = MinMaxScaler()
        combined = np.concatenate([bm25_scores, dense_scores])
        scaler.fit(combined.reshape(-1, 1))
        normalized_bm25 = scaler.transform(bm25_scores.reshape(-1, 1)).flatten()
        normalized_dense = scaler.transform(dense_scores.reshape(-1, 1)).flatten()

        # Weighted sum
        alpha = RERANK_ALPHA
        combined_scores = alpha * normalized_bm25 + (1 - alpha) * normalized_dense

        # Exact match boost
        boost = np.array([1.0 if query == text else 0.0 for text in candidate_texts])
        combined_scores += EXACT_MATCH_BOOST * boost

        top_k_indices = np.argsort(combined_scores)[::-1][:top_k]

        top_k_rows = matched_rows.iloc[top_k_indices].copy()
        top_k_rows["similarity_score"] = [float(combined_scores[idx]) for idx in top_k_indices]
        top_k_rows["rank"] = list(range(1, len(top_k_indices) + 1))
        return top_k_rows

    def query_instruction(self, user_input: str,
                          index: faiss.Index
                          ) -> Tuple[np.ndarray, np.ndarray]:
        """Return FAISS distances and indices for a user query.

        Args:
            user_input: Query string.
            index: FAISS index.

        Returns:
            distances and indices arrays.
        """
        query_embedding = self.embedder.encode([user_input], convert_to_numpy=True)
        if query_embedding.ndim == 1:
            query_embedding = query_embedding.reshape(1, -1)
        top_k = index.ntotal
        distances, indices = index.search(query_embedding, top_k)
        return distances, indices

    def operator_mapping(self, raw_op: str) -> str:
        """Map human-readable operators to symbolic forms.

        Args:
            raw_op: Operator string like "EQUALS" or "GREATER THAN"

        Returns:
            Symbolic operator like "==" or ">"
        """
        key = raw_op.upper()
        if key in OPERATOR_MAP:
            value: str = OPERATOR_MAP[key]
            return value
        return raw_op

    def construct_fullname(self, distinguishname: str, attribute: str) -> Any:
        """Build Rego-style MO path with wildcards.

        Args:
            distinguishname: Dot-separated MO path.
            attribute: Attribute to append.

        Returns:
            Rego path string.
        """
        parts = distinguishname.split(".")
        result_parts = [part if part == "ManagedElement" else f"{part}[_]" for part in parts]
        return ".".join(result_parts) + f".{attribute}"

    def rel_name(self, motype: str) -> Tuple[str, str, str]:
        """Return relation name, key, and object variable for an MO type.

        Args:
            motype: Managed object type.

        Returns:
            Tuple of (relation name, relation key, object variable)
        """
        if motype == "pnf":
            return motype + "-name", motype + "." + motype + "-name", motype + "_name"
        return motype + "-id", motype + "." + motype + "-id", motype + "_id"

    def retrieve_usecase(self) -> List[Dict[str, Any]]:
        """Load and return usecases from JSON config.

        Returns:
            List of usecase dictionaries.
        """
        usecase_info = get_config_value(CONFIG_USECASE_INFO)
        with open(usecase_info, "r") as f:
            data = json.load(f)
        usecases: List[Dict[str, Any]] = cast(List[Dict[str, Any]], data.get("usecase", []))
        return usecases
