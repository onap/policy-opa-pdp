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

"""RAG evaluation utilities for multi-parameter policy generation."""
import numpy as np
from sklearn.metrics.pairwise import cosine_similarity
from typing import List, Union, Dict, Any, Tuple, Optional, cast

from libs.logs import Logger
from constants import (
    DEFAULT_SIMILARITY_THRESHOLD,
    DEFAULT_TOP_K_VALUES,
    VENDOR_SCORE_NORMALIZATION,
    EVAL_OPERATOR_MAP,
    SCORE_NAME_PRESENT,
    SCORE_MOTYPE_GENERIC,
    SCORE_MOTYPE_VENDOR,
    SCORE_MISSING,
)

logger = Logger.get(__name__)


class MultiParamRAGEvaluator:
    """Evaluator for multi-parameter RAG outputs.

    Computes retrieval and generation metrics including MRR, Top-K accuracy,
    faithfulness, and relevancy of generated policies.
    """

    def __init__(self, state: Any, dp: Any) -> None:
        """Initialize evaluator with run state and a data processor.

        Args:
            state: Run state object containing parameters, vendor info, etc.
            dp: Data processor with embedding model (must have `.embedder`).

        """
        self.state = state
        self.embedder = dp.embedder
        self.operator_map = EVAL_OPERATOR_MAP

    def compute_semantic_similarity(self, a: str, b: str) -> float:
        """Calculate semantic similarity between two texts.

        Args:
            a: First text string.
            b: Second text string.

        Returns:
            Cosine similarity score between 0 and 1.

        """
        emb_a = self.embedder.encode([a], convert_to_numpy=True)
        emb_b = self.embedder.encode([b], convert_to_numpy=True)
        return float(cosine_similarity(emb_a, emb_b)[0][0])

    def cosine_similarity_to_reference(
        self, texts: List[str], reference: str
    ) -> List[float]:
        """Calculate semantic similarity between texts and reference.

        Args:
            texts: List of text strings to compare.
            reference: Reference text string.

        Returns:
            List of similarity scores.

        """
        if not texts:
            return []
        text_embeddings: np.ndarray = self.embedder.encode(
            texts, convert_to_numpy=True
        )
        ref_embedding: np.ndarray = self.embedder.encode(
            [reference], convert_to_numpy=True
        )
        similarities: np.ndarray = cosine_similarity(
            text_embeddings, ref_embedding
        )
        return cast(List[float], similarities.flatten().tolist())

    def top_k_accuracy(
        self,
        retrieved_contexts: List[str],
        ground_truth: Union[str, List[str]],
        k: Optional[int] = None,
        threshold: float = DEFAULT_SIMILARITY_THRESHOLD,
    ) -> float:
        """Calculate top-k accuracy for retrieved contexts.

        Returns 1.0 if any of top-k retrieved contexts matches ground_truth
        semantically above threshold, else 0.0.

        Args:
            retrieved_contexts: List of retrieved context strings.
            ground_truth: Ground truth string(s) for comparison.
            k: Number of top contexts to consider (default: all).
            threshold: Semantic similarity threshold (default: 0.8).

        Returns:
            1.0 if match found in top-k, else 0.0.

        """
        if not retrieved_contexts:
            return 0.0

        ground_truths: List[str] = (
            [ground_truth] if isinstance(ground_truth, str) else ground_truth
        )
        if k is None:
            k = len(retrieved_contexts)
        elif k <= 0:
            return 0.0
        else:
            k = min(k, len(retrieved_contexts))
        top_k_contexts = retrieved_contexts[:k]

        for context in top_k_contexts:
            if any(
                self.compute_semantic_similarity(context, gt) >= threshold
                for gt in ground_truths
            ):
                return 1.0
        return 0.0

    def mrr_score(
        self,
        retrieved_contexts: List[str],
        ground_truth: Union[str, List[str]],
        threshold: float = 0.8,
    ) -> float:
        """Compute Mean Reciprocal Rank (MRR) for retrieved contexts.

        Args:
            retrieved_contexts: List of retrieved context strings.
            ground_truth: Ground truth string(s) for comparison.
            threshold: Semantic similarity threshold (default: 0.8).

        Returns:
            MRR score (1/rank of first match, or 0.0 if no match).

        """
        if not retrieved_contexts:
            return 0.0

        ground_truths: List[str] = (
            [ground_truth] if isinstance(ground_truth, str) else ground_truth
        )

        for rank, context in enumerate(retrieved_contexts, start=1):
            if any(
                self.compute_semantic_similarity(context, gt) >= threshold
                for gt in ground_truths
            ):
                return 1.0 / rank
        return 0.0

    def _score_vendor(self, vendor: str, policy_lower: str) -> float:
        """Score vendor presence in policy text.

        Args:
            vendor: Vendor name to check.
            policy_lower: Lowercase policy text.

        Returns:
            1.0 if vendor found, else 0.0.

        """
        return 1.0 if vendor and vendor.lower() in policy_lower else 0.0

    def _score_faithfulness_param(
        self, param: Dict[str, Any], policy_lower: str, vendor: str
    ) -> Dict[str, Any]:
        """Score a single parameter for faithfulness.

        Args:
            param: Parameter dictionary with 'Attr' and 'MOType' keys.
            policy_lower: Lowercase policy text.
            vendor: Vendor name.

        Returns:
            Dictionary with score components and missing fields.

        """
        pname = str(param["attr"]).lower()
        mo_type = str(param["motype"]).lower()
        scores: Dict[str, Any] = {}
        missing: List[str] = []

        # Name score
        scores["name"] = SCORE_NAME_PRESENT if pname in policy_lower else SCORE_MISSING
        if pname not in policy_lower:
            missing.append(f"{pname} -> name missing")

        # MO Type score
        if mo_type in policy_lower:
            scores["mo_type"] = (
                SCORE_MOTYPE_GENERIC
                if vendor == "Generic"
                else SCORE_MOTYPE_VENDOR
            )
        else:
            scores["mo_type"] = SCORE_MISSING
            missing.append(f"{pname} -> mo_type missing")

        scores["Missing Fields"] = missing
        return scores

    def _score_relevancy_param(
        self, param: Any, policy_lower: str, vendor: str
    ) -> Dict[str, Any]:
        """Score a single parameter for relevancy.

        Args:
            param: Parameter object with param_name, mo_type, range attrs.
            policy_lower: Lowercase policy text.
            vendor: Vendor name.

        Returns:
            Dictionary with score components and missing fields.

        """
        pname: str = getattr(param, "param_name", "").lower()
        mo_type: str = getattr(param, "mo_type", "").lower()

        scores: Dict[str, Any] = {}
        missing: List[str] = []

        scores["name"] = SCORE_NAME_PRESENT if pname in policy_lower else SCORE_MISSING
        if pname not in policy_lower:
            missing.append(f"{pname} -> name missing")
        # MO Type score
        if mo_type in policy_lower:
            scores["mo_type"] = (
                SCORE_MOTYPE_GENERIC
                if vendor == "Generic"
                else SCORE_MOTYPE_VENDOR
            )
        else:
            scores["mo_type"] = SCORE_MISSING
            missing.append(f"{pname} -> mo_type missing")

        scores["Missing Fields"] = missing
        return scores

    def _normalize_score(
        self, score_dict: Dict[str, Any], vendor: str
    ) -> float:
        """Normalize a parameter's score to a maximum of 1.0.

        Args:
            score_dict: Dictionary with 'name' and 'mo_type' score keys.
            vendor: Vendor name, affects normalization for Generic vendor.

        Returns:
            Normalized score as float.

        """
        # Cast to float to avoid mypy errors
        name_score = float(score_dict.get("name", 0.0))
        mo_type_score = float(score_dict.get("mo_type", 0.0))
        total = name_score + mo_type_score
        if vendor != "Generic":
            return total / float(VENDOR_SCORE_NORMALIZATION)
        return total

    def _finalize_scores(
        self, results: Dict[str, Any], param_scores: List[float]
    ) -> Tuple[float, Dict[str, Any]]:
        """Compute average score and return results dictionary.

        Args:
            results: Detailed score dictionary for each parameter.
            param_scores: List of normalized parameter scores.

        Returns:
            Tuple of average score and the results dictionary.

        """
        avg_score = (
            sum(param_scores) / len(param_scores) if param_scores else 0.0
        )
        return avg_score, results

    def compute_faithfulness(
        self, generated_policy: str, context: List[Dict[str, Any]]
    ) -> Tuple[float, Dict[str, Any]]:
        """Compute faithfulness metrics for a generated policy.

        Args:
            generated_policy: Generated policy string.
            context: List of parameter dictionaries from the context.

        Returns:
            Tuple containing average faithfulness score and detailed scores.

        """
        policy_lower = generated_policy.lower()
        vendor: str = getattr(self.state, "vendor", "Generic")

        results: Dict[str, Any] = {}
        param_scores: List[float] = []

        if vendor != "Generic":
            results["vendor"] = self._score_vendor(vendor, policy_lower)

        for param in context:
            score = self._score_faithfulness_param(param, policy_lower, vendor)
            pname = param["attr"].lower()
            results[pname] = score
            param_scores.append(self._normalize_score(score, vendor))

        return self._finalize_scores(results, param_scores)

    def compute_relevancy(
        self, generated_policy: str
    ) -> Tuple[float, Dict[str, Any]]:
        """Compute relevancy metrics for a generated policy.

        Args:
            generated_policy: Generated policy string.

        Returns:
            Tuple containing average relevancy score and detailed scores.

        """
        policy_lower = generated_policy.lower()
        vendor: str = getattr(self.state, "vendor", "Generic")

        results: Dict[str, Any] = {}
        param_scores: List[float] = []

        if vendor != "Generic":
            results["vendor"] = self._score_vendor(vendor, policy_lower)

        for param in getattr(self.state, "parameters", []):
            score = self._score_relevancy_param(param, policy_lower, vendor)
            pname = getattr(param, "param_name", "").lower()
            results[pname] = score
            param_scores.append(self._normalize_score(score, vendor))

        return self._finalize_scores(results, param_scores)

    def evaluate_retrieval(
        self,
        ground_truth: Union[str, List[str]],
        retrieved_contexts: List[str],
        k_values: Optional[List[int]] = None,
        threshold: float = DEFAULT_SIMILARITY_THRESHOLD,
    ) -> Dict[str, Any]:
        """Evaluate retrieval metrics: MRR and Top-K accuracy.

        Args:
            ground_truth: Ground truth string(s) for context.
            retrieved_contexts: List of retrieved context strings.
            k_values: List of K values for Top-K evaluation (default: [1,3,5,10]).
            threshold: Semantic similarity threshold (default: 0.8).

        Returns:
            Dictionary containing MRR and Top-K accuracy metrics.

        """
        if k_values is None:
            k_values = DEFAULT_TOP_K_VALUES

        if not retrieved_contexts:
            return {"error": "No documents retrieved."}
        results: Dict[str, Any] = {}
        results["MRR"] = self.mrr_score(
            retrieved_contexts, ground_truth, threshold
        )

        for k in k_values:
            if k <= len(retrieved_contexts):
                results[f"Top_{k}_Accuracy"] = self.top_k_accuracy(
                    retrieved_contexts, ground_truth, k, threshold
                )

        return results

    def evaluate_generation(
        self, generated_policy: str, context: List[Dict[str, Any]]
    ) -> Tuple[Dict[str, float], Dict[str, Any], Dict[str, Any]]:
        """Compute generation metrics: faithfulness and relevancy.

        Args:
            generated_policy: Generated policy string.
            context: List of parameter dictionaries from the context.

        Returns:
            Tuple containing:
            - Dictionary with overall Faithfulness and Relevancy scores.
            - Detailed faithfulness scores per parameter.
            - Detailed relevancy scores per parameter.

        """
        faithfulness: float
        faith_details: Dict[str, Any]
        faithfulness, faith_details = self.compute_faithfulness(
            generated_policy, context
        )

        relevancy: float
        rel_details: Dict[str, Any]
        relevancy, rel_details = self.compute_relevancy(generated_policy)

        gen_metrics: Dict[str, float] = {
            "Faithfulness": faithfulness,
            "Relevancy": relevancy,
        }

        return gen_metrics, faith_details, rel_details
