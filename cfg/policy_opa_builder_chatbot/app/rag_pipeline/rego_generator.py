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

"""Generate Rego policy code using language models with constraint-based generation."""

from typing import Any, Dict, List, Optional

import json
import torch
from transformers import (
    AutoModelForCausalLM,
    AutoTokenizer,
    LogitsProcessor,
    LogitsProcessorList,
    TextStreamer,
)
import yaml

from libs.logs import Logger
from constants import (
    CONFIG_PATH,
    PLACEHOLDER_START,
    PLACEHOLDER_END,
    UNSLOTH_MODEL,
    MISTRAL_MODEL,
    MAX_SEQ_LENGTH,
    MAX_NEW_TOKENS,
    MAX_BLOCK_TOKENS,
    MAX_CLASSIFICATION_TOKENS,
    CUDA_DEVICE,
    CUDA,
    GEN_TEMPERATURE,
    GEN_TOP_K,
    GEN_TOP_P,

)
import textwrap
logger = Logger.get(__name__)


class RegoGenerator:
    """Generate Rego policy text and prompts using a language model."""

    def __init__(self) -> None:
        """Initialize the tokenizer and language model."""
        self._placeholder_start: str = PLACEHOLDER_START
        self._placeholder_end: str = PLACEHOLDER_END

        with open(CONFIG_PATH, "r") as f:
            config: Dict[str, Any] = json.load(f)

        # Use Any type to avoid redefinition errors
        model: Any
        tokenizer: Any

        if config.get("unsloth_run") == "True":
            logger.info("----Running with unsloth----")
            from unsloth import FastLanguageModel

            model, tokenizer = FastLanguageModel.from_pretrained(
                model_name=UNSLOTH_MODEL,
                max_seq_length=MAX_SEQ_LENGTH,
                dtype=None,
                load_in_4bit=True,
                device_map="auto",
            )
            FastLanguageModel.for_inference(model)
        else:
            logger.info("----Running without unsloth-----")
            tokenizer = AutoTokenizer.from_pretrained(
                MISTRAL_MODEL, trust_remote_code=True  # nosec
            )
            model = AutoModelForCausalLM.from_pretrained(  # nosec
                MISTRAL_MODEL,
                device_map="auto",
                load_in_4bit=True,
                trust_remote_code=True,
            )

        # Assign to instance attributes after if/else
        self.llm_model: Any = model
        self.tokenizer: Any = tokenizer
        self.streamer: TextStreamer = TextStreamer(self.tokenizer)

    def generate_rego(self, prompt: str) -> str:
        """Generate Rego policy code from a prompt.

        Args:
            prompt: Input text prompt to guide Rego code generation.

        Returns:
            Generated Rego code as a string.

        """
        inputs = self.tokenizer(prompt, return_tensors="pt").to(CUDA_DEVICE)
        output_ids = self.llm_model.generate(
            **inputs,
            max_new_tokens=MAX_NEW_TOKENS,
            do_sample=False,
            temperature=GEN_TEMPERATURE,
            top_k=GEN_TOP_K,
            top_p=GEN_TOP_P,
            eos_token_id=self.tokenizer.eos_token_id,
        )
        output_text: str = self.tokenizer.decode(
            output_ids[0], skip_special_tokens=True
        )
        return output_text.replace(prompt, "").strip()

    def classify_query(self, user_message: str) -> str:
        """Classify a user query for Rego/OPA relevance.

        Args:
            user_message: The input user message.

        Returns:
            JSON string indicating classification.

        """
        messages: List[Dict[str, str]] = [
            {
                "role": "system",
                "content": (
                    "You are a classification assistant. Respond with ONLY one of these "
                    "exact outputs: "
                    "'None' OR a dictionary in the format "
                    "{\"category\": \"...\", \"object\": \"...\"}. "
                    "Do not include any other text, explanations, or punctuation. "
                    "The response must be either the exact string 'None' or a valid "
                    "JSON dictionary."
                ),
            },
            {
                "role": "user",
                "content": textwrap.dedent(
                    f"""Analyze the user's query to determine if it relates to 'Rego'
                    or 'OPA' (Open Policy Agent).

                    ### Output Rules:
                    1. **Not Rego:** If the query does not relate to Rego/OPA, respond with:
                    {{"category": null, "object": null}}
                    2. **Rego General:** If the query is about Rego but does not mention a specific
                    target object to filter, respond with: {{"category": "rego", "object": "None"}}
                    3. **Rego with Object:** If the user asks to generate, filter, or return a
                    specific target resource, **extract the resource name exactly**
                    - Rule: Remove spaces (e.g., "item A" -> "itemA").
                    - Rule: The object name is usually the noun following words like "for",
                    "return","filter", "of".

                    ### Generic Examples (Pattern Matching Only):

                    User: Generate rego policy
                    Assistant: {{"category": "rego", "object": "None"}}

                    User: Generate rego policy for my resource
                    Assistant: {{"category": "rego", "object": "myresource"}}

                    User: I need a filter to return specific obj
                    Assistant: {{"category": "rego", "object": "specific"}}

                    User: code to return targetitem
                    Assistant: {{"category": "rego", "object": "targetitem"}}

                    User: Can you help with filter to return Big Database Table objects
                    Assistant: {{"category": "rego", "object": "BigDatabaseTable"}}

                    User: write a policy for AnythingHere
                    Assistant: {{"category": "rego", "object": "AnythingHere"}}

                    User: can you help with opa policy
                    Assistant: {{"category": "rego", "object": "None"}}

                    User:can you help with creating filter objects
                    Assistant: {{"category": "rego", "object": "None"}}

                    User: Hello
                    Assistant: {{"category": null, "object": null}}

                    ## Current Query:
                    "{user_message}"

                    ### Classification:

                    :"""
                ).strip()
            }
        ]
        prompt: str = self.tokenizer.apply_chat_template(
            messages, tokenize=False, add_generation_prompt=True
        )
        inputs = self.tokenizer(prompt, return_tensors="pt").to(CUDA)

        outputs = self.llm_model.generate(
            **inputs,
            max_new_tokens=MAX_CLASSIFICATION_TOKENS,
            use_cache=True,
            pad_token_id=self.tokenizer.eos_token_id,
            do_sample=False,
            temperature=0.0,
        )
        response: str = self.tokenizer.decode(
            outputs[0][inputs["input_ids"].shape[1]:],
            skip_special_tokens=True,
        )
        return response.strip()

    def generate_rego_tokenized(
        self,
        context_data: Dict[str, List[Dict[str, Any]]],
        template_file: str,
    ) -> str:
        """Generate a Rego program using block-wise token constraints.

        The method:
        1) Parses the template into ordered blocks.
        2) Tokenizes each block against the current accumulated text using delta/LCP.
        3) Uses a logits processor to force the model to follow the block sequences.
        4) Decodes the final model output into a Rego source string.
        """
        # Read example Rego from file
        with open(template_file) as f:
            template_data = yaml.safe_load(f)
        context_keys = list(context_data.keys())
        context_keys_str = ", ".join(context_keys)
        logger.info("Keys:%s", context_keys_str)
        template_index = {item["id"]: item["body"] for item in template_data}
        structure_order = []

        # TEMPLATE order is canonical; iterate through it
        for block in template_data:
            block_id = block["id"]
            logger.info("Block_id: %s", block_id)
            if block_id in context_keys_str:
                structure_order.append(block_id)
        logger.info("Struture order %s", structure_order)
        logger.info("Context %s", context_data)
        # build sequences for all blocks
        block_sequences = []
        block_lengths = []
        for bid in structure_order:
            if bid in template_index and bid in context_data:
                block_sequences.append(
                    self.tokenize_block(template_index[bid], context_data[bid])
                )
                block_lengths.append(len(context_data[bid]))
        # -----------------------------
        # 5. Build prompt
        # -----------------------------
        prompt = (
            "Generate Rego using TEMPLATE. "
            "Replace placeholders from CONTEXT exactly. "
            "Output only the code.\n\n"
        )
        inputs = self.tokenizer(prompt, return_tensors="pt").to(self.llm_model.device)

        processor = BlockSequenceConstraint(
            self.tokenizer, block_sequences, start_len=inputs.input_ids.shape[1]
        )
        logits_processor_list = LogitsProcessorList([processor])

        # -----------------------------
        # 6. Generate
        # -----------------------------
        with torch.no_grad():
            outputs = self.llm_model.generate(
                **inputs,
                max_new_tokens=MAX_BLOCK_TOKENS,
                temperature=0.0,
                do_sample=False,
                logits_processor=logits_processor_list,
                eos_token_id=self.tokenizer.eos_token_id,
                pad_token_id=self.tokenizer.eos_token_id,
            )

        # -----------------------------
        # 7. Decode
        # -----------------------------
        # Prevent decoder heuristics from modifying spaces
        full_response = self.tokenizer.decode(
            outputs[0], skip_special_tokens=True, clean_up_tokenization_spaces=False
        )

        prompt_text = self.tokenizer.decode(
            inputs.input_ids[0],
            skip_special_tokens=True,
            clean_up_tokenization_spaces=False,
        )

        generated_rego = full_response[len(prompt_text):].lstrip()
        generated_rego = "\n".join(
            line.lstrip() for line in generated_rego.splitlines()
        )
        return generated_rego

    def longest_common_prefix_len(self, a: List[int], b: List[int]) -> int:
        """Compute the longest common prefix length between two token lists.

        Args:
            a: First list of token IDs.
            b: Second list of token IDs.

        Returns:
            Length of the longest common prefix.

        """
        n: int = min(len(a), len(b))
        i: int = 0
        while i < n and a[i] == b[i]:
            i += 1
        return i

    def encode_delta(self, prev_text: str, new_fragment: str) -> List[int]:
        """Encode only the additional tokens needed for a new fragment.

        Args:
            prev_text: Previously accumulated text.
            new_fragment: New text fragment to append.

        Returns:
            List of token IDs for the new fragment.

        """
        ids_prev: List[int] = self.tokenizer.encode(
            prev_text, add_special_tokens=False
        )
        ids_combined: List[int] = self.tokenizer.encode(
            prev_text + new_fragment, add_special_tokens=False
        )
        lcp: int = self.longest_common_prefix_len(ids_prev, ids_combined)
        return ids_combined[lcp:]

    def tokenize_block(
        self,
        template_body: str,
        context_entries: Optional[List[Dict[str, Any]]] = None,
    ) -> List[List[int]]:
        """Tokenize a template block for all context entries.

        Args:
            template_body: Template string with placeholders.
            context_entries: List of dictionaries to replace placeholders.

        Returns:
            A list of token ID sequences, one per context entry.

        """
        if not context_entries:
            context_entries = [{}]
        block_tokens: List[List[int]] = []
        for entry in context_entries:
            fragments: List[str] = self._split_template(template_body, entry)
            seq_ids: List[int] = self._encode_fragments(fragments)
            block_tokens.append(seq_ids)
        return block_tokens

    def _split_template(
        self, template_body: str, entry: Dict[str, Any]
    ) -> List[str]:
        """Split template into literal and placeholder fragments.

        Args:
            template_body: Template string.
            entry: Dictionary of placeholder replacements.

        Returns:
            Ordered list of string fragments.

        """
        fragments: List[str] = []
        pos: int = 0
        while True:
            start: int = template_body.find(self._placeholder_start, pos)
            if start == -1:
                if pos < len(template_body):
                    fragments.append(template_body[pos:])
                break
            end: int = template_body.find(self._placeholder_end, start)
            if end == -1:
                raise ValueError("Unclosed placeholder in template")
            if start > pos:
                fragments.append(template_body[pos:start])
            placeholder_name: str = template_body[start + 2: end].strip()
            if placeholder_name in entry:
                fragments.append(str(entry[placeholder_name]).strip())
            else:
                fragments.append(template_body[start: end + 2])
            pos = end + 2
        return fragments

    def _encode_fragments(self, fragments: List[str]) -> List[int]:
        """Encode template fragments into token IDs using delta encoding.

        Args:
            fragments: List of string fragments.

        Returns:
            Flattened list of token IDs.

        """
        seq_ids: List[int] = []
        accum_text: str = ""
        for frag in fragments:
            if not frag:
                continue
            delta_ids: List[int] = self.encode_delta(accum_text, frag)
            seq_ids.extend(delta_ids)
            accum_text += frag
        return seq_ids


class BlockSequenceConstraint(LogitsProcessor):  # type: ignore[misc]
    """Enforce block-wise token sequence constraints during generation."""

    def __init__(
        self,
        tokenizer: Any,
        block_sequences: List[List[List[int]]],
        start_len: int,
    ) -> None:
        """Initialize the constraint processor.

        Args:
            tokenizer: Tokenizer for encoding/decoding.
            block_sequences: Pre-tokenized block sequences.
            start_len: Number of prompt tokens before constraint applies.

        """
        super().__init__()
        self.block_sequences: List[List[List[int]]] = block_sequences
        self.start_len: int = start_len
        self.tokenizer: Any = tokenizer
        self.block_idx: int = 0
        self.entry_idx: int = 0
        self.token_idx: int = 0

    def __call__(
        self, input_ids: torch.LongTensor, scores: torch.FloatTensor
    ) -> torch.FloatTensor:
        """Apply token mask to enforce block sequence.

        Args:
            input_ids: Current token IDs.
            scores: Logits for the next token.

        Returns:
            Modified logits tensor with forbidden tokens masked.

        """
        if self.block_idx >= len(self.block_sequences):
            mask: torch.Tensor = torch.full_like(scores, float("-inf"))
            eos_id = getattr(self.tokenizer, "eos_token_id", None)
            if eos_id is not None:
                mask[:, eos_id] = 0.0
            result: torch.Tensor = scores + mask
            return result

        current_entries: List[List[int]] = self.block_sequences[
            self.block_idx
        ]
        current_seq: List[int] = current_entries[self.entry_idx]

        if self.token_idx >= len(current_seq):
            self.entry_idx += 1
            self.token_idx = 0
            if self.entry_idx >= len(current_entries):
                self.block_idx += 1
                self.entry_idx = 0
            return self.__call__(input_ids, scores)

        next_token: int = current_seq[self.token_idx]
        mask = torch.full_like(scores, float("-inf"))
        mask[:, next_token] = 0.0
        self.token_idx += 1
        result = scores + mask
        return result
