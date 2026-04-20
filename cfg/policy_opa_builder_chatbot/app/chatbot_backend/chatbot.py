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

"""Chatbot orchestration for parameter search, navigation, and Rego generation."""

import json
import os
import pandas as pd
import re
from typing import List, Tuple, Optional, Any, Dict, Callable, Hashable
from dataclasses import dataclass, field
from .chat_engine import ChatbotEngine
from .chat_context import ChatbotContext
from .navigation import NavigationHandler
from libs.utilities import (
    context_to_text,
    fetch_mo_from_path,
    print_generative_metrics,
    print_comprehensive_metrics,
    calculate_comprehensive_averages,
    get_config_value,
    find_parent_child,
)
from constants import (
    AllowedOperation, ChatStep, GENERIC_VENDOR,
    STEP_RESET_MAP, STEP_DEFAULT_MAP, step_descriptions
)
import numpy as np
from rag_pipeline.rag_multiparam import MultiParamRAGEvaluator
from rag_pipeline.rag_context_builder import ContextBuilder, transform_context
from libs.logs import Logger

logger = Logger.get(__name__)

class MultiParameterChatbot:
    """Enhanced chatbot for multiple parameter selection with improved error handling."""

    def __init__(
        self,
        faiss_obj: Any,
        rt_module: Any,
        dp_module: Any,
        val_module: Any,
        gen_rego_module: Optional[Any] = None,
    ) -> None:
        """Initialize retrieval, data providers, generators, and state."""
        self.faiss_obj = faiss_obj
        self.rt = rt_module
        self.dp = dp_module
        self.val = val_module
        self.gen_rego = gen_rego_module
        self.state = ChatbotContext()
        self.build_context = ContextBuilder()
        self.nav_handler = NavigationHandler(self)
        self.evaluator = MultiParamRAGEvaluator(self.state, self.dp)
        self.filtered_df: pd.DataFrame = pd.DataFrame()
        self.engine = ChatbotEngine(self)

    
    def chatbot_func(self, message: str, history=None) -> str:
        """Public API for chat interaction."""
        return self.engine.chatbot_func(message, history)


    def search_parameters(
        self, vendor_dataset: Any, partial_param: str
    ) -> List[Dict[Hashable, Any]]:
        """Search parameters in the Excel data for a partial match."""
        self.filtered_df = vendor_dataset
        matching_df = self.filtered_df[
            self.filtered_df["ParameterShortName"].str.contains(
                partial_param, case=False, na=False
            )
        ]

        result: List[Dict[Hashable, Any]] = matching_df[
            ["ParameterShortName", "ManagedObject", "HierarchicalPath", "Range"]
        ].to_dict(orient="records")
        return result

    def handle_invalid_input(self, context_message: str = "") -> str:
        """Enhanced invalid input handler with navigation options."""
        return self.nav_handler.handle_invalid_input_with_navigation(context_message)

    def reset_conversation(self) -> None:
        """Reset conversation to beginning."""
        self.state = ChatbotContext()
        self.nav_handler = NavigationHandler(self)
        self.build_context = ContextBuilder()
        self.evaluator = MultiParamRAGEvaluator(self.state, self.dp)

    def validate_number_selection(
        self, message: str, max_value: int
    ) -> Tuple[bool, Optional[int]]:
        """Validate number selection input."""
        try:
            selected_number = int(message.strip())
            if 1 <= selected_number <= max_value:
                return True, selected_number
            return False, None
        except ValueError:
            return False, None

    def format_options_list(self, items: List[str], start_index: int = 1) -> str:
        """Format a list of items with numbered options."""
        return "\n".join([f"{i + start_index}. {item}" for i, item in enumerate(items)])

    def process_usecase_selection(self, message: str) -> str:
        """Process initial usecase retrieval."""
        try:
            logger.info(f"Processing message: {message}")
            usecase = self.rt.retrieve_usecase()
            if not usecase:
                return self.handle_invalid_input(
                    "No usecases found for your query. "
                    "Please try describing your needs differently."
                )

            self.state.usecase = usecase
            self.state.usecases = self.format_options_list(usecase)
            self.state.step = ChatStep.LIST_USECASE
            self.state.reset_attempts()
            return (
                f"We've following use cases, please specify the use case for which "
                "rego policy has to be generated?\n"
                f"{self.state.usecases}"
            )
        except Exception as e:
            logger.error(f"Error in process_usecase_selection: {e}")
            return "An error occurred while retrieving usecases. Please try again."

    def process_usecase_number_selection(self, message: str) -> str:
        """Process usecase number selection."""
        is_valid, selected_number = self.validate_number_selection(
            message, len(self.state.usecase)
        )

        if not is_valid:
            context = f"Please enter a number between 1 and {len(self.state.usecase)}."
            return self.handle_invalid_input(context)

        try:
            if selected_number is None:
                return self.handle_invalid_input("Invalid selection")

            selected_usecase = self.state.usecase[selected_number - 1]
            self.state.selected_usecase = selected_usecase
            self.state.step = ChatStep.USECASE_SELECTED

            # Prepare vendors list
            vendors_array = self.dp.get_all_vendors()
            vendors_array = np.insert(vendors_array, 0, "Generic")
            vendors: list[str] = vendors_array.tolist()
            self.state.vendors = vendors

            if not vendors:
                return "No vendors available from dataset."

            options = self.format_options_list(vendors)
            return (
                "Please let me know if you want the parameter for any specific vendors:\n"
                f"{options}"
            )

        except Exception as e:
            logger.error(f"Error in process_usecase_number_selection: {e}")
            return (
                "An error occurred while processing your selection. Please try again."
            )

    def process_vendor_selection(self, message: str) -> str:
        """Process vendor selection.

        Args:
                message (str): The user input message.

        Returns:
                str: Response based on vendor selection.
        """
        vendor = self._get_vendor_from_input(message)
        if vendor:
            return self._handle_vendor_selected(vendor)

        context = (
            f"Please enter a number between 1 and {len(self.state.vendors)} "
            "or type the exact vendor name."
        )
        return self.handle_invalid_input(context)

    def _get_vendor_from_input(self, message: str) -> Optional[str]:
        """Get vendor from input message.

        Args:
            message (str): User input.

        Returns:
            Optional[str]: Vendor name if valid, else None.
        """
        vendor_name = message.strip()
        for v in self.state.vendors:
            if v.lower() == vendor_name.lower():
                return v

        is_valid, selected_number = self.validate_number_selection(
            message, len(self.state.vendors)
        )
        if is_valid and selected_number is not None:
            try:
                return self.state.vendors[selected_number - 1]
            except IndexError:
                return None
        return None

    def _handle_vendor_selected(self, vendor: str) -> str:
        """Handle vendor selection logic.

        Args:
            vendor (str): Selected vendor.

        Returns:
            str: Response based on MO type filter.
        """
        self.state.selected_vendor = vendor
        self.state.step = ChatStep.VENDOR_SELECTED
        self.state.reset_attempts()
        self.set_category()
        self.set_vendor_dataset()
        if self.state.mo_type_filter is None or self.state.mo_type_filter == "None":
            self.state.step = ChatStep.PARAMETER_SELECTION_STEP
            return self._ask_for_parameters()
        return self._handle_mo_filter()

    def _handle_mo_filter(self) -> str:
        """Handle MO type filter logic.

        Returns:
            str: Response for MO selection.
        """
        self.state.mo_list = self.fetch_all_mos()
        if not self.state.mo_list:
            self.state.step = ChatStep.PARAMETER_SELECTION_STEP
            self.state.mo_type_filter = "None"
            return (
                f"No MOs found matching '{self.state.managed_object}'.\n"
                f"{self._ask_for_parameters()}"
            )
        if len(self.state.mo_list) == 1:
            return (
                f"I found one HierarchicalPath:\n{self.state.mo_list[0]} "
                f"\nmatching '{self.state.mo_type_filter}'\n"
                "\nPlease enter 1 to select this MO"
            )
        return self._format_multiple_mos()

    def _format_multiple_mos(self) -> str:
        """Format multiple MOs for selection.

        Returns:
            str: Formatted options string.
        """
        options = "\n".join(f"{idx + 1}. {match}" for idx, match in enumerate(self.state.mo_list))
        return (
            f"I found multiple MOs matching '{self.state.mo_type_filter}':\n"
            f"{options}\n"
            "Please select the one you want (enter the number), or type 'none' to skip:"
        )

    def _ask_for_parameters(self) -> str:
        """Ask user to input parameters.

        Returns:
            str: Instruction for parameter input.
        """
        return (
            "Please type the parameter names separated by commas "
            "(e.g., mcc, mnc).\nI'll search for all parameters."
        )

    def set_vendor_dataset(self) -> None:
        """Set state.data based on vendor selection."""
        if self.state.selected_vendor != "Generic":
            self.state.data = self.faiss_obj.vendor_dataset[self.state.selected_vendor]
        else:
            self.state.data = self.faiss_obj.aai_data

    def fetch_all_mos(self) -> List[str]:
        """Fetch all MOs matching the current MO type filter.

        Returns:
            List[str]: List of HierarchicalPaths.
        """
        if not self.state.mo_type_filter or self.state.data is None:
            return []
        mo_obj = self.state.mo_type_filter.lower()
        mask = self.state.data["ManagedObject"].str.lower().str.contains(mo_obj, na=False)
        paths = (
            self.state.data.loc[mask, "HierarchicalPath"]
            .drop_duplicates()
        )
        return [str(path) for path in paths]

    def process_mo_selection(self, message: str) -> Optional[str]:
        """Process MO selection input from user.

        Args:
            message (str): User input message.

        Returns:
            Optional[str]: Response message or None on error.
        """
        is_valid, selected_number = self.validate_number_selection(
            message, len(self.state.mo_list)
        )
        if not is_valid:
            context = f"Please enter a number between 1 and {len(self.state.usecase)}."
            return self.handle_invalid_input(context)
        try:
            if selected_number is None:
                return self.handle_invalid_input("Invalid selection")
            try:
                selected_mo_path = self.state.mo_list[selected_number - 1]
                self.state.selected_mo_path = selected_mo_path
                if selected_mo_path is not None:
                    mo = fetch_mo_from_path(self.state.data, selected_mo_path)
                    if mo is not None:
                        self.state.selected_mo = mo
                self.state.step = ChatStep.PARAMETER_SELECTION_STEP
                return self._ask_for_parameters()
            except IndexError as e:
                logger.warning("Selected MO index out of range: %s - %s", selected_number, e)
                return self.handle_invalid_input(
                    f"Number {selected_number} is not valid. Please select a valid number."
                )
        except Exception as e:
            logger.warning("Error in MO selection: %s", e)
            return None

    def set_category(self) -> None:
        """Set category based on vendor selection."""
        if self.state.selected_vendor != "Generic":
            logger.info("----Category set to Vendor----")
            self.state.category = "vendor"
        else:
            logger.info("----Category set to AAI----")
            self.state.category = "aai"
        logger.info("Category set to %s", self.state.category)

    def process_multiple_parameter_search(self, message: str) -> str:
        """
        Process a search for multiple parameters given a comma-separated message.

        Steps:
        1. Parse the input message into search terms.
        2. Search for each term in the DataFrame.
        3. Apply vendor-specific or generic logic.
        4. Filter results by MO type if applicable.
        5. Initialize state for sequential confirmation.

        Args:
            message (str): Comma-separated parameter names.

        Returns:
            str: Response message for the user.
        """
        try:
            search_terms: List[str] = self._parse_search_terms(message)
            if not search_terms:
                return f"No valid search terms provided.\n{self.handle_invalid_input()}"

            self._reset_search_state(search_terms)

            all_results: List[str] = self._search_terms(search_terms)
            if not all_results:
                return (
                    "No matching parameters found for any of the search terms.\n"
                    "Please try different parameter names.\n"
                    f"{self.handle_invalid_input()}"
                )
            if self.state.selected_vendor != "Generic":
                all_results = self._filter_results_by_mo_type(all_results)
            if not all_results:
                return (
                    f"No matching parameters found for {message}"
                    "under MO {self.state.selected_mo}\n"
                    "Please try different parameter names.\n"
                    "or go back to previous step and select different mo type.\n"
                )
            self.state.current_param_index = 0
            self.state.step = ChatStep.SELECT_FILTERED_MO
            return self.get_next_parameter_confirmation()

        except Exception as e:
            logger.error("Error in process_multiple_parameter_search: %s", e, exc_info=True)
            return "Error during parameter search. Please try again."

    def _parse_search_terms(self, message: str) -> List[str]:
        """Split input by commas and remove empty terms."""
        return [term.strip() for term in message.split(",") if term.strip()]

    def _reset_search_state(self, search_terms: List[str]) -> None:
        """Reset state variables before starting a new multi-parameter search."""
        self.state.total_params_needed = len(search_terms)
        self.state.current_search_terms = search_terms
        self.state.current_matches = {}

    def _search_terms(self, search_terms: List[str]) -> List[str]:
        """
        Search each term in the DataFrame and return formatted result strings.

        Handles vendor-specific vs Generic logic, deduplicates results,
        and stores entries in `self.state.current_matches`.

        Args:
            search_terms (List[str]): List of search terms entered by the user.

        Returns:
            List[str]: Formatted strings representing matching parameter entries.
        """
        all_results: List[str] = []
        seen_keys: set[str] = set()
        df = self.state.data  # type: pd.DataFrame
        vendor: str = self.state.selected_vendor

        for term in search_terms:
            matches: List[Dict[Hashable, Any]] = self.search_parameters(df, term)
            if not matches:
                continue

            for match in matches:
                key, match_entry, display_str = self._prepare_match_entry(match, term, vendor)
                if key not in seen_keys:
                    seen_keys.add(key)
                    # store the actual match entry in state
                    self.state.current_matches[key] = match_entry
                    all_results.append(display_str)
                else:
                    logger.debug("Skipped duplicate key: %s", key)

        return all_results

    def _prepare_match_entry(
            self, match: Dict[Hashable, Any], term: str, vendor: str
    ) -> Tuple[str, Dict[str, Any], str]:
        """
        Prepare the entry and display string for a matched parameter.

        Returns:
            key (str): Unique key for this match.
            match_entry (dict): Dictionary to store in current_matches.
            display_str (str): String to show the user.
        """
        mo = match.get("ManagedObject", "UnknownMO")
        param = match.get("ParameterShortName", "UnknownParam")
        hierarchical_path = match.get("HierarchicalPath", "DefaultDN")

        key = f"{hierarchical_path}.{param}"
        entry: Dict[str, Any] = {
            "param": param,
            "distinguish_name": hierarchical_path,
            "mo_type": mo,
            "search_term": term,
        }
        if vendor != "Generic":
            entry["range"] = match.get("Range")

        display_str = f"{hierarchical_path}.{param} - matching '{term}'"
        return key, entry, display_str

    def _filter_results_by_mo_type(
        self, all_results: List[str]
    ) -> List[str]:
        """Apply MO type filtering if `mo_type_filter` is set in state."""
        if getattr(self.state, "mo_type_filter", None) and self.state.mo_type_filter != "None":
            filtered_results = self.filter_by_mo_hierarchy(
                all_results,
                self.state.selected_mo or "",
            )
            if not filtered_results:
                return []

            filtered_matches: Dict[str, Dict[str, Any]] = {}
            for key in filtered_results:
                clean_key = key.split(" - matching")[0].strip()
                if clean_key in self.state.current_matches:
                    filtered_matches[clean_key] = self.state.current_matches[clean_key]
            self.state.current_matches = filtered_matches
            return filtered_results

        return all_results

    def filter_by_mo_hierarchy(self, all_matches: List[str], user_mo_type: str) -> List[str]:
        """Filter matches to show only attributes that are part of the given MO's hierarchy."""
        if not user_mo_type:
            return all_matches
        filtered: List[str] = []
        for match in all_matches:
            clean_match = match.split(" - matching")[0].strip()
            path_parts = clean_match.split(".")
            parent_path, child_path = find_parent_child(
                self.state.selected_mo_path, path_parts[0]
            )
            if parent_path and child_path is not None:
                filtered.append(match)
        return filtered

    def get_next_parameter_confirmation(self) -> str:
        """Get confirmation for the next parameter."""
        search_terms = self.state.current_search_terms
        if self.state.current_param_index >= len(search_terms):
            return self.show_parameter_summary()

        current_term = search_terms[self.state.current_param_index]
        matches_for_term = [
            key
            for key, value in self.state.current_matches.items()
            if value["search_term"] == current_term
        ]

        if not matches_for_term:
            self.state.current_param_index += 1
            return (
                f"No matches found for '{current_term}'. "
                "Skipping to next parameter.\n\n"
                f"{self.get_next_parameter_confirmation()}"
            )

        self.state.pending_matches = matches_for_term

        if len(matches_for_term) == 1:
            match_key = matches_for_term[0]
            match_info = self.state.current_matches[match_key]
            return (
                f"I found {match_info['param']} "
                f"({match_info['distinguish_name']}) "
                f"matching '{current_term}'. "
                "Do you want to select this parameter? (Yes/No):"
            )
        else:
            options = "\n".join(
                f"{idx + 1}. {match}"
                for idx, match in enumerate(matches_for_term)
            )
            return (
                f"I found multiple parameters matching '{current_term}':\n{options}\n"
                f"\n\nPlease select the one you want (enter the number), or type 'none' to skip:"
            )

    def process_parameter_confirmation(self, message: str) -> str:
        """Process user's confirmation (Yes/No or numbered selection)."""
        try:
            message_lower = message.strip().lower()
            # Single match case expecting Yes/No
            if len(self.state.pending_matches) == 1:
                match_key = self.state.pending_matches[0]
                match_info = self.state.current_matches[match_key]

                if message_lower == "yes":
                    self.state.confirmed_params.append(match_info)
                elif message_lower == "no":
                    return self.show_parameter_summary()
                    #  return self.handle_invalid_input(
                    #      "Please respond with 'Yes' to confirm or 'No' to skip this parameter."
                    #  )

                self.state.current_param_index += 1
                self.state.pending_matches = []
                self.state.reset_attempts()
                return self.get_next_parameter_confirmation()

            # Multiple match case expecting number or 'none'
            if message_lower == "none":
                self.state.current_param_index += 1
                self.state.pending_matches = []
                self.state.reset_attempts()
                return self.get_next_parameter_confirmation()

            try:
                selection = int(message.strip())
                if 1 <= selection <= len(self.state.pending_matches):
                    match_key = self.state.pending_matches[selection - 1]
                    match_info = self.state.current_matches[match_key]
                    self.state.confirmed_params.append(match_info)
                    self.state.current_param_index += 1
                    self.state.pending_matches = []
                    self.state.reset_attempts()
                    return self.get_next_parameter_confirmation()
            except ValueError:
                pass

            context = (
                f"Please enter a number between 1 and {len(self.state.pending_matches)}, "
                "or type 'none' to skip."
            )
            return self.handle_invalid_input(context)

        except Exception as e:
            logger.error(f"Error in process_parameter_confirmation: {e}")
            return self.handle_invalid_input()

    def show_parameter_summary(self) -> str:
        """Show summary of selected parameters."""
        if not self.state.confirmed_params:
            # Enforce at least one parameter rule
            self.state.step = ChatStep.PARAMETER_SELECTION_STEP
            self.state.current_param_index = 0
            self.state.current_matches = {}
            self.state.pending_matches = []
            self.state.reset_attempts()
            return (
                "At least one parameter must be selected.\n\n"
                "Please type part of the parameter names separated by commas "
                "(e.g., mcc, retrytimer):"
            )
#            return self.handle_invalid_input(
#                "No parameters were selected. Please try the parameter search again."
#            )

        param_list = "\n\n".join(
            f"  {p['param']} ({p['distinguish_name']})" for p in self.state.confirmed_params
        )
        self.state.step = ChatStep.CONFIRM_PARAM_STEP
        self.state.reset_attempts()
        return (
            "Following are the list of parameters to be used:\n"
            f"\n{param_list}\n\n"
            "Please check if this list is fine (Yes/No):"
        )

    def process_parameter_list_confirmation(self, message: str) -> str:
        """Process confirmation of the parameter list."""
        message_lower = message.strip().lower()
        if message_lower == "yes":
            self.state.current_param_index = 0
            for param_info in self.state.confirmed_params:
                self.state.add_parameter(
                    param_name=param_info["param"],
                    distinguish_name=param_info["distinguish_name"],
                    mo_type=param_info.get("mo_type", ""),
                )
            if (
                self.state.mo_type_filter != "None"
                and param_info["mo_type"].lower()
                != self.state.selected_mo.lower()
            ):
                if self.state.selected_vendor == "Generic":
                    logger.info("----Category set to aai_relation----")
                    self.state.category = "aai_relation"
                else:
                    logger.info("----Category set to vendor_hierarchy----")
                    self.state.category = "vendor_hierarchy"
            self.state.step = ChatStep.SELECT_OPERATOR
            return self.request_next_operator()

        elif message_lower == "no":
            self.state.step = ChatStep.PARAMETER_SELECTION_STEP
            self.state.confirmed_params = []
            self.state.current_matches = {}
            self.state.current_param_index = 0
            return (
                "Let's select parameters again. Please type part of the parameter names "
                "separated by commas (e.g., mcc, retrytimer):"
            )

        return self.handle_invalid_input(
            "Please respond with 'Yes' to confirm or 'No' to select parameters again."
        )

    def request_next_operator(self) -> str:
        """Request operator for the next parameter."""
        if self.state.current_param_index >= len(self.state.parameters):
            return self.generate_rego_policy()

        param = self.state.parameters[self.state.current_param_index]
        operators = self.format_options_list(self.state.allowed_ops)
        return (
            f"Please enter the operator you want to apply for {param.param_name} "
            f"in {param.mo_type} MOType:\n{operators}"
        )

    def process_operator_selection(self, message: str) -> str:
        """Process operator selection for current parameter."""
        is_valid, selected_number = self.validate_number_selection(
            message, len(self.state.allowed_ops)
        )
        if not is_valid or selected_number is None:
            context = f"Please enter a number between 1 and {len(self.state.allowed_ops)}."
            return self.handle_invalid_input(context)

        selected_op = self.state.allowed_ops[selected_number - 1]
        param = self.state.parameters[self.state.current_param_index]
        param.operator = selected_op
        self.state.current_param_index += 1

        if self.state.current_param_index < len(self.state.parameters):
            return self.request_next_operator()

        self.state.current_param_index = 0
        self.state.step = ChatStep.GENERATE_REGO
        return self.generate_rego_policy()

    def generate_rego_policy(self) -> str:
        """Generate Rego policy based on selected parameters and retrieval."""
        try:
            contexts, retrieval_metrics = self._create_contexts()
            context_text = transform_context(contexts,
                                             self.state.category, self.state.selected_vendor)
            template_file = get_config_value("template_file")
            if self.gen_rego is None:
                raise ValueError("gen rego module must be provided")
            generated_policy = self.gen_rego.generate_rego_tokenized(context_text, template_file)
            logger.info("----Generated rego policy is----: %s", generated_policy)

            self._evaluate_generation_metrics(
                generated_policy,
                contexts,
                retrieval_metrics,
            )
            self.state.generated_policy = generated_policy
            self.state.retrieval_metrics = retrieval_metrics
            self.state.step = 8
            return (
                f"{generated_policy}\n\n"
                "Please enter 'Yes' to save the rego code "
                "& validate with OPA binary"
            )
        except Exception as e:
            logger.exception(f"Error in generate_rego_policy: {e}")
            return f"Error generating policy: {str(e)}"

    def _create_contexts(self) -> Tuple[List[Any], Dict[str, Dict[str, float]]]:
        """Create contexts for all parameters and compute retrieval metrics."""
        contexts: List[str] = []
        context_dict: Dict[str, Any] = {}
        ret_metrics: Dict[str, Any] = {}

        for param in self.state.parameters:
            query = (
                f"Attribute {param.param_name} "
                f"in HierarchicalPath {param.distinguish_name}"
            )
            retrieved_rows = self.rt.retrieve_row(
                query,
                self.state.selected_vendor,
                self.state.data,
                top_k=5,
            )
            retrieved_contexts: List[str] = []
            retrieved_contexts_text: List[str] = []
            best_contexts: List[Any] = []
            for _, row in retrieved_rows.iterrows():
                retrieval_context = self.build_context.create_base_fields(
                    row,
                    param.operator,
                    self.state.category,
                    self.state.selected_mo,
                )
                context_text = context_to_text(
                    retrieval_context,
                )
                retrieved_contexts_text.append(context_text)
                retrieved_contexts.append(retrieval_context)
            eval_results = self.evaluator.evaluate_retrieval(
                query,
                retrieved_contexts_text,
                k_values=[1, 3, 5],
                threshold=0.8
            )
            best_contexts.append(retrieved_contexts[0])
            context = self.build_context.create_context(
                self.filtered_df,
                best_contexts[0],
                self.state.selected_vendor,
                self.state.category,
                self.state.selected_mo,
                self.state.selected_mo_path,
            )
            logger.info("----context is----", context)
            context_dict[param.param_name] = context
            ret_metrics[param.param_name] = {
                "top_1_accuracy": eval_results.get("Top_1_Accuracy", 0.0),
                "top_3_accuracy": eval_results.get("Top_3_Accuracy", 0.0),
                "mrr": eval_results.get("MRR", 0.0),
            }
            contexts.append(context)
        return contexts, ret_metrics

    def _evaluate_generation_metrics(
        self,
        generated_policy: str,
        contexts: List[Any],
        retrieval_metrics: Dict[str, Dict[str, float]],
    ) -> None:
        """Evaluate generation quality and print/log metrics."""
        gen_metrics_results, faith_per_param, rel_per_param = (
            self.evaluator.evaluate_generation(generated_policy, contexts)
        )
        # Calculate comprehensive averages (uncomment when metrics are available)
        avg_metrics = calculate_comprehensive_averages(retrieval_metrics)

        # Print comprehensive results (uncomment when metrics are available)
        print_comprehensive_metrics(retrieval_metrics, avg_metrics)
        print_generative_metrics(
            gen_metrics_results, faith_per_param, rel_per_param, self.state.selected_vendor
        )

    def perform_opa_validation(self, message: str) -> str:
        """Validate generated Rego policy using OPA."""
        message_lower = message.strip().lower()
        if message_lower != "yes":
            self.reset_conversation()
            return "Please start over for another policy generation. Type 'restart' to start."
        file_name = self.write_to_file()
        result = self.val.validate_rego(file_name)
        self.reset_conversation()
        if result.returncode == 0:
            return (
                "Rego policy generated is valid.\n"
                "Please start over for another policy generation."
            )
        else:
            logger.error("Error from OPA binary: %s", result.stderr)
            error_message = result.stderr.strip()
            return (
                "Validation failed:\n"
                f"{error_message}\n"
                "Please start over for another policy generation."
            )

    def write_to_file(self) -> str:
        """Write generated policy to file."""
        lines = self.state.generated_policy.split("\n")
        start_index = next(
            (
                i
                for i, line in enumerate(lines)
                if line.strip().startswith("package")
            ),
            None,
        )

        if start_index is not None:
            end_index = next(
                (
                    i + 1
                    for i, line in enumerate(
                        lines[start_index + 1:],
                        start_index + 1,
                    )
                    if "}" in line
                ),
                len(lines),
            )

            rego_policy = "\n".join(lines[start_index:end_index])

            package_match = re.search(
                r"package\s+([^\s]+)",
                lines[start_index],
            )

            if package_match:
                filename = (
                    f"{package_match.group(1).replace('.', '_')}.rego"
                )
            else:
                filename = "default_policy.rego"
        else:
            rego_policy = ""
            filename = "default_policy.rego"

        dir_path = get_config_value("rego_policy_dir")
        # Create directory if it does not exist
        os.makedirs(dir_path, exist_ok=True)

        filepath = os.path.join(dir_path, filename)
        with open(filepath, "w") as file:
            file.write(rego_policy)
        return filepath

    def _handle_step_0(self, message: str) -> str:
        """Step 0: classify user query using LLM."""
        if self.gen_rego is None:
            raise ValueError("gen rego module must be provided")
        classification_result = self.gen_rego.classify_query(message)
        try:
            classification_result = json.loads(classification_result)
        except json.JSONDecodeError:
            return self.handle_invalid_input("Could not classify your query. Please try again.")
        logger.info("Classification result", classification_result)
        self.state.mo_type_filter = classification_result.get("object")
        self.state.category = classification_result.get("category")
        self.state.managed_object = classification_result.get("object")

        if self.state.category == "rego":
            return self.process_usecase_selection(message)

        return self.handle_invalid_input("Currently I can only help with rego related policies")
