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

from dataclasses import dataclass, field
from typing import Any, List, Optional, Dict
import  pandas as pd
import numpy as np
from constants import (
    AllowedOperation, ChatStep, GENERIC_VENDOR,
    STEP_RESET_MAP, STEP_DEFAULT_MAP
)


@dataclass
class ParameterConfig:
    """Configuration for a single parameter."""

    param_name: str
    distinguish_name: str
    mo_type: str
    value: str = ""
    operator: str = "equals"
    parameter_row: Any = None

    def __str__(self) -> str:
        """Return a human-readable summary of the parameter configuration."""
        return f"{self.param_name} ({self.mo_type})"

@dataclass
class ChatbotContext:
    """Manages chatbot conversation state with support for multiple parameters."""

    def __init__(self) -> None:
        """Initialize conversation state and multi-parameter tracking."""
        self._init_core_state()
        # Multi-parameter support
        self._multi_param_support()
        # Current parameter processing
        self._current_parameters_processing()
        # Single parameter backward compatibility
        self._init_single_parameter_state()

    def _init_core_state(self) -> None:
        self.step: int = 0
        self.usecase: List[Any] = []
        self.usecases: str = ""
        self.response_template: str = ""
        self.vendors: List[str] = []
        self.selected_vendor: str = GENERIC_VENDOR
        self.selected_usecase: str = ""
        self.mo_list: List[Any] = []
        self.selected_mo: str = ""
        self.selected_mo_path: Any = []
        self.matching_params: List[Any] = []
        self.selected_param: str = ""
        self.mo_type: str = ""
        self.mo_type_filter: Optional[str] = None
        self.data: pd.DataFrame
        self.managed_object: str = ""
        self.param_mo_combo: List[Any] = []
        self.invalid_attempts: int = 0
        self.max_attempts: int = 3
        self.category: str = "aai"
        self.filtered_df: pd.DataFrame = pd.DataFrame()

    def _current_parameters_processing(self) -> None:
        self.current_search_terms: List[str] = []
        self.current_matches: Dict[str, Any] = field(default_factory=dict)
        self.pending_matches: List[str] = []

    def _multi_param_support(self) -> None:
        self.parameters: List[ParameterConfig] = []
        self.current_param_index: int = 0
        self.total_params_needed: int = 1
        self.multi_param_mode: bool = False
        self.pending_params: List[Any] = []
        self.confirmed_params: List[Any] = []

    def _init_single_parameter_state(self) -> None:
        self.parameter_row: Any = None
        self.default_val: Any = None
        self.val: str = ""
        self.operation: str = "equals"
        self.allowed_ops = [op.value for op in AllowedOperation]
        self.context: str = ""
        self.generated_policy: str = ""
        self.retrieval_metrics: Dict[str, Any] = {}

    def reset_attempts(self) -> None:
        """Reset invalid attempts counter."""
        self.invalid_attempts = 0

    def increment_attempts(self) -> bool:
        """Increment invalid attempts counter."""
        self.invalid_attempts += 1
        return self.invalid_attempts >= self.max_attempts

    def has_exceeded_max_attempts(self) -> bool:
        """Check if maximum attempts have been exceeded."""
        return self.invalid_attempts >= self.max_attempts

    def add_parameter(
        self,
        param_name: str,
        distinguish_name: str,
        mo_type: str = "",
        value: str = "",
        operator: str = "equals",
        parameter_row: Any = None,
    ) -> None:
        """Add a parameter configuration."""
        param_config = ParameterConfig(
            param_name=param_name,
            distinguish_name=distinguish_name,
            mo_type=mo_type,
            value=value,
            operator=operator,
            parameter_row=parameter_row,
        )
        self.parameters.append(param_config)

    def get_current_parameter(self) -> Optional[ParameterConfig]:
        """Get the current parameter being processed."""
        if 0 <= self.current_param_index < len(self.parameters):
            return self.parameters[self.current_param_index]
        return None

    def has_more_parameters(self) -> bool:
        """Check if there are more parameters to process."""
        return self.current_param_index < len(self.parameters) - 1

    def reset_to_step(self, target_step: ChatStep) -> None:
        """Reset to a specific step, clearing relevant state."""
        self.step = target_step
        self.reset_attempts()

        for step, fields in STEP_RESET_MAP.items():
            if target_step <= step:
                for field_val in fields:
                    setattr(self, field_val, STEP_DEFAULT_MAP[field_val])


