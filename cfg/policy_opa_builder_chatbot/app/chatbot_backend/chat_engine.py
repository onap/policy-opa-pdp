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

"""core orchestration logic for the conversational chatbot workflow."""
from typing import Optional, List, Dict, Callable, Any
from constants import (
    ChatStep
)
from libs.logs import Logger

logger = Logger.get(__name__)


class ChatbotEngine:
    """Core engine for managing chatbot conversation flow and handler execution."""

    
    def __init__(self, controller):
        """
        Initialize the ChatbotEngine.

        Args:
            controller: The owning chatbot instance (MultiParameterChatbot)
                        that implements all step handlers and holds state.
        """
        self.controller = controller


    def chatbot_func(self, message: str, history: Optional[List[str]] = None) -> str:
        """Chatbot interactions."""
        if history is None:
            history = []

        message = message.strip()
        if not message:
            return "Please provide a valid input."

        try:
            is_nav, nav_response = self.controller.nav_handler.process_navigation_command(message)
        except Exception as e:
            logger.error(f"Navigation handler failed: {e}")
            is_nav, nav_response = False, ""

        if is_nav:
            return nav_response

        step_handlers: Dict[ChatStep, Callable[[str], Any]] = {
            ChatStep.INITIAL: self.controller._handle_step_0,
            ChatStep.LIST_USECASE: self.controller.process_usecase_number_selection,
            ChatStep.USECASE_SELECTED: self.controller.process_vendor_selection,
            ChatStep.VENDOR_SELECTED: self.controller.process_mo_selection,
            ChatStep.PARAMETER_SELECTION_STEP: self.controller.process_multiple_parameter_search,
            ChatStep.SELECT_FILTERED_MO: self.controller.process_parameter_confirmation,
            ChatStep.CONFIRM_PARAM_STEP: self.controller.process_parameter_list_confirmation,
            ChatStep.SELECT_OPERATOR: self.controller.process_operator_selection,
            ChatStep.GENERATE_REGO: self.controller.perform_opa_validation,
        }

        handler = step_handlers.get(ChatStep(self.controller.state.step))
        if handler:
            return str(handler(message))

        self.reset_conversation()
        return "Something went wrong. Let's start over. Please describe what you're looking for:"
