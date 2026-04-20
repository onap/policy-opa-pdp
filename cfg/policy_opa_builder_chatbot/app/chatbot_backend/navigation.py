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

from typing import Any, Tuple, Dict
from constants import (
     step_descriptions, ChatStep
)

class NavigationHandler:
    """Handles navigation and invalid input with user options."""

    def __init__(self, chatbot_instance: Any) -> None:
        """Initialize navigation handler and bind to chatbot state."""
        self.chatbot = chatbot_instance
        self.state = chatbot_instance.state

    def handle_invalid_input_with_navigation(self, context_message: str = "") -> str:
        """Handle invalid input with navigation options."""
        exceeded = self.state.increment_attempts()
        if exceeded or self.state.has_exceeded_max_attempts():
            return self.get_max_attempts_options()
        current_step_desc = step_descriptions.get(
            self.state.step, f"step {self.state.step}"
        )
        base_message = f"Invalid input for {current_step_desc}."
        # if context_message:
        #    base_message += f" {context_message}"
        navigation_options = (
            f"{base_message}\n\nOptions:\nTry again\n"
            " Type 'previous' to go back\n"
            " Type 'restart' to start over"
        )
        return navigation_options

    def get_max_attempts_options(self) -> str:
        """Get options when max attempts exceeded."""
        current_step = self.state.step
        message = "Too many invalid attempts.\n\nYour options:\n"

        if current_step > 0:
            message += (
                "'previous' - go back to "
                f"{step_descriptions.get(current_step - 1, 'previous step')}\n"
            )
        if current_step > 1:
            message += (
                "'back2' - go back to "
                f"{step_descriptions.get(current_step - 2, 'two steps back')}\n"
            )
        message += "'restart' - start completely over\n"
        return message

    def process_navigation_command(self, message: str) -> Tuple[bool, str]:
        """Process navigation commands. Returns (is_navigation_command, response)."""
        message_lower = message.strip().lower()

        if message_lower in ["help", "?"]:
            return True, self.get_help_for_current_step()

        elif message_lower in ["restart", "start over", "reset"]:
            self.chatbot.reset_conversation()
            return (
                True,
                "Restarted completely. Please describe what you need a Rego policy for:",
            )

        elif message_lower in ["previous", "back", "prev"]:
            return True, self.go_back_one_step()

        elif message_lower == "back2":
            return True, self.go_back_two_steps()

        return False, ""

    def go_back_one_step(self) -> str:
        """Go back one step."""
        current_step = self.state.step
        if current_step <= 0:
            return "Already at the beginning. Cannot go back further."
        target_step = current_step - 1
        if target_step == ChatStep.SELECT_FILTERED_MO:
            target_step = ChatStep.PARAMETER_SELECTION_STEP
        print(f"[DEBUG] Target step after back: {target_step}")
        return self.navigate_to_step(target_step)

    def go_back_two_steps(self) -> str:
        """Go back two steps."""
        current_step = self.state.step
        if current_step <= 1:
            return "Cannot go back two steps from here."
        target_step = max(0, current_step - 2)
        return self.navigate_to_step(target_step)

    def navigate_to_step(self, target_step: int) -> str:
        """Navigate to specific step."""
        self.state.step = target_step
        self.state.reset_to_step(target_step)
        print(f"[DEBUG] Step after reset: {self.state.step}")
        print(f"[DEBUG] parameters: {self.state.parameters}")
        print(f"[DEBUG] confirmed_params: {self.state.confirmed_params}")
        print(f"[DEBUG] current_param_index: {self.state.current_param_index}")
        print(f"[DEBUG] pending_matches: {self.state.pending_matches}")
        return self.get_prompt_for_step(target_step)

    def get_prompt_for_step(self, step: int) -> str:
        """Get appropriate prompt for a step."""
        prompts: Dict[int, str] = {
            0: (
                "Back to the beginning. Please describe what you need a Rego "
                "policy for:"
            ),
            1: (
                "Back to use case selection.\n"
                "Available use cases:\n"
                "{val}\n"
                "Select a use case:"
            ).format(
                val=(
                    self.chatbot.format_options_list(self.state.usecase)
                    if self.state.usecase
                    else "Please start with your query first."
                )
            ),
            2: (
                "Back to vendor selection.\n"
                "Available vendors:\n"
                "{val}\n"
                "Select a vendor:"
            ).format(
                val=(
                    self.chatbot.format_options_list(self.state.vendors)
                    if self.state.vendors
                    else "No vendors available."
                )
            ),
            3: (
                "Back to parameter search. Please enter at least 1 parameter name:"
            ),
            4: (
                "Back to parameter confirmation. Let me show you the current "
                "parameter options again..."
            ),
            5: (
                "Back to parameter selection.\n"
                "{val}\n"
                "Please select the one you want (enter the number), or type 'none' to skip:"
            ).format(
                val=(
                    self.chatbot.format_options_list(self.state.pending_matches)
                    if self.state.pending_matches
                    else "No options available. Please go back to parameter search."
                )

            ),
            6: (
                "Back to operator selection. Please select an operator for the current parameter."
            ),
        }

        return prompts.get(
            step,
            f"Returned to step {step}. Please continue from here.",
        )

    def get_help_for_current_step(self) -> str:
        """Get help for the current step."""
        step = self.state.step

        help_messages: Dict[int, str] = {
            0: (
                "Enter a description of what you need a Rego policy for.\n"
                "Example: 'I need a rego policy for kubernetes resource limits'"
            ),
            1: (
                "Select a use case by entering its number "
                f"(1 to {len(self.state.usecase) if self.state.usecase else 'N'})."
            ),
            2: (
                "Select a vendor by entering its number "
                f"(1 to {len(self.state.vendors) if self.state.vendors else 'N'}) "
                "or type the vendor name."
            ),
            3: (
                f"Enter {self.state.total_params_needed} parameter names separated by commas.\n"
                "Example: 'mcc, retrytimer'"
            ),
            4: "Respond with 'Yes'/'No' to confirm parameters, or select from numbered options.",
            5: "Respond with 'Yes' to proceed with the parameter list, or 'No' to modify it.",
            6: (
                "Select an operator by entering its number "
                f"(1 to {len(self.state.allowed_ops)})."
            ),
            7: "Type 'Yes' to validate and save the policy, or 'No' to start over.",
        }

        help_text = help_messages.get(step, "No specific help available.")
        help_text += "\n\nNavigation: 'previous', 'restart', or 'help'"
        return help_text
