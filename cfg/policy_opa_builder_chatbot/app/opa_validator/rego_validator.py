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

"""Utility module for downloading and validating the OPA binary."""

import subprocess  # nosec B404
from typing import Optional
from constants import (
    OPA_BINARY_NAME,
    OPA_EXECUTABLE_PATH,
    OPA_DOWNLOAD_URL
)
from libs.logs import Logger

logger = Logger.get(__name__)


class RegoValidator:
    """Validate and manage the Open Policy Agent (OPA) binary."""

    def setup_opa(self) -> None:
        """Download the OPA binary and make it executable."""
        logger.info("Downloading OPA...")

        subprocess.run(  # nosec B603 B607
            [
                "curl",
                "-L",
                "-o",
                OPA_BINARY_NAME,
                OPA_DOWNLOAD_URL,
            ],
            check=True,
        )

        subprocess.run(  # nosec B603 B607
            ["chmod", "+x", OPA_BINARY_NAME],
            check=True,
        )

        logger.debug("OPA downloaded and made executable.")

    def check_opa_version(self) -> None:
        """Check and print the installed OPA version."""
        logger.info("Checking OPA version...")

        result = subprocess.run(  # nosec B603 B607
            [OPA_EXECUTABLE_PATH, "version"],
            capture_output=True,
            text=True,
            check=True,
        )

        logger.info(result.stdout)

    def validate_rego(self, filepath: str) -> Optional[subprocess.CompletedProcess[str]]:
        """Validate a rego file using OPA."""
        try:
            result = subprocess.run(  # nosec B603 B607
                [OPA_EXECUTABLE_PATH, "check", filepath],
                capture_output=True,
                text=True,
                check=True,
            )
            return result

        except subprocess.CalledProcessError as exc:
            logger.error("OPA check failed: %s", exc.stderr)
            return None
