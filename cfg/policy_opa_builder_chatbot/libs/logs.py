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

import logging
import os
import warnings
from typing import Any
from constants import LOG_FILE_PATH

# -------------------------
# Custom TRACE level
# -------------------------
TRACE_LEVEL = 5
logging.addLevelName(TRACE_LEVEL, "TRACE")
log_dir=os.path.dirname(LOG_FILE_PATH)

class CustomLogger(logging.Logger):
    """
    Custom Logger class that supports TRACE level logging.
    """

    def trace(self, message: str, *args: Any, **kwargs: Any) -> None:
        """
        Log a message with TRACE severity level.
        """
        if self.isEnabledFor(TRACE_LEVEL):
            self._log(TRACE_LEVEL, message, args, **kwargs)


# Register the custom logger class globally
logging.setLoggerClass(CustomLogger)


# -------------------------
# Central Logger Utility
# -------------------------
class Logger:
    """
    Factory for getting configured loggers with a standard format and level.
    """

    @staticmethod
    def _get_log_level() -> int:
        """
        Get log level from environment variable LOG_LEVEL.
        Defaults to INFO if not set or invalid.
        """
        level_str = os.getenv("LOG_LEVEL", "INFO").upper()
        return {
            "TRACE": TRACE_LEVEL,
            "DEBUG": logging.DEBUG,
            "INFO": logging.INFO,
            "WARN": logging.WARNING,
            "WARNING": logging.WARNING,
            "ERROR": logging.ERROR,
            "CRITICAL": logging.CRITICAL,
        }.get(level_str, logging.INFO)

    @staticmethod
    def get(name: str) -> CustomLogger:
        """
        Get a logger instance with the given name, configured with stream handler.

        Args:
            name (str): Logger name.

        Returns:
            CustomLogger: Configured logger instance.
        """
        global LOG_FILE_PATH
        logger = logging.getLogger(name)
        if not isinstance(logger, CustomLogger):
            # fallback: wrap in CustomLogger or issue a warning
            import warnings
            warnings.warn(f"Logger is not a CustomLogger, got {type(logger).__name__}")
            logger = CustomLogger(logger.name)  # optional: wrap standard logger

        if not logger.handlers:
            logger.setLevel(Logger._get_log_level())
            #os.makedirs("/opt/var/", exist_ok=True)
            console_handler = logging.StreamHandler()
            console_handler.setLevel(logging.INFO)
            if not os.path.exists(log_dir):
                try:

                    # This creates /opt/var/ if it doesn't exist
                    os.makedirs(log_dir, exist_ok=True)
                except Exception as e:
                    LOG_FILE_PATH="logs.log"
            file_handler = logging.FileHandler(LOG_FILE_PATH)
            file_handler.setLevel(Logger._get_log_level())
            
            formatter = logging.Formatter(
                "%(asctime)s | %(levelname)s | %(name)s | %(message)s"
            )
            file_handler.setFormatter(formatter)
            console_handler.setFormatter(formatter)
            logger.addHandler(file_handler)
            logger.addHandler(console_handler)
            logger.propagate = False

        return logger
    if __name__ == "__main__":
        # Get the logger instance
        my_logger = Logger.get("TestApp")

        # Write a test message
        my_logger.info("Hello! If you see this, the file was created successfully.")
