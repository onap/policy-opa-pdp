# ========================LICENSE_START=================================
# Copyright (C) 2025-2026: Deutsche Telekom
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
# SPDX-License-Identifier: Apache-2.0
# ========================LICENSE_END===================================

"""Constants file."""

from enum import Enum, IntEnum
from typing import Dict
import os


# --------------------Chatbot----------------------------
class AllowedOperation(str, Enum):
    """Operations currently supported."""

    EQUALS = "equals"
    NOT_EQUALS = "not equals"
    GREATER_THAN = "greater than"
    LESS_THAN = "less than"
    IN = "in"


class ChatStep(IntEnum):
    """Chatbot step identifiers."""

    INITIAL = 0
    LIST_USECASE = 1
    USECASE_SELECTED = 2
    VENDOR_SELECTED = 3
    PARAMETER_SELECTION_STEP = 4
    SELECT_FILTERED_MO = 5
    CONFIRM_PARAM_STEP = 6
    SELECT_OPERATOR = 7
    GENERATE_REGO = 8


STEP_RESET_MAP: Dict[ChatStep, tuple[str, ...]] = {
    ChatStep.INITIAL: (
        "usecase",
        "selected_usecase",
        "vendors",
        "vendor",
        "parameters",
        "confirmed_params",
        "current_matches",
        "current_search_terms",
        "pending_matches",
        "total_params_needed",
        "current_param_index",
    ),
    ChatStep.LIST_USECASE: (
        "selected_usecase",
        "vendors",
        "vendor",
        "parameters",
        "confirmed_params",
        "current_matches",
        "current_search_terms",
        "pending_matches",
    ),
    ChatStep.USECASE_SELECTED: (
        "vendor",
        "parameters",
        "confirmed_params",
        "current_matches",
        "current_search_terms",
        "pending_matches",
    ),
    ChatStep.VENDOR_SELECTED: (
        "parameters",
        "confirmed_params",
        "current_matches",
        "current_search_terms",
        "pending_matches",
        "total_params_needed",
    ),
    ChatStep.PARAMETER_SELECTION_STEP: (
        "parameters",
        "confirmed_params",
        "current_matches",
        "current_search_terms",
        "pending_matches",
    ),
    ChatStep.SELECT_FILTERED_MO: (
        "parameters",
        "confirmed_params",
        "current_matches",
        "current_search_terms",
        "current_param_index",
    ),
    ChatStep.CONFIRM_PARAM_STEP: (
        "parameters",
        "confirmed_params",
        "current_matches",
        "current_search_terms",
        "pending_matches",
        "current_param_index",
    ),
    ChatStep.SELECT_OPERATOR: (
        "current_param_index",
    ),
}

STEP_DEFAULT_MAP: dict[str, object] = {
    "usecase": [],
    "selected_usecase": "",
    "vendors": [],
    "vendor": None,
    "parameters": [],
    "confirmed_params": [],
    "current_matches": [],
    "current_search_terms": [],
    "pending_matches": [],
    "total_params_needed": 1,
    "current_param_index": 0,
}


# Step descriptions
step_descriptions: Dict[int, str] = {
    0: "initial query",
    1: "use case selection",
    2: "vendor selection",
    3: "motype selection",
    4: "parameter search",
    5: "parameter confirmation",
    6: "parameter list confirmation",
    7: "operator selection",
    8: "policy validation",
}

# ------------------------------------------------------------
# AAI Parser
AAI_XML_PATH = "./dataset/aai_oxm_v30.xml"
AAI_TARGET_TYPES = {"cell", "pnf"}
AAI_OUTPUT_EXCEL = "./dataset/AAI_hierarchy.xlsx"

# Streamlit UI
PAGE_TITLE = "Rego Policy Generator"
PAGE_ICON = "🧩"
PAGE_LAYOUT = "wide"
SIDEBAR_STATE = "expanded"

# OPA configuration
OPA_BINARY_NAME = "opa"
OPA_EXECUTABLE_PATH = "./opa"
OPA_DOWNLOAD_URL = "https://openpolicyagent.org/downloads/latest/opa_linux_amd64"

# ---------------- Streamlit UI ----------------

APP_HEADER = "Rego Policy Generator"
APP_SUBTEXT = "Generate secure OPA policies instantly"
APP_TITLE = "Rego policy generator chatbot"

INPUT_PLACEHOLDER = "Describe the policy you need..."

BUTTON_BACK = "Back"
BUTTON_RESTART = "Restart"

SPINNER_TEXT = "Generating response..."

SESSION_MESSAGES = "messages"
SESSION_PENDING_RESPONSE = "pending_response"
SESSION_CHATBOT = "chatbot_instance"

USER_AVATAR = "👤"
ASSISTANT_AVATAR = "✨"

REGO_REGEX = r"(package[\s\S]+?\})"

TYPING_DELAY = 0.05

# ---------------- Config ----------------

CONFIG_FILE_PATH = "./config/config.json"

# ---------------- Excel columns ----------------

COL_MANAGED_OBJECT = "ManagedObject"
COL_HIERARCHY_PATH = "HierarchicalPath"
COL_PARAM_SHORT_NAME = "ParameterShortName"
COL_PARAM_LONG_NAME = "ParameterLongName"

# ---------------- Regex ----------------

PATH_SPLIT_REGEX = r"[./]"
INDEX_REGEX_TEMPLATE = r"{}(\d+)$"

# ---------------- MO types ----------------

BASE_MO = ["ManagedElement", "interfaces", "NE"]

# ---------------- Metrics ----------------

METRIC_TOP_K = "top_k"
METRIC_MRR = "mrr"

# ---------------- Logging ----------------

LOG_SEPARATOR = "=" * 60
LOG_SUB_SEPARATOR = "-" * 40
LOG_FILE_PATH = os.getenv("LOG_FILE_PATH", "/opt/var/logs.log")

# -------- Embedding --------

EMBEDDING_MODEL = "all-MiniLM-L6-v2"

# -------- Excel columns --------

COL_PARAM_SHORT = "ParameterShortName"
COL_HIERARCHY_PATH = "HierarchicalPath"

# -------- Filtering --------

INVALID_PARAMETER_VALUES = ["$instance"]

# -------- FAISS --------

FAISS_INDEX_EXTENSION = ".faiss"

# -------- Config keys --------

CONFIG_VENDORS_KEY = "vendors"
# -------- Context Categories --------

CTX_AAI = "aai"
CTX_VENDOR = "vendor"
CTX_AAI_RELATION = "aai_relationship"
CTX_VENDOR_HIERARCHY = "vendor_hierarchy"

# -------- Default package --------

DEFAULT_PACKAGE_NAME = "parameterconsistencyfilter"

# -------- Managed object --------

MANAGED_ELEMENT = "ManagedElement"

# -------- Operator mapping --------

OPERATOR_MAP: Dict[str, str] = {
    "EQUALS": "==",
    "NOT EQUALS": "!=",
    "GREATER THAN": ">",
    "LESS THAN": "<",
    "GREATER THAN OR EQUALS": ">=",
    "LESS THAN OR EQUALS": "<=",
}

# -------- Output blocks --------

OUTPUT_HEADER = "header"
OUTPUT_BLOCK_END = "block_end"
# -------- Vendors --------
GENERIC_VENDOR = "Generic"

# -------- FAISS --------
FAISS_VENDOR_INDEX_PATH = "faiss_store/faiss_index_{vendor}_dataset.faiss"
FAISS_AAI_INDEX_PATH = "faiss_store/faiss_index_aai_dataset.faiss"

# -------- Excel columns --------
COL_PARAM_SHORT = "ParameterShortName"
COL_HIERARCHY_PATH = "HierarchicalPath"

# -------- Retrieval text template --------
ATTRIBUTE_PATH_TEMPLATE = "Attribute {attr} in HierarchicalPath {path}"

# -------- Reranking weights --------
RERANK_ALPHA = 0.5
EXACT_MATCH_BOOST = 0.2

# -------- Config keys --------
CONFIG_USECASE_INFO = "usecase_info"

# -------- Managed element --------
MANAGED_ELEMENT = "ManagedElement"

# -------- Operator mapping --------
OPERATOR_MAP = {
    "EQUALS": "==",
    "NOT EQUALS": "!=",
    "GREATER THAN": ">",
    "LESS THAN": "<",
    "GREATER THAN OR EQUALS": ">=",
    "LESS THAN OR EQUALS": "<=",
}

# -------- Vendor --------
GENERIC_VENDOR = "Generic"

# -------- Retrieval Evaluation --------
DEFAULT_SIMILARITY_THRESHOLD = 0.8
DEFAULT_TOP_K_VALUES = [1, 3, 5, 10]

# -------- Faithfulness weights --------
NAME_SCORE_WEIGHT = 0.5
MO_TYPE_SCORE_GENERIC = 0.5
MO_TYPE_SCORE_VENDOR = 0.25

# -------- Normalization --------
VENDOR_SCORE_NORMALIZATION = 0.75

# -------- Operator Mapping --------
EVAL_OPERATOR_MAP = {
    "equals": "==",
    "not equals": "!=",
    "greater than": ">",
    "less than": "<",
    "in": "in",
}
# ---------- Config ----------
CONFIG_PATH = "./config/config.json"
CONFIG_UNSLOTH_FLAG = "unsloth_run"

# ---------- Placeholder tokens ----------
PLACEHOLDER_START = "{{"
PLACEHOLDER_END = "}}"

# ---------- Models ----------
UNSLOTH_MODEL = "unsloth/mistral-7b-instruct-v0.3-bnb-4bit"
MISTRAL_MODEL = "mistralai/Mistral-7B-Instruct-v0.3"

# ---------- Model settings ----------
MAX_SEQ_LENGTH = 2048
MAX_NEW_TOKENS = 1024
MAX_BLOCK_TOKENS = 2000
MAX_CLASSIFICATION_TOKENS = 30

# ---------- Device ----------
CUDA_DEVICE = "cuda:0"
CUDA = "cuda"

# ---------- Generation ----------
GEN_TEMPERATURE = 0.0
GEN_TOP_K = 1
GEN_TOP_P = 1.0


SCORE_NAME_PRESENT = 0.5
SCORE_MOTYPE_GENERIC = 0.5
SCORE_MOTYPE_VENDOR = 0.25
SCORE_MISSING = 0.0

# ----UI Constants-------
MSG_INVALID_INPUT: str = "Please provide a valid input."
MSG_NOT_INITIALIZED: str = "Chatbot not initialized. Please initialize the chatbot first."
MSG_EMPTY_RESPONSE = "Error: Chatbot returned an empty response."
MSG_GENERIC_ERROR = "Error generating response. Please try again."
USER_AVATAR = "👤"
