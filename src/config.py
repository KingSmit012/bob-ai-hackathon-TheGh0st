"""
config.py — Central configuration for the Threat Intel Correlation Assistant.

All tuneable parameters live here. Values come from environment variables
(via a .env file) with sensible defaults so the tool works out-of-the-box
for development/demo purposes.
"""

import os
from dotenv import load_dotenv

# Load .env file from the src/ directory (or parent).
# This lets you set secrets like API keys without hardcoding them.
load_dotenv()

# =============================================================================
# LLM PROVIDER SETTINGS
# =============================================================================
# Which LLM provider to use: "watsonx" or "anthropic"
LLM_PROVIDER = os.getenv("LLM_PROVIDER", "watsonx")

# --- IBM watsonx.ai ---
WATSONX_API_KEY = os.getenv("WATSONX_API_KEY", "")
WATSONX_PROJECT_ID = os.getenv("WATSONX_PROJECT_ID", "")
WATSONX_URL = os.getenv("WATSONX_URL", "https://us-south.ml.cloud.ibm.com")
# Model to use on watsonx — Granite is a good default for instruction-following
WATSONX_MODEL_ID = os.getenv("WATSONX_MODEL_ID", "ibm/granite-13b-instruct-v2")

# --- Anthropic (fallback) ---
ANTHROPIC_API_KEY = os.getenv("ANTHROPIC_API_KEY", "")
ANTHROPIC_MODEL = os.getenv("ANTHROPIC_MODEL", "claude-sonnet-4-20250514")

# =============================================================================
# CORRELATION SETTINGS
# =============================================================================
# Time window (in minutes) within which alerts sharing an IP pair or
# destination asset are merged into one incident.
CORRELATION_TIME_WINDOW_MINUTES = int(
    os.getenv("CORRELATION_TIME_WINDOW_MINUTES", "30")
)

# =============================================================================
# PRIORITISATION WEIGHTS
# =============================================================================
# These weights control how the final priority score is computed.
# They should sum to 1.0 (but the code normalises anyway).
WEIGHT_SEVERITY = float(os.getenv("WEIGHT_SEVERITY", "0.35"))
WEIGHT_CONFIDENCE = float(os.getenv("WEIGHT_CONFIDENCE", "0.25"))
WEIGHT_ASSET_CRITICALITY = float(os.getenv("WEIGHT_ASSET_CRITICALITY", "0.25"))
WEIGHT_ALERT_DENSITY = float(os.getenv("WEIGHT_ALERT_DENSITY", "0.15"))

# =============================================================================
# FILE PATHS (relative to src/ directory)
# =============================================================================
DATA_DIR = os.path.join(os.path.dirname(__file__), "data")
SYNTHETIC_ALERTS_FILE = os.path.join(DATA_DIR, "synthetic_alerts.json")
MITRE_ATTACK_FILE = os.path.join(DATA_DIR, "mitre_attack.json")
ASSET_CRITICALITY_FILE = os.path.join(DATA_DIR, "asset_criticality.json")

# =============================================================================
# LLM GENERATION PARAMETERS
# =============================================================================
# Max tokens the LLM should generate per request.
LLM_MAX_TOKENS = int(os.getenv("LLM_MAX_TOKENS", "1024"))
# Temperature controls randomness: 0 = deterministic, 1 = creative.
# We want consistent, factual outputs, so keep this low.
LLM_TEMPERATURE = float(os.getenv("LLM_TEMPERATURE", "0.1"))
