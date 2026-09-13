"""
llm/llm_client.py — LLM client abstraction for watsonx.ai and Anthropic.

This module provides a simple interface to call an LLM for text generation.
It supports two providers:

  1. IBM watsonx.ai (PRIMARY) — uses the ibm-watsonx-ai Python SDK
  2. Anthropic Claude  (FALLBACK) — uses the anthropic Python SDK

A factory function get_llm_client() reads the LLM_PROVIDER env var and
returns the right client. All clients expose the same .generate(prompt)
method, so the rest of the codebase doesn't need to know which provider
is being used.

DESIGN DECISION: We use a simple class hierarchy (not a complex plugin
system) because we only have two providers and this is a hackathon.
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from config import (
    LLM_PROVIDER,
    WATSONX_API_KEY, WATSONX_PROJECT_ID, WATSONX_URL, WATSONX_MODEL_ID,
    ANTHROPIC_API_KEY, ANTHROPIC_MODEL,
    LLM_MAX_TOKENS, LLM_TEMPERATURE,
)


class LLMClient:
    """
    Base class for LLM clients. Subclasses must implement generate().
    """

    def generate(self, prompt: str) -> str:
        """
        Send a prompt to the LLM and return the generated text.

        Args:
            prompt: The full prompt string (including any system instructions)

        Returns:
            The LLM's response as a plain string.
        """
        raise NotImplementedError("Subclasses must implement generate()")


class WatsonxClient(LLMClient):
    """
    IBM watsonx.ai client using the ibm-watsonx-ai SDK.

    This is the primary LLM provider for the hackathon since the Bob AI
    Hackathon values IBM technology integration.

    Requires environment variables:
        WATSONX_API_KEY     — Your IBM Cloud API key
        WATSONX_PROJECT_ID  — Your watsonx.ai project ID
        WATSONX_URL         — The watsonx.ai endpoint URL
    """

    def __init__(self):
        """Initialise the watsonx.ai client and model."""
        try:
            from ibm_watsonx_ai.foundation_models import ModelInference
            from ibm_watsonx_ai import Credentials
        except ImportError:
            raise ImportError(
                "ibm-watsonx-ai package not installed. "
                "Run: pip install ibm-watsonx-ai"
            )

        if not WATSONX_API_KEY:
            raise ValueError(
                "WATSONX_API_KEY not set. Add it to your .env file."
            )
        if not WATSONX_PROJECT_ID:
            raise ValueError(
                "WATSONX_PROJECT_ID not set. Add it to your .env file."
            )

        # Set up credentials
        credentials = Credentials(
            url=WATSONX_URL,
            api_key=WATSONX_API_KEY,
        )

        # Configure generation parameters
        self.gen_params = {
            "max_new_tokens": LLM_MAX_TOKENS,
            "temperature": LLM_TEMPERATURE,
            "top_p": 0.95,
            "repetition_penalty": 1.05,
        }

        # Initialise the model
        self.model = ModelInference(
            model_id=WATSONX_MODEL_ID,
            credentials=credentials,
            project_id=WATSONX_PROJECT_ID,
            params=self.gen_params,
        )

        print(f"[LLM] Initialised watsonx.ai client (model: {WATSONX_MODEL_ID})")

    def generate(self, prompt: str) -> str:
        """Send a prompt to watsonx.ai and return the response."""
        try:
            response = self.model.generate_text(prompt=prompt)
            return response.strip()
        except Exception as e:
            print(f"[LLM] watsonx.ai error: {e}")
            return f"ERROR: LLM generation failed — {e}"


class AnthropicClient(LLMClient):
    """
    Anthropic Claude client (fallback provider).

    Useful for development/testing when you don't have watsonx.ai access.

    Requires environment variable:
        ANTHROPIC_API_KEY — Your Anthropic API key
    """

    def __init__(self):
        """Initialise the Anthropic client."""
        try:
            import anthropic
        except ImportError:
            raise ImportError(
                "anthropic package not installed. Run: pip install anthropic"
            )

        if not ANTHROPIC_API_KEY:
            raise ValueError(
                "ANTHROPIC_API_KEY not set. Add it to your .env file."
            )

        self.client = anthropic.Anthropic(api_key=ANTHROPIC_API_KEY)
        self.model = ANTHROPIC_MODEL
        print(f"[LLM] Initialised Anthropic client (model: {self.model})")

    def generate(self, prompt: str) -> str:
        """Send a prompt to Anthropic Claude and return the response."""
        try:
            message = self.client.messages.create(
                model=self.model,
                max_tokens=LLM_MAX_TOKENS,
                temperature=LLM_TEMPERATURE,
                messages=[
                    {"role": "user", "content": prompt}
                ],
            )
            # Anthropic returns a list of content blocks; get the text
            return message.content[0].text.strip()
        except Exception as e:
            print(f"[LLM] Anthropic error: {e}")
            return f"ERROR: LLM generation failed — {e}"


def get_llm_client() -> LLMClient:
    """
    Factory function: returns the right LLM client based on LLM_PROVIDER.

    Usage:
        from llm.llm_client import get_llm_client
        client = get_llm_client()
        response = client.generate("Explain this alert...")

    The LLM_PROVIDER env var controls which client is created:
        "watsonx"   -> WatsonxClient (default)
        "anthropic" -> AnthropicClient
    """
    provider = LLM_PROVIDER.lower().strip()

    if provider == "anthropic":
        return AnthropicClient()
    elif provider == "watsonx":
        return WatsonxClient()
    else:
        raise ValueError(
            f"Unknown LLM_PROVIDER: '{provider}'. "
            f"Set LLM_PROVIDER to 'watsonx' or 'anthropic' in your .env file."
        )
