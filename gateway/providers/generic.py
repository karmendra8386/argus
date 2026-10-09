"""Generic OpenAI-compatible adapter: vLLM, Ollama, llama.cpp, any proxy.

This is how self-hosted models sit behind the security layer — point at any
OpenAI-shaped endpoint.
"""

from __future__ import annotations

import os

from .openai import OpenAIProvider


class GenericProvider(OpenAIProvider):
    """An OpenAI-shaped endpoint that isn't OpenAI."""

    def __init__(
        self,
        base_url: str,
        api_key: str | None = None,
        name: str = "generic",
        client=None,
    ):
        super().__init__(
            api_key=api_key or os.environ.get("GENERIC_API_KEY", "none"),
            base_url=base_url,
            client=client,
        )
        self.name = name
