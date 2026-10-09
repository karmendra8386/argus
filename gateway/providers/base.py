"""Normalized provider interface.

Every provider adapter speaks this shape, so routing, costing, and the HTTP
layer never care which backend answered.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Dict, List, Optional


@dataclass
class ChatMessage:
    role: str  # system | user | assistant | tool
    content: str


@dataclass
class ChatRequest:
    model: str
    messages: List[ChatMessage]
    max_tokens: Optional[int] = None
    temperature: Optional[float] = None
    extra: Dict[str, object] = field(default_factory=dict)


@dataclass
class ChatResponse:
    text: str
    input_tokens: int
    output_tokens: int
    model: str
    provider: str


class Provider(ABC):
    """One LLM backend behind the gateway."""

    name: str = "base"

    @abstractmethod
    async def chat(self, req: ChatRequest) -> ChatResponse:
        """Send a chat request; raise ProviderError on failure."""
        ...


class ProviderError(Exception):
    """A provider call failed (network, auth, rate limit, bad response)."""

    def __init__(self, provider: str, message: str, retryable: bool = True):
        super().__init__(f"[{provider}] {message}")
        self.provider = provider
        self.retryable = retryable
