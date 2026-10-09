"""Deterministic mock provider for tests and offline demos.

Token counts are derived from text length (~4 chars/token) so cost math stays
exercisable without network access.
"""

from __future__ import annotations

from .base import ChatRequest, ChatResponse, Provider


class MockProvider(Provider):
    name = "mock"

    def __init__(self, reply: str = "mock reply"):
        self.reply = reply
        self.calls: list[ChatRequest] = []

    async def chat(self, req: ChatRequest) -> ChatResponse:
        self.calls.append(req)
        prompt_chars = sum(len(m.content) for m in req.messages)
        return ChatResponse(
            text=self.reply,
            input_tokens=max(1, prompt_chars // 4),
            output_tokens=max(1, len(self.reply) // 4),
            model=req.model,
            provider=self.name,
        )
