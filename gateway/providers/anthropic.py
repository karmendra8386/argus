"""Anthropic provider adapter (Messages API)."""

from __future__ import annotations

import os

import httpx

from .base import ChatMessage, ChatRequest, ChatResponse, Provider, ProviderError

_ANTHROPIC_VERSION = "2023-06-01"


class AnthropicProvider(Provider):
    name = "anthropic"

    def __init__(
        self,
        api_key: str | None = None,
        base_url: str = "https://api.anthropic.com",
        client: httpx.AsyncClient | None = None,
    ):
        self.api_key = api_key or os.environ.get("ANTHROPIC_API_KEY", "")
        self.base_url = base_url.rstrip("/")
        self._client = client

    def _to_anthropic(self, messages: list[ChatMessage]) -> tuple[str | None, list[dict]]:
        system = None
        out = []
        for m in messages:
            if m.role == "system":
                system = (system + "\n" if system else "") + m.content
            else:
                out.append({"role": m.role, "content": m.content})
        return system, out

    async def chat(self, req: ChatRequest) -> ChatResponse:
        system, messages = self._to_anthropic(req.messages)
        payload: dict = {
            "model": req.model,
            "messages": messages,
            "max_tokens": req.max_tokens or 1024,
        }
        if system:
            payload["system"] = system
        if req.temperature is not None:
            payload["temperature"] = req.temperature
        client = self._client or httpx.AsyncClient(timeout=120)
        try:
            resp = await client.post(
                f"{self.base_url}/v1/messages",
                headers={
                    "x-api-key": self.api_key,
                    "anthropic-version": _ANTHROPIC_VERSION,
                    "content-type": "application/json",
                },
                json=payload,
            )
        except httpx.HTTPError as e:
            raise ProviderError(self.name, f"network error: {e}", retryable=True) from e
        if resp.status_code == 429:
            raise ProviderError(self.name, "rate limited (429)", retryable=True)
        if resp.status_code >= 500:
            raise ProviderError(self.name, f"server error {resp.status_code}", retryable=True)
        if resp.status_code != 200:
            raise ProviderError(
                self.name,
                f"HTTP {resp.status_code}: {resp.text[:200]}",
                retryable=False,
            )
        data = resp.json()
        try:
            text = "".join(
                b.get("text", "") for b in data.get("content", []) if b.get("type") == "text"
            )
            usage = data.get("usage", {})
        except (KeyError, TypeError) as e:
            raise ProviderError(self.name, f"malformed response: {e}", retryable=False) from e
        return ChatResponse(
            text=text,
            input_tokens=int(usage.get("input_tokens", 0)),
            output_tokens=int(usage.get("output_tokens", 0)),
            model=data.get("model", req.model),
            provider=self.name,
        )
