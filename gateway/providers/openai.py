"""OpenAI (and OpenAI-compatible) provider adapter."""

from __future__ import annotations

import os

import httpx

from .base import ChatRequest, ChatResponse, Provider, ProviderError


class OpenAIProvider(Provider):
    name = "openai"

    def __init__(
        self,
        api_key: str | None = None,
        base_url: str = "https://api.openai.com/v1",
        client: httpx.AsyncClient | None = None,
    ):
        self.api_key = api_key or os.environ.get("OPENAI_API_KEY", "")
        self.base_url = base_url.rstrip("/")
        self._client = client

    async def chat(self, req: ChatRequest) -> ChatResponse:
        payload: dict = {
            "model": req.model,
            "messages": [{"role": m.role, "content": m.content} for m in req.messages],
        }
        if req.max_tokens is not None:
            payload["max_tokens"] = req.max_tokens
        if req.temperature is not None:
            payload["temperature"] = req.temperature
        client = self._client or httpx.AsyncClient(timeout=120)
        try:
            resp = await client.post(
                f"{self.base_url}/chat/completions",
                headers={"Authorization": f"Bearer {self.api_key}"},
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
            choice = data["choices"][0]["message"]
            usage = data.get("usage", {})
        except (KeyError, IndexError) as e:
            raise ProviderError(self.name, f"malformed response: {e}", retryable=False) from e
        return ChatResponse(
            text=choice.get("content") or "",
            input_tokens=int(usage.get("prompt_tokens", 0)),
            output_tokens=int(usage.get("completion_tokens", 0)),
            model=data.get("model", req.model),
            provider=self.name,
        )
