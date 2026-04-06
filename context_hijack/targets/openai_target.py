"""OpenAI-compatible target adapter."""
from __future__ import annotations

from openai import AsyncOpenAI
from context_hijack.core.models import Message
from context_hijack.targets.base import BaseTarget


class OpenAITarget(BaseTarget):
    name = "openai"

    def __init__(self, api_key: str, model: str = "gpt-4o", base_url: str = "") -> None:
        kwargs: dict = {"api_key": api_key}
        if base_url:
            kwargs["base_url"] = base_url
        self.client = AsyncOpenAI(**kwargs)
        self.model = model

    async def chat(self, messages: list[Message]) -> str:
        resp = await self.client.chat.completions.create(
            model=self.model,
            messages=[{"role": m.role, "content": m.content} for m in messages],
        )
        return resp.choices[0].message.content or ""

    async def close(self) -> None:
        await self.client.close()
