from __future__ import annotations

from anthropic import AsyncAnthropic
from mnemo.core.models import Message
from mnemo.targets.base import BaseTarget


class AnthropicTarget(BaseTarget):
    name = "anthropic"

    def __init__(self, api_key: str, model: str = "claude-sonnet-4-6", base_url: str = "") -> None:
        kwargs: dict = {"api_key": api_key}
        if base_url:
            kwargs["base_url"] = base_url
        self.client = AsyncAnthropic(**kwargs)
        self.model = model

    async def chat(self, messages: list[Message]) -> str:
        system_text = ""
        chat_messages = []
        for m in messages:
            if m.role == "system":
                system_text += m.content + "\n"
            else:
                chat_messages.append({"role": m.role, "content": m.content})

        kwargs: dict = {"model": self.model, "max_tokens": 8192, "messages": chat_messages}
        if system_text.strip():
            kwargs["system"] = system_text.strip()

        resp = await self.client.messages.create(**kwargs)
        for block in resp.content:
            if hasattr(block, "text"):
                return block.text
        return ""

    async def close(self) -> None:
        await self.client.close()
