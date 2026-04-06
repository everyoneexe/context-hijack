"""Abstract base class for AI model targets."""
from __future__ import annotations

import abc
from context_hijack.core.models import Message


class BaseTarget(abc.ABC):
    name: str = "base"

    @abc.abstractmethod
    async def chat(self, messages: list[Message]) -> str: ...

    async def close(self) -> None:
        pass
