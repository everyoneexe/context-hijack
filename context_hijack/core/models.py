"""Data models for context-hijack."""
from __future__ import annotations

from pydantic import BaseModel, Field
from typing import Any


class Message(BaseModel):
    role: str
    content: str


class HijackConfig(BaseModel):
    """Configuration for a hijack attack."""
    goal: str = Field(description="What the attack should achieve")
    codebase_url: str = Field(default="", description="GitHub repo URL to use as context")
    codebase_path: str = Field(default="", description="Local path to codebase")
    category: str = Field(default="auto", description="Attack category: cheat, drm, exploit, scraper, rat, phishing, generic, auto")
    target_provider: str = Field(default="anthropic", description="Target AI provider")
    target_model: str = Field(default="", description="Target model")
    max_history: int = Field(default=30, description="Max messages in fake history")


class AttackResult(BaseModel):
    strategy: str = ""
    confidence: float = 0.0
    bypass: bool = False
    response: str = ""
    history_length: int = 0
    model: str = ""
    metadata: dict[str, Any] = Field(default_factory=dict)
