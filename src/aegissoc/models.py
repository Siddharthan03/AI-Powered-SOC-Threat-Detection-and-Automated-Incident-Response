from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field


class Severity(str, Enum):
    low = "low"
    medium = "medium"
    high = "high"
    critical = "critical"


class Alert(BaseModel):
    """A normalised alert. `raw` comes from monitored systems, so it is untrusted."""

    id: str
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    source: str = "wazuh"
    rule_id: str
    rule_name: str
    attack_techniques: list[str] = Field(default_factory=list)
    host: str | None = None
    user: str | None = None
    src_ip: str | None = None
    raw: dict[str, Any] = Field(default_factory=dict)


class TriageResult(BaseModel):
    severity: Severity
    summary: str = Field(max_length=1000)
    likely_technique: str | None = None
    recommended_actions: list[str] = Field(default_factory=list, max_length=8)
    confidence: float = Field(ge=0.0, le=1.0)
    mode: str = "llm"  # "llm" or "fallback"