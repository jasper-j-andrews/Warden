from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, Field, ConfigDict

class SecurityEvent(BaseModel):
    model_config = ConfigDict(extra="forbid")

    event_id: str
    timestamp: datetime

    source: str
    event_type: str

    src_ip: str | None = None
    dst_ip: str | None = None

    username: str | None = None
    outcome: Literal["success", "failure", "unknown"] = "unknown"

    event_count: int = Field(default=1, ge=1)
    window_seconds: int | None = Field(default=None, ge=1)

    tags: list[str] = Field(default_factory=list)
    raw: dict[str, Any] = Field(default_factory=dict)

class RiskAssessement(BaseModel):
    event_id: str
    risk_score: int = Field(ge=0, le=100)
    severity: Literal["low", "medium", "high", "critical"]
    reasons: list[str]
    rule_ids: list[str]
    recommended_actions: list[str]