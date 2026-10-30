from __future__ import annotations
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any
import json


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")

@dataclass
class Asset:
    kind: str
    value: str
    source: str
    status: str = "observed"
    details: dict[str, Any] = field(default_factory=dict)
    discovered_at: str = field(default_factory=utc_now)

@dataclass
class Finding:
    title: str
    severity: str
    confidence: str
    asset: str
    description: str
    evidence: dict[str, Any] = field(default_factory=dict)
    recommendation: str = ""
    status: str = "potential"
    discovered_at: str = field(default_factory=utc_now)

@dataclass
class ScanResult:
    scan_id: str
    target: str
    started_at: str
    finished_at: str = ""
    assets: list[Asset] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    stats: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent, sort_keys=True)
