from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Optional, List


class Severity(str, Enum):
    INFO = "INFO"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class Confidence(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"


@dataclass
class Component:
    name: str
    type: str  # activity|service|receiver|provider
    exported: bool
    permission: Optional[str]
    intent_filters: List[str]
    authority: Optional[str] = None
    notes: Optional[str] = None


@dataclass
class EvidenceStep:
    kind: str  # SOURCE|PROPAGATION|SANITIZER|SINK|NOTE|WEAK_CHECK|MISSING_ENFORCEMENT
    description: str
    method: Optional[str] = None
    notes: Optional[str] = None


@dataclass
class Finding:
    id: str
    title: str
    description: str
    severity: Severity
    confidence: Confidence
    component_name: Optional[str]
    entrypoint_method: Optional[str]
    evidence: List[EvidenceStep]
    recommendation: str
    references: List[str]
    component_desc: Optional[str] = None
    primary_method: Optional[str] = None
    sink_method: Optional[str] = None
    related_methods: List[str] = field(default_factory=list)
    severity_basis: str = "IMPACT"
    confidence_basis: Optional[str] = None
    fingerprint: Optional[str] = None
