from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional, List

from core.dataflow.taint_provider import BaseTaintProvider

from core.models import Component
from core.log import Logger


@dataclass
class ScanConfig:
    scan_mode: str
    component_filter: Optional[str]
    verbose: bool
    max_depth: int


@dataclass
class ScanContext:
    apk_path: str
    apk: object
    analysis: object
    dex: object
    components: List[Component]
    config: ScanConfig
    rules: dict
    androguard_version: str
    logger: Logger
    taint_provider: Optional[BaseTaintProvider] = None
    metrics: dict = field(default_factory=dict)
