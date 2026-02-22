from __future__ import annotations

from typing import List

from core.config import ScanContext
from core.models import Finding
from scanners.base import BaseScanner


class WebViewScanner(BaseScanner):
    name = "webview"

    def run(self, ctx: ScanContext) -> List[Finding]:
        ctx.metrics.setdefault("scanner_stats", {})[self.name] = {
            "total": 0,
            "analyzed": 0,
            "skipped": 0,
            "skipped_no_code": 0,
            "findings": 0,
        }
        ctx.logger.debug(f"stats name={self.name} methods=0 analyzed=0 skipped_no_code=0 findings=0")
        return []
