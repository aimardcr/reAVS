#!/usr/bin/env python3
"""AVS - Android Vulnerability Scanner.

Thin entry point.  All logic lives in :mod:`core.cli`.
"""
from __future__ import annotations

import sys

import androguard

from core.cli import main, parse_args, dedup_findings  # noqa: F401 – re-exported for tests
from core.loader import load_apk  # noqa: F401
from core.manifest import get_components  # noqa: F401
from core.rules.catalog import load_rules  # noqa: F401
from scanners.intent import IntentInjectionScanner  # noqa: F401
from scanners.provider import ContentProviderScanner  # noqa: F401
from scanners.execution import CodeExecutionScanner  # noqa: F401
from scanners.crypto import CryptographyScanner  # noqa: F401
from scanners.sql import SQLInjectionScanner  # noqa: F401
from scanners.deeplinks import DeepLinksScanner  # noqa: F401
from scanners.webview import WebViewScanner  # noqa: F401

if __name__ == "__main__":
    androguard.util.set_log("CRITICAL")
    raise SystemExit(main(sys.argv[1:]))
